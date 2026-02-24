/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
        
/**     
 * @file                cdx_ehash.c     
 * @description         cdx DPAA external hash functions
 */             
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include "linux/netdevice.h"
#include "portdefs.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "misc.h"
#include "types.h"
#include "cdx.h"
#include "cdx_common.h"
#include "list.h"
#include "cdx_ioctl.h"
#include "layer2.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_ipsec.h"
#include "control_tunnel.h"
#include "control_bridge.h"
#include "fm_ehash.h"
#include "dpa_control_mc.h"
#include "control_pppoe.h"
#include "control_socket.h"
#include "module_rtp_relay.h"
#include "cdx_dpa_ipsec.h"
#include "dpa_wifi.h"
#include "module_qm.h"
#include "control_tx.h"

//#define CDX_DPA_DEBUG 1

#ifdef CDX_DPA_DEBUG
#define CDX_DPA_DPRINT(fmt, args...) printk(KERN_ERR "%s:: " fmt, __func__, ##args)
#else
#define CDX_DPA_DPRINT(fmt, args...) do { } while(0)
#endif

#define PAD(val, padsize) ((val) % (padsize)) ? ((padsize) - ((val) % (padsize))) : 0

//db entry for reusing a hm chain
#define TTL_HM_VALID            (1 << 0)
#define NAT_HM_REPLACE_SIP      (1 << 1)
#define NAT_HM_REPLACE_DIP      (1 << 2)
#define NAT_HM_REPLACE_SPORT    (1 << 3)
#define NAT_HM_REPLACE_DPORT    (1 << 4)
#define NAT_HM_VALID            ( NAT_HM_REPLACE_SIP | NAT_HM_REPLACE_DIP | NAT_HM_REPLACE_SPORT | NAT_HM_REPLACE_DPORT)
#define VLAN_STRIP_HM_VALID     (1 << 5)
#define VLAN_ADD_HM_VALID       (1 << 6)
#define EHASH_BRIDGE_FLOW       (1 << 7)
#define PPPoE_STRIP_HM_VALID    (1 << 8)
#define NAT_HM_NATPT            (1 << 9)
#define NAT_V6	                (1 << 10)
#define EHASH_IPV6_FLOW		(1 << 11)

#ifdef VLAN_FILTER
#define ROUTE_FLOW_VLAN_FIL_EN  (1 << 12) /* Flag indicating vlan filter is enabled on a bridge that involves in routing */
#define ROUTE_FLOW_PVID_SET     (1 << 13) /* Flag indicating PVID is set on rx interface in bridge, which will be set to route flow*/
#endif

#define L2_HDR_OPS(l2_info) ((l2_info.vlan_present) || (l2_info.pppoe_present) || (l2_info.num_egress_vlan_hdrs) || (l2_info.add_pppoe_hdr)) 
#define L3_HDR_OPS(l3_info) (l3_info.tnl_header_present || l3_info.add_tnl_header || l3_info.ipsec_inbound_flow)
#define L2_L3_HDR_OPS(info) (L3_HDR_OPS(info->l3_info) || L2_HDR_OPS(info->l2_info))
#define IS_IPV4_NAT(entry) ( IS_IPV4(entry) && (entry->status & CONNTRACK_NAT) )
#define IS_IPV6_NAT(entry) ( IS_IPV6(entry) && ( entry->status & ( CONNTRACK_SNAT | CONNTRACK_DNAT) ))

#define MURAM_VIRT_TO_PHYS_ADDR(addr)	((uint32_t)((uint8_t *)addr - (uint8_t *)FmMurambaseAddr) & 0xffffff)

void display_SockEntries(PSockEntry SockA, PSockEntry SockB);
void cdx_deinit_fragment_bufpool(void);

static int insert_opcodeonly_hm(struct ins_entry_info *info, uint8_t opcode);
static int create_nat_hm(struct ins_entry_info *info);
static int create_tunnel_insert_hm(struct ins_entry_info *info);
static int create_ethernet_hm(struct ins_entry_info *info, uint32_t rebuild_hdr);
static int create_ttl_hm(struct ins_entry_info *info);
static int create_hoplimit_hm(struct ins_entry_info *info);
static int create_update_dscp_hm(struct ins_entry_info *info,uint8_t opcode);
static int create_strip_eth_hm(struct ins_entry_info *info);
static int create_enque_hm(struct ins_entry_info *info);
static int create_replicate_hm(struct ins_entry_info *info);
static int fill_mcast_member_actions(RouteEntry *pRtEntry, struct ins_entry_info *info);
static int fill_pppoe_relay_actions(struct ins_entry_info *info,pPPPoE_Info entry);
static int create_tunnel_remove_hm(struct ins_entry_info *info);
static int create_pppoe_ins_hm(struct ins_entry_info *info);
static int create_pppoe_relay_hm(struct ins_entry_info *info,pPPPoE_Info entry);
static int insert_remove_pppoe_hm(struct ins_entry_info *info, uint32_t itf_index);
#ifdef VLAN_FILTER
static int insert_remove_outer_vlan_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index);
#endif
static int insert_remove_vlan_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index);
static int create_vlan_ins_hm(struct ins_entry_info *info);
static int create_eth_rx_stats_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index);
static int cdx_create_fragment_bufpool(void);
#ifdef ENABLE_INGRESS_QOS
static int create_preemptive_checks_hm(struct ins_entry_info *info,uint16_t queue_no);
#else
static int create_preemptive_checks_hm(struct ins_entry_info *info);
#endif
extern uint32_t get_logical_ifstats_base(void);

extern t_Error FM_MURAM_FreeMem(t_Handle h_FmMuram, void *ptr);
extern void  * FM_MURAM_AllocMem(t_Handle h_FmMuram, uint32_t size, uint32_t align);
extern uint64_t SYS_VirtToPhys(uint64_t addr);
extern void *FmMurambaseAddr;

#define create_ethernet_remove_hm(info) insert_opcodeonly_hm(info, STRIP_ETH_HDR)
#define create_pppoe_remove_hm(info) insert_opcodeonly_hm(info, STRIP_PPPoE_HDR)

#define CDX_FRAG_BUFFERS_CNT	2048
#define CDX_FRAG_BUFF_SIZE	1500

/* Flags that reside in MSB of t_IPF_TD.FragmentedFramesCounter field       */
#define DF_ACTION_MASK          0x30  /* DFAction mask                */
#define DF_ACTION_ERROR         0x00  /* DFAction: treat as error     */
#define DF_ACTION_IGNORE        0x10  /* DFAction: ignore DF bit      */
#define DF_ACTION_DONT_FRAG     0x20  /* DFAction: don't fragment     */

#define BPID_ENABLE              0x08  /* BufferPoolIDEn field         */
#define OPT_COUNTER_EN           0x04  /* IP options copy or not            */
#define CDX_FRAG_USE_BUFF_POOL

typedef struct __attribute__ ((packed)) cdx_ucode_frag_info_s
{
	uint16_t frag_options; // configure the dfAction whether to ignore or honor the DF bit
	uint16_t pad;
	uint32_t alloc_buff_failures;
	uint32_t v4_frames_counter;
	uint32_t v6_frames_counter;
	uint32_t v4_frags_counter;
	uint32_t v6_frags_counter;
	uint32_t v6_identification;
}cdx_ucode_frag_info_t;

typedef struct cdx_muram_memory_cmn_db_s
{
	cdx_ucode_frag_info_t	muram_frag_params;
	cdx_dscp_fqid_t		dscp_fqid_map;
}cdx_muram_memory_cmn_db_t;

typedef struct cdx_dscp_fq_map_fp_s
{
	int32_t				port_id;
	cdx_muram_memory_cmn_db_t	*muram_addr;
}cdx_dscp_fq_map_fp_t;

typedef struct cdx_frag_info_s
{
	struct dpa_bp 			*frag_bufpool;
	cdx_ucode_frag_info_t		*muram_frag_params;
//	uint32_t			muram_frag_params_addr;
	struct port_bman_pool_info	parent_pool_info;
	uint8_t				frag_bp_id;
} cdx_frag_info_t;

cdx_frag_info_t  		frag_info_g;
cdx_dscp_fq_map_fp_t		dscp_fq_map_ff_g;

struct dpa_bp* get_frag_bp(void)
{
	return (frag_info_g.frag_bufpool);
}

/*
 * This function returns the muRam address of dscp fqid mapping.
 * In failure case it returns NULL.
*/
cdx_dscp_fqid_t* get_dscp_fqid_map(uint32_t portid)
{
		/* No port id is configured. */
	if (dscp_fq_map_ff_g.port_id == NO_PORT)
		return NULL;
	
		/* Given port is matching */
	if (dscp_fq_map_ff_g.port_id != portid)
		return NULL;

		/* At this place, this should not be NULL */
	if (!dscp_fq_map_ff_g.muram_addr)
		return NULL;

	return &(dscp_fq_map_ff_g.muram_addr->dscp_fqid_map);
}

/*
 * This function to enable dscp fqid mapping on new interface, it updates
 * port id and resets the earlier port dscp fqid mappings. It returns
 * SUCCESS in success case, otherwise returns FAILURE.
*/
int enable_dscp_fqid_map(uint32_t portid)
{
	cdx_dscp_fqid_t *dscp_fqid_map = NULL;

	if (dscp_fq_map_ff_g.port_id != portid)
	{
		/* Now supporting only one interface, so directly updating the portid. */
		if (dscp_fq_map_ff_g.port_id == NO_PORT)
		{
			/* Make sure reset the dscp fqid map */
			if (dscp_fq_map_ff_g.muram_addr)
			{
				dscp_fqid_map =(cdx_dscp_fqid_t *) &(dscp_fq_map_ff_g.muram_addr->dscp_fqid_map);
			}

			DPA_INFO("%s()::%d muram_addr %p dscp_fqid_map %p \n", __func__, __LINE__, dscp_fq_map_ff_g.muram_addr, dscp_fqid_map);
			if ((!dscp_fqid_map) || (reset_all_dscp_fq_map_ff(dscp_fqid_map)))
				return FAILURE;

			dscp_fq_map_ff_g.port_id = portid;
		}
		else
		{
			DPA_ERROR("%s()::%d Before enable dscp fq map on portid %u, first disable on  portid %u\n",
				__FUNCTION__, __LINE__, portid, dscp_fq_map_ff_g.port_id);
			return FAILURE;
		}
	}
	else
	{
		DPA_ERROR("%s()::%d dscp fq map already mapped to the given port id %u\n",
				__FUNCTION__, __LINE__, portid);
	}

	return SUCCESS;
}

/*
 * This function to disable dscp fqid mapping on an interface, it resets the port id to -1
 * and resets all the dscp fqid mapings. It returns SUCCESS in success case otherwise returns
 * FAILURE.
*/
int disable_dscp_fqid_map(uint32_t portid)
{
	cdx_dscp_fqid_t *dscp_fqid_map = NULL;

	if (dscp_fq_map_ff_g.port_id != portid)
	{
		if (dscp_fq_map_ff_g.port_id == NO_PORT)
		{
			DPA_ERROR("%s()::%d Presently dscp fqid map is not enabled on any interface\n", __FUNCTION__, __LINE__);
		}
		else
		{
			DPA_ERROR("%s()::%d dscp fqid mapping not enabled on user input portid %u(enabled on portid %u)\n",
				__FUNCTION__, __LINE__, portid, dscp_fq_map_ff_g.port_id);
		}
		return FAILURE;
	}
	if (dscp_fq_map_ff_g.muram_addr)
		dscp_fqid_map = &(dscp_fq_map_ff_g.muram_addr->dscp_fqid_map);

	if ((!dscp_fqid_map) || (reset_all_dscp_fq_map_ff(dscp_fqid_map)))
		return FAILURE;
	/* Now supporting only one interface, so directly updating the portid. */
	dscp_fq_map_ff_g.port_id = NO_PORT;

	return SUCCESS;
}

/*
 * This function sets dscp vlan pcp mapping configuration.
 * In failure case it returns -1(nonzero).
*/
int set_dscp_vlan_pcp_map_cfg(uint8_t dscp, uint8_t vlan_pcp)
{
	en_dscp_vlanpcp_map_cfg	dscp_vlanpcp_map;

	if (ExternalHashGetDscpVlanpcpMapCfg(&dscp_vlanpcp_map) != 0)
	{
		DPA_ERROR("%s()::%d Failed to disable DSCP VLANPCP MAP configuration:\n", 
								__func__, __LINE__);
		return FAILURE;
	}

	dscp_vlanpcp_map.dscp_vlanpcp[dscp] = vlan_pcp;
	if (ExternalHashSetDscpVlanpcpMapCfg(&dscp_vlanpcp_map) != 0)
	{
		DPA_ERROR("%s()::%d Failed to disable DSCP VLANPCP MAP configuration:\n", 
								__func__, __LINE__);
		return FAILURE;
	}
	
	return SUCCESS;
}

/*
 * This function gets dscp vlan pcp mapping configuration.
 * In failure case it returns -1(nonzero).
*/
int get_dscp_vlan_pcp_map_cfg(PQueryDSCPVlanPCPMapCmd pDscpVlanPcpMap)
{
	if (ExternalHashGetDscpVlanpcpMapCfg((en_dscp_vlanpcp_map_cfg *)pDscpVlanPcpMap->vlan_pcp) != 0)
	{
		DPA_ERROR("%s()::%d Failed to disable DSCP VLANPCP MAP configuration:\n", 
								__func__, __LINE__);
		return FAILURE;
	}

	return SUCCESS;
}

/*
 * This function resets dscp vlan pcp mapping configuration.
 * In failure case it returns -1(nonzero).
*/
int reset_dscp_vlan_pcp_map_cfg(void)
{
	en_dscp_vlanpcp_map_cfg	dscp_vlanpcp_map;

	memset(&dscp_vlanpcp_map, 0, sizeof(en_dscp_vlanpcp_map_cfg));
	if (ExternalHashSetDscpVlanpcpMapCfg(&dscp_vlanpcp_map) != 0)
	{
		DPA_ERROR("%s()::%d Failed to reset DSCP VLANPCP MAP configuration:\n", 
								__func__, __LINE__);
		return FAILURE;
	}
	
	return SUCCESS;
}

#define PTR_TO_UINT(_ptr)           ((uintptr_t)(_ptr))
uint64_t XX_VirtToPhys(void * addr)
{
    return (uint64_t)SYS_VirtToPhys(PTR_TO_UINT(addr));
}

static int Get_Tnl_Ethertype(int mode )
{
	switch(mode)
	{
		case TNL_MODE_6O4:
			return ( (0x0800 << 16) | 0x86dd);
		case TNL_MODE_4O6:		
			return ( (0x86dd << 16) | 0x0800);
		default:
			return 0;
	}
}

static int fill_key_info(PCtEntry entry, uint8_t *keymem, uint32_t port_id)
{
	union dpa_key *key;
	unsigned char *saddr, *daddr;
	int i;
	uint32_t key_size;

	key = (union dpa_key *)keymem;
	//portid added to key
	key->portid = port_id;
	switch (entry->proto) {
		case IPPROTOCOL_TCP: 
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);;
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];
				key->ipv6_tcpudp_key.ipv6_protocol = entry->proto;
				key->ipv6_tcpudp_key.ipv6_sport = entry->Sport;
				key->ipv6_tcpudp_key.ipv6_dport = entry->Dport;
			}
			else
			{

				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = entry->proto;
				key->ipv4_tcpudp_key.ipv4_sport = entry->Sport;
				key->ipv4_tcpudp_key.ipv4_dport = entry->Dport;
			}
			break;

		case IPPROTOCOL_UDP:
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_tcpudp_key.ipv6_protocol = entry->proto;
				key->ipv6_tcpudp_key.ipv6_sport = entry->Sport;
				key->ipv6_tcpudp_key.ipv6_dport = entry->Dport;
                                if(entry->Sport == 0 && entry->Dport == 0)
				  	key_size -= 4;
			}
			else
			{
				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = entry->proto;
				key->ipv4_tcpudp_key.ipv4_sport = entry->Sport;
				key->ipv4_tcpudp_key.ipv4_dport = entry->Dport;
                                if(entry->Sport == 0 && entry->Dport == 0)
					key_size -= 4;
			}
			break;
		case IPPROTOCOL_ESP:
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_tcpudp_key.ipv6_protocol = IPPROTOCOL_ESP;
				key_size -= 4;
			}
			else
			{
				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = IPPROTOCOL_ESP;
				key_size -= 4;
			}
			break;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, entry->proto);
			key_size = 0;
	}
#ifdef CDX_DPA_DEBUG
	if (key_size) {
		DPA_INFO("keysize %d\n", key_size);
		display_buf(key, key_size);
	}
#endif
	return key_size;
}

/* check activity */
void hw_ct_get_active(struct hw_ct *ct)
{
	struct en_tbl_entry_stats stats;
	memset(&stats, 0, sizeof(struct en_tbl_entry_stats));
	ExternalHashTableEntryGetStatsAndTS(ct->handle, &stats);
	ct->pkts = stats.pkts;
	ct->bytes = stats.bytes;
	ct->timestamp = stats.timestamp;
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::ct %p pkts %lu, bytes %lu, timestamp %x jiffies %x\n", 
		__FUNCTION__, ct, (unsigned long)ct->pkts, (unsigned long)ct->bytes, ct->timestamp,
		JIFFIES32);
#endif
}

/* delete classif entry from table */
int delete_entry_from_classif_table(PCtEntry entry)
{
	if (!entry)
	{
		DPA_ERROR("%s:: Ct entry is NULL\n", __FUNCTION__);
		return FAILURE;
	}

	CDX_DPA_DPRINT("\n");
	if (ExternalHashTableDeleteKey(entry->ct->td, 
			entry->ct->index, entry->ct->handle)) {
                DPA_ERROR("%s::unable to remove entry from hash table\n", __FUNCTION__);
		return FAILURE;
	}
	//free table entry
	ExternalHashTableEntryFree(entry->ct->handle);
	entry->ct->handle =  NULL;
	kfree(entry->ct);
	entry->ct = NULL;
	return SUCCESS;
}

int delete_pppoe_relay_entry_from_classif_table(pPPPoE_Info entry)
{
	struct hw_ct *ct;

	ct = entry->hw_entry.ct;

	CDX_DPA_DPRINT("\n");
	if(ExternalHashTableDeleteKey(ct->td,ct->index, ct->handle))
	{
		DPA_ERROR("%s::unable to remove entry from hash table\n", __FUNCTION__);
		return FAILURE;
	}
	//free table entry
	ExternalHashTableEntryFree(ct->handle);
	ct->handle =  NULL;
	kfree(ct);
	ct = NULL;
	return SUCCESS;
}

/* delete classif entry from table */
int delete_l2br_entry_classif_table(struct L2Flow_entry *entry)
{
	struct hw_ct *ct = entry->ct;
	
	if (ct) {
		if (ct->handle) {
			if (ct->td) {
				if (ExternalHashTableDeleteKey(ct->td, ct->index, ct->handle)) {
					DPA_ERROR("%s::unable to remove entry from hash table\n",
							__FUNCTION__);
					return FAILURE;
				}
			}
			/* free table entry */
			ExternalHashTableEntryFree(ct->handle);
		}
		kfree(ct);
	}
	hlist_del(&entry->node);
	kfree(entry);
	return SUCCESS;
}

static int get_table_type(PCtEntry entry, uint32_t *type)
{
	switch (entry->proto) {
		case IPPROTOCOL_TCP:
			if (IS_IPV6_FLOW(entry)) 
				*type = IPV6_TCP_TABLE;
			else
				*type = IPV4_TCP_TABLE;
			return SUCCESS;

		case IPPROTOCOL_ESP:
			if (IS_IPV6_FLOW(entry))
				*type = IPV6_MULTICAST_TABLE;
			else
				*type = IPV4_MULTICAST_TABLE;
			return SUCCESS;

		case IPPROTOCOL_UDP:
			if (IS_IPV6_FLOW(entry)) {
				if(entry->Sport == 0 && entry->Dport == 0)
					*type = IPV6_MULTICAST_TABLE;
				else 
					*type = IPV6_UDP_TABLE;
			}
			else {
				if(entry->Sport == 0 && entry->Dport == 0)
					*type = IPV4_MULTICAST_TABLE;
				else
					*type = IPV4_UDP_TABLE;
			}
			return SUCCESS;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, entry->proto);
			break;
	}
	return FAILURE;
}

static int fill_actions(PCtEntry entry, struct ins_entry_info *info)
{
	PCtEntry twin_entry;
	uint32_t ii; 
	uint32_t rebuild_l2_hdr = 0;
#ifdef ENABLE_INGRESS_QOS
	uint16_t quenum = 0;
	union ctentry_qosmark *qosmark = (union ctentry_qosmark *)&entry->qosmark;
#endif
	uint32_t iif_index = 0, underlying_iif_index = 0;
	struct dpa_iface_info *iface_info;
	uint16_t ethertype = ETHERTYPE_IPV4;

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: entry %p, opc_ptr %p, param_ptr %p, size %d\n", 
			__FUNCTION__, entry, info->opcptr, info->paramptr, info->param_size);
#endif
	twin_entry = CT_TWIN(entry);

	//routing and ttl decr are mandatory
	//ttl decr handled as part of NAT-PT

	//mask it as ipv6 flow if required
	if (IS_IPV6_FLOW(entry))
	{
		info->flags |= EHASH_IPV6_FLOW;
		ethertype   =  ETHERTYPE_IPV6; 
	}

	if (!IS_NATPT(entry))
		info->flags |= TTL_HM_VALID;

	//strip vlan on ingress if incoming iface is vlan
	if (info->l2_info.vlan_present)
		info->flags |= VLAN_STRIP_HM_VALID;

	//strip pppoe on ingress if incoming iface is pppoe 
	if (info->l2_info.pppoe_present)
		info->flags |= PPPoE_STRIP_HM_VALID;

#ifdef VLAN_FILTER
	if(entry->pRtEntry->vlan_filter_flags & VLAN_INGRESS_FILTERED)
	{
		info->flags |= ROUTE_FLOW_VLAN_FIL_EN;
		if(entry->pRtEntry->vlan_filter_flags & VLAN_PVID)
			info->flags |= ROUTE_FLOW_PVID_SET;
	}
#endif
	//perform NAT where required
	if (IS_NATPT(entry)) {
		info->flags |= (NAT_HM_NATPT | NAT_HM_REPLACE_SPORT | NAT_HM_REPLACE_DPORT);
		info->nat_sport = twin_entry->Dport;
		info->nat_dport = twin_entry->Sport;
		if (IS_IPV6_FLOW(twin_entry))
		{
			info->flags |= NAT_V6;
			memcpy(info->v6.nat_sip, twin_entry->Daddr_v6, IPV6_ADDRESS_LENGTH);
			memcpy(info->v6.nat_dip, twin_entry->Saddr_v6, IPV6_ADDRESS_LENGTH);
		}
		else
		{
			info->v4.nat_sip = entry->twin_Daddr;
			info->v4.nat_dip = entry->twin_Saddr;
		}
		rebuild_l2_hdr = 1;
	} else {
		if (IS_IPV4_NAT(entry) || IS_IPV6_NAT(entry)) {
			switch(entry->proto) {
				case IPPROTOCOL_TCP:
				case IPPROTOCOL_UDP:
					if (entry->Sport != twin_entry->Dport) {
						info->flags |= NAT_HM_REPLACE_SPORT;
						info->nat_sport = (twin_entry->Dport);
					}
					if (entry->Dport != twin_entry->Sport) {
						info->flags |= NAT_HM_REPLACE_DPORT;
						info->nat_dport = (twin_entry->Sport);
					}
					break;
				default:
					break; 
			}
		}
		//check if ip replacement have to be done
		//nat sip if required

		if (IS_IPV6(entry))
		{
			if (entry->status & CONNTRACK_SNAT)
			{
				memcpy(info->v6.nat_sip, twin_entry->Daddr_v6 ,IPV6_ADDRESS_LENGTH);
				info->flags |= NAT_HM_REPLACE_SIP;
			}
			if (entry->status & CONNTRACK_DNAT)
			{
				memcpy(info->v6.nat_dip, twin_entry->Saddr_v6 ,IPV6_ADDRESS_LENGTH);
				info->flags |= NAT_HM_REPLACE_DIP;
			}
		}
		else 
		{
			if (entry->Saddr_v4 != entry->twin_Daddr) {
				info->v4.nat_sip = (entry->twin_Daddr);
				info->flags |= NAT_HM_REPLACE_SIP;
			}
			//nat dip if required
			if (entry->Daddr_v4 != entry->twin_Saddr) {
				info->v4.nat_dip = (entry->twin_Saddr);
				info->flags |= NAT_HM_REPLACE_DIP;
			}
		}
	}
	if (info->l2_info.num_egress_vlan_hdrs) {

		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}
	//fill all opcodes and parameters
	if(L2_L3_HDR_OPS(info))	{
		/*If L2 /L3 Headers need to be stripped off or  enabled, we strip and rebuild the headers */
		rebuild_l2_hdr = 1;
		info->eth_type  = ethertype;
	}


	while(1) {
		if ((!entry->pRtEntry) ||
				(!entry->pRtEntry->input_itf) ||
				(!entry->pRtEntry->underlying_input_itf)) {
			DPA_ERROR("%s::%d RtEntry or input_itf or underlying_input_itf is NULL\n",
					__FUNCTION__, __LINE__);
			break;
		}
		iif_index = entry->pRtEntry->input_itf->index;
		underlying_iif_index = entry->pRtEntry->underlying_input_itf->index;

		iface_info = dpa_get_ifinfo_by_itfid(entry->pRtEntry->itf->index);

#ifdef ENABLE_INGRESS_QOS
		if(qosmark->iqid_valid) {
			quenum = (qosmark->iqid & (INGRESS_FLOW_POLICER_QUEUES - 1));
		}
		if(create_preemptive_checks_hm(info,quenum))
#else
		if(create_preemptive_checks_hm(info))
#endif
			break;

#ifdef INCLUDE_ETHER_IFSTATS
		if (create_eth_rx_stats_hm(info, iif_index, underlying_iif_index))
			break;
#endif
		if(rebuild_l2_hdr || info->num_mcast_members) { 
			/* strip Eth hdr */
			if (create_strip_eth_hm(info ))
				break;
		}

		/* strip vlan hdrs is called mandatorily to validate the vlan id's,
		   for vlan traffic receiving on non-vlan interface.
		   Also to strip the vlan header for vlan-0 packets received on non-vlan interface.*/
		if (insert_remove_vlan_hm(info, iif_index, underlying_iif_index))
			break;

		if (info->l2_info.pppoe_present) {
			struct _itf *itf = NULL;

			if ((entry->pRtEntry->input_itf) && (entry->pRtEntry->input_itf->type & IF_TYPE_PPPOE))
				itf = entry->pRtEntry->input_itf;
			else
				itf = entry->pRtEntry->underlying_input_itf;

			/* strip pppoe hdrs */
			if (insert_remove_pppoe_hm(info, itf->index))
				break;
		}

		if (info->l3_info.tnl_header_present) { 
			if (create_tunnel_remove_hm(info))
				break;
		}
		if (info->flags & NAT_HM_VALID) {
			/* needs nat, create nat hm, roll in ttl as well */
			if(create_nat_hm(info))
				break;
		} else {
			/* update L3 with TTL/ HopLimit */
			if (info->flags & TTL_HM_VALID) {
				if (info->flags & EHASH_IPV6_FLOW) {
					if (create_hoplimit_hm(info))
						break;
				} else {
					if (create_ttl_hm(info))
						break;
				}
			}
		}

		if (info->num_mcast_members)
		{
			info->replicate_params =  info->paramptr;
			/* Replicate Packet */
			if (create_replicate_hm(info))
				break;
			/* We're done in the classification part, 
			 * all header manipulation per replica  will happen in the multicast member entry */
			return SUCCESS;
		}

		if (info->l3_info.add_tnl_header) {
			/* Insert Tnl header */
			if (create_tunnel_insert_hm(info)) 
				break;
		}

		if (!info->to_sec_fqid )
		{
			if (info->l2_info.add_pppoe_hdr)  {
				/* TBD why add ethernet header at all for Secure packets, 
				 * today there seems to be an expectation to have ethernet hdr + 
				 * ethertype to be copied in the encrypted packet */
				/* insert PPPoE header */
				if (create_pppoe_ins_hm(info))
					break;
			}

			if (info->l2_info.num_egress_vlan_hdrs) {
				/* insert vlan header */
				if (create_vlan_ins_hm(info))
					break;
			}
		}

		/* insert Ethernet header */
		if(create_ethernet_hm(info, rebuild_l2_hdr))
			break;

		/* enqueue Packet */
		if(create_enque_hm(info))
			break;

		return SUCCESS;	
	}
	return FAILURE;
}

/* insert classif entry into table */
int insert_entry_in_classif_table(PCtEntry entry)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	struct _itf *underlying_input_itf;
	uint32_t tbl_type;
	uint16_t flags;
	uint32_t key_size;
	uint8_t *ptr;
	int retval;

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::\n", __FUNCTION__);
	display_ctentry(entry);
#endif

	entry->ct = NULL;
	tbl_entry = NULL;	

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info)
		return FAILURE;
	info->entry = entry;
	// This can never be NULL for connection routes.
	underlying_input_itf = entry->pRtEntry->underlying_input_itf;
	//clear hw entry pointer
	entry->ct = NULL;
	if (add_incoming_iface_info(entry))
	{
		DPA_ERROR("%s::unable to get interface %d\n",__FUNCTION__,
				entry->inPhyPortNum);
		goto err_ret1;
	}
	//get fman index and port index and port id where this entry need to be added
	if (dpa_get_fm_port_index(entry->inPhyPortNum, underlying_input_itf->index, &info->fm_idx,
				&info->port_idx, &info->port_id)) {
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",
				__FUNCTION__, entry->inPhyPortNum);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) inPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
			__FUNCTION__, __LINE__, entry->inPhyPortNum, underlying_input_itf->index,
			info->fm_idx, info->port_idx, info->port_id);
#endif // CDX_DPA_DEBUG
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
				__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	if (get_table_type(entry, &tbl_type)) {
		DPA_ERROR("%s::unable to get table type\n",
				__FUNCTION__);
		goto err_ret;
	}
	info->tbl_type = tbl_type;

#if 0
	if (entry->pRtEntry->input_itf->type & IF_TYPE_WLAN)
		td = get_oh_port_td(fm_idx, port_idx, tbl_type);
	else
		//get table descriptor based on type and port
		td = dpa_get_tdinfo(fm_idx, port_idx, tbl_type);
#endif
	//get table descriptor based on type and port
	info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, tbl_type);
	if (info->td == NULL) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
				__FUNCTION__, entry->inPhyPortNum,
				tbl_type);
		goto err_ret;
	}

	if (dpa_get_tx_info_by_itf(entry->pRtEntry, &info->l2_info,
				&info->l3_info, entry->tnl_route, &entry->qosmark, (uint32_t)entry->hash)) {
		DPA_ERROR("%s::unable to get tx params\n",
				__FUNCTION__);
		goto err_ret;
	}

#ifdef DPA_IPSEC_OFFLOAD
	/* if the connection is a secure one  and  SA direction is inbound
	 * then, we should add the entry into offline ports's classification
	 * table. cdx_ipsec_fill_sec_info()  will check for the SA direction
	 * and if it is inbound will replace the table id;
	 * if the SA is outbound direction then it will fill sec_fqid in the 
	 * info struture.  
	 */ 
	if(entry->status &  CONNTRACK_SEC)
	{
		if(cdx_ipsec_fill_sec_info(entry,info))
		{
			DPA_ERROR("%s::unable to get td for offline port, type %d\n",
					__FUNCTION__, info->tbl_type);
			goto err_ret;
		}
	}
#endif

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: td info :%p\n", __FUNCTION__, info->td);
#endif
	//allocate connection tracker entry
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
				__FUNCTION__);
		goto err_ret;
	}
	//save table descriptor for entry release
	entry->ct->td = info->td;
	//get fm context
	entry->ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (entry->ct->fm_ctx == NULL) {
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
				__FUNCTION__, info->fm_idx);
		goto err_ret;
	}

	//allocate hash table entry
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::info->td %p\n", __FUNCTION__, info->td);
#endif
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
				__FUNCTION__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
#endif
	flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
		cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = cpu_to_be32(JIFFIES32);
	entry->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
	//fill key information from entry
	key_size = fill_key_info(entry, &tbl_entry->hashentry.key[0], info->port_id);
	if (!key_size) {
		DPA_ERROR("%s::unable to compose key\n",
				__FUNCTION__);
		goto err_ret;
	}	

	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];          
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	//set start of opcode list 
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - 
			GET_PARAM_OFFSET(flags));
	if (fill_actions(entry, info)) {
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
	tbl_entry->enqueue_params = info->enqueue_params;
	entry->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry); 
	if (retval == -1) {
		DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
		goto err_ret;
	}	
	entry->ct->index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	//release all allocated items
	if (entry->ct) {
		kfree(entry->ct);
		entry->ct = NULL;
	}
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
err_ret1:
	kfree(info);
	return FAILURE;
}

int insert_mcast_entry_in_classif_table(struct _tCtEntry *entry, 
					unsigned int num_members, uint64_t first_member_flow_addr,
					void *first_listener_entry)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	struct _itf *underlying_input_itf;
	uint32_t tbl_type;
	uint16_t flags;
	uint32_t key_size;
	uint8_t *ptr;
	int retval;
	
	DPA_INFO("%s::\n", __FUNCTION__);
#ifdef CDX_DPA_DEBUG
/*	display_ctentry(entry); */
#endif
	
	entry->ct = NULL;
	tbl_entry = NULL;	
	
	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info)
		return FAILURE;
	
	info->entry = entry;
	// same as above function insert_entry_in_classif_table, FOLLOWING TWO LINES ADDED ADDITIONALLY
	info->first_member_flow_addr_hi = cpu_to_be16((first_member_flow_addr >> 32) & 0xffff);
	info->first_member_flow_addr_lo = cpu_to_be32(first_member_flow_addr  & 0xffffffff);
	info->num_mcast_members = num_members;
	info->first_listener_entry = first_listener_entry;
	// This can never be NULL for connection routes.
	underlying_input_itf = entry->pRtEntry->underlying_input_itf;
	//clear hw entry pointer
	entry->ct = NULL;
	if (add_incoming_iface_info(entry))
	{
		DPA_ERROR("%s::unable to get interface %d\n",__FUNCTION__,
							entry->inPhyPortNum);
		goto err_ret1;
	}
	//get fman index and port index and port id where this entry need to be added
	if (dpa_get_fm_port_index(entry->inPhyPortNum, underlying_input_itf->index, &info->fm_idx,
			&info->port_idx, &info->port_id)) {
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",
						__FUNCTION__, entry->inPhyPortNum);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) inPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
			__FUNCTION__, __LINE__, entry->inPhyPortNum, underlying_input_itf->index,
			info->fm_idx, info->port_idx, info->port_id);
#endif // CDX_DPA_DEBUG
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
					__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	if (get_table_type(entry, &tbl_type)) {
		DPA_ERROR("%s::unable to get table type\n",
							__FUNCTION__);
		goto err_ret;
	}
	
	//get table descriptor based on type and port
	info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, tbl_type);
	if (info->td == NULL) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
							__FUNCTION__, entry->inPhyPortNum,
								tbl_type);
		goto err_ret;
	}
	DPA_INFO("%s:: td info :%p\n", __FUNCTION__, info->td);
	//allocate connection tracker entry
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
								__FUNCTION__);
		goto err_ret;
	}
	//save table descriptor for entry release
	entry->ct->td = info->td;
	//get fm context
	entry->ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (entry->ct->fm_ctx == NULL) {
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
						__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	
	if (dpa_get_tx_info_by_itf(entry->pRtEntry, &info->l2_info,
			&info->l3_info, entry->tnl_route, &entry->qosmark, (uint32_t)entry->hash)) {
		DPA_ERROR("%s::unable to get tx params\n",
									__FUNCTION__);
		goto err_ret;
	}
	
	//allocate hash table entry
	DPA_INFO("%s::info->td %p\n", __FUNCTION__, info->td);
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
									__FUNCTION__);
		goto err_ret;
	}
	DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
		flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
			cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = cpu_to_be32(JIFFIES32);
	entry->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
//fill key information from entry
	key_size = fill_key_info(entry, &tbl_entry->hashentry.key[0], info->port_id);
	if (!key_size) {
		DPA_ERROR("%s::unable to compose key\n",
								__FUNCTION__);
		goto err_ret;
	}	
		
	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];			
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	//set start of opcode list 
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - 
		GET_PARAM_OFFSET(flags));
	if (fill_actions(entry, info)) {
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
	tbl_entry->replicate_params = info->replicate_params;
	tbl_entry->enqueue_params = info->enqueue_params;
	entry->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry); 
	if (retval == -1) {
		DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
		goto err_ret;
	}	
	entry->ct->index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	//release all allocated items
	if (entry->ct)
		kfree(entry->ct);
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
err_ret1:
	kfree(info);
	return FAILURE;
}

static int fill_bridge_actions(struct ins_entry_info *info, POnifDesc ifdesc)
{
	struct L2Flow_entry *entry;
	int ii;
	int rebuild_l2_hdr = 0;

	entry = (struct L2Flow_entry *)info->entry;
	info->flags |= EHASH_BRIDGE_FLOW;
#ifdef INCLUDE_ETHER_IFSTATS

	if (create_eth_rx_stats_hm(info, ifdesc->itf->index, 0)) 
		return FAILURE;
#endif
#ifdef VLAN_FILTER
	if ((entry->l2flow.vlan_flags & VLAN_FILTERED) || info->l2_info.vlan_present)
#else
	if (info->l2_info.vlan_present)
#endif
	{
		info->flags |= VLAN_STRIP_HM_VALID;
	}

#ifdef VLAN_FILTER
	if ((entry->l2flow.vlan_flags & VLAN_FILTERED)) {
		info->l2_info.vlan_filtering = 1;
		if (!(entry->l2flow.vlan_flags & VLAN_UNTAGGED)) {
			/* Add tag */
			info->flags |= VLAN_ADD_HM_VALID;
			info->l2_info.num_egress_vlan_hdrs = 1;
			info->l2_info.egress_vlan_hdrs[0].tpid = ETHERTYPE_VLAN;
			info->l2_info.egress_vlan_hdrs[0].tci = entry->l2flow.vid;
			info->vlan_ids[0] = info->l2_info.egress_vlan_hdrs[0].tci;
			/* For egress tagged, if inner vlan present, then it is double tagged.
			   info->ethtype is set accordingly to use it further while filling insert_remove_vlan_hm */
			if (entry->l2flow.cvlan_tag) {
				info->eth_type = ETHERTYPE_VLAN;
			}
		}
		else {
			/* Do not add the tag*/
			info->l2_info.num_egress_vlan_hdrs = 0;
			/* For egress untagged, if  vlan present, then it is double tagged.
			   info->ethtype is set accordingly to use it further while filling create_ethernet_hm*/
			if (entry->l2flow.svlan_tag) {
				info->eth_type = ETHERTYPE_VLAN;
			}
		}
	}
	else if (info->l2_info.num_egress_vlan_hdrs)
#else
	if (info->l2_info.num_egress_vlan_hdrs)
#endif
	{

		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}

	if(info->flags & (VLAN_STRIP_HM_VALID | VLAN_ADD_HM_VALID))
		rebuild_l2_hdr = 1;


	if(rebuild_l2_hdr) { 
		/* strip Eth hdr */
		if (create_strip_eth_hm(info ))
			return FAILURE;
	}
	/* strip vlan headers in the ingress packet */
#ifdef VLAN_FILTER
	if ((entry->l2flow.vlan_flags & VLAN_FILTERED)) {
		/* Always try to strip outer vlan header if present */
		if (insert_remove_outer_vlan_hm(info, ifdesc->itf->index, 0 )) {
			DPA_ERROR("%s::unable to strip outer vlan header\n", __FUNCTION__);
			return FAILURE;
		}
	}
	else {
#else
		{
#endif
		if (insert_remove_vlan_hm(info, ifdesc->itf->index, 0 )) {
			DPA_ERROR("%s::unable to strip vlan header\n", __FUNCTION__);
			return FAILURE;
		}
	}

	if (info->l2_info.num_egress_vlan_hdrs) {
		printk("VLAN hm insert\n");
		if (create_vlan_ins_hm(info))
			return FAILURE;
	}


	if(rebuild_l2_hdr)
		if(create_ethernet_hm(info, rebuild_l2_hdr))
			return FAILURE;

	if(create_enque_hm(info))
		return FAILURE;
	return SUCCESS;
}

int insert_pppoe_relay_entry_in_classif_table(pPPPoE_Info entry)  /* struct _tPPPoE_Info *entry)*/
{
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	union dpa_key *key;
	struct ins_entry_info *info;
	uint8_t *ptr;
	POnifDesc ifdesc;
	uint32_t portid,flags,key_size;
	struct hw_ct *ct = NULL;
	int retval;

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if(!info)
	{
		DPA_ERROR("%s::unable to allocate mem for info\n", __FUNCTION__);
		goto err_ret;
	}
	DPA_INFO("%s(%d) incoming interface %s\n",__FUNCTION__,__LINE__,&entry->hw_entry.in_ifname[0]);
	DPA_INFO("%s(%d) outgoing interface %s\n",__FUNCTION__,__LINE__,&entry->relay->hw_entry.in_ifname[0]);   

	if((ifdesc = get_onif_by_name(&entry->hw_entry.in_ifname[0])) == NULL)
	{
		DPA_ERROR("%s::unable to validate incoming iface %s\n", __FUNCTION__,&entry->hw_entry.in_ifname[0]);
		goto err_ret;
	}
	DPA_INFO("%s(%d) ifdesc->itf->index %d\n",__FUNCTION__,__LINE__,ifdesc->itf->index);

	if(dpa_get_fm_port_index(ifdesc->itf->index,0, &info->fm_idx,&info->port_idx, &portid))
	{
		DPA_ERROR("%s::unable to get fm-index for input iface %s\n",__FUNCTION__, &entry->hw_entry.in_ifname[0]);
		goto err_ret;
	}
	DPA_INFO("%s(%d) fm_idx %d, port_idx %d, port_id %d\n",__FUNCTION__,__LINE__,info->fm_idx, info->port_idx, portid);

	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if(!info->fm_pcd)
	{
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	DPA_INFO("%s(%d) fm_pcd %p \n",__FUNCTION__,__LINE__, info->fm_pcd);

	//get egress FQID
	if(dpa_get_tx_fqid_by_name(&entry->relay->hw_entry.in_ifname[0], &info->l2_info.fqid, &info->l2_info.is_dscp_fq_map, (uint32_t)entry->sessionID))
	{
		DPA_ERROR("%s::unable to get tx params-fqid\n",__FUNCTION__);
		goto err_ret;
	}
	DPA_INFO("\r\n egress fq_id = %d \r\n",info->l2_info.fqid); 

	//disable frag
	info->l2_info.mtu = 0xffff;

#ifdef CDX_DPA_DEBUG
	//     DPA_INFO("%s:: mtu %d\n", __FUNCTION__, dev->mtu);
#endif

	//get table descriptor based on type and port
	info->td = dpa_get_tdinfo(info->fm_idx, portid, PPPOE_RELAY_TABLE);    //ETHERNET_TABLE
	if(info->td == NULL)
	{
		DPA_ERROR("%s::unable to get td for input iface %s\n",__FUNCTION__, &entry->hw_entry.in_ifname[0]);
		goto err_ret;
	}
	DPA_INFO("%s(%d) td %p \n",__FUNCTION__,__LINE__, info->td); 

	//allocate hw entry
	ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct) , GFP_KERNEL);
	if(!ct)
	{
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",__FUNCTION__);
		goto err_ret;
	}

	entry->hw_entry.ct = ct;
	ct->handle = NULL;
	//save table descriptor for entry release
	ct->td = info->td;

	//get fm context
	ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if(ct->fm_ctx == NULL)
	{
		DPA_ERROR("%s::failed to get ctx from fm idx %d\n", __FUNCTION__, info->fm_idx);
		goto err_ret;
	}

	//Allocate hash table entry
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if(!tbl_entry)
	{
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",__FUNCTION__);
		goto err_ret;
	}

#ifdef CDX_DPA_DEBUG
	printk("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
#endif

	//fill key info
	key = (union dpa_key *)&tbl_entry->hashentry.key[0];
	//portid added to key
	key->portid = portid;

	//fill src mac address,ethtype and pppoe session id
	memcpy(&key->pppoe_relay_key.ether_sa[0], &entry->DstMAC[0],6);
	key->pppoe_relay_key.ether_type = cpu_to_be16(0x8864);
	DPA_INFO("\r\n session id %x",entry->sessionID);
	DPA_INFO("\r\n relay session id %x",entry->relay->sessionID);
	key->pppoe_relay_key.session_id = entry->sessionID;
	key_size = (sizeof(struct pppoe_relay_key) + 1);
	DPA_INFO("\r\n key size = %d",key_size);

#ifdef CDX_DPA_DEBUG
	if(key_size)
	{
		DPA_INFO("keysize %d\n", key_size);
		display_buf(key, key_size);
	}
#endif

	flags = 0;

	//round off keysize to next 4 bytes boundary
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);

	info->opcptr = ptr;   //set start of opcode list
	ptr += MAX_OPCODES;   //ptr now after opcode section

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));

	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	/* param pointer and opcode pointer now valid */
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - GET_PARAM_OFFSET(flags));

	/* fill the pppoe relay parameters */

	if(fill_pppoe_relay_actions(info,entry))
	{
		DPA_ERROR("%s::unable to fill pppoe relay actions\n", __FUNCTION__);
		goto err_ret;
	}
	DPA_INFO("\r\ninsert_pppoe_relay_entry_in_classif_table:pppoe relay actions are filled successfully");
	ct->handle = tbl_entry;

#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif 

	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry);
	if(retval == -1)
	{
		DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
		goto err_ret;
	}
	DPA_INFO("\r\n insert_pppoe_relay_entry_in_classif_table: Added the pppoe relay key successfully");
	ct->index = (uint16_t)retval;
	ct->handle = tbl_entry;
	kfree(info);
	return SUCCESS;

err_ret:
	DPA_INFO("%s::unable to add entry in hash table\n", __FUNCTION__);
	//release all allocated items
	if(entry->hw_entry.ct)
		kfree(entry->hw_entry.ct);
	if(tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);

	kfree(info);
	return FAILURE;
}     

//fill all opcodes and parameters for pppoe relay functionality.
static int fill_pppoe_relay_actions(struct ins_entry_info *info,pPPPoE_Info entry) /* struct _tPPPoE_Info *entry) */
{

#ifdef CDX_DPA_DEBUG
	// DPA_INFO("%s:: entry %p, opc_ptr %p, param_ptr %p, size %d\n",
	//          __FUNCTION__, pRtEntry, info->opcptr, info->paramptr, info->param_size);
#endif

	DPA_INFO("%s(%d) create_pppoe_relay_hm\n",__FUNCTION__,__LINE__);
	if(create_pppoe_relay_hm(info,entry))
		return FAILURE;  
	return SUCCESS;
}

int add_l2flow_to_hw(struct L2Flow_entry *entry)
{
	int retval;
	POnifDesc ifdesc, oifdesc; 
	uint32_t flags;
	uint32_t fm_idx;
	uint32_t port_idx;
	void *td;
	uint8_t *ptr;
	struct ins_entry_info *info;
	struct hw_ct *ct;
	uint32_t portid;
	struct en_exthash_tbl_entry *tbl_entry;

	if((ifdesc = get_onif_by_name(&entry->in_ifname[0])) == NULL) {
		DPA_ERROR("%s::%d unable to validate in iface %s\n", 
				__FUNCTION__, __LINE__, &entry->in_ifname[0]);
		return FAILURE;
	}
	if (dpa_get_fm_port_index(ifdesc->itf->index,0, &fm_idx,
				&port_idx, &portid)) {
		DPA_ERROR("%s::%d unable to get fmindex for iface %s\n",
				__FUNCTION__, __LINE__, &entry->in_ifname[0]);
		return FAILURE;
	}

	//get table handle	
	td = dpa_get_tdinfo(fm_idx, portid, ETHERNET_TABLE);
	if (td == NULL) {
		DPA_ERROR("%s::%d unable to get td for out iface %s\n",
				__FUNCTION__, __LINE__, &entry->in_ifname[0]); 
		return FAILURE;
	}

	if((oifdesc = get_onif_by_name(&entry->out_ifname[0])) == NULL){
		DPA_ERROR("%s::unable to validate iface %s\n", __FUNCTION__,
				&entry->out_ifname[0]);
		return FAILURE;
	}

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info) {
		DPA_ERROR("%s::unable to allocate mem for info\n",
				__FUNCTION__);
		return FAILURE;
	}
	info->td = td;
	tbl_entry = NULL;
	info->entry = entry;
	//allocate hw entry
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct) , GFP_KERNEL);
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
				__FUNCTION__);
		goto err_ret;
	}
	ct = entry->ct;
	ct->handle = NULL;
	ct->td = td;

	/* Get ingress l2 information */
	if (dpa_check_for_logical_iface_types(ifdesc->itf, NULL, &info->l2_info, NULL)) {
		DPA_ERROR("%s::get_iface_type failed iface %d\n", __FUNCTION__,  ifdesc->itf->index);
		goto err_ret;
	} 

	/* Get egress l2 information */
	if (dpa_get_tx_l2info_by_itf(&info->l2_info, oifdesc, (uint32_t)entry->hash))
	{
		DPA_ERROR("%s::unable to get tx params\n",__FUNCTION__);
		goto err_ret;
	}

	//allocate hash table entry
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
				__FUNCTION__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
#endif
	{
		union dpa_key *key;

		//fill key info
		key = (union dpa_key *)&tbl_entry->hashentry.key[0];
		//portid added to key
		key->portid = portid;
		//fill mac addresses and type
		memcpy(&key->ether_key.ether_da[0], &entry->l2flow.da[0], ETH_ALEN);
		memcpy(&key->ether_key.ether_sa[0], &entry->l2flow.sa[0], ETH_ALEN);
		key->ether_key.ether_type = (entry->l2flow.ethertype); 
		memcpy(&info->l2_info.l2hdr[0], &entry->l2flow.da[0], ETH_ALEN);
		memcpy(&info->l2_info.l2hdr[ETH_ALEN], &entry->l2flow.sa[0], ETH_ALEN);
	}
	//round off keysize to next 4 bytes boundary
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
	ptr += ALIGN((sizeof(struct ethernet_key) + 1), TBLENTRY_OPC_ALIGN);
	//set start of opcode list
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	flags = 0;
	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
		cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = cpu_to_be32(JIFFIES32);
	entry->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - GET_PARAM_OFFSET(flags));
	//disable frag
	info->l2_info.mtu = 0xffff;
	info->eth_type = ntohs(entry->l2flow.ethertype);
	info->port_id = portid;

	/* fill actions required by entry*/
	if (fill_bridge_actions(info, ifdesc)) {
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
	/* add entry to table */
	retval = ExternalHashTableAddKey(info->td, 
			(sizeof(struct ethernet_key) + 1), tbl_entry);
	if (retval == -1) {
		DPA_ERROR("%s::unable to add table entry\n", __FUNCTION__);
		goto err_ret;
	}
	entry->ct->index = retval;
	/* save handle for delete */
	ct->handle = tbl_entry;
	kfree(info);
	return SUCCESS;
err_ret:
	if (tbl_entry) {
		ExternalHashTableEntryFree(tbl_entry);
	}
	if (entry->ct) {
		kfree(entry->ct);
	}
	kfree(info);
	return FAILURE;
}

static int create_pppoe_relay_hm(struct ins_entry_info *info,pPPPoE_Info entry) /* struct _tPPPoE_Info *entry) */
{
	struct en_ehash_replace_pppoe_hdr_params *param;

	if(info->opc_count == MAX_OPCODES)
		return FAILURE;
	if(sizeof(struct en_ehash_replace_pppoe_hdr_params) > info->param_size)
		return FAILURE;

	param = (struct en_ehash_replace_pppoe_hdr_params *)info->paramptr;
	info->paramptr += sizeof(struct en_ehash_replace_pppoe_hdr_params);
	info->param_size -= sizeof(struct en_ehash_replace_pppoe_hdr_params);
	*(info->opcptr) = REPLACE_PPPOE_HDR;
	info->opc_count++;
	info->opcptr++;

	memcpy(&param->destination_mac[0], &entry->relay->DstMAC[0], ETHER_ADDR_LEN);
	memcpy(&param->source_mac[0], &entry->relay->hw_entry.SrcMAC[0], ETHER_ADDR_LEN);
	param->session_id = entry->relay->sessionID;
	param->fqid = cpu_to_be32(info->l2_info.fqid);

#ifdef INCLUDE_ETHER_IFSTATS
	{
		uint8_t offset;
		uint32_t word;

		offset = info->l2_info.ether_stats_offset;
		word = ((get_logical_ifstats_base() +
					(offset * sizeof(struct en_ehash_stats))) & 0xffffff);
		param->stats_ptr = cpu_to_be32(word);

#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, (word & 0xffffff));
#endif
	}
#else
	param->stats_ptr = 0;
#endif  

	return SUCCESS;
}

static int create_pppoe_ins_hm(struct ins_entry_info *info)
{
	struct en_ehash_insert_pppoe_hdr *param;	
	uint32_t word;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_insert_pppoe_hdr) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_insert_pppoe_hdr *)info->paramptr;
	info->paramptr += sizeof(struct en_ehash_insert_pppoe_hdr);
	info->param_size -= sizeof(struct en_ehash_insert_pppoe_hdr);
	*(info->opcptr) = INSERT_PPPoE_HDR;
	info->opc_count++;
	info->opcptr++;
	/* Update the Ethertype now PPPoE is the outermost header  */
	info->eth_type = ETHERTYPE_PPPOE;
#ifdef INCLUDE_PPPoE_IFSTATS
	{
		uint8_t offset;

		offset = (info->l2_info.pppoe_stats_offset & ~STATS_WITH_TS);
		word = (get_logical_ifstats_base() + 
				(offset * sizeof(struct en_ehash_stats_with_ts)));
		param->stats_ptr = cpu_to_be32(word);
	}
#else
	param->stats_ptr = 0;	
#endif
	word = ((PPPoE_VERSION << 28) | (PPPoE_TYPE << 24) | (PPPoE_CODE << 16) | 
			(info->l2_info.pppoe_sess_id));
	param->word = cpu_to_be32(word);
	return SUCCESS;
}

static int create_vlan_ins_hm(struct ins_entry_info *info)
{
	int32_t ii, jj;
	uint32_t word;
	struct en_ehash_insert_vlan_hdr *param;
	struct dpa_l2hdr_info *l2_info;
	uint32_t *ptr;
	uint32_t param_size;
	uint32_t num_egress_vlan_hdrs;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	
	l2_info = &(info->l2_info);
	param = (struct en_ehash_insert_vlan_hdr *)info->paramptr;
	num_egress_vlan_hdrs = l2_info->num_egress_vlan_hdrs;
	/* dscp vlan pcp mapping enabled. */
	if (l2_info->dscp_vlanpcp_map_enable) {
		word = (1 << 30); /* Enable dscp vlanpcp map_enable bit in opcode */
	}
	else
		word = 0; /* Disable dscp vlanpcp map_enable bit in opcode */

	param_size = (sizeof(struct en_ehash_insert_vlan_hdr) + 
			(num_egress_vlan_hdrs * sizeof(uint32_t)));
	if (param_size > info->param_size)
		return FAILURE;

	word |= (num_egress_vlan_hdrs << 24);
	/* add vlan headers */
	ptr = (uint32_t *)&param->vlanhdr[0];
	info->vlan_hdrs = ptr;
	for (jj =0 ,ii = num_egress_vlan_hdrs - 1 ; ii >=0 ; ii--) {
		*(ptr + ii) = cpu_to_be32((l2_info->egress_vlan_hdrs[jj++].tci << 16) | (uint32_t )info->eth_type);
		info->eth_type = l2_info->egress_vlan_hdrs[ii].tpid;
	}

#ifdef INCLUDE_VLAN_IFSTATS
	/* If there are no actual vlans, then should not update interface stats pointer */
	/* because there is no vlan interfaces on egress side.*/
	/* vlan id can be 0 when there is only one vlan, and in word stats_ptr bits */
	/* already set to 0(NULL), so we can skip the stats.*/
	if (!l2_info->egress_vlan_hdrs[0].tci)
		goto skip_stats;
#ifdef VLAN_FILTER
	if (!l2_info->vlan_filtering)
#endif
	{
		uint8_t *st_ptr;

		if (num_egress_vlan_hdrs > 1) {
			/* set pointer last vlan offset */
			st_ptr = (uint8_t *)((uint32_t *)ptr + (num_egress_vlan_hdrs ));
			param_size = ALIGN(param_size + num_egress_vlan_hdrs, sizeof(uint32_t));
			if (param_size > info->param_size)
				return FAILURE;	
			/* add stats base */
			word |= (get_logical_ifstats_base());
			for (ii = num_egress_vlan_hdrs - 1 ; ii >=0 ; ii--) {
				*st_ptr = l2_info->vlan_stats_offsets[ii];
				/* save offset reversed order so that uCode can update easily */
				st_ptr++;
			}
		} else {
			/* single Vlan header, add stats ptr directly */
			word |= (get_logical_ifstats_base() + 
					l2_info->vlan_stats_offsets[0] * sizeof(struct en_ehash_stats));
		}
	}
#else
	DPA_INFO("%s::Vlan statistics disabled\n", __FUNCTION__);
#endif
skip_stats:
	/* write word */
	param->word = cpu_to_be32(word);
	/* write opcode and update pointers */
	*(info->opcptr) = INSERT_VLAN_HDR;
	info->opc_count++;
	info->opcptr++;
	info->paramptr += param_size;
	info->param_size -= param_size;
	return SUCCESS;
}

static int create_ethernet_hm(struct ins_entry_info *info, uint32_t update_ethtype)
{
	struct dpa_l2hdr_info *l2_info;
	uint32_t ii;
	uint32_t header_padding;
	uint32_t hdrlen;
	struct en_ehash_insert_l2_hdr *l2param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;

	l2_info = &info->l2_info;
	l2param = (struct en_ehash_insert_l2_hdr *)info->paramptr;
	hdrlen = (ETHER_ADDR_LEN * 2);
	if (update_ethtype) /* updating ether header here */ 
		hdrlen +=ETHER_TYPE_LEN;
	ii = ALIGN((hdrlen + sizeof(struct en_ehash_insert_l2_hdr)), sizeof(uint32_t));
	if (ii > info->param_size)
		return FAILURE;
	//adjust param ptrs and size
	info->paramptr += ii;
	info->param_size -= ii;
	header_padding =  ((hdrlen + sizeof(struct en_ehash_insert_l2_hdr))% sizeof(uint32_t));
	ii =  hdrlen |(header_padding << 29);
	//add opcode, adjust size and ptr
	l2param->word = cpu_to_be32(ii);
	*(info->opcptr) = INSERT_L2_HDR;
	info->opc_count++;
	info->opcptr++;
	if (l2_info->add_pppoe_hdr) {
		//if pppoe header required, replace dest with ac conc address
		memcpy(&l2param->l2hdr[0], &l2_info->ac_mac_addr[0],
				ETHER_ADDR_LEN);
	} else {
		//if no pppoe header required, replace dest with gw address
		memcpy(&l2param->l2hdr[0], &l2_info->l2hdr[0],
				ETHER_ADDR_LEN);
	}
	// write source address
	memcpy(&l2param->l2hdr[ETHER_ADDR_LEN], &l2_info->l2hdr[ETHER_ADDR_LEN],
			ETHER_ADDR_LEN);
	*(uint16_t*) (&l2param->l2hdr[2*ETHER_ADDR_LEN]) = htons(info->eth_type);

	return SUCCESS;
}

static int insert_remove_pppoe_hm(struct ins_entry_info *info, uint32_t itf_index)
{
	uint32_t param_size;
	struct en_ehash_strip_pppoe_hdr *param;
	uint32_t stats_ptr;
	PCtEntry ctentry;

	param = (struct en_ehash_strip_pppoe_hdr *)info->paramptr;
	param_size = sizeof(struct en_ehash_strip_pppoe_hdr);
	if (param_size > info->param_size)
		return FAILURE;
	ctentry = info->entry;
#ifdef INCLUDE_PPPoE_IFSTATS
	{
		uint8_t offset;

		if (dpa_get_iface_stats_entries(itf_index, 0, &offset, RX_IFSTATS, IF_TYPE_PPPOE)) {
			DPA_ERROR("%s::unable to get stats offset on pppoe iface on ingress\n",
					__FUNCTION__);
			return FAILURE;
		}
		offset &= ~STATS_WITH_TS;
		stats_ptr = (get_logical_ifstats_base() + 
				(offset * sizeof(struct en_ehash_stats_with_ts)));
#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, stats_ptr);
#endif
	}
#else
	stats_ptr = 0;
	DPA_INFO("%s:PPPoE ingress stats disabled\n", __FUNCTION__);
#endif
	param->stats_ptr = cpu_to_be32(stats_ptr);
	//add opcode
	*(info->opcptr) = STRIP_PPPoE_HDR;
	//adjust opc, param ptrs and size
	info->opc_count++;
	info->opcptr++;
	info->param_size -= param_size;
	info->paramptr += param_size;
	return SUCCESS;
}

#ifdef VLAN_FILTER
static int insert_remove_outer_vlan_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index)
{
	uint32_t param_size;
	struct en_ehash_strip_first_vlan_hdr *param;
	struct L2Flow_entry *entry;

	param = (struct en_ehash_strip_first_vlan_hdr *)info->paramptr;
	param_size = sizeof(struct en_ehash_strip_first_vlan_hdr);

	if (param_size > info->param_size)
                return FAILURE;

	entry = (struct L2Flow_entry *)info->entry;

	param->stats_ptr = 0;
	param->vlan_id = cpu_to_be16(entry->l2flow.vid);

	/* add opcode */
	*(info->opcptr) = STRIP_FIRST_VLAN_HDR;
	/* adjust opc, param ptrs and size */
	info->opc_count++;
	info->opcptr++;
	info->param_size -= param_size;
	info->paramptr += param_size;
	return SUCCESS;
}
#endif

static int insert_remove_vlan_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index)
{
	uint32_t param_size;
	struct en_ehash_strip_all_vlan_hdrs *param;
	uint32_t num_entries;
	uint32_t word;
	int i = 0;

	param = (struct en_ehash_strip_all_vlan_hdrs *)info->paramptr;
	param_size = sizeof(struct en_ehash_strip_all_vlan_hdrs);
#ifdef INCLUDE_VLAN_IFSTATS
	{
		uint32_t padding;
		if (dpa_get_num_vlan_iface_stats_entries(iif_index,underlying_iif_index,
					&num_entries)) {
			DPA_ERROR("%s::unable to get number on vlan iface on ingress\n",
					__FUNCTION__);
			return FAILURE;
		}
		if (num_entries > 1) {
			padding = PAD(num_entries, sizeof(uint32_t));
			param_size += (padding + num_entries);
			//check if we have room
			if (param_size > info->param_size)
				return FAILURE;
			word = ((padding << 30) | (num_entries << 24)| get_logical_ifstats_base());
			if (dpa_get_iface_stats_entries(iif_index, underlying_iif_index, 
						&param->stats_offsets[0], RX_IFSTATS, IF_TYPE_VLAN)) {
				DPA_ERROR("%s::unable to get stats offset on vlan iface on ingress\n",
						__FUNCTION__);
				return FAILURE;
			}
		} else {
			uint8_t offset;

			padding = 0;
			//check if we have room
			if (param_size > info->param_size)
				return FAILURE;
			if (dpa_get_iface_stats_entries(iif_index, underlying_iif_index,
						&offset, RX_IFSTATS, IF_TYPE_VLAN)) {
				DPA_ERROR("%s::unable to get stats offset on vlan iface on ingress\n",
						__FUNCTION__);
				return FAILURE;
			}
			word = ((num_entries << 24) |
					(get_logical_ifstats_base() + 
					 (offset * sizeof(struct en_ehash_stats))));
		}
#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::padding %d, stats ptr %x, num_entries %d\n", \
				__FUNCTION__, padding, (word & 0xffffff), num_entries);
#endif
	}
#else
	if (param_size > info->param_size)
		return FAILURE;
	word = 0;
	DPA_INFO("%s::Vlan ingress stats disabled\n", __FUNCTION__);
#endif
	param->word = cpu_to_be32(word);
	if( info->l2_info.num_ingress_vlan_hdrs)
	{
		/* Outer vlan id is stored first in param ptr and then inner vlan id.
		This is for convenience in writing ucode to validate the vlan's.
		In ucode first outer vlan is validated and then inner vlan */
		for (i = 0 ; i < info->l2_info.num_ingress_vlan_hdrs; i++) {
			param->vlan_id[i] = cpu_to_be16(info->l2_info.ingress_vlan_hdrs[info->l2_info.num_ingress_vlan_hdrs-i-1].tci);
		}
	}

	/* Physical interface(non-vlan interface) that is part of bridge can accept packets having without vlan tags.
	   where as in routing, untagged packets should not be accepted by VLAN logical interface.*/
	if(info->flags & EHASH_BRIDGE_FLOW)
	{
		if (!info->l2_info.vlan_present)
			param->op_flags |= OP_SKIP_VLAN_VALIDATE;
	}

#ifdef VLAN_FILTER
	/* When vlan filtering is enabled on a bridge(rx) and PVID is set for that flow, packets are allowed to forward*/
	if(info->flags & ROUTE_FLOW_VLAN_FIL_EN)
	{
		param->op_flags |= OP_VLAN_FILTER_EN;
		if(info->flags & ROUTE_FLOW_PVID_SET)
			param->op_flags |= OP_VLAN_FILTER_PVID_SET;
	}
#endif

	//add opcode
	*(info->opcptr) = STRIP_ALL_VLAN_HDRS;
	//adjust opc, param ptrs and size
	info->opc_count++;
	info->opcptr++;
	info->param_size -= param_size;
	info->paramptr += param_size;
	return SUCCESS;
}


/* Removes all logical headers retaining the Ethernet header as required by Sec, While stripping the headers,
 *  stats is also handled */

static int insert_remove_l2_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index)
{
	uint32_t param_size;
	struct en_ehash_strip_l2_hdrs *param;
	uint32_t num_entries;
	uint32_t word;
	uint8_t i = 0;

	param = (struct en_ehash_strip_l2_hdrs*)info->paramptr;
	param_size = sizeof(struct en_ehash_strip_l2_hdrs);
#ifdef INCLUDE_VLAN_IFSTATS
	{
		uint32_t padding;
		if (dpa_get_num_vlan_iface_stats_entries(iif_index,underlying_iif_index,
					&num_entries)) {
			DPA_ERROR("%s::unable to get number on vlan iface on ingress\n",
					__FUNCTION__);
			return FAILURE;
		}
		if (num_entries > 0) {
			if (dpa_get_iface_stats_entries(iif_index, underlying_iif_index, 
						&param->stats_offsets[0], RX_IFSTATS, IF_TYPE_VLAN)) {
				DPA_ERROR("%s::unable to get stats offset on vlan iface on ingress\n",
						__FUNCTION__);
				return FAILURE;
			}
		} 
		if(info->l2_info.pppoe_present){
			if (dpa_get_iface_stats_entries(iif_index, underlying_iif_index, 
						&param->stats_offsets[num_entries], RX_IFSTATS, IF_TYPE_PPPOE)) {
				DPA_ERROR("%s::unable to get stats offset on vlan iface on ingress\n",
						__FUNCTION__);
				return FAILURE;
				param->stats_offsets[num_entries++] &= ~STATS_WITH_TS;
			}
		}

		padding = PAD(num_entries, sizeof(uint32_t));
		param_size += (padding + num_entries);
		/* check if we have room */
		if (param_size > info->param_size)
			return FAILURE;

		word = ((padding << 30) | (num_entries << 24)| get_logical_ifstats_base());

#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::padding %d, stats ptr %x, num_entries %d\n", \
				__FUNCTION__, padding, (word & 0xffffff), num_entries);
#endif
	}
#else
	if (param_size > info->param_size)
		return FAILURE;
	word = 0;
	DPA_INFO("%s::Vlan / PPPoE ingress stats disabled\n", __FUNCTION__);
#endif
	param->word = cpu_to_be32(word);
	if( info->l2_info.num_ingress_vlan_hdrs)
	{
		/* Outer vlan id is stored first in param ptr and then inner vlan id.
		This is for convenience in writing ucode to validate the vlan's.
		In ucode first outer vlan is validated and then inner vlan */
		for (i = 0 ; i < info->l2_info.num_ingress_vlan_hdrs; i++) {
			param->vlan_id[i] = cpu_to_be16(info->l2_info.ingress_vlan_hdrs[info->l2_info.num_ingress_vlan_hdrs-i-1].tci);
		}
	}
	*(info->opcptr) = STRIP_L2_HDR;
	info->opc_count++;
	info->opcptr++;
	info->param_size -= param_size;
	info->paramptr += param_size;
	return SUCCESS;
}

static int create_ttl_hm(struct ins_entry_info *info)
{
	if(insert_opcodeonly_hm(info,UPDATE_TTL) == SUCCESS)
		return create_update_dscp_hm(info,UPDATE_TTL);

	return FAILURE;
}

static int create_hoplimit_hm(struct ins_entry_info *info)
{
	if(insert_opcodeonly_hm(info,UPDATE_HOPLIMIT) == SUCCESS)
		return create_update_dscp_hm(info,UPDATE_HOPLIMIT);

	return FAILURE;
}

static int create_update_dscp_hm(struct ins_entry_info *info,uint8_t opcode)
{
	struct en_ehash_update_dscp *ptr;
	PCtEntry ctentry = info->entry;
	union ctentry_qosmark *qosmark = (union ctentry_qosmark *)&ctentry->qosmark;
	uint32_t dscp_mark = 0;

	/* do dscp marking in the disguise of ttl/hoplimit since V3 subclass has only 3 bits */
	if((opcode == UPDATE_TTL) || (opcode == UPDATE_HOPLIMIT)) {

		if (info->param_size < sizeof(struct en_ehash_update_dscp))
			return FAILURE;

		ptr = (struct en_ehash_update_dscp *)info->paramptr;

		if(qosmark->dscp_mark_flag) {

			dscp_mark |= ((qosmark->dscp_mark_value << 2) | 0x2); /* mark the 2nd bit for dscp marking */
			ptr->dscp = cpu_to_be32(dscp_mark);
		}
		else
			ptr->dscp = 0;

		info->paramptr += sizeof(struct en_ehash_update_dscp);
		info->param_size -= sizeof(struct en_ehash_update_dscp);
	}
	return SUCCESS;
}

static int insert_opcodeonly_hm(struct ins_entry_info *info, uint8_t opcode)
{
	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	*(info->opcptr) = opcode;
	info->opc_count++;
	info->opcptr++;
	return SUCCESS;
}

static int create_nat_hm(struct ins_entry_info *info)
{
	uint8_t opcode;
	uint32_t size;
	int ret = SUCCESS;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	opcode = 0;
	if (info->flags & NAT_HM_REPLACE_SPORT) {
		opcode = UPDATE_SPORT;
	}
	if (info->flags & NAT_HM_REPLACE_DPORT) {
		opcode |= UPDATE_DPORT;
	}
	//add port translation info
	if (opcode) {
		struct en_ehash_update_port *natport;

		if (info->param_size < sizeof(struct en_ehash_update_port))
			return FAILURE;
		*(info->opcptr) = opcode;
		info->opcptr++;
		info->opc_count--;
		natport = (struct en_ehash_update_port *)info->paramptr;

		natport->sport = (info->nat_sport);
		natport->dport = (info->nat_dport);

		info->paramptr += sizeof(struct en_ehash_update_port);
		info->param_size -= sizeof(struct en_ehash_update_port);
	}

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;

	//handle NATPT case
	if (info->flags & NAT_HM_NATPT) {
		struct en_ehash_natpt_hdr *ptr;
		PCtEntry entry;
		PCtEntry twin_entry;
		uint32_t word;

		entry = info->entry;
		twin_entry = CT_TWIN(entry);
		ptr = (struct en_ehash_natpt_hdr *)info->paramptr;
		if (IS_IPV4_FLOW(twin_entry)) {
			ipv4_hdr_t *hdr;
			info->eth_type = ETHERTYPE_IPV4;

			/* 6 to 4 */
			printk("%s::changing ipv6 hdr to ipv4\n", __FUNCTION__);
			opcode = NATPT_6to4;
			size = (sizeof(struct en_ehash_natpt_hdr) +
					sizeof(ipv4_hdr_t));
			if (size > info->param_size)
				return FAILURE;
			memset(ptr, 0, size);
			/* inherit TOS and TTL values from ipv6 header fields
				 ipident from flow */
			word = (NATPT_TOU | NATPT_TLU | (sizeof(ipv4_hdr_t) << 16)
					| IPID_STARTVAL);
			ptr->word = cpu_to_be32(word);
			hdr = (ipv4_hdr_t *)&ptr->l3hdr[0];
			hdr->Version_IHL = 0x45;
			hdr->SourceAddress = (twin_entry->Daddr_v4);
			hdr->DestinationAddress = (twin_entry->Saddr_v4);
		} 
		else 
		{
			ipv6_hdr_t *hdr;
			info->eth_type = ETHERTYPE_IPV6;

			/* 4 to 6 */
			printk("%s::changing ipv4 hdr to ipv6\n", __FUNCTION__);
			opcode = NATPT_4to6;
			size = (sizeof(struct en_ehash_natpt_hdr) +
					sizeof(ipv6_hdr_t));
			if (size > info->param_size)
				return FAILURE;
			memset(ptr, 0, size);
			/* inherit Traffic class and hoplimit from ipv4 header fields */
			word = (NATPT_TCU | NATPT_HLU | (sizeof(ipv6_hdr_t) << 16));
			ptr->word = cpu_to_be32(word);
			hdr = (ipv6_hdr_t *)&ptr->l3hdr[0];
			hdr->Version_TC_FLHi = 0x60;
			memcpy(&hdr->SourceAddress[0], twin_entry->Daddr_v6, 16);
			memcpy(&hdr->DestinationAddress[0], twin_entry->Saddr_v6, 16);
		}
		//update opcode and param pointers and size
		info->paramptr += size;
		info->param_size -= size;
		*(info->opcptr) = opcode;
		info->opcptr++;
		return SUCCESS;
	}
	size = 0;
	opcode = 0;
	if(info->flags & TTL_HM_VALID) {
		if (info->flags & EHASH_IPV6_FLOW)
		{
			opcode |= UPDATE_HOPLIMIT;
			ret = create_update_dscp_hm(info,UPDATE_HOPLIMIT);
		} else {
			opcode |= UPDATE_TTL;
			ret = create_update_dscp_hm(info,UPDATE_TTL);
		}
	}

	if (info->flags & NAT_HM_REPLACE_SIP) {
		if (info->flags & EHASH_IPV6_FLOW) {
			opcode |= UPDATE_SIP_V6;
			size += sizeof(struct en_ehash_update_ipv6_ip);
		} else {
			opcode |= UPDATE_SIP_V4;
			size += sizeof(struct en_ehash_update_ipv4_ip);
		}
	}
	if (info->flags & NAT_HM_REPLACE_DIP) {
		if (info->flags & EHASH_IPV6_FLOW) {
			opcode |= UPDATE_DIP_V6;
			size += sizeof(struct en_ehash_update_ipv6_ip);
		} else {
			opcode |= UPDATE_DIP_V4;
			size += sizeof(struct en_ehash_update_ipv4_ip);
		}
	}
	if (opcode) {
		uint8_t *ptr;
		if (size > info->param_size)
			return FAILURE;
		ptr = info->paramptr;
		if (info->flags & NAT_HM_REPLACE_SIP) {
			if (info->flags & EHASH_IPV6_FLOW) {
				memcpy(ptr, &info->v6.nat_sip[0], sizeof(struct en_ehash_update_ipv6_ip));
				ptr += sizeof(struct en_ehash_update_ipv6_ip);
			} else {
				memcpy(ptr, &info->v4.nat_sip, sizeof(struct en_ehash_update_ipv4_ip));
				ptr += sizeof(struct en_ehash_update_ipv4_ip);
			}
		}	
		if (info->flags & NAT_HM_REPLACE_DIP) {
			if (info->flags & EHASH_IPV6_FLOW) {
				memcpy(ptr, &info->v6.nat_dip[0], sizeof(struct en_ehash_update_ipv6_ip));
				ptr += sizeof(struct en_ehash_update_ipv6_ip);
			} else {
				memcpy(ptr, &info->v4.nat_dip, sizeof(struct en_ehash_update_ipv4_ip));
				ptr += sizeof(struct en_ehash_update_ipv4_ip);
			}
		}
		info->paramptr = ptr;
		info->param_size -= size;
	}
	*(info->opcptr) = opcode;
	info->opcptr++;
	return ret;
}
static int create_tunnel_insert_hm(struct ins_entry_info *info) 
{
	uint32_t size;
	uint32_t word;

	struct en_ehash_insert_l3_hdr *ptr;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	size = (sizeof(struct en_ehash_insert_l3_hdr) + 
			info->l3_info.header_size);
	size = ALIGN(size, sizeof(uint32_t));
	if (size > info->param_size)
		return FAILURE;

	ptr = (struct en_ehash_insert_l3_hdr *)info->paramptr;
	switch (info->l3_info.mode) {
		case TNL_MODE_4O6:
			word = (TYPE_4o6 << 24);		
			memcpy(&ptr->l3hdr[0], &info->l3_info.header_v6, 
					info->l3_info.header_size);
			info->eth_type = ETHERTYPE_IPV6;	
			if(info->l3_info.tunnel_flags & INHERIT_TC)
				word |= (1 << 27); /* propagate tos */
			break;
		case TNL_MODE_6O4:
			word = (TYPE_6o4 << 24);		
			memcpy(&ptr->l3hdr[0], &info->l3_info.header_v4, 
					info->l3_info.header_size);
			info->eth_type = ETHERTYPE_IPV4;	
			break;
		default:
			//other types to be supported later
			return FAILURE;
	}
	word |= ((info->l3_info.header_size << 16) | IPID_STARTVAL);
	//TODO:CCS, DF, not handled now
	ptr->word = cpu_to_be32(word);
	//TODO: routing destination offset is now 0
	word = 0;
#ifdef INCLUDE_TUNNEL_IFSTATS
	{
		uint8_t offset;
		PCtEntry ctentry;

		ctentry = info->entry;
		if ((!ctentry) || (!ctentry->pRtEntry) || (!ctentry->pRtEntry->itf)) {
			DPA_ERROR("%s::%d unable to get stats offset on tunnel iface on egress\n",
					__FUNCTION__, __LINE__);
			return FAILURE;
		}
		if (dpa_get_iface_stats_entries(ctentry->pRtEntry->itf->index, 0,
					&offset, TX_IFSTATS, IF_TYPE_TUNNEL)) {
			DPA_ERROR("%s::%d unable to get stats offset on tunnel iface on egress\n",
					__FUNCTION__, __LINE__);
			return FAILURE;
		}
		word |= ((get_logical_ifstats_base() +
					(offset * sizeof(struct en_ehash_stats))) & 0xffffff);
#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, (word & 0xffffff));
#endif
	}
#endif
	info->tnl_hdr_size += info->l3_info.header_size;
	ptr->word_1 = cpu_to_be32(word);
	*(info->opcptr) = INSERT_L3_HDR;
	info->opcptr++;
	info->opc_count--;
	info->param_size -= size;
	info->paramptr += size;
	return SUCCESS;
}

static int create_tunnel_remove_hm(struct ins_entry_info *info)
{
	PCtEntry ctentry;
	struct en_ehash_remove_first_ip_hdr *param;
	uint32_t word = 0;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_remove_first_ip_hdr) > info->param_size)
		return FAILURE;
	ctentry = info->entry;
	param = (struct en_ehash_remove_first_ip_hdr *)info->paramptr;

	if ((!ctentry) || (!ctentry->pRtEntry) || (!ctentry->pRtEntry->input_itf)) {
		DPA_ERROR("%s::%d unable to get stats offset on tunnel iface on ingress\n",
				__FUNCTION__, __LINE__);
		return FAILURE;
	}

#ifdef INCLUDE_TUNNEL_IFSTATS
	{
		uint8_t offset;
		if (dpa_get_iface_stats_entries(ctentry->pRtEntry->input_itf->index, 0,
					&offset, RX_IFSTATS, IF_TYPE_TUNNEL)) {
			DPA_ERROR("%s::unable to get stats offset on tunnel iface on ingress\n",
					__FUNCTION__);
			return FAILURE;
		}
		word |= ((get_logical_ifstats_base() +
                                (offset * sizeof(struct en_ehash_stats))) & 0xffffff);
		DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, word);
	}
#else
	word = 0;
#endif
	info->eth_type = Get_Tnl_Ethertype(info->l3_info.mode) & 0xFFFF;	
	param->stats_ptr = cpu_to_be32(word);
	if(info->l3_info.tunnel_flags & DSCP_COPY)
	{
		word |= COPY_DSCP_OUTER_INNER;
		param->flags = cpu_to_be32(word);
	}
	//update opcode and param ptr
	*(info->opcptr) = REMOVE_FIRST_IP_HDR;
	info->opcptr++;
	info->opc_count--;
	info->param_size -= sizeof(struct en_ehash_remove_first_ip_hdr);
	info->paramptr += sizeof(struct en_ehash_remove_first_ip_hdr);
	return SUCCESS;
}

/* The preemptive checks header manipulation is one that can only be sealed when we know 
   where we are enqueueing the packet (opcode: ENQUEUE_PKT) which is the very last OPCODE 
   a packet manipulation goes through. The purpose of the PREEMPTIVE_CHECKS_ON_PKT is to 
   identify preemptive failures before enqueue and handle them gracefully.

   Since the opcode params are heavily dependent on other params, that might or might not be set 
   through the process of HM config, create_preemptive_checks_hm only serves as a place holder 
   for the OPcode params they will be appropriately sealed in the corresponding coupled HM  */

#ifdef ENABLE_INGRESS_QOS
static int create_preemptive_checks_hm(struct ins_entry_info *info,uint16_t queue_no)
#else
static int create_preemptive_checks_hm(struct ins_entry_info *info)
#endif
{
	struct en_ehash_preempt_op *param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_preempt_op) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_preempt_op *)info->paramptr;
	*(info->opcptr) = PREEMPTIVE_CHECKS_ON_PKT;
	info->opcptr++;
	info->opc_count--;
	info->preempt_params = info->paramptr;
	info->param_size -= sizeof(struct en_ehash_preempt_op);
	info->paramptr += sizeof(struct en_ehash_preempt_op);
#ifdef ENABLE_INGRESS_QOS
#ifdef SEC_PROFILE_SUPPORT
	if(info->to_sec_fqid) {
		if((param->pp_no = cdx_get_policer_profile_id(info->fm_idx, 
				INGRESS_SEC_POLICER_QUEUE_NUM))) {
			param->OpMask |= PREEMPT_POLICE_PKT;
		}
	}
	else
#endif /* endif for SEC_PROFILE_SUPPORT */
	{
		if((param->pp_no = cdx_get_policer_profile_id(info->fm_idx,queue_no))) {
			param->OpMask |= PREEMPT_POLICE_PKT;
		}
	}
#endif

	return SUCCESS;
}

/* This function creates preeemptive checks for NATT packets */
static int create_ipsec_preemptive_checks_hm(struct ins_entry_info *info, uint32_t spi)
{
	struct en_ehash_ipsec_preempt_op *param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_ipsec_preempt_op) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_ipsec_preempt_op *)info->paramptr;
	param->op_flags = VALIDATE_SPI;
	param->spi_param[0].spi = spi;
	param->spi_param[0].fqid = cpu_to_be32(info->to_sec_fqid);
	param->natt_arr_mask = cpu_to_be16(0x1 << 0);
	*(info->opcptr) = PREEMPTIVE_CHECKS_ON_IPSEC_PKT;
	info->opcptr++;
	info->opc_count--;
	info->preempt_params = info->paramptr;
	info->param_size -= sizeof(struct en_ehash_ipsec_preempt_op);
	info->paramptr += sizeof(struct en_ehash_ipsec_preempt_op);
	return SUCCESS;
}


static int seal_preemptive_checks_hm(struct ins_entry_info *info)
{
	struct en_ehash_preempt_op *param;
	if (!info->enqueue_params || !info->preempt_params)
		return FAILURE;
	param = (struct en_ehash_preempt_op *)info->preempt_params;
	param->mtu_offset = (info->enqueue_params - info->preempt_params); /* Offset to MTU in Param Array */

	if (!info->l2_info.is_wlan_iface)
		param->OpMask |= PREEMPT_TX_VALIDATE;

	if(!(info->flags & EHASH_IPV6_FLOW))
		param->OpMask |= PREEMPT_DFBIT_HONOR;
	return SUCCESS;	
}

static int create_eth_rx_stats_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index)
{
#ifdef INCLUDE_ETHER_IFSTATS
	uint8_t offset;
	uint32_t stats_ptr;
	struct en_ehash_update_ether_rx_stats *param;

	if(dpaa_is_oh_port(info->port_id))
		return SUCCESS;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_update_ether_rx_stats) > info->param_size)
		return FAILURE;

	param = (struct en_ehash_update_ether_rx_stats *)info->paramptr;

	if (dpa_get_iface_stats_entries(iif_index, underlying_iif_index,
				&offset, RX_IFSTATS, IF_TYPE_ETHERNET)) {
		DPA_ERROR("%s::unable to get stats offset on ethernet iface on ingress\n",
				__FUNCTION__);
		return FAILURE;
	}
	stats_ptr = (get_logical_ifstats_base() + (offset * sizeof(struct en_ehash_stats)));

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, stats_ptr);
#endif
	param->stats_ptr = cpu_to_be32(stats_ptr);
	//update opcode and param ptr
	*(info->opcptr) = UPDATE_ETH_RX_STATS;
	info->opcptr++;
	info->opc_count--;
	info->param_size -= sizeof(struct en_ehash_update_ether_rx_stats);
	info->paramptr += sizeof(struct en_ehash_update_ether_rx_stats);
#endif
	return SUCCESS;
}

static int create_strip_eth_hm(struct ins_entry_info *info)
{
	return (insert_opcodeonly_hm(info, STRIP_ETH_HDR));
}

static inline int create_enque_only_hm(struct ins_entry_info *info)
{
        return (insert_opcodeonly_hm(info, ENQUEUE_ONLY));
}

static int create_enque_hm(struct ins_entry_info *info)
{
	struct en_ehash_enqueue_param *param;
	PCtEntry entry = (PCtEntry)info->entry;
	uint32_t word = 0;

	if (info->l2_info.mtu == 0) {
		DPA_ERROR("%s::mtu is null\n", __FUNCTION__);
		return FAILURE;
	}
	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_enqueue_param) > info->param_size)
		return FAILURE;
	info->enqueue_params = info->paramptr;
	param = (struct en_ehash_enqueue_param *)info->paramptr;
	param->mtu = cpu_to_be16(info->l2_info.mtu);
	//param->bpid = cpu_to_be16(frag_info_g.frag_bp_id);
	param->bpid = frag_info_g.frag_bp_id;
#if 0
{
int ii;
	struct bm_buffer bmb[128];
for (ii =0; ii< 128; ii++)
{
	if (bman_acquire(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0) != 1) {
	DPA_INFO("%s(%d) bman_acquire failed \n", __FUNCTION__,__LINE__);
		bmb[ii].addr = 0;
	}
	else
	{
		DPA_INFO("%s(%d) bman_acquire success (ii %d) ,%lx \n", 
			__FUNCTION__,__LINE__,ii,(long unsigned int)bmb[ii].opaque);
	}
}
for (ii =0; ii< 128; ii++)
{
if (bmb[ii].addr)
	bman_release(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0);
}

}
#endif /* endif for #if 0 */
	word = 0;
#ifdef ENABLE_EGRESS_QOS	
	/* dscp_to_fq_map should be applied to packets which are getting 
	   transmitted on xmit_fqs of interface and not for pkts 
	   transmitted to secure frame queues */
	if ((info->l2_info.is_dscp_fq_map) && (!info->to_sec_fqid))
		word = DSCP_FQ_MAP_ENABLE;

	/* info->entry will be set when adding l2 or l3 flow */
	if ((info->to_sec_fqid) && (info->entry))
	{
		/* Disable PRE FRAGMENTATION when packets are destined to SEC*/
		word |= (FRAG_DISABLE);
		/* Enabling DPOVRD setting either the flow is ipv4 or ipv6 only. */
		if (IS_IPV4_FLOW(entry))
			word |= (IPSEC_DPOVRD_ENABLE|IPSEC_IPV4_ENCAPSULATION);
		else if (IS_IPV6_FLOW(entry))
			word |= (IPSEC_DPOVRD_ENABLE|IPSEC_IPV6_ENCAPSULATION);
	}
	word = word << 24;
#endif
	word |= MURAM_VIRT_TO_PHYS_ADDR(dscp_fq_map_ff_g.muram_addr);
	param->word2 = cpu_to_be32(word);
	word = 0;
	if(info->to_sec_fqid) {
		param->stats_ptr = 0;
		param->fqid = cpu_to_be32(info->to_sec_fqid);
	} else if (info->l2_info.is_wlan_iface){ /* Don't increment stats if wifi is the tx interface */
		param->stats_ptr = 0;
		word |= (uint32_t)info->l2_info.rspid << 24;
		param->word = cpu_to_be32(word);
		param->fqid = cpu_to_be32(info->l2_info.fqid);
	} else {
#ifdef INCLUDE_ETHER_IFSTATS
		uint8_t offset;

		offset = info->l2_info.ether_stats_offset;
		word = ((get_logical_ifstats_base() +
			(offset * sizeof(struct en_ehash_stats))) & 0xffffff);
		param->word  = cpu_to_be32(word);
#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, (word & 0xffffff));
#endif

#else
		param->stats_ptr = 0;
#endif

		param->fqid = cpu_to_be32(info->l2_info.fqid);
	}

	param->hdr_xpnd_sz = info->tnl_hdr_size;
	seal_preemptive_checks_hm(info);
	*(info->opcptr) = ENQUEUE_PKT;
	info->opcptr++;
	info->param_size -= sizeof(struct en_ehash_enqueue_param);
	info->paramptr += sizeof(struct en_ehash_enqueue_param);
	return SUCCESS;
}

static int create_rtprelay_process_opcode(struct ins_entry_info *info, 
				uint32_t *in_sockstats_ptr, uint32_t *rtpinfo_ptr,
				uint32_t *out_sockstats_ptr, uint8_t opcode)
{
	struct en_ehash_rtprelay_param *param;
	uint32_t ptr_val;
	
	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_rtprelay_param) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_rtprelay_param *)info->paramptr;
	ptr_val = PTR_TO_UINT(rtpinfo_ptr);
	param->rtpinfo_ptr =  cpu_to_be32(ptr_val);
	ptr_val = PTR_TO_UINT(in_sockstats_ptr);
	param->in_sock_stats_ptr =  cpu_to_be32(ptr_val);
	ptr_val = PTR_TO_UINT(out_sockstats_ptr);
	param->out_sock_stats_ptr =  cpu_to_be32(ptr_val);
	*(info->opcptr) = opcode;
	info->opcptr++;
	info->param_size -= sizeof(struct en_ehash_rtprelay_param);
	info->paramptr += sizeof(struct en_ehash_rtprelay_param);
	return SUCCESS;
}

static int create_replicate_hm(struct ins_entry_info *info)
{
	struct en_ehash_replicate_param *param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_replicate_param) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_replicate_param *)info->paramptr;
	param->first_member_flow_addr_hi = info->first_member_flow_addr_hi;
	param->first_member_flow_addr_lo = info->first_member_flow_addr_lo;
	param->first_listener_entry =  info->first_listener_entry;
	*(info->opcptr) = REPLICATE_PKT;
	info->opcptr++;
	info->param_size -= 8;
	info->paramptr += 8;
	return SUCCESS;
}

int fill_ipsec_actions(PSAEntry entry, struct ins_entry_info *info, 
			uint32_t sa_dir_in)
{
	uint32_t ii;
	uint32_t rebuild_l2_hdr = 0;

	if (sa_dir_in)
	{
		//strip vlan on ingress if incoming iface is vlan
		if (info->l2_info.vlan_present)
			info->flags |= VLAN_STRIP_HM_VALID;

		//strip pppoe on ingress if incoming iface is pppoe
		if (info->l2_info.pppoe_present)
			info->flags |= PPPoE_STRIP_HM_VALID;
	} else {
		//routing and ttl decr are mandatory
		info->flags = (TTL_HM_VALID);

		if (info->l2_info.num_egress_vlan_hdrs ) {
			info->flags |= VLAN_ADD_HM_VALID;
			for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
				info->vlan_ids[ii] =
					(info->l2_info.egress_vlan_hdrs[ii].tci);
			}
		}

	}

	info->eth_type = (entry->family == PROTO_IPV4) ? (ETHERTYPE_IPV4) : (ETHERTYPE_IPV6);


	/*  Addition of IP header requires the header to be inserted at
	 * the start of the packet. So we need to strip and rebuild the
	 * l2 header after tunnel header insertion. */
	if (L2_L3_HDR_OPS(info))
		rebuild_l2_hdr = 1;

	if(!sa_dir_in) {
		if(rebuild_l2_hdr) { 
			/* strip Eth hdr */
			if (create_strip_eth_hm(info ))
				return FAILURE;
		}

		if (info->l3_info.add_tnl_header) {
			/* Insert Tnl header */
			if (create_tunnel_insert_hm(info)) 
				return FAILURE;
		}

		if (info->l2_info.add_pppoe_hdr)  {
			/* insert PPPoE header */
			if (create_pppoe_ins_hm(info))
				return FAILURE;
		}

		if (info->l2_info.num_egress_vlan_hdrs) {
			/* insert vlan header */
			if (create_vlan_ins_hm(info))
				return FAILURE;
		}

		/* insert Ethernet header */
		if(create_ethernet_hm(info, 1 ))
			return FAILURE;

	} 
	else {
		if(IS_NATT_SA(entry))
		{
			if (create_ipsec_preemptive_checks_hm(info, entry->id.spi))
			{
				DPA_ERROR("%s::unable to add ipsec preemptive checks\n",
						__FUNCTION__);
				return FAILURE;
			}
		}

#ifdef INCLUDE_ETHER_IFSTATS
		/*update fast path ethernet stats for ESP packets
		TODO: underlying_iif_index needs to be taken care
		in sa_itf_id tunnel type cases*/
		if (create_eth_rx_stats_hm(info,info->sa_itf_id, 0)) {
			DPA_ERROR("%s::unable to add ethernet stats\n",
					__FUNCTION__);
			return FAILURE;
		}
#endif

		/* strip Eth hdrs is called mandatorily to validate the vlan id's,
		   for vlan traffic receiving on non-vlan interface.
		   Also to strip the vlan header for vlan-0 packets received on non-vlan interface.*/
		if (insert_remove_l2_hm(info, info->sa_itf_id, 0 ))
			return FAILURE;

		if(IS_NATT_SA(entry))
		{
			if(create_enque_only_hm(info)) {
				DPA_ERROR("%s::unable to add enque hm\n",
						__FUNCTION__);
				return FAILURE;
			}
			return SUCCESS;
		}

	}
	//enqueue
	if(create_enque_hm(info)) {
		DPA_ERROR("%s::unable to add enque hm\n",
				__FUNCTION__);
		return FAILURE;
	}
	return SUCCESS;
}

struct en_exthash_tbl_entry* create_exthash_entry4mcast_member(RouteEntry *pRtEntry,
	struct ins_entry_info *pInsEntryInfo, MC4Output	*pListener, struct en_exthash_tbl_entry* prev_tbl_entry, 
	uint32_t tbl_type)
{
	POnifDesc onif_desc;
	int fm_idx, port_idx;
	struct dpa_l2hdr_info *pL2Info;
	struct dpa_l3hdr_info *pL3Info;
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	struct net_device *dev;
	uint64_t phyaddr;
	uint16_t flags;
	uint8_t *ptr;

	DPA_INFO("%s(%d) listener output device %s\n",__FUNCTION__,__LINE__,pListener->output_device_str);
	onif_desc = get_onif_by_name(pListener->output_device_str); 
	if (!onif_desc)
	{
		DPA_ERROR("%s::unable to get onif for iface %s\n", __FUNCTION__, pListener->output_device_str);
		goto err_ret;
	}


	DPA_INFO("%s(%d) onif_desc->itf->index %d\n",__FUNCTION__,__LINE__,onif_desc->itf->index);
	if(dpa_get_fm_port_index(onif_desc->itf->index,0, &fm_idx, &port_idx, &pInsEntryInfo->port_id))
	{
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",__FUNCTION__, onif_desc->itf->index);
		goto err_ret;
	}

	DPA_INFO("%s(%d) fm_idx %d, port_idx %d, port_id %d\n",__FUNCTION__,__LINE__,fm_idx, port_idx, pInsEntryInfo->port_id);
	pInsEntryInfo->fm_pcd = dpa_get_pcdhandle(fm_idx);
	if (!pInsEntryInfo->fm_pcd)
	{
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",__FUNCTION__, fm_idx);
		goto err_ret;
	} 

	DPA_INFO("%s(%d) fm_pcd %p \n",__FUNCTION__,__LINE__, pInsEntryInfo->fm_pcd);
	//get table descriptor based on type and port
	pInsEntryInfo->td = dpa_get_tdinfo(pInsEntryInfo->fm_idx, pInsEntryInfo->port_id, tbl_type);
	if (pInsEntryInfo->td == NULL) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
				__FUNCTION__, onif_desc->itf->index,tbl_type);
		goto err_ret;
	}
	DPA_INFO("%s(%d) td %p \n",__FUNCTION__,__LINE__, pInsEntryInfo->td);

	//Code to create hm for mcast single member

	pInsEntryInfo->fm_idx = fm_idx;
	pInsEntryInfo->port_idx = port_idx;
	pL2Info = &pInsEntryInfo->l2_info;
	pL3Info = &pInsEntryInfo->l3_info;


	//Code to get Tx fqid of given interface

	pRtEntry->itf = onif_desc->itf;
	pRtEntry->input_itf = onif_desc->itf;
	pRtEntry->underlying_input_itf =  pRtEntry->input_itf;

	//Using default queue for multicast packets
	{
		union ctentry_qosmark qosmark;

		qosmark.markval = 0;
		if (dpa_get_tx_info_by_itf(pRtEntry, pL2Info, pL3Info, NULL, &qosmark, 0))
		{
			DPA_ERROR("%s::unable to get tx params\n",__FUNCTION__);
			goto err_ret;
		}
	}
	DPA_INFO("dpa_get_tx_info_by_itf success\n");
	dev = dev_get_by_name(&init_net, pListener->output_device_str);
	if(dev == NULL)
	{
		goto err_ret;
	}

	pL2Info->mtu = dev->mtu;
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: mtu %d\n", __FUNCTION__, dev->mtu);
#endif

	dev_put(dev);
	//allocate hash table entry
	tbl_entry = ExternalHashTableAllocEntry(pInsEntryInfo->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",__FUNCTION__);
		goto err_ret;
	}

	//#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
	//#endif
	flags = 0;
	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];			
	//set start of opcode list 
	pInsEntryInfo->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(pInsEntryInfo->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	pInsEntryInfo->paramptr = ptr;
	pInsEntryInfo->param_size = (MAX_EN_EHASH_ENTRY_SIZE - 
			GET_PARAM_OFFSET(flags));
	if(tbl_type == IPV6_MULTICAST_TABLE)
		pInsEntryInfo->flags |= EHASH_IPV6_FLOW;

	if (fill_mcast_member_actions(pRtEntry, pInsEntryInfo)) {
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, 0);
#endif // CDX_DPA_DEBUG
	phyaddr = XX_VirtToPhys(tbl_entry);
	//fill next pointer info and link into chain
	if (prev_tbl_entry)
	{
		prev_tbl_entry->next = tbl_entry;
		tbl_entry->prev = prev_tbl_entry;
		//adjust the prev pointer in the old entry
		//fill next pointer physaddr for uCode
		prev_tbl_entry->hashentry.next_entry_hi = cpu_to_be16((phyaddr >> 32) & 0xffff);
		prev_tbl_entry->hashentry.next_entry_lo = cpu_to_be32((phyaddr & 0xffffffff));
	}
	return tbl_entry;
err_ret:
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	return NULL;
}

static int fill_mcast_member_actions(RouteEntry *pRtEntry, struct ins_entry_info *info)
{
	uint32_t ii; 
	uint32_t rebuild_l2_hdr = 0;
	//POnifDesc onif_desc;


#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: entry %p, opc_ptr %p, param_ptr %p, size %d\n", 
			__FUNCTION__, pRtEntry, info->opcptr, info->paramptr, info->param_size);
#endif

	//routing and ttl decr are mandatory
	//ttl decr handled as part of NAT-PT

	/*  Addition of IP header requires the header to be inserted at the start of the packet.
			So we need to strip and rebuild the l2 header after tunnel header insertion. */
	rebuild_l2_hdr = 1;
	//		info->l2_info.add_eth_type = 1;
	if(info->flags & EHASH_IPV6_FLOW)
		info->eth_type = ETHERTYPE_IPV6;
	else
		info->eth_type = ETHERTYPE_IPV4;

	DPA_INFO("%s(%d) rebuild_l2_hdr  %d\n",__FUNCTION__,__LINE__,rebuild_l2_hdr);
	if (info->l2_info.num_egress_vlan_hdrs) {
		DPA_INFO("%s(%d) num egress vlan hdrs %d\n",
				__FUNCTION__,__LINE__, info->l2_info.num_egress_vlan_hdrs);
		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}
	//fill all opcodes and parameters
	while(1) {
		if (info->l3_info.add_tnl_header) {
			/* Insert Tnl header */
			if (create_tunnel_insert_hm(info)) 
				break;
		}

		if (info->l2_info.add_pppoe_hdr)  {
			/* insert PPPoE header */
			if (create_pppoe_ins_hm(info))
				break;
		}

		if (info->l2_info.num_egress_vlan_hdrs) {
			/* insert vlan header */
			if (create_vlan_ins_hm(info))
				break;
		}


		/* insert Ethernet header */
		if(create_ethernet_hm(info, rebuild_l2_hdr))
			return FAILURE;

		/* enqueue Packet */
		if(create_enque_hm(info))
			break;
		DPA_INFO("%s(%d) create_enque_hm\n",__FUNCTION__,__LINE__);

		return SUCCESS;
	}
	return FAILURE;
}

int cdx_init_frag_procfs(void);


int cdx_init_frag_module(void)
{
	int ret;
	uint16_t frag_options;
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;
	cdx_ucode_frag_info_t  *ucode_frag_args;


#ifdef CDX_FRAG_USE_BUFF_POOL
	ret = cdx_create_fragment_bufpool();
	if (ret)
	{
		DPA_ERROR("%s(%d) create_fragment_bufpool failed\n",__FUNCTION__,__LINE__);
		return -1;
	}
	frag_options = BPID_ENABLE;
#endif //CDX_FRAG_USE_BUFF_POOL

	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
#ifdef CDX_FRAG_USE_BUFF_POOL
		cdx_deinit_fragment_bufpool();
#endif //CDX_FRAG_USE_BUFF_POOL
		return -1;
	}

	dscp_fq_map_ff_g.muram_addr = (cdx_muram_memory_cmn_db_t *)FM_MURAM_AllocMem(h_FmMuram, 
					sizeof(cdx_muram_memory_cmn_db_t), 32);
	if (!dscp_fq_map_ff_g.muram_addr)
	{
#ifdef CDX_FRAG_USE_BUFF_POOL
		cdx_deinit_fragment_bufpool();
#endif /*CDX_FRAG_USE_BUFF_POOL*/
		return -1;
	}
	frag_info_g.muram_frag_params = (cdx_ucode_frag_info_t *)dscp_fq_map_ff_g.muram_addr;
	dscp_fq_map_ff_g.port_id = NO_PORT;
	if ((ucode_frag_args = kmalloc(sizeof(cdx_ucode_frag_info_t), GFP_KERNEL)) == NULL)
	{
		DPA_ERROR("%s(%d) Failed to allocate memory:\n", __FUNCTION__, __LINE__);
		FM_MURAM_FreeMem(h_FmMuram, (void *)dscp_fq_map_ff_g.muram_addr);
		dscp_fq_map_ff_g.muram_addr = NULL;
		frag_info_g.muram_frag_params = NULL;
#ifdef CDX_FRAG_USE_BUFF_POOL
		cdx_deinit_fragment_bufpool();
#endif /* CDX_FRAG_USE_BUFF_POOL */
		return -1;
	}

	ucode_frag_args->alloc_buff_failures = 0;
	ucode_frag_args->v4_frames_counter = 0;
	ucode_frag_args->v6_frames_counter = 0;
	ucode_frag_args->v6_frags_counter = 0;
	ucode_frag_args->v4_frags_counter = 0;
	ucode_frag_args->v6_identification = cpu_to_be32(1);
	frag_options |= OPT_COUNTER_EN;
	ucode_frag_args->frag_options = cpu_to_be16(frag_options); 

	copy_ddr_to_muram_and_free_ddr((void *)frag_info_g.muram_frag_params, (void **)&ucode_frag_args, sizeof(cdx_ucode_frag_info_t));

	cdx_init_frag_procfs();
	register_cdx_deinit_func(cdx_deinit_frag_module);
	return 0;
}

#define PROC_FRAG_DIR "ucode_frag"
struct file_operations frag_stats_fp;
struct file_operations buf_alloc_test_fp;

static struct proc_dir_entry *frag_proc_dir, *stats_file, *alloc_free_test_file;

ssize_t stats_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	int  tot_len = 0;
	cdx_ucode_frag_info_t  *ucode_frag_args;

	if (!create_ddr_and_copy_from_muram((void *)frag_info_g.muram_frag_params, (void **)&ucode_frag_args, sizeof(cdx_ucode_frag_info_t)))
		return 0;
	
	if (*ppos)
		return 0;

	tot_len += sprintf(buf+tot_len, "IPv4 frames received : %u\n", be32_to_cpu(ucode_frag_args->v4_frames_counter));
	tot_len += sprintf(buf+tot_len, "IPv6 frames received : %u\n", be32_to_cpu(ucode_frag_args->v6_frames_counter));
	tot_len += sprintf(buf+tot_len, "Number of IPv4 fragments sent : %u\n", be32_to_cpu(ucode_frag_args->v4_frags_counter));
	tot_len += sprintf(buf+tot_len, "Number of IPv6 fragments sent : %u\n", be32_to_cpu(ucode_frag_args->v6_frags_counter));
	tot_len += sprintf(buf+tot_len, "Failures in allocating buffers: %u\n", be32_to_cpu(ucode_frag_args->alloc_buff_failures));
	*ppos += tot_len;

	kfree(ucode_frag_args);
	return tot_len;
}


ssize_t buff_alloc_test(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	int ii;
	struct bm_buffer bmb[128];
	if (*ppos)
		return 0;

	for (ii =0; ii< 128; ii++)
	{
		if (bman_acquire(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0) != 1) {
			DPA_INFO("%s(%d) bman_acquire failed \n", __FUNCTION__,__LINE__);
			bmb[ii].addr = 0;
		}
		else
		{
			DPA_INFO("%s(%d) bman_acquire success (ii %d) ,%lx \n", 
					__FUNCTION__,__LINE__,ii,(long unsigned int)bmb[ii].opaque);
		}
	}
	for (ii =0; ii< 128; ii++)
	{
		if (bmb[ii].addr) {
			if (bman_release(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0))
				DPA_ERROR("%s::bman release failed\n", __FUNCTION__);
		}
	}
	ii = sprintf(buf, "128 buffers allocated and freed successfully\n");
	*ppos += ii;
	return ii;
}



int cdx_init_frag_procfs(void)
{
	frag_proc_dir = proc_mkdir(PROC_FRAG_DIR, NULL);
	if (!frag_proc_dir)
	{
		DPA_INFO("%s(%d) proc_mkdir failed \n",__FUNCTION__,__LINE__);
		return -1;
	}
	memset (&frag_stats_fp, 0, sizeof(frag_stats_fp));
	memset (&buf_alloc_test_fp, 0, sizeof(buf_alloc_test_fp));
	frag_stats_fp.read = stats_read;

	stats_file = proc_create("stats", 0444, frag_proc_dir, &frag_stats_fp);
	if (!stats_file)
	{
		DPA_INFO("%s(%d) proc_create failed\n",__FUNCTION__,__LINE__);
		return -1;
	}

	buf_alloc_test_fp.read = buff_alloc_test;
	alloc_free_test_file = proc_create("test_alloc_buf_n_free", 0444, frag_proc_dir, &buf_alloc_test_fp);
	if (!alloc_free_test_file)
	{
		DPA_INFO("%s(%d) proc_create failed\n",__FUNCTION__,__LINE__);
		return -1;
	}

	return 0;
}

void cdx_deinit_frag_module(void)
{
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;
#ifdef CDX_FRAG_USE_BUFF_POOL
	cdx_deinit_fragment_bufpool();
#endif //CDX_FRAG_USE_BUFF_POOL
	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		return;
	}
	//FM_MURAM_FreeMem(h_FmMuram, (void *)frag_info_g.muram_frag_params_addr);
	FM_MURAM_FreeMem(h_FmMuram, (void *)dscp_fq_map_ff_g.muram_addr);
	dscp_fq_map_ff_g.muram_addr = NULL;
	frag_info_g.muram_frag_params = NULL;
	//frag_info_g.muram_frag_params_addr = 0;
	return;
}

static int cdx_create_fragment_bufpool(void)
{
	struct dpa_bp *bp, *bp_parent;
	int buffer_count = 0, ret = 0, refill_cnt ;

	bp = kzalloc(sizeof(struct dpa_bp), 0);
	if (unlikely(bp == NULL)) {
		DPA_ERROR("%s::failed to allocate mem for bman pool \n",
				__FUNCTION__);
		return -1;
	}

	bp->size = CDX_FRAG_BUFF_SIZE;
	bp->config_count = CDX_FRAG_BUFFERS_CNT;

	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(CDX_FRAG_BUFF_SIZE, &frag_info_g.parent_pool_info)) {
		DPA_ERROR("%s::failed to locate eth bman pool\n", 
				__FUNCTION__);
		bman_free_pool(bp->pool);
		kfree(bp);
		return -1;
	}

	bp_parent = dpa_bpid2pool(frag_info_g.parent_pool_info.pool_id);
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPA_ERROR("%s::dpa_bp_alloc failed\n",
				__FUNCTION__);
		kfree(bp);
		return -1;
	}
	DPA_INFO("%s::bp->size :%zu, bpid %d\n", __FUNCTION__, bp->size, bp->bpid);


	frag_info_g.frag_bufpool = bp;
	frag_info_g.frag_bp_id = bp->bpid;

	while (buffer_count < CDX_FRAG_BUFFERS_CNT)
	{
		refill_cnt = 0;
		ret = dpaa_eth_refill_bpools(bp, &refill_cnt,
			CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD);
		if (ret < 0)
		{
			DPA_ERROR("%s:: Error returned for dpaa_eth_refill_bpools %d\n", __FUNCTION__,ret);
			break;
		}

		buffer_count += refill_cnt;
	}
	bp->config_count = buffer_count;

	DPA_INFO("%s::buffers_allocated %d\n", __FUNCTION__,bp->config_count);
	return 0;
}

void cdx_deinit_fragment_bufpool()
{
	if (frag_info_g.frag_bufpool)
	{
		drain_tx_bp_pool(frag_info_g.frag_bufpool);
		frag_info_g.frag_bufpool = NULL;
		frag_info_g.frag_bp_id = 0;
	}
	return;
}

int cdx_check_rx_iface_type_vlan(struct _itf *input_itf);
static int cdx_rtpflow_fill_actions(PSockEntry pFromSocket, PSockEntry pToSocket,
						PRTPflow pFlow, struct ins_entry_info *info)
{
	uint32_t ii; 
	uint32_t rebuild_l2_hdr = 0;
	uint8_t opcode;
	uint32_t iif_index = 0, underlying_iif_index = 0;


#ifdef CDX_DPA_DEBUG
	DPA_INFO(" opc_ptr %p, param_ptr %p, size %d dport %d , (pToSocket->Dport mod 2) %d\n", 
			info->opcptr, info->paramptr, info->param_size,
			htons(pToSocket->Dport), (htons(pToSocket->Dport) % 2));
#endif


	//routing and ttl decr are mandatory
	//ttl decr handled as part of NAT-PT

	//mask it as ipv6 flow if required
	if (pFromSocket->SocketFamily == PROTO_IPV6)
		info->flags |= EHASH_IPV6_FLOW;
	// setting TTL bit
	info->flags |= TTL_HM_VALID;

	if (!pFromSocket->pRtEntry)
	{
		DPA_ERROR("%s(%d) socket route entry is NULL.\n",
				__FUNCTION__, __LINE__);
		return FAILURE;
	}
	//strip vlan on ingress if incoming iface is vlan
	//	if (info->l2_info.vlan_present)
	if (cdx_check_rx_iface_type_vlan(pFromSocket->pRtEntry->itf))
		info->flags |= VLAN_STRIP_HM_VALID;

	//strip pppoe on ingress if incoming iface is pppoe 
	if (info->l2_info.pppoe_present)
		info->flags |= PPPoE_STRIP_HM_VALID;

	if(L2_L3_HDR_OPS(info))
		rebuild_l2_hdr = 1;

	//TODO IPSEC for RTP relay traffic
#ifdef TODO_IPSEC
	if((entry->status & CONNTRACK_SEC) && (!info->to_sec_fqid)){ 
		info->eth_type  = (IS_IPV4(entry)) ? htons(ETHERTYPE_IPV4) : htons(ETHERTYPE_IPV6);
		//.		info->l2_info.add_eth_type = 1;
	}
#endif // TODO_IPSEC

	//Not expecting NATPT for rtp-relay traffic
	info->flags |= NAT_HM_REPLACE_SPORT;
	info->flags |= NAT_HM_REPLACE_DPORT;
	info->flags |= NAT_HM_REPLACE_SIP;
	info->flags |= NAT_HM_REPLACE_DIP;
	switch(pFromSocket->proto) 
	{
		case IPPROTOCOL_TCP:
		case IPPROTOCOL_UDP:
			info->nat_sport = pToSocket->Dport;
			info->nat_dport = pToSocket->Sport;
			break;
		default:
			break; 
	}

	//ip replacement have to be done
	//nat sip if required

	if (pFromSocket->SocketFamily == PROTO_IPV6)
	{
		memcpy(info->v6.nat_sip, pToSocket->Daddr_v6 ,IPV6_ADDRESS_LENGTH);
		memcpy(info->v6.nat_dip, pToSocket->Saddr_v6 ,IPV6_ADDRESS_LENGTH);
	}
	else 
	{
		info->v4.nat_sip = pToSocket->Daddr_v4;
		info->v4.nat_dip = pToSocket->Saddr_v4;
	}
	if (info->l2_info.num_egress_vlan_hdrs)
	{

		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}
	//fill all opcodes and parameters
	while(1)
	{
		if ((!pFromSocket->pRtEntry->input_itf) || (!pFromSocket->pRtEntry->underlying_input_itf)) {
			DPA_ERROR("%s::%d input itf OR underlying input itf is NULL\n",
					__FUNCTION__, __LINE__);
			break;
		}
		iif_index = pFromSocket->pRtEntry->input_itf->index;
		underlying_iif_index = pFromSocket->pRtEntry->underlying_input_itf->index;

#ifdef INCLUDE_ETHER_IFSTATS
		DPA_INFO("%s(%d) calling cdx_rtpflow_create_eth_rx_stats_hm\n",
				__FUNCTION__, __LINE__);

		if (create_eth_rx_stats_hm(info, iif_index, underlying_iif_index)) 
			break;
#endif
		if (rebuild_l2_hdr){
			if (create_strip_eth_hm(info))
				break;
		}

		if (info->l2_info.pppoe_present)
		{
			struct _itf *itf = NULL;

			DPA_INFO("%s(%d) \n", __FUNCTION__, __LINE__);

			/* strip pppoe hdrs */
			if ((pFromSocket->pRtEntry->input_itf) && (pFromSocket->pRtEntry->input_itf->type & IF_TYPE_PPPOE))
				itf = pFromSocket->pRtEntry->input_itf;
			else
				itf = pFromSocket->pRtEntry->underlying_input_itf;

			if (insert_remove_pppoe_hm(info, itf->index))
				break;
		}
		if (cdx_check_rx_iface_type_vlan(pFromSocket->pRtEntry->itf))
		{
			DPA_INFO("%s(%d) \n", __FUNCTION__, __LINE__);

			/* strip vlan hdrs */
			if (insert_remove_vlan_hm(info, iif_index, underlying_iif_index))
				break;
		}
		/* create RTP_PROCESS opcode */
		pFlow->hw_flow->ehash_rtp_relay_params =  info->paramptr;
		if ((htons(pToSocket->Dport)) % 2)
			opcode = PROCESS_RTCP_PAYLOAD;
		else
			opcode = PROCESS_RTP_PAYLOAD;

		DPA_INFO("%s(%d) opcode %x \n", __FUNCTION__, __LINE__, opcode);

		if (create_rtprelay_process_opcode(info, pFromSocket->hw_stats, 
					(uint32_t *)pFlow->hw_flow->rtp_info,
					pToSocket->hw_stats, opcode))
		{
			DPA_ERROR("%s(%d) create_rtprelay_process_opcode failed\n",__FUNCTION__, __LINE__);
			break;
		}


		DPA_INFO("%s(%d) \n", __FUNCTION__, __LINE__);

		if (info->l2_info.num_egress_vlan_hdrs)
			pFlow->hw_flow->vlan_hdr_ptr = info->vlan_hdrs;
		pFlow->hw_flow->num_vlan_hdrs = info->l2_info.num_egress_vlan_hdrs;
		if (info->flags & NAT_HM_VALID)
		{
			if(create_nat_hm(info))
				break;
		}
		else
		{
		//may need only TTL hm
			if (info->flags & TTL_HM_VALID)
			{
				if (info->flags & EHASH_IPV6_FLOW) 
				{
					DPA_INFO("%s(%d) \n",
							__FUNCTION__, __LINE__);
					if (create_hoplimit_hm(info))
						break;
				} 
				else
				{
					DPA_INFO("%s(%d) \n",
							__FUNCTION__, __LINE__);
					if (create_ttl_hm(info))
						break;
				}
			}
		}
		//enqueue
		DPA_INFO("%s(%d) \n",
				__FUNCTION__, __LINE__);


		if (info->l2_info.add_pppoe_hdr)  {
			/* insert PPPoE header */
			if (create_pppoe_ins_hm(info))
				break;
		}

		if (info->l2_info.num_egress_vlan_hdrs) {
			/* insert vlan header */
			if (create_vlan_ins_hm(info))
				break;
		}
		if (create_ethernet_hm(info, rebuild_l2_hdr))
			break;
		if(create_enque_hm(info))
			break;
		return SUCCESS;
	}
	return FAILURE;
}

static int get_rtp_classif_table_type(PSockEntry pSocket, uint32_t *type)
{
	switch (pSocket->proto) {
		case IPPROTOCOL_TCP:
			if (pSocket->SocketFamily == PROTO_IPV4)
			{
				if (!pSocket->unconnected)
					*type = IPV4_TCP_TABLE;
				else
					*type = IPV4_3TUPLE_TCP_TABLE;
			}
			else
			{
				if (!pSocket->unconnected)
					*type = IPV6_TCP_TABLE;
				else
					*type = IPV6_3TUPLE_TCP_TABLE;
			}
			return SUCCESS;
			
		case IPPROTOCOL_UDP:
			if (pSocket->SocketFamily == PROTO_IPV4)
			{
				if (!pSocket->unconnected)
					*type = IPV4_UDP_TABLE;
				else
					*type = IPV4_3TUPLE_UDP_TABLE;
			}
			else
			{
				if (!pSocket->unconnected)
					*type = IPV6_UDP_TABLE;
				else
					*type = IPV6_3TUPLE_UDP_TABLE;
			}
			return SUCCESS;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, pSocket->proto);
			break;
	}
	return FAILURE;
}

static int cdx_rtpflow_fill_key_info(PSockEntry pSocket, uint8_t *keymem, uint32_t port_id)
{
	union dpa_key *key;
	unsigned char *saddr, *daddr;
	int i;
	uint32_t key_size;

	key = (union dpa_key *)keymem;
	//portid added to key
	key->portid = port_id;
	switch (pSocket->SocketFamily) {
		case PROTO_IPV4: 
			if (pSocket->unconnected) // unconnected, key = daddr + proto + dport
			{
				key_size = (sizeof(struct ipv4_3tuple_tcpudp_key) + 1);
				key->ipv4_3tuple_tcpudp_key.ipv4_daddr = pSocket->Daddr_v4;
				key->ipv4_3tuple_tcpudp_key.ipv4_protocol = pSocket->proto;
				key->ipv4_3tuple_tcpudp_key.ipv4_dport = pSocket->Dport;
			}
			else
			{
				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = pSocket->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = pSocket->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = pSocket->proto;
				key->ipv4_tcpudp_key.ipv4_sport = pSocket->Sport;
				key->ipv4_tcpudp_key.ipv4_dport = pSocket->Dport;
			}
			break;

		case PROTO_IPV6:
			// in case of connected , key will have 5 tuples, 
			// in case of unconnected, key will have only 3 tuples
			if (!pSocket->unconnected)
			{
				saddr = (unsigned char*)pSocket->Saddr_v6;
				daddr = (unsigned char*)pSocket->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_tcpudp_key.ipv6_protocol = pSocket->proto;
				key->ipv6_tcpudp_key.ipv6_sport = pSocket->Sport;
				key->ipv6_tcpudp_key.ipv6_dport = pSocket->Dport;
			}
			else
			{
				daddr = (unsigned char*)pSocket->Daddr_v6;
				key_size = (sizeof(struct ipv6_3tuple_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_3tuple_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_3tuple_tcpudp_key.ipv6_protocol = pSocket->proto;
				key->ipv6_3tuple_tcpudp_key.ipv6_dport = pSocket->Dport;
			}
			break;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, pSocket->proto);
			key_size = 0;
	}
#ifdef CDX_DPA_DEBUG
	if (key_size) {
		DPA_INFO("keysize %d\n", key_size);
		display_buf(key, key_size);
	}
#endif
	return key_size;
}

//display socket entries
void display_SockEntries(PSockEntry SockA, PSockEntry SockB)
{
	printk("SockA unconnected \t%x SockB unconnected \t%x\n\n", SockA->unconnected, SockB->unconnected);
	if (SockA->SocketFamily == PROTO_IPV6) {
		printk("SOCK_A ipv6 entry\n");
		printk("source ip	\t");
		display_ipv6_addr((uint8_t *)SockA->Saddr_v6);
		printk("dest ip		\t");
		display_ipv6_addr((uint8_t *)SockA->Daddr_v6);
		
		printk("SOCK_B ipv6 entry\n");
		printk("source ip	\t");
		display_ipv6_addr((uint8_t *)SockB->Saddr_v6);
		printk("dest ip		\t");
		display_ipv6_addr((uint8_t *)SockB->Daddr_v6);
	} else {
		printk("SOCK_A ipv4 entry\n");
		printk("source ip	\t");
		display_ipv4_addr(SockA->Saddr_v4);
		printk("dest ip		\t");
		display_ipv4_addr(SockA->Daddr_v4);
		printk("SOCK_B ipv4 entry\n");
		printk("source ip	\t");
		display_ipv4_addr(SockB->Saddr_v4);
		printk("dest ip		\t");
		display_ipv4_addr(SockB->Daddr_v4);
	}
	if ((SockA->proto == IPPROTOCOL_UDP) ||
			(SockA->proto == IPPROTOCOL_TCP)) {
		printk("SOCK_A protocol	\t%d\n", SockA->proto);
		printk("SOCK_A sport		\t%d\n", htons(SockA->Sport));
		printk("SOCK_A dport		\t%d\n", htons(SockA->Dport));
		printk("SOCK_B protocol	\t%d\n", SockA->proto);
		printk("SOCK_B sport		\t%d\n", htons(SockA->Sport));
		printk("SOCK_B dport		\t%d\n", htons(SockA->Dport));
	}
	printk("SOCK_A Route entry	\t%p\n", SockA->pRtEntry);
	if (SockA->pRtEntry) {
		display_route_entry(SockA->pRtEntry);
	}
	else
	{
		printk("No route entry\n");
	}
	printk("SOCK_B Route entry	\t%p\n", SockB->pRtEntry);
	if (SockB->pRtEntry)
	{
		display_route_entry(SockB->pRtEntry);
	}
	else 
	{
		printk("No route entry\n");
	}
	printk(">>>>>\n");
}
EXPORT_SYMBOL(display_SockEntries);

#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
int cdx_create_rtp_qos_slowpath_flow(PSockEntry pSocket)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	struct en_ehash_enqueue_param *param;
	struct dpa_iface_info *iface_info;
	/*struct _itf *underlying_input_itf;*/
	uint32_t uiTblType;
	uint32_t uiKeySize;
	uint16_t usFlags;
	uint8_t *pPtr;
	uint8_t	ucInPhyPortNum;
	int iRetVal;

	tbl_entry = NULL;	

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info)
	{
		DPA_ERROR("%s(%d)::unable to create memory.\n",__FUNCTION__, __LINE__);
		return FAILURE;
	}
	ucInPhyPortNum = pSocket->iifindex;

	if ((iface_info = dpa_get_ifinfo_by_itfid(pSocket->iifindex)) == NULL)
	{
		DPA_ERROR("%s::%d unable to find the dpa interface for index(%u).\n",
				__FUNCTION__, __LINE__, pSocket->iifindex);
		goto err_ret;
	}

	if (dpa_get_fm_port_index(ucInPhyPortNum, /*underlying_input_itf->index*/0, &info->fm_idx,
				&info->port_idx, &info->port_id))
	{
		DPA_ERROR("%s(%d)::unable to get fmindex for itfid %d\n",
				__FUNCTION__, __LINE__, ucInPhyPortNum);
		goto err_ret;
	}
	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) ucInPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
			__FUNCTION__, __LINE__, ucInPhyPortNum, 0/*underlying_input_itf->index*/,
			info->fm_idx, info->port_idx, info->port_id);
#endif /* CDX_DPA_DEBUG */
	/* get pcd handle based on determined fman */
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd)
	{
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
				__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	if (get_rtp_classif_table_type(pSocket, &uiTblType))
	{
		DPA_ERROR("%s::%d unable to get table type\n", __FUNCTION__, __LINE__);
		goto err_ret;
	}
	info->tbl_type = uiTblType;

	/* get table descriptor based on type and port based on incoming packet Socket */
	info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, uiTblType);
	if (info->td == NULL)
	{
		DPA_ERROR("%s::%d unable to get td for itfid %d, type %d\n",
				__FUNCTION__, __LINE__, ucInPhyPortNum, uiTblType);
		goto err_ret;
	}
	/*info->l2_info.mtu = 1500;*/
	if (dpa_get_rtp_qos_slowpath_fq(&iface_info->eth_info, 
				pSocket->hash, &info->l2_info.fqid) < 0)
	{
		DPA_ERROR("%s::%d unable to find the frame queue for rtp qos slowpath traffic.\n",
				__FUNCTION__, __LINE__);
		goto err_ret;
	}

	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry)
	{
		DPA_ERROR("%s::%d unable to alloc hash tbl memory\n", __FUNCTION__, __LINE__);
		goto err_ret;
	}
	/* fill key information from entry */
	uiKeySize = cdx_rtpflow_fill_key_info(pSocket, &tbl_entry->hashentry.key[0], info->port_id);
	if (!uiKeySize)
	{
		DPA_ERROR("%s::%d unable to compose key.\n", __FUNCTION__, __LINE__);
		goto err_ret;
	}	
	usFlags = 0;
	/* round off keysize to next 4 bytes boundary */
	pPtr = (uint8_t *)&tbl_entry->hashentry.key[0];			
	pPtr += ALIGN(uiKeySize, TBLENTRY_OPC_ALIGN);
	/* set start of opcode list */
	info->opcptr = pPtr;
	/* pPtr now after opcode section*/
	pPtr += MAX_OPCODES;

	/* set offset to first opcode */
	SET_OPC_OFFSET(usFlags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	/* set param offset */
	SET_PARAM_OFFSET(usFlags, (uint32_t)(pPtr - (uint8_t *)tbl_entry));
	/* param_ptr now points after timestamp location */
	tbl_entry->hashentry.flags = cpu_to_be16(usFlags);
	/* param pointer and opcode pointer now valid */
	info->paramptr = pPtr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - GET_PARAM_OFFSET(usFlags));

	if (info->opc_count == MAX_OPCODES)
		goto err_ret;
	if (sizeof(struct en_ehash_enqueue_param) > info->param_size)
		goto err_ret;
	info->enqueue_params = info->paramptr;
	param = (struct en_ehash_enqueue_param *)info->paramptr;
	param->mtu = cpu_to_be16(65535/*info->l2_info.mtu*/);
	param->bpid = frag_info_g.frag_bp_id;
	param->muram_frag_param_addr = MURAM_VIRT_TO_PHYS_ADDR(dscp_fq_map_ff_g.muram_addr);
	param->fqid = cpu_to_be32(info->l2_info.fqid);
	*(info->opcptr) = ENQUEUE_PKT;
	info->opcptr++;
	info->param_size -= sizeof(struct en_ehash_enqueue_param);
	info->paramptr += sizeof(struct en_ehash_enqueue_param);
	tbl_entry->enqueue_params = info->enqueue_params;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, uiKeySize);
#endif /* CDX_DPA_DEBUG */
	/* insert entry into hash table */
	if ((iRetVal = ExternalHashTableAddKey(info->td, uiKeySize, tbl_entry)) == -1) {
		DPA_ERROR("%s::%d unable to add entry in hash table\n", __FUNCTION__, __LINE__);
		goto err_ret;
	}	
	pSocket->SktEhTblHdl.eeh_entry_handle = tbl_entry;
	pSocket->SktEhTblHdl.eeh_entry_index = (uint16_t)iRetVal;
	pSocket->SktEhTblHdl.td = info->td;
	kfree(info);
	return SUCCESS;
err_ret:
	/* release all allocated items */
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	kfree(info);
	return FAILURE;
}
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */

int cdx_create_rtp_conn_in_classif_table (PRTPflow pFlow, PSockEntry pFromSocket, PSockEntry pToSocket)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	struct _itf *underlying_input_itf;
	uint32_t tbl_type;
	uint16_t flags;
	uint32_t key_size;
	uint8_t *ptr;
	int retval;

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
	display_SockEntries(pFromSocket, pToSocket);
#endif

	tbl_entry = NULL;	

	if (!pFromSocket->pRtEntry)
	{
		DPA_INFO("%s(%d)\n",__FUNCTION__,__LINE__);
		return FAILURE;
	}

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info)
		return FAILURE;

	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
	info->entry = pFlow;

	// This can never be NULL for connection routes.
	if (pFromSocket->pRtEntry->underlying_input_itf)
		underlying_input_itf = pFromSocket->pRtEntry->underlying_input_itf;
	else
	{
		underlying_input_itf = pFromSocket->pRtEntry->itf ;
		pFromSocket->pRtEntry->underlying_input_itf = pFromSocket->pRtEntry->itf;
	}

	if (!pFromSocket->pRtEntry->input_itf)
		pFromSocket->pRtEntry->input_itf = pFromSocket->pRtEntry->itf;
	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);

	//clear hw entry pointer
	if ((!pFromSocket->pRtEntry) || ( (!pFromSocket->pRtEntry->input_itf) 
				&& (!pFromSocket->pRtEntry->itf)))
	{
		DPA_ERROR("%s(%d)::unable to get interface \n",__FUNCTION__,
				__LINE__);
		goto err_ret;
	}
	if (!pFromSocket->pRtEntry->input_itf) 
		pFlow->inPhyPortNum = pFromSocket->pRtEntry->itf->index;
	else
		pFlow->inPhyPortNum = pFromSocket->pRtEntry->input_itf->index;

	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
	//get fman index and port index and port id where this entry need to be added
	if (dpa_get_fm_port_index(pFlow->inPhyPortNum, underlying_input_itf->index, &info->fm_idx,
				&info->port_idx, &info->port_id))
	{
		DPA_ERROR("%s(%d)::unable to get fmindex for itfid %d\n",
				__FUNCTION__, __LINE__, pFlow->inPhyPortNum);
		goto err_ret;
	}
	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) inPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
			__FUNCTION__, __LINE__, pFlow->inPhyPortNum, underlying_input_itf->index,
			info->fm_idx, info->port_idx, info->port_id);
#endif // CDX_DPA_DEBUG
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd)
	{
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
				__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	if (get_rtp_classif_table_type(pFromSocket, &tbl_type))
	{
		DPA_ERROR("%s::unable to get table type\n",
				__FUNCTION__);
		goto err_ret;
	}
	info->tbl_type = tbl_type;

	//get table descriptor based on type and port based on incoming packet Socket A
	info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, tbl_type);
	if (info->td == NULL)
	{
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
				__FUNCTION__, pFlow->inPhyPortNum,
				tbl_type);
		goto err_ret;
	}
#ifdef TODO_DPA_IPSEC_OFFLOAD
	/* if the connection is a secure one  and  SA direction is inbound
	 * then, we should add the entry into offline ports's classification
	 * table. cdx_ipsec_fill_sec_info()  will check for the SA direction
	 * and if it is inbound will replace the table id;
	 * if the SA is outbound direction then it will fill sec_fqid in the 
	 * info struture.  
	 */ 
	if(entry->status & CONNTRACK_SEC)
	{
		if(cdx_ipsec_fill_sec_info(entry,info))
		{
			DPA_ERROR("%s::unable to get td for offline port, type %d\n",
					__FUNCTION__, info->tbl_type);
			goto err_ret;
		}
	}
#endif

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: td info :%p\n", __FUNCTION__, info->td);
#endif

	//save table descriptor for entry release
	pFlow->hw_flow->td = info->td;
	//get fm context
	pFlow->hw_flow->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (pFlow->hw_flow->fm_ctx == NULL)
	{
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
				__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	if (!pToSocket->pRtEntry)
	{
		DPA_ERROR("%s:: No route entry for to_socket \n",
				__FUNCTION__);
		goto err_ret;
	}
	if (!pToSocket->pRtEntry->input_itf)
	{
		DPA_INFO("%s(%d) pToSocket->pRtEntry->itf %p\n",
				__FUNCTION__, __LINE__, pToSocket->pRtEntry->itf);
		pToSocket->pRtEntry->input_itf =  pToSocket->pRtEntry->itf;
	}

	if (!pToSocket->pRtEntry->underlying_input_itf)
	{
		DPA_INFO("%s(%d) pToSocket->pRtEntry->itf %p\n",
				__FUNCTION__, __LINE__, pToSocket->pRtEntry->itf);
		pToSocket->pRtEntry->underlying_input_itf = pToSocket->pRtEntry->itf;
	}
	{
		union ctentry_qosmark qosmark;

		qosmark.markval = 0;
		qosmark.queue = pToSocket->queue;
		if (dpa_get_tx_info_by_itf(pToSocket->pRtEntry, &info->l2_info,
					&info->l3_info, NULL, &qosmark, (uint32_t)pToSocket->hash))
		{	
			DPA_ERROR("%s::unable to get tx params\n",
					__FUNCTION__);
			goto err_ret;
		}
	}

	//allocate hash table entry
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::info->td %p\n", __FUNCTION__, info->td);
#endif
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry)
	{
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
				__FUNCTION__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
#endif
	flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
		cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = cpu_to_be32(JIFFIES32);
	pFlow->hw_flow->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
	//fill key information from entry
	key_size = cdx_rtpflow_fill_key_info(pFromSocket, &tbl_entry->hashentry.key[0], info->port_id);
	if (!key_size)
	{
		DPA_ERROR("%s::unable to compose key\n",
				__FUNCTION__);
		goto err_ret;
	}	

	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];			
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	//set start of opcode list 
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - GET_PARAM_OFFSET(flags));
	if (cdx_rtpflow_fill_actions(pFromSocket, pToSocket, pFlow, info))
	{
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
	tbl_entry->enqueue_params = info->enqueue_params;
	pFlow->hw_flow->eeh_entry_handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry); 
	if (retval == -1) {
		DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
		goto err_ret;
	}	
	pFlow->hw_flow->eeh_entry_index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	//release all allocated items
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	kfree(info);
	return FAILURE;
}

void cdx_ehash_set_rtp_info_params(uint8_t *rtp_relay_param, PRTPflow pFlow, PSockEntry pSocket)
{
	struct en_ehash_rtprelay_param *param;
	uint16_t rtp_flags;

	param = (struct en_ehash_rtprelay_param *)rtp_relay_param;

	rtp_flags = 0;

	if (pSocket->unconnected == SOCKET_UNCONNECTED)
	{
		if (pSocket->SocketFamily == PROTO_IPV4)
		{
			param->src_ipv4_val = pSocket->Saddr_v4;
			//			param->src_ipv4_val = cpu_to_be32(pSocket->Saddr_v4);
		}
		else
		{
			param->src_ipv6_val[0] = pSocket->Saddr_v6[0];
			param->src_ipv6_val[1] = pSocket->Saddr_v6[1];
			param->src_ipv6_val[2] = pSocket->Saddr_v6[2];
			param->src_ipv6_val[3] = pSocket->Saddr_v6[3];
			//			param->src_ipv6_val[0] = cpu_to_be32(pSocket->Saddr_v6[0]);
			//		param->src_ipv6_val[1] = cpu_to_be32(pSocket->Saddr_v6[1]);
			//	param->src_ipv6_val[2] = cpu_to_be32(pSocket->Saddr_v6[2]);
			//param->src_ipv6_val[3] = cpu_to_be32(pSocket->Saddr_v6[3]);
		}
	}
	param->TimeStampIncr =  cpu_to_be32(pFlow->TimeStampIncr);
	param->seq_base =  cpu_to_be16(pFlow->Seq);
	param->egress_socketID = cpu_to_be16(pFlow->egress_socketID);
	param->DTMF_PT[0] =  gDTMF_PT[0];
	param->DTMF_PT[1] =  gDTMF_PT[1];
	param->SSRC_1 =  cpu_to_be32(pFlow->SSRC_1);
	if (pSocket->expt_flag == 1)
	{
		rtp_flags |= EEH_RTP_SEND_FIRST_PACKET_TO_CP;
	}

	if (pFlow->pkt_dup_enable)
	{
		rtp_flags |= EEH_RTP_DUPLICATE_PKT_SEND_TO_CP;
	}

	if (pFlow->hw_flow->flags & RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING)
	{
		rtp_flags |= EEH_RTP_ENABLE_VLAN_P_BIT_LEARN;
		DPA_INFO("%s(%d) enabling VLAN p bit learning feature in UCODE\n",
				__FUNCTION__,__LINE__);
	}

	param->rtp_flags = cpu_to_be16(rtp_flags);
}

void cdx_ehash_update_rtp_info_params(uint8_t *rtp_relay_param, uint32_t *rtpinfo_ptr)
{
	struct en_ehash_rtprelay_param *param;
	uint32_t ptr_val;
	
	param = (struct en_ehash_rtprelay_param *)rtp_relay_param;
	ptr_val = PTR_TO_UINT(rtpinfo_ptr);
	param->rtpinfo_ptr =  cpu_to_be32(ptr_val);
	return;
}

void cdx_ehash_update_dtmf_rtp_info_params(uint8_t *rtp_relay_param, uint8_t *DTMF_PT)
{
	struct en_ehash_rtprelay_param *param;
	
	param = (struct en_ehash_rtprelay_param *)rtp_relay_param;
	param->DTMF_PT[0] = DTMF_PT[0];
	param->DTMF_PT[1] = DTMF_PT[1];
	return;
}

