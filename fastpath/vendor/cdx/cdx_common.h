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
 * @file                cdx_common.h     
 * @description         structures and definitions common to kernel and user
 *			modules.
 */

//#include <linux/fsl_dpa_classifier.h>
#include "fm_ehash.h"

#ifndef CDX_COMMON_H
#define CDX_COMMON_H 1

#define DPA_PACKED __attribute__ ((packed))

//mac logical interfaces - vlan, ppoe, tunnels...
#define MAX_LOGICAL_INTERFACES  128
//max pppoe tunnels
#define MAX_PPPoE_INTERFACES  4


//include support for tunnel interfaces
#define TUNNEL_IF_SUPPORT 1

//include interface statistics to be collected
#define INCLUDE_VLAN_IFSTATS 1

//include interface statistics to be collected
#define INCLUDE_PPPoE_IFSTATS 1

#ifdef TUNNEL_IF_SUPPORT
//include interface statistics to be collected
#define INCLUDE_TUNNEL_IFSTATS 1
#endif

//include ethernet fast path statistics
#define INCLUDE_ETHER_IFSTATS 1

#if defined(INCLUDE_VLAN_IFSTATS) || defined(INCLUDE_PPPoE_IFSTATS) || defined(INCLUDE_TUNNEL_IFSTATS) || defined(INCLUDE_ETHER_IFSTATS)
#define INCLUDE_IFSTATS_SUPPORT 1
#endif

#define log_err(...) \
		do { \
			pr_err("Error - %s:%d (%s)\n", \
					__FILE__, __LINE__, __func__); \
			pr_err(__VA_ARGS__); \
		} while (0);


//stats structure that is used for all ifaces other than pppoe
struct cdx_iface_ifinfo {
	union {
		struct en_ehash_ifstats stats;
		struct en_ehash_ifportinfo pinfo;
		struct cdx_iface_ifinfo *next;
	};
};
//stats structure that is used for pppoe, includes timestamp on rx,tx 
struct cdx_pppoe_iface_ifinfo{
	union {
		struct en_ehash_ifstats_with_ts stats;
		struct cdx_pppoe_iface_ifinfo *next;
	};
};

//stats types
enum {
	RX_IFSTATS,
	TX_IFSTATS
};

typedef struct  IPv4_HDR_STRUCT
{
	unsigned char Version_IHL;
	unsigned char TypeOfService;
	unsigned short TotalLength;
	unsigned short Identification;
	unsigned short Flags_FragmentOffset;
	unsigned char  TTL;
	unsigned char  Protocol;
	unsigned short HeaderChksum;
	unsigned int SourceAddress;
	unsigned int DestinationAddress;
}  ipv4_hdr_t;

typedef struct IPv6_HDR_STRUCT
{
	union
	{
		unsigned int Ver_TC_FL;
		struct {
			unsigned short Version_TC_FLHi;
			unsigned short FlowLabelLo;
		};
	};
	unsigned short TotalLength;
	unsigned char  NextHeader;
	unsigned char  HopLimit;
	unsigned int SourceAddress[4];
	unsigned int DestinationAddress[4];
} ipv6_hdr_t;


#define IPV6_ADDRESS_LENGTH	16

//ipv4 tcp key used in cc table
struct ipv4_tcpudp_key{
	uint32_t ipv4_saddr;	//src addr
	uint32_t ipv4_daddr;	//dest addr
	uint8_t ipv4_protocol;	//protocol
	uint16_t ipv4_sport;	//source port
	uint16_t ipv4_dport;	//dest port
}DPA_PACKED;

//ipv4 3 tuple tcp key used in cc table
struct ipv4_3tuple_tcpudp_key{
	uint32_t ipv4_daddr;	//dest addr
	uint8_t ipv4_protocol;	//protocol
	uint16_t ipv4_dport;	//dest port
}DPA_PACKED;

//ipv6 tcp key used in cc table
struct ipv6_tcpudp_key{
	uint8_t ipv6_saddr[16];	//src addr
	uint8_t ipv6_daddr[16]; //dest addr
	uint8_t ipv6_protocol;  //protocol
	uint16_t ipv6_sport;    //source port
	uint16_t ipv6_dport;    //dest port
}DPA_PACKED;

//ipv6 3tuple tcp key used in cc table
struct ipv6_3tuple_tcpudp_key{
	uint8_t ipv6_daddr[16]; //dest addr
	uint8_t ipv6_protocol;  //protocol
	uint16_t ipv6_dport;    //dest port
}DPA_PACKED;


//pppoe key used in cc table
struct pppoe_key{
	union {
		struct {
			uint8_t ac_macaddr[6]; //ac mac address
			uint16_t eth_type; //eth type for PPPoE Sessions
			uint16_t session_id; //session id for pppoe
			uint16_t ppp_pid; //next protocol type
		}DPA_PACKED;
		uint32_t key_info[3];
	};
};

//ether key used in cc table
struct ethernet_key{
	uint8_t ether_da[6];	//dest mac
	uint8_t ether_sa[6];    //src mac
	uint16_t ether_type;    //ether type
};

//pppoe-relay key used in cc table
struct pppoe_relay_key{
	uint8_t   ether_sa[6];  //src mac
	uint16_t  ether_type;   //0x8864 for pppoe offloaded session traffic
	uint16_t  session_id;   //pppoe session id
}DPA_PACKED;

//ipv4 esp key used in esp table
struct ipv4_esp_key{
	uint32_t ipv4_daddr;    //dest addr
	uint8_t ipv4_protocol;  //protocol
	uint32_t spi;   //spi
}DPA_PACKED;

//ipv6 esp  key used in esp table
struct ipv6_esp_key{
	uint8_t ipv6_daddr[16]; //dest addr
	uint8_t ipv6_protocol;  //protocol
	uint32_t spi;   //spi
}DPA_PACKED;



//possible key combinations
union dpa_key {
	struct {
		uint8_t	portid;
		union {
			struct ipv4_tcpudp_key ipv4_tcpudp_key;
			struct ipv6_tcpudp_key ipv6_tcpudp_key;
			struct pppoe_key pppoe_key;
			struct pppoe_relay_key pppoe_relay_key;
			struct ethernet_key ether_key;
			struct ipv4_esp_key ipv4_esp_key;
			struct ipv6_esp_key ipv6_esp_key;
			struct ipv4_3tuple_tcpudp_key ipv4_3tuple_tcpudp_key;
			struct ipv6_3tuple_tcpudp_key ipv6_3tuple_tcpudp_key;
		};
	}DPA_PACKED;
	char key_array[0];
}DPA_PACKED;
#define MAX_KEY_SIZE    sizeof(union dpa_key)
struct iface_stats_info {
	uint32_t num_stats_entries;
	uint8_t stats_offsets[1];	//min
}; 

/* Maximum number of VLAN tags supported by the insert header manipulation */
#define DPA_CLS_HM_MAX_VLANs					6

/* Description of the VLAN header */
struct vlan_header {
	uint16_t			tpid;
	uint16_t			tci;
};


//info required to create a routing hm node
struct dpa_l2hdr_info {
	struct {
		uint32_t vlan_present:1;
#ifdef VLAN_FILTER
		uint32_t vlan_filtering:1;
#endif
		uint32_t pppoe_present:1;
		uint32_t is_wlan_iface:1;
		uint32_t add_pppoe_hdr:1;
		uint32_t add_eth_type:1;
		uint32_t dscp_vlanpcp_map_enable:1;
	};
	uint32_t fqid;
	uint8_t rspid;
	uint8_t is_dscp_fq_map;
	uint16_t mtu;
	uint32_t num_egress_vlan_hdrs;
	uint32_t num_ingress_vlan_hdrs;
	struct vlan_header egress_vlan_hdrs[DPA_CLS_HM_MAX_VLANs];
	struct vlan_header ingress_vlan_hdrs[DPA_CLS_HM_MAX_VLANs];
#ifdef INCLUDE_VLAN_IFSTATS
	uint8_t vlan_stats_offsets[DPA_CLS_HM_MAX_VLANs];
#endif
	uint8_t l2hdr[6 * 2];
	uint8_t ac_mac_addr[6];
	uint16_t pppoe_sess_id;
#ifdef INCLUDE_PPPoE_IFSTATS
	uint8_t pppoe_stats_offset;
#endif
#ifdef INCLUDE_ETHER_IFSTATS
	uint8_t ether_stats_offset;
#endif
};


struct dpa_l3hdr_info {
	uint8_t mode;
	struct	{
		uint8_t add_tnl_header:1;
		uint8_t tnl_header_present:1;
		uint8_t ipsec_inbound_flow:1; /* Flag to identify ipsec inbound flow */
	};
	uint8_t tunnel_flags; /* used in dscp propagation */
	uint8_t pad;

	uint16_t proto;
	uint16_t header_size;
	uint32_t local_ip[4];
	uint32_t remote_ip[4]; 
	union {
		uint8_t	   header[40];
		ipv4_hdr_t header_v4;
		ipv6_hdr_t header_v6;
	};
};

//max FMAN instances in this SOC
#define MAX_FRAME_MANAGERS	2
#define MAX_PORTS_PER_FMAN	5
#define MAX_OF_PORTS        4


#define MAX_VLAN_HDRS            8
#define ETHER_ADDR_LEN		 6
#define VLAN_HDR_SIZE		 4
#define ETHER_TYPE_LEN		 2
struct ins_entry_info {
	uint32_t flags;
	uint32_t type;
	struct dpa_l2hdr_info l2_info;
	struct dpa_l3hdr_info l3_info;
	uint32_t fm_idx;
	uint32_t port_idx;
	uint32_t port_id;
	void *fm_pcd;
	void *td;
	uint16_t nat_sport;
	uint16_t nat_dport;
	union {
		struct {
			uint32_t nat_sip;
			uint32_t nat_dip;
		} v4;
		struct {
			uint32_t nat_sip[4];
			uint32_t nat_dip[4];
		} v6;
	};
	uint16_t vlan_ids[MAX_VLAN_HDRS];
	uint8_t l2_hdr[(ETHER_ADDR_LEN * 2)];
	uint8_t *opcptr;
	uint8_t *paramptr;
	uint32_t param_size;
	uint32_t opc_count;
	uint32_t tbl_type;
	uint32_t to_sec_fqid;
	uint16_t tnl_hdr_size;
	uint16_t sa_family;
	uint16_t eth_type;
	uint32_t sa_itf_id; /* To store sa incoming interface id.*/
	void *entry;
	uint16_t	num_mcast_members:16; // number of multicast members
	uint16_t	first_member_flow_addr_hi; // first multicast member flow entry address
	uint32_t	first_member_flow_addr_lo; // first multicast member flow entry address
	uint8_t		*replicate_params;
	uint8_t		*enqueue_params;
	uint8_t		*preempt_params;
	uint32_t	*vlan_hdrs;
	void	*first_listener_entry;
}; 


/* hardware connection tracker info */
struct hw_ct {
	void *fm_ctx;
	void *hm_info;	/* used by old hash tables */
	void *td;
	void *handle;
	uint8_t natt_out_refcnt; /* Same NATT conntrack is used by multiple outbound SAs */
	uint8_t natt_in_refcnt; /* Same NATT conntrack is used by multiple inbound SAs */
	uint16_t natt_in_spi_arr_mask; /* SPI array mask for inbound SAs is stored here */
	uint16_t index;
	uint32_t timestamp;
	uint64_t pkts;
	uint64_t bytes;
	uint64_t reset_pkts;
	uint64_t reset_bytes;
};

//uncomment to include flow timestamps
#define ENABLE_FLOW_TIME_STAMPS 	1
//uncomment to include flow statistics
//#define ENABLE_FLOW_STATISTICS		1

//for the ASK if timestamp is enabled flow stats are mandatory
#ifdef ENABLE_FLOW_TIME_STAMPS
#ifndef ENABLE_FLOW_STATISTICS
#define ENABLE_FLOW_STATISTICS 1
#endif
#endif
//which time stamp counter to use
#define EXTERNAL_TIMESTAMP_TIMERID 0

#define PORT_TYPE_10G 10

void display_buf(void *buf, uint32_t size);
void *dpa_get_pcdhandle(uint32_t fm_index);
void *dpa_get_tdinfo(uint32_t fm_index, uint32_t port_idx, uint32_t type);
void *dpa_get_fm_ctx(uint32_t fm_idx);
void *  get_oh_port_td(uint32_t fm_index, uint32_t port_idx, uint32_t type);
int dpa_get_tx_chnl_info(uint32_t fqid, uint32_t *ch_id, uint32_t *wq_id);
int dpa_add_oh_if(char *name);

int cdx_init_frag_module(void);
void cdx_deinit_frag_module(void);
int cdx_init_ip_reassembly(void);

void hw_ct_get_active(struct hw_ct *ct);

int cdx_set_expt_rate(uint32_t fm_index, uint32_t type, uint32_t limit, uint32_t burst_size);
int cdx_get_expt_rate(void *cmd);
int cdx_set_ff_rate(char *ifname, uint32_t cir, uint32_t pir);
int cdx_get_ff_rate(void *cmd);
void get_plcr_counter(void *handle, uint32_t *counterval, uint32_t clear);
int cdx_get_policer_profile_id(uint32_t fm_index, uint32_t queue_no);
int cdx_ingress_enable_or_disable_qos(uint32_t fm_index,uint32_t queue_no,uint32_t oper);
int cdx_ingress_policer_modify_config(uint32_t fm_index,uint32_t queue_no,uint32_t cir,uint32_t pir, uint32_t cbs, uint32_t pbs);
int cdx_ingress_policer_reset(uint32_t fm_index);
int cdx_ingress_policer_stats(uint32_t fm_index,uint32_t queue_no,void *stats,uint32_t clear);
#ifdef SEC_PROFILE_SUPPORT
int cdx_sec_policer_reset(uint32_t fm_index);
#endif /* endif for SEC_PROFILE_SUPPORT */
#endif
