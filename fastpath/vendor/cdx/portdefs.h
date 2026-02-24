/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**
 * @file                port_defs.h
 * @description         dpaa port/interface management module header file
 */ 

#ifndef PORT_DEFS_H
#define PORT_DEFS_H  1

#include "dpaa_eth.h"
#include "cdx_common.h"
#include "types.h"

#define ETH_ALEN		6	
#define MAX_PORT_BMAN_POOLS     8	//max bman pools per port
#define MAX_POSSIBLE_POOLS	64	//max possible bman pools on SOC

#ifndef ENABLE_EGRESS_QOS
#define DPAA_FWD_TX_QUEUES	8	/* max forwarding(PCD) queues per port */
#else
#define DPAA_FWD_TX_QUEUES	16	/* max forwarding(PCD) queues per port */
#endif

#define PORT_1G_SPEED		1000
#define PORT_10G_SPEED		10000

//fq infor associated with fman controlled ports
struct port_fq_info {
	uint32_t fq_base;		//base fq
	uint32_t num_fqs;		//num of fqs from base
};


//bman pool info
struct port_bman_pool_info
{
  uint32_t pool_id;		//pool id known to system
  uint32_t buf_size;		//size of buffers managed by pool
  uint32_t count;		//number of buffer filled into pool
  uint64_t base_addr;		//base address of buffers (phys)
};


//types of FQs 
typedef enum {	
	TX_ERR_FQ,		//transmit error FQ
	TX_CFM_FQ,		//transmit confirmation FQ
	RX_ERR_FQ,		//receive error FQ
	RX_DEFA_FQ,		//default receive FQ	
	MAX_FQ_TYPES
}fq_types;

//ethernet device information
struct eth_iface_info {
	struct net_device *net_dev;	//os device ref
	uint32_t speed;			//port speed
	uint32_t fman_idx;		//fman index within SOC
	uint32_t port_idx;		//port index within fman
	uint32_t portid;		//identification provided in xml pcd file
	uint32_t hardwarePortId;	//hardware port id
	uint32_t tx_index;		//transmit que to use next
	t_Handle *vsp_h;			//VSP info for given eth interface
	struct port_fq_info fqinfo[MAX_FQ_TYPES];	//fq info for defa types
	struct port_fq_info eth_tx_fqinfo[DPAA_ETH_TX_QUEUES];	//ethdrv TX FQs 
	struct qman_fq fwd_tx_fqinfo[DPAA_FWD_TX_QUEUES]; /* cctable TX FQs */ 
	uint32_t rx_channel_id;		//channel id rx
	uint32_t tx_channel_id;		//channel id tx
	uint32_t tx_wq;			//tx work queue
	uint32_t rx_pcd_wq;		//wq used by ethernet driver pcd queues
	qman_cb_dqrr dqrr;
	uint32_t num_pools;	//pools used by port
	struct port_bman_pool_info pool_info[MAX_PORT_BMAN_POOLS]; //pool info
	uint8_t mac_addr[ETH_ALEN];	//mac address
	uint8_t br_mac_addr[ETH_ALEN];	//bridge mac address
	uint8_t is_bridged;		// flag to check if interface is bridged or not
	uint32_t max_dist;		//max PCD distributions
	struct cdx_dist_info *dist_info;//pointer to array of pcd dist
	struct dpa_fq *defa_rx_dpa_fq; //default rx fq pointer
	struct dpa_fq *err_rx_dpa_fq;  //rx err fq pointer
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	struct dpa_fq	*voip_fqs;
	uint8_t	ucNumFqs;
#endif
};

//offline port device information
struct oh_iface_info {
        uint32_t fman_idx;              //fman index within SOC
        uint32_t port_idx;              //port index within fman
        uint32_t portid;                //portid from xml file
        struct port_fq_info fqinfo[MAX_FQ_TYPES]; //fq info for defa types
        uint32_t channel_id;            //channel id
        uint32_t max_dist;              //max PCD distributions
        struct cdx_dist_info *dist_info;//pointer to array of pcd dist
};

//vlan device information
struct vlan_iface_info {
	struct dpa_iface_info *parent;
	uint16_t vlan_id;
	uint8_t is_bridged; 		/* Flag to check if interface is bridged or not */
	uint8_t pad;  			/* not used */
	uint8_t mac_addr[ETH_ALEN]; 	/* Vlan interface mac address */
	uint8_t br_mac_addr[ETH_ALEN]; 	/* Bridge mac address stored if interface is part of bridge group */
};

//pppoe device information
struct pppoe_iface_info {
	struct dpa_iface_info *parent;
	uint16_t session_id;
	uint8_t mac_addr[ETH_ALEN];
};

struct wlan_iface_info {
	uint16_t vap_id;
	uint8_t is_bridged;		/* Flag to check if interface is bridged or not */
	uint8_t pad;			/* not used */
	uint8_t mac_addr[ETH_ALEN];	/* Wlan interface mac address */
	uint8_t br_mac_addr[ETH_ALEN];	/* Bridge mac address stored if interface is part of bridge group */
	uint32_t fman_idx;
	uint32_t port_idx;
	uint32_t portid;
};


//tunnel device information
struct tunnel_iface_info {

	struct dpa_iface_info *parent;
	uint8_t mode; /*4o6/6o4/remote_any*/
	uint8_t proto;
	uint8_t flags;
	uint8_t  pad;
	uint16_t header_size;
	uint32_t local_ip[4];
	uint32_t remote_ip[4];
	uint8_t dstmac[ETH_ALEN];
	union {
		uint8_t   header[40];
		ipv4_hdr_t header_v4;
		ipv6_hdr_t header_v6;
	};
};

struct iface_stats {
	uint32_t tx_packets;
	uint32_t rx_packets;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
};

//dpa interface structure
struct dpa_iface_info {
	struct dpa_iface_info *next; //single link to next iface
	uint32_t if_flags; 	//from itf structure
	uint32_t itf_id;	//from itf_structure
	uint32_t osid;		//linux interface id
	uint32_t mtu;		//iface mtu

	uint8_t name[IF_NAME_SIZE]; //name as seen by OS
	union {
		struct eth_iface_info eth_info; //info if iface type is eth
		struct vlan_iface_info vlan_info; //info if type is vlan
		struct pppoe_iface_info pppoe_info; //info if type is pppoe
		struct tunnel_iface_info tunnel_info; //info if type is tunnel
		struct wlan_iface_info wlan_info; //internal wlan  info
		struct oh_iface_info oh_info; //internal oh parsing port info

	};
	void *tx_proc_entry;
	void *rx_proc_entry;
	void *pcd_proc_entry;
	struct qman_fq *egress_fqs[DPAA_ETH_TX_QUEUES]; /* storage for ethernet FQs replaces by CEETM FQs */
#ifdef INCLUDE_IFSTATS_SUPPORT
	void *stats;
	struct iface_stats *last_stats;
	uint8_t rxstats_index;
	uint8_t txstats_index;
#endif
};


//flags field values in struct oh_port_fq_td_info
#define IPV4_TBL_VALID          (1 << 0)
#define IPV6_TBL_VALID          (1 << 1)
#define ETHERNET_TBL_VALID      (1 << 2)
#define OF_FQID_VALID           (1 << 8)
#define IN_USE                  (1 << 9)
#define PORT_VALID              (1 << 16)
#define PORT_TYPE_WIFI          (1 << 12)
#define PORT_TYPE_IPSEC         (2 << 12)
#define PORT_TYPE_MASK          (3 << 12)

int find_pcd_fq_info(uint32_t fqid);
void add_pcd_fq_info(struct dpa_fq *fq_info);
int get_dpa_eth_iface_info(struct eth_iface_info *iface_info, char *name);
int cdxdrv_create_of_fqs(struct dpa_iface_info *iface_info);
void display_ohport_info(struct oh_iface_info *ohinfo);
int get_ofport_fman_and_portindex(uint32_t fm_index, uint32_t handle, uint32_t* fm_idx, uint32_t* port_idx,
		uint32_t *portid);
int alloc_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface);
void free_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface);
int get_ofport_portid(uint32_t fm_idx, uint32_t handle, uint32_t *portid);
int get_ofport_info(uint32_t fm_idx, uint32_t handle, uint32_t *channel, void **td);
int get_ofport_max_dist(uint32_t fm_idx, uint32_t handle, uint32_t* max_dist);
int dpa_get_wan_port(uint32_t fm_index, uint32_t *port_idx);
int get_phys_port_poolinfo_bysize(uint32_t size, struct port_bman_pool_info *pool_info);
int alloc_offline_port(uint32_t fm_idx, uint32_t type, qman_cb_dqrr defa_rx, qman_cb_dqrr err_rx);
int get_oh_port_pcd_fqinfo(uint32_t fm_idx, uint32_t handle, uint32_t type,
			uint32_t *pfqid, uint32_t *count);
int ohport_set_ofne(uint32_t handle, uint32_t nia_val);
int ohport_set_dma(uint32_t handle, uint32_t val);
int release_offline_port(uint32_t fm_idx, int handle);
int get_dpa_oh_iface_info(struct oh_iface_info *iface_info, char *name);
int  get_tableInfo_by_portid( int fm_index, int portid,  void **td,  int * flags);
int dpa_add_port_to_list(struct dpa_iface_info *iface_info);
struct dpa_iface_info *dpa_get_ifinfo_by_itfid(uint32_t itf_id);
struct dpa_iface_info *dpa_get_ohifinfo_by_portid(uint32_t portid);
void display_iface_info(struct dpa_iface_info *iface_info);
int cdx_copy_eth_rx_channel_info(uint32_t fman_idx, struct dpa_fq *dpa_fq);
int cdx_create_fq(struct dpa_fq *dpa_fq, uint32_t flags, void *pcd_proc_entry);
int dpa_get_itfid_by_fman_params(uint32_t fman_index, uint32_t portid);
void dpa_release_iflist(void);
uint32_t get_logical_ifstats_base(void);
void *dpa_get_fm_MURAM_handle(uint32_t fm_idx, uint64_t *phyBaseAddr,
					uint32_t *MuramSize);
int dpaa_vwd_init(void);
void dpaa_vwd_exit(void);
U16 dpa_iface_stats_get( struct dpa_iface_info *iface_info, struct iface_stats *ifstats);
void  dpa_iface_stats_reset(struct dpa_iface_info *iface_info, struct iface_stats *stats);
struct qman_fq *cdx_get_txfq(struct eth_iface_info *eth_info, void *markval);
int cdx_get_tx_dscp_fq_map(struct eth_iface_info *eth_info, uint8_t *is_dscp_fq_map, void *markval);
int dpaa_is_oh_port(uint32_t portid);
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
int dpa_create_eth_if_voip_fqs(struct dpa_iface_info *iface_info);
int dpa_get_rtp_qos_slowpath_fq(struct eth_iface_info *eth_info/*struct qman_fq *voip_fqs*/, 
				uint16_t usHash, uint32_t *puiFqId);
int create_voip_fqs(struct dpa_iface_info *iface_info, uint8_t ucChannelType,
		uint32_t usCpuMask, uint16_t usNoFqs/*, uint16_t *usCreatedFqs*/);
#if 0
int dpa_destroy_eth_if_voip_fqs(struct dpa_iface_info *iface_info);
#endif
#endif
#endif
