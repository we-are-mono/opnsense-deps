/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _DPAA_HOST_GENERIC_H_
#define _DPAA_HOST_GENERIC_H_

#include <linux/cdev.h>
#include <linux/interrupt.h>
#include "cdx_ioctl.h"
#include "portdefs.h"
#include "system.h"

#define VWD_BHR_MODE 0
#define VWD_NAS_MODE 1
#define VWD_BHR_NAS_MODE 2

#define VWD_TXQ_CNT	16
#define VWD_RXQ_CNT	3

#define VWD_MINOR               0
#define VWD_MINOR_COUNT         1
#define VWD_DRV_NAME            "vwd"
#define VWD_DEV_COUNT           1
#define VWD_RX_POLL_WEIGHT	64 - 16
#define	WIFI_TOE_PE_ID	5

#define VWD_INFOSTR_LEN          32

#define CFG_WIFI_OFFLOAD

#define FMAN_IDX		0
#define DEFA_WQ_ID      	0
#define DEFA_VWD_WQ_ID      	5
//used for PCD FQ creation
#define NUM_PKT_DATA_LINES_IN_CACHE     2
#define NUM_ANN_LINES_IN_CACHE          1

#define VAPDEV_BUFSIZE  1700
#define VAPDEV_BUFCOUNT 1024
#define VAPBUF_HEADROOM 128
#define USE_PCD_FQ	1
#define CDX_VWD_FWD_FQ_MAX (1 << 6)

//values for state
#if 0
#define VAP_ST_FREE				0
#define VAP_ST_INUSE				1
#define VAP_ST_UP				2
#define VAP_ST_DOWN				3
#endif
#define VAP_ST_CLOSE            0
#define VAP_ST_OPEN             1
#define VAP_ST_CONFIGURED       2
#define VAP_ST_CONFIGURING      3

struct vap_desc_s {
	struct dpaa_vwd_priv_s			*vwd;
	struct net_device 			*wifi_dev;
	unsigned int				ifindex;
	unsigned int				state;
	int									cpu_id;
	char								ifname[IFNAMSIZ];
	unsigned char  				macaddr[ETH_ALEN];
	unsigned short 				vapid;
	unsigned short 				programmed;
	unsigned short 				bridged;
	unsigned short  			direct_rx_path;          /* Direct path support from offload device=>VWD */
	unsigned short  			direct_tx_path;          /* Direct path support from offload VWD=>device */
	unsigned short				no_l2_itf;
#ifdef DPAA_VWD_TX_STATS
	unsigned int 				stop_queue_total[VWD_TXQ_CNT];
	unsigned int 				stop_queue_hif[VWD_TXQ_CNT];
	unsigned int 				stop_queue_hif_client[VWD_TXQ_CNT];
	unsigned int 				clean_fail[VWD_TXQ_CNT];
	unsigned int 				was_stopped[VWD_TXQ_CNT];
#endif
	uint32_t						channel;
	struct dpa_fq				*wlan_fq_to_fman;
	struct dpa_fq				*wlan_fq_from_fman[CDX_VWD_FWD_FQ_MAX];
	void * td[MAX_MATCH_TABLES];
	struct vap_stats_s  __percpu         	*vap_stats;
};

struct vap_stats_s {
	u32                                pkts_local_tx_dpaa;
	u32                                pkts_transmitted;
	u32                                pkts_slow_forwarded;
	u32                                pkts_tx_dropped;
	u32                                pkts_rx_fast_forwarded;
	u32                                pkts_tx_sg;
	u32                                pkts_tx_cloned;
	u32                                pkts_tx_no_head;
	u32                                pkts_tx_non_linear;
	u32                                pkts_tx_realign;
	u32                                pkts_tx_route;
	u32                                pkts_tx_bridge;
	u32                                pkts_direct_rx;
	u32                                pkts_rx_ipsec;
	u32                                pkts_oh_buf_threshold_drop;
	u32                                pkts_slow_path_drop;
};

//action values in vap_cmd_s

#define         ADD             0
#define         REMOVE          1
#define         UPDATE          2
#define         RESET           3
#define         CONFIGURE       4

struct vap_cmd_s {
	int32_t	action;
	int32_t	ifindex;
	int16_t vapid;
	int16_t direct_rx_path;
	unsigned short	no_l2_itf;
	unsigned char 	ifname[IFNAMSIZ];
	unsigned char 	macaddr[ETH_ALEN];
};


struct dpaa_vwd_priv_s {

	unsigned char 				name[IFNAMSIZ];
	int 					vwd_major;
	struct class 				*vwd_class;
	struct device 				*vwd_device;
	struct net_device			*vwd_net_dev;
	struct dpa_priv_s			*eth_priv;
	struct dpa_bp 				*sg_bp;
	struct dpa_bp 				*txconf_bp;
	struct dpa_bp 				*tx_bp;
	struct port_bman_pool_info		parent_pool_info;
	uint32_t						oh_port_handle;
	struct dpa_fq				*wlan_exception_fq;
	uint32_t						expt_fq_count; /* Number of FQs created to HOST */
	unsigned int 				vap_dev_hw_features;
	unsigned int 				vap_dev_features;
	struct vap_desc_s 	vaps[MAX_WIFI_VAPS];
	int								vap_count;
	spinlock_t 				vaplock;
	spinlock_t 				txlock;
	int 					fast_path_enable;
	int 					fast_bridging_enable;
	int 					fast_routing_enable;
	struct vwd_global_stats_s  __percpu         	*vwd_global_stats;
	u32 					msg_enable;
};

/* Common stats not corresponding to specific vap*/
struct vwd_global_stats_s {
	u32 					pkts_total_local_tx;
	u32 					pkts_slow_fail;
	u32 					pkts_dev_down_drop;
};

static inline void display_fd(struct qm_fd *fd)
{
        printk("fd %p\n", fd);
        printk("dd %d, eliodn_offset %x, liodn_offset %x, bpid %d\n",
                fd->dd, fd->eliodn_offset, fd->liodn_offset,
                fd->bpid);
        printk("format %d, offset %d, length %d, addr %llx cmd %x\n",
                fd->format, fd->offset, fd->length20,
                (uint64_t)fd->addr, fd->cmd);
}
int dpaa_get_vap_fwd_fq(uint16_t vap_id, uint32_t* fqid, uint32_t hash);
int dpaa_get_wifi_dev(uint16_t vap_id, void** netdev);
int dpaa_get_wifi_ohport_handle( uint32_t* oh_handle);
void drain_tx_bp_pool(struct dpa_bp *bp);
int vwd_is_no_l2_itf_device(struct net_device* dev);

/* function called after fq-id creation ,
to avoid multiple declarations , declaration added here
other header files are added in many files where the struct qman_fq 
definition is not found */
void cdx_create_fqid_info_in_procfs(uint32_t fqid, 
					struct qman_fq *fq);
void cdx_remove_fqid_info_in_procfs(uint32_t fqid);

#endif /* _DPAA_HOST_GENERIC_H_ */
