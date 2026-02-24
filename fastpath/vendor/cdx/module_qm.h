/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _MODULE_QM_H_
#define _MODULE_QM_H_

#include "types.h"
#include <linux/if.h>

struct ceetm_fq {
	struct net_device  *net_dev;
	struct qman_fq    egress_fq;
};

#define NO_PORT		-1

#define NUM_PQS			8
#define NUM_WBFQS		8
#define NUM_CHANNEL_SHAPERS	8
#define MAX_SCHEDULER_QUEUES	(NUM_PQS + NUM_WBFQS)
#define DEFAULT_MAX_QDEPTH 	96
#define GET_CEETM_PRIORITY(x)	((x) < NUM_PQS) ? ((x) ^ (NUM_PQS - 1)) : (x)
#define MAX_CONNMARK_VAL 16
#define EGRESS_MAX_CQ_PROFILES  (MAX_SCHEDULER_QUEUES * NUM_CHANNEL_SHAPERS)


/* For byte mode this is the max expected pkt size */
#define DEFAULT_INGRESS_BYTE_MODE_CBS 2000
#define DEFAULT_INGRESS_BYTE_MODE_PBS 2000

enum {
	CDX_EGRESS_MIN_CQ_PROFILE=CDX_INGRESS_ALL_PROFILES + 1,
	CDX_EGRESS_MAX_CQ_PROFILES=(CDX_EGRESS_MIN_CQ_PROFILE + (EGRESS_MAX_CQ_PROFILES -1))
};

struct shaper_info {
	uint64_t rate;
	uint32_t enable;
	uint32_t bsize;
	struct qm_ceetm_rate token_cr;
};

struct classque_info {
	struct ceetm_fq ceetmfq;
	uint32_t ceetm_idx;
	void *ccg;			
	void *cq;
	void *lfq;			
	union {
		uint32_t ch_shaper_enable;	/* for Priority queues */
		uint32_t weight;	/* for WBFQs */
	};
	uint32_t qdepth;		/* CQ depths */
	uint32_t shaper_rate;	/* shaper rate in Kbps */
	uint32_t cq_shaper_enable;	/* cq shaper */
	uint32_t shaper_bsize;	/* bucket size */
	uint8_t  pp_num;		/* policer profile number */
	void     *pp_handle;	/* policer profile handle */
	void     *pcd_handle;       /* handle to fm_pcd device for this fman */
};

#define MAX_DSCP	64
struct qm_dscp_fq_map {
	struct qman_fq  *dscp_fq[MAX_DSCP];
};

typedef struct cdx_dscp_fqid_s
{
	uint32_t	fqid[MAX_DSCP];
}cdx_dscp_fqid_t;

typedef struct tQM_context_ctl {
        struct cdx_port_info *port_info;
	struct dpa_iface_info *iface_info;
	struct net_device *net_dev;
	struct qm_ceetm_lni *lni;
	struct qm_ceetm_sp *sp;
	struct qm_dscp_fq_map *dscp_fq_map;
	uint32_t qos_enabled;		/* port qos control */
	uint32_t chnl_map;
	struct shaper_info shaper_info; /* port shaper config */
} __attribute__((aligned(32))) QM_context_ctl, *PQM_context_ctl;

struct ceetm_chnl_info {
	struct qm_ceetm_channel *channel;
	uint32_t idx;
	uint32_t wbfq_priority;
	uint32_t wbfq_chshaper;
	void *pcd_handle;	/* handle to fm_pcd device for this fman */
	struct shaper_info shaper_info; 
	PQM_context_ctl qm_ctx;
	struct classque_info cq_info[MAX_SCHEDULER_QUEUES]; 
};
#define QM_GET_CONTEXT(output_port) (&gQMCtx[output_port])

// commands
typedef struct _tQosResetCommand {
	uint16_t status;
	uint16_t reserved;
	unsigned char ifname[IFNAMSIZ];
}QosResetCommand, *PQosResetCommand;

/* return values */
#define QOS_ENERR_NOT_CONFIGURED 	1
#define QOS_ENERR_IO	          	2
#define QOS_ENERR_INVAL_PARAM    	3
typedef struct _tQosEnableCommand {
	uint16_t status;
	uint16_t reserved;
	unsigned char ifname[IFNAMSIZ];
	unsigned short enable_flag;
}QosEnableCommand, *PQosEnableCommand;

#define RATE_VALID          	(1 << 0)
#define BSIZE_VALID          	(1 << 1)
#define PORT_SHAPER_CFG         (1 << 2)
#define CHANNEL_SHAPER_CFG      (0 << 2)
#define SHAPER_CFG_VALID        (1 << 3)

#define SHAPER_ON               1
#define SHAPER_OFF              2

#define DISABLE_POLICER         0
#define DEFAULT_CQ_CIR_VALUE 0xffffffff
#define DEFAULT_CQ_PIR_VALUE 0xffffffff
/* For byte mode this is the max expected pkt size */
#define DEFAULT_CQ_BYTE_MODE_CBS 2000
#define DEFAULT_CQ_BYTE_MODE_PBS 2000

typedef struct _tQosShaperConfigCommand {
	uint16_t status;
	uint16_t reserved;
	union {
		uint8_t ifname[IFNAMSIZ];
		uint32_t channel_num;
	};
	uint32_t enable;
	uint32_t cfg_flags;
	uint32_t rate;
	uint32_t bsize;
}__attribute__((__packed__)) QosShaperConfigCommand, *PQosShaperConfigCommand;


#define WBFQ_PRIORITY_VALID     (1 << 0)
#define WBFQ_SHAPER_VALID     (1 << 1)
typedef struct _tQosWbfqConfigCommand {
	uint16_t status;
	uint16_t reserved;
	uint32_t channel_num;
	uint32_t priority;
	uint32_t wbfq_chshaper;
	uint32_t cfg_flags;
} __attribute__((__packed__)) QosWbfqConfigCommand, *PQosWbfqConfigCommand;


#define CQ_SHAPER_CFG_VALID (1 << 0)
#define CQ_WEIGHT_VALID (1 << 1)
#define CQ_TDINFO_VALID (1 << 2)    
#define CQ_CMINFO_VALID (1 << 3)
#define CQ_RATE_VALID   (1 << 4)

typedef struct _tQosCqConfigCommand {
	uint16_t status;
	uint16_t reserved;
	uint32_t channel_num;
	uint32_t quenum;
	uint32_t tdthresh;
	uint32_t cfg_flags;
	union { 
		uint32_t ch_shaper_en;
		uint32_t weight;
	};
	uint32_t cq_shaper_on;
	uint32_t shaper_rate;
} __attribute__((__packed__)) QosCqConfigCommand, *PQosCqConfigCommand;


typedef struct _tQosChnlAssignCommand {
	uint16_t status;
	uint16_t reserved;
	uint8_t ifname[IFNAMSIZ];
	uint32_t channel_num;
} __attribute__((__packed__)) QosChnlAssignCommand, *PQosChnlAssignCommand;

typedef struct _tQosDscpChnlClsq_mapCmd {
	uint8_t channel_num;
	uint8_t clsqueue_num;
	uint8_t dscp;
	uint8_t status;
	uint8_t ifname[IFNAMSIZ];
} __attribute__((__packed__)) QosDscpChnlClsq_mapCmd, *PQosDscpChnlClsq_mapCmd;

/* structure passed from CMM to QM containing Fast forward Rate Limiting configuration */
enum ratelim_counter {
	RED_TOTAL,
	YELLOW_TOTAL,
	GREEN_TOTAL,
	RED_RECOLORED,
	YELLOW_RECOLORED,
	MAX_RATLIM_CNTR
};

typedef struct _tQosExptRateCommand {
        uint16_t status;
	unsigned short expt_iftype; // WIFI or ETH or PCAP
	unsigned int pkts_per_sec;
	uint32_t burst_size;
	uint32_t clear;
	uint32_t counterval[MAX_RATLIM_CNTR];
}QosExptRateCommand, *PQosExptRateCommand;

typedef struct _tQosIfaceDscpFqidMapCommand {
	uint16_t	status;
	uint8_t		pad;
	uint8_t		enable;
	uint8_t		ifname[IFNAMSIZ];
	uint32_t	fqid[MAX_DSCP];
}QosIfaceDscpFqidMapCommand, *PQosIfaceDscpFqidMapCommand;

typedef struct _tQosFFRateCommand {
	uint16_t status;
	uint16_t reserved;
	uint8_t interface[IFNAMSIZ];    /* interface name */
	unsigned int cir;
	unsigned int pir;
	uint32_t clear;
	uint32_t counterval[MAX_RATLIM_CNTR];
}__attribute__((__packed__)) QosFFRateCommand, *PQosFFRateCommand;

typedef struct _tQosRlkuery
{
	unsigned short action;
	unsigned short mask;
	unsigned int   aggregate_bandwidth;
	unsigned int   bucket_size;	
} __attribute__((packed)) QosRlQuery,*pQosRlQuery;


struct QosChnlShaperInfo {
	uint32_t valid;
	uint32_t shaper_enabled;    	/* port shaper enable */
	uint32_t rate;			/* port shaper rate */
	uint32_t bsize;			/* port shaper bucket size */
};

typedef struct _tQosQueryCommand
{
	uint16_t status;
	uint16_t reserved;
	uint8_t interface[IFNAMSIZ];    /* interface name */
	uint32_t if_qos_enabled;        /* global qos enabled */
	uint32_t shaper_enabled;    	/* port shaper enable */
	uint32_t rate;			/* port shaper rate */
	uint32_t bsize;			/* port shaper bucket size */
	struct QosChnlShaperInfo chnl_shaper_info[NUM_CHANNEL_SHAPERS];
}__attribute__((packed)) QosQueryCmd, *pQosQueryCmd;

typedef struct _tQosCqQueryCommand {
	uint16_t status;
	uint16_t reserved;
	uint32_t channel_num;
	uint32_t queuenum;              /* que num 0 -15, if >15 for port */
	uint32_t clear_stats;
	uint32_t wbfq_priority;         /* priority if wbfq class que */
	uint32_t wbfq_chshaper;         /* wbfq channel shaper */
	union { 
		uint32_t cq_ch_shaper;    	/* class que shaper enable */
		uint32_t weight;                /* weight for WBFQ queues */
	};
	uint32_t qdepth;                /* TD threshold for queues */
	uint32_t fqid;                  /* FQID for queue */
	uint32_t frm_count;
	uint32_t deque_pkts_high;
	uint32_t deque_pkts_lo;
	uint32_t deque_bytes_high;
	uint32_t deque_bytes_lo;
	uint32_t reject_pkts_high;
	uint32_t reject_pkts_lo;
	uint32_t reject_bytes_high;
	uint32_t reject_bytes_lo;
	uint32_t cq_shaper_on;
	uint32_t cir;
	uint32_t counterval[MAX_RATLIM_CNTR];
}__attribute__((packed)) QosCqQueryCmd, *pQosCqQueryCmd;

#ifdef ENABLE_INGRESS_QOS
typedef struct _tIngressQosEnableCommand {
	uint16_t queue_no;
	uint16_t enable_flag;
}__attribute__((__packed__))IngressQosEnableCommand, *PIngressQosEnableCommand;

/* structure passed from CMM to QM containing Ingress policing configuration */
typedef struct _tIngressQosConfigCommand {
        uint16_t status;
        uint16_t queue_no;
        uint32_t cir;
        uint32_t pir;
}__attribute__((__packed__)) IngressQosCfgCommand, *PIngressQosCfgCommand;

typedef struct _tIngressQosStat {
	uint32_t policer_on;
        uint32_t cir;
        uint32_t pir;
        uint32_t cbs;
        uint32_t pbs;
	uint32_t counterval[MAX_RATLIM_CNTR];
}__attribute__((packed)) IngressQosStat, *pIngressQosStat;

typedef struct _tIngressQosStatCommand {
	uint32_t clear;
	struct _tIngressQosStat policer_stats[INGRESS_FLOW_POLICER_QUEUES];
}__attribute__((packed)) IngressQosStatCmd, *pIngressQosStatCmd;

#ifdef SEC_PROFILE_SUPPORT
typedef struct _tSecQosStatCommand {
	uint32_t clear;
	struct _tIngressQosStat policer_stats;
}__attribute__((packed)) SecQosStatCmd, *pSecQosStatCmd;

typedef struct _tQosSecRateCommand {
	uint16_t status;
	uint16_t reserved;
	unsigned int cir;
	unsigned int pir;
	uint32_t cbs;
	uint32_t pbs;
	uint32_t clear;
	uint32_t counterval[MAX_RATLIM_CNTR];
}__attribute__((__packed__)) QosSecRateCommand, *PQosSecRateCommand;
#endif /* endif for SEC_PROFILE_SUPPORT */

#endif
int qm_init(void);
void qm_exit(void);
extern QM_context_ctl gQMCtx[MAX_PHY_PORTS];

cdx_dscp_fqid_t* get_dscp_fqid_map(uint32_t portid);
int ceetm_get_dscp_fq_map(struct tQM_context_ctl *qm_ctx, PQosIfaceDscpFqidMapCommand cmd);
int ceetm_enable_disable_dscp_fq_map(struct tQM_context_ctl *qm_ctx, uint8_t status); 
int enable_dscp_fqid_map(uint32_t portid);
int disable_dscp_fqid_map(uint32_t portid);
int reset_dscp_fq_map_ff(cdx_dscp_fqid_t *muram_dscp_fqid_map, uint8_t dscp);
int reset_all_dscp_fq_map_ff(cdx_dscp_fqid_t *muram_dscp_fqid_map);

#endif /* _MODULE_QM_H_ */
