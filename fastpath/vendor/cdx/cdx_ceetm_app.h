/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef CDX_CEETM_APP_H
#define CDX_CEETM_APP_H

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <net/pkt_sched.h>

#include <linux/skbuff.h>
#include <linux/fsl_qman.h>
#include "cdx.h"


/**********************************************************************************************************************
 DEBUG definitions
***********************************************************************************************************************/
/*define CEETM_DEBUG to enable debug prints from ceetm module */
/* #define CEETM_DEBUG */

#define CEETM_SUCCESS	0
#define CEETM_FAILURE   -1

#define ceetm_err(fmt, arg...)  \
  printk(KERN_ERR"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
  __LINE__, __func__, ##arg)

#ifdef CEETM_DEBUG
#define ceetm_dbg(fmt, arg...)  \
  printk(KERN_INFO fmt, ##arg)
#else
#define ceetm_dbg(fmt, arg...)
#endif

/**********************************************************************************************************************
Structure and Macro definitions
**********************************************************************************************************/
/* max CEETM instances on SOC equal to number of FMAN instances */
#define MAX_CEETM 				1
/* max number of logical network interfaces */
#define CDX_CEETM_MAX_LNIS                      8
/* max number of channels */
#define CDX_CEETM_MAX_CHANNELS                 	8
/* CEETM FQ Context A */
/* set context_A for FQ, SET OVFQ, OVOM,A0V, B0V, A2V and EBD */
#define VQA_DPAA_VAL_TO_RELEASE_BUFFER 0x9e00000080000000ull
/* max number of queues per channel */
#define CDX_CEETM_MAX_QUEUES_PER_CHANNEL       16
/* shaper control */
#define SHAPER_ON               1
#define SHAPER_OFF              2
/* queue types */
#define CEETM_PRIO_QUEUE        0
#define CEETM_WBFQ_QUEUE        1
/* max number of 10 Gig interfaces on the SoC */
#define MAX_10G_INTERFACES      2
/* max number of 1 Gig interfaces on the SoC */
#define MAX_1G_INTERFACES       6
/* number of class queues */
#define NUM_CLASS_QUEUES        CDX_CEETM_MAX_QUEUES_PER_CHANNEL
/* default TD thresold on Channel Queue */
#define DEFAULT_CG_TD_THRESHOLD 8
/* default WEIGHT for WBFQ queues */
#define DEFAULT_WBFQ_WEIGHT     1
/* start channel number for WBFQ */
#define CEETM_WBFS_START        8
/* default shaper bucket size */
#define CEETM_DEFA_BSIZE        0x2000
/* default value to add for shaper calculations */
#define CEETM_DEFA_OAL          24
/* default priority of WBFQs as programmed from cmm, 0-6 */
#define CEETM_DEFA_WBFQ_PRIORITY 0
/* max values for shaper fields */
#define CEETM_TOKEN_WHOLE_MAXVAL        0x7ff
#define CEETM_TOKEN_FRAC_MAXVAL         0x1fff
/* default TD value */
#define DEFAULT_CQ_DEPTH        8

/* shaper types */
#define CHANNEL_SHAPER_TYPE	0		
#define PORT_SHAPER_TYPE	1


/**********************************************************************************************************************
   Function Prototypes
**********************************************************************************************************************/
typedef struct qman_fq* (*FnHandler)(struct net_device *net_dev, int queue);
void RegisterCEETMHandler(FnHandler pCeetmGetQueue);

int ceetm_create_lni(struct tQM_context_ctl *qm_ctx);
int ceetm_init_channels(void);
int ceetm_cfg_lni(struct tQM_context_ctl *qm_ctx, PQosShaperConfigCommand params);
int ceetm_release_lni(void *handle);
int ceetm_cfg_channel(void *handle, uint32_t rate, uint32_t limit, uint32_t bsize);
int ceetm_cfg_class_queue(struct tQM_context_ctl *qm_ctx, uint32_t classque);
int cdx_enable_ceetm_on_iface(struct dpa_iface_info *iface_info);
int ceetm_reset_qos(struct tQM_context_ctl *qm_ctx);
int ceetm_enable_or_disable_qos(struct tQM_context_ctl *qm_ctx, uint32_t oper);
int ceetm_configure_shaper(void *cfg);
int ceetm_configure_wbfq(void *cfg);
int ceetm_configure_cq(void *cfg);
int ceetm_assign_chnl(struct tQM_context_ctl *qm_ctx, uint32_t channel_num);
int ceetm_get_qos_cfg(struct tQM_context_ctl *qm_ctx, pQosQueryCmd cmd);
int ceetm_get_cq_query(pQosCqQueryCmd cmd);
int ceetm_dscp_fq_map(struct tQM_context_ctl *qm_ctx, uint8_t dscp, uint8_t channel_num, uint8_t clsqueue_num);
int ceetm_dscp_fq_unmap(struct tQM_context_ctl *qm_ctx, uint8_t dscp);
int cdx_dscp_fq_map_on_iface_update_status(struct tQM_context_ctl *qm_ctx, uint8_t status);
#ifdef ENABLE_EGRESS_QOS
int ceetm_exit(void);
#endif

extern int qman_sp_enable_ceetm_mode(enum qm_dc_portal portal, u16 sub_portal);
#endif
