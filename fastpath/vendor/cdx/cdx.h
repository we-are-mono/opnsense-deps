/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _CDX_H_
#define _CDX_H_

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/elf.h>
#include <linux/dmapool.h>
#include <linux/platform_device.h>
#include <asm/byteorder.h>
#include <asm/io.h>
#include "fm_eh_types.h"


#ifdef CDX_DEBUG_ENABLE
#define DPRINT(fmt, args...) printk(KERN_ERR "%s: " fmt, __func__, ##args)
#else
#define DPRINT(fmt, args...) do { } while(0)
#endif

#define DPRINT_ERROR(fmt, args...) printk(KERN_CRIT "%s: " fmt, __func__, ##args)

#include "types.h"
#include "list.h"
#include "fe.h"
#include "cdx_hal.h"
#include "cdx_common.h"
#include "cdx_ctrl.h"
#include "cdx_ioctl.h"
#include "cdx_timer.h"
#include "cdx_cmdhandler.h"
#include "layer2.h"
#include "globals.h"
#include "devman.h"
#include "voip.h"

/* ls104x hardware has a single fman */
#define FMAN_INDEX 0 

#define MAX_CDX_INIT_FUNCTIONS  16
typedef void (*cdx_deinit_func)(void);
void register_cdx_deinit_func(cdx_deinit_func func);
extern atomic_t num_active_connections;
extern struct cdx_fman_info *fman_info;

/* qosconnmark definitions */
#define CQID_MASK       0xf     /* class que mask for originator */
#define CHID_MASK       0xf     /* channel id mask for originator */
#define REPLIER_CONNMARK_VALID  ((uint64_t)1 << 63) /* valid bit for replier qosconnmark */

#define CONN_ORIG		1
#define CONN_REPLIER		0

/* function to determine ct entry version of connmark from iptable qosconnmark value */
/* currently handles only chid and cqid bits */ 
static inline uint32_t get_ctentry_qosmark_from_qosconnmark(uint64_t qosconnmark, uint32_t direction)
{
	uint32_t markval;

	if (direction == CONN_ORIG) {
		markval = (qosconnmark & 0xffffffff);
	} else {
		if (qosconnmark & REPLIER_CONNMARK_VALID) {
			markval = (qosconnmark >> 32);
		} else 
			markval = 0;
	}
	if (direction == CONN_ORIG) {
		DPRINT(KERN_ERR "%s:originator: qosmark %llx markval %x\n", __FUNCTION__, qosconnmark, markval);
	} else {
		DPRINT(KERN_ERR "%s:replier: qosmark %llx markval %x\n", __FUNCTION__, qosconnmark, markval);
	}
	return markval;
}


#endif /* _CDX_H_ */
