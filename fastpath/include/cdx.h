/*
 * CDX master header — FreeBSD replacement
 *
 * Replaces the original cdx.h which includes Linux kernel headers.
 * Routes through our compat headers instead, then includes the
 * CDX-specific headers from cdx-5.03.1/.
 *
 * This file shadows the original cdx.h because freebsd/include/
 * is earlier in the -I path than cdx-5.03.1/.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _CDX_H_
#define _CDX_H_

/* FreeBSD kernel headers */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/types.h>
#include <sys/endian.h>

/* Linux compat shims */
#include "linux_compat.h"
#include "linux_mutex_compat.h"
#include "linux_list_compat.h"
#include "linux_workqueue_compat.h"
#include "linux_kthread_compat.h"
#include "linux_device_compat.h"

/* Stub DPAA headers (shadow Linux DPAA SDK) */
#include "fm_eh_types.h"

/* CDX's own OS-independent headers (from cdx-5.03.1/) */
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

/* LS104x hardware has a single fman */
#define FMAN_INDEX	0

#define MAX_CDX_INIT_FUNCTIONS	16
typedef void (*cdx_deinit_func)(void);
void register_cdx_deinit_func(cdx_deinit_func func);
extern atomic_t num_active_connections;
extern struct cdx_fman_info *fman_info;

/* qosconnmark definitions */
#define CQID_MASK		0xf
#define CHID_MASK		0xf
#define REPLIER_CONNMARK_VALID	((uint64_t)1 << 63)

#define CONN_ORIG		1
#define CONN_REPLIER		0

static inline uint32_t get_ctentry_qosmark_from_qosconnmark(
    uint64_t qosconnmark, uint32_t direction)
{
	uint32_t markval;

	if (direction == CONN_ORIG) {
		markval = (qosconnmark & 0xffffffff);
	} else {
		if (qosconnmark & REPLIER_CONNMARK_VALID)
			markval = (qosconnmark >> 32);
		else
			markval = 0;
	}
	return (markval);
}

#ifdef CDX_DEBUG_ENABLE
#define DPRINT(fmt, args...) printf("%s: " fmt, __func__, ##args)
#else
#define DPRINT(fmt, args...) do { } while (0)
#endif

#define DPRINT_ERROR(fmt, args...) printf("%s: " fmt, __func__, ##args)

#endif /* _CDX_H_ */
