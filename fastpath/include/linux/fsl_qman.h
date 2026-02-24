/*
 * Shadow header for <linux/fsl_qman.h>
 *
 * Provides QMan types used by cdx_ceetm_app.h and module_qm.h.
 * Core CEETM types (qm_ceetm_rate, etc.) are in dpaa_eth.h (included
 * earlier via portdefs.h). This header adds the remaining QMan types.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_FSL_QMAN_H_COMPAT_
#define _LINUX_FSL_QMAN_H_COMPAT_

#include <sys/types.h>
#include "dpaa_eth.h"	/* qm_ceetm_rate, qm_ceetm_lni, etc. */

/* QMan FQ descriptor — used by procfs.c (stubbed) */
struct qm_fqd {
	uint32_t fq_ctrl;
	struct {
		uint16_t channel;
		uint8_t wq;
	} dest;
	uint32_t context_b;
	struct {
		uint64_t opaque;
	} context_a;
};

/* QMan FQ non-programmable fields */
struct qm_mcr_queryfq_np {
	uint32_t state;
	uint32_t frm_cnt;
	uint32_t byte_cnt;
};

/* QMan dequeue result entry — opaque */
struct qm_dqrr_entry {
	uint32_t fqid;
};

/* QMan portal — opaque */
struct qman_portal {
	uint32_t idx;
};

/* QMan query functions — stubbed */
static inline int qman_query_fq(struct qman_fq *fq, struct qm_fqd *fqd)
{
	return (-1);
}

static inline int qman_query_fq_np(struct qman_fq *fq,
    struct qm_mcr_queryfq_np *np)
{
	return (-1);
}

/*
 * CEETM kernel API declarations — resolved at kldload time.
 * These are implemented in the kernel's qman_ceetm.c and exported.
 * Only cdx_ceetm_freebsd.c calls them (it includes qman_ceetm.h directly
 * for full type definitions). This header provides the declaration for
 * cdx_ceetm_app.h's `extern int qman_sp_enable_ceetm_mode(...)`.
 */
#ifndef _QMAN_CEETM_H
/* Forward declaration if qman_ceetm.h not included */
extern int	qman_sp_enable_ceetm_mode(enum qm_dc_portal portal,
		    uint16_t sub_portal);
extern int	qman_sp_disable_ceetm_mode(enum qm_dc_portal portal,
		    uint16_t sub_portal);
#endif

#endif /* _LINUX_FSL_QMAN_H_COMPAT_ */
