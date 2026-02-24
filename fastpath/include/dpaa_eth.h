/*
 * Stub DPAA ethernet header for FreeBSD port.
 *
 * Provides minimal type stubs for DPAA SDK types used by portdefs.h
 * and other CDX headers. Real implementations come in Phase 5.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _DPAA_ETH_H_STUB_
#define _DPAA_ETH_H_STUB_

#include <sys/types.h>

/* DPAA ethernet TX queue count — must be >= MAX_SCHEDULER_QUEUES (16) */
#ifndef DPAA_ETH_TX_QUEUES
#define DPAA_ETH_TX_QUEUES	16
#endif

/* Generic handle type (from ncsw) */
typedef void *t_Handle;

/*
 * CEETM type definitions.
 *
 * If <dev/dpaa/qman_ceetm.h> was included first, it provides the real
 * kernel struct definitions (with TAILQ linkage, full fields, etc.).
 * Otherwise, provide opaque stubs sufficient for pointer usage and
 * by-value embedding of qm_ceetm_rate in module_qm.h's shaper_info.
 */
#ifndef _QMAN_CEETM_H

/* QMan CEETM rate — used by module_qm.h */
struct qm_ceetm_rate {
	uint32_t whole;
	uint32_t fraction;
};

/* QMan CEETM structures — opaque, used as pointers only */
struct qm_ceetm_lni {
	uint32_t _opaque[16];	/* sized to avoid stack-allocated misuse */
};

struct qm_ceetm_sp {
	uint32_t _opaque[8];
};

struct qm_ceetm_channel {
	uint32_t _opaque[16];
};

/* QMan DC portal enum */
enum qm_dc_portal {
	qm_dc_portal_fman0 = 0,
	qm_dc_portal_fman1,
};

/* QMan frame queue */
#ifndef _QMAN_FQ_DEFINED
#define	_QMAN_FQ_DEFINED
struct qman_fq {
	uint32_t fqid;
	uint32_t flags;
};
#endif

#else /* _QMAN_CEETM_H already included — real types available */

/* qm_ceetm_rate, qm_ceetm_lni, qm_ceetm_sp, qm_ceetm_channel,
 * enum qm_dc_portal, struct qman_fq all defined in qman_ceetm.h */

#endif /* _QMAN_CEETM_H */

/* QMan dequeue callback type */
typedef int (*qman_cb_dqrr)(void *);

/* DPA frame queue info — used by portdefs.h */
struct dpa_fq {
	struct qman_fq fq;
	uint32_t fqid;
	uint32_t flags;
	uint32_t channel;
	uint32_t wq;
	struct dpa_fq *next;	/* PCD FQ singly-linked list */
};

/* BMan pool — opaque stub */
struct dpa_bp {
	uint32_t bpid;
	uint32_t buf_size;
};

/* Linux net_device stub — used by portdefs.h eth_iface_info */
struct net_device {
	char name[16];
	unsigned int ifindex;
	unsigned int mtu;
	unsigned char dev_addr[6];
	void *wifi_offload_dev;
};

/* Linux init_net — global network namespace (stub) */
struct net { int dummy; };
extern struct net init_net;

/* Linux dev_get_by_name / dev_put — find/release net_device (stubs) */
static inline struct net_device *
dev_get_by_name(struct net *ns __unused, const char *name __unused)
{
	return (NULL);
}

static inline void
dev_put(struct net_device *dev __unused)
{
}

/* Linux netdev_priv — returns driver-private data from net_device (stub) */
static inline void *
netdev_priv(const struct net_device *dev __unused)
{
	return (NULL);
}

/* NXP DPAA ethernet driver private structure — minimal stub.
 * Only qm_ctx member accessed by control_qm.c (Tier 1). */
struct tQM_context_ctl;
struct dpa_priv_s {
	void *qm_ctx;
};

#endif /* _DPAA_ETH_H_STUB_ */
