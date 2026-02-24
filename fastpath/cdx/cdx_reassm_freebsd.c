/*
 * cdx_reassm_freebsd.c — IP reassembly with EHASH for FreeBSD
 *
 * Port of cdx-5.03.1/cdx_reassm.c.  Creates BMan buffer pools for
 * reassembly contexts and fragments, allocates a TX-confirm FQR for
 * buffer release, runs a timer kthread that ticks the IPR timestamp
 * in MURAM, and configures the EHASH tables via
 * ExternalHashSetReasslyPool().
 *
 * The Linux version uses dpa_bp_alloc/bman_acquire/bman_release
 * which are Linux DPAA SDK APIs.  On FreeBSD, we use the NCSW
 * bman_pool_create/bman_pool_fill API and qman_fqr_create for FQs.
 *
 * ExternalHashSetReasslyPool and ipr_update_timestamp are implemented
 * in the kernel fm_ehash_freebsd.c.  They are currently stubs until
 * the kernel EHASH code supports IPR offload (EXCLUDE_FMAN_IPR_OFFLOAD
 * removed).
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kthread.h>
#include <sys/proc.h>
#include <sys/sched.h>

#include <vm/uma.h>

#include "portdefs.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "cdx_common.h"
#include "misc.h"
#include "fm_ehash.h"

/* FreeBSD DPAA1 APIs */
#include <dev/dpaa/bman.h>
#include <dev/dpaa/qman.h>

/* NCSW types for FQR and BM pool */
#include <contrib/ncsw/inc/ncsw_ext.h>
#include <contrib/ncsw/inc/Peripherals/qm_ext.h>

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/* ================================================================
 * IPR configuration — populated by cdx_dpa_takeover.c
 * ================================================================ */

struct cdx_ipr_info ipr_info;

/* ================================================================
 * Constants
 * ================================================================ */

#define	IPR_TIMER_FREQUENCY	10	/* ticks per second */
#define	IPR_CTX_POOL_BUFS	64	/* reassembly context buffers */
#define	IPR_FRAG_POOL_BUFS	256	/* fragment buffers */
#define	IPR_POOL_ALIGN		256	/* DMA alignment for buffers */

/* ================================================================
 * BMan pool state
 * ================================================================ */

struct ipr_pool {
	t_Handle	pool;		/* NCSW BM pool handle */
	uma_zone_t	zone;		/* UMA zone for buffer allocation */
	uint8_t		bpid;		/* BMan pool ID */
	uint16_t	buf_size;	/* buffer size */
	char		zname[32];	/* zone name */
};

static struct ipr_pool ipr_ctx_pool;	/* reassembly context pool */
static struct ipr_pool ipr_frag_pool;	/* fragment pool */

/* ================================================================
 * TX-confirm FQR
 * ================================================================ */

static t_Handle ipr_txc_fqr;		/* TX-confirm FQ range */
static uint32_t ipr_txc_fqid;		/* base FQID */

/* ================================================================
 * Timer kthread
 * ================================================================ */

static struct thread *ipr_timer_td;
static volatile int ipr_timer_should_stop;

static uint32_t ipr_txc_count;		/* TX-confirm counter */

/* ================================================================
 * BMan pool callbacks — allocate/free via UMA zone
 * ================================================================ */

static uint8_t *
ipr_pool_get_buf(t_Handle h_pool, t_Handle *context)
{
	struct ipr_pool *p;

	p = h_pool;
	return (uma_zalloc(p->zone, M_NOWAIT));
}

static t_Error
ipr_pool_put_buf(t_Handle h_pool, uint8_t *buffer, t_Handle context)
{
	struct ipr_pool *p;

	p = h_pool;
	uma_zfree(p->zone, buffer);
	return (E_OK);
}

/* ================================================================
 * Pool creation / destruction
 * ================================================================ */

static int
ipr_pool_create(struct ipr_pool *p, const char *name, uint16_t buf_size,
    uint16_t num_bufs)
{

	memset(p, 0, sizeof(*p));
	p->buf_size = buf_size;

	snprintf(p->zname, sizeof(p->zname), "cdx_ipr_%s", name);
	p->zone = uma_zcreate(p->zname, buf_size, NULL, NULL, NULL, NULL,
	    IPR_POOL_ALIGN - 1, 0);
	if (p->zone == NULL) {
		DPA_ERROR("cdx: ipr: failed to create UMA zone '%s'\n",
		    p->zname);
		return (-1);
	}

	p->pool = bman_pool_create(&p->bpid, buf_size,
	    0, 0, num_bufs,		/* max=0, min=0, alloc=num_bufs */
	    ipr_pool_get_buf, ipr_pool_put_buf,
	    0, 0, 0, 0,		/* no depletion thresholds */
	    NULL,			/* no depletion callback */
	    p,				/* h_BufferPool = our pool struct */
	    NULL, NULL);		/* default phys/virt translation */

	if (p->pool == NULL) {
		DPA_ERROR("cdx: ipr: bman_pool_create failed for '%s'\n",
		    p->zname);
		uma_zdestroy(p->zone);
		p->zone = NULL;
		return (-1);
	}

	DPA_INFO("cdx: ipr: pool '%s' created — bpid=%u buf_size=%u "
	    "bufs=%u\n", name, p->bpid, buf_size, num_bufs);

	return (0);
}

static void
ipr_pool_destroy(struct ipr_pool *p)
{

	if (p->pool != NULL) {
		bman_pool_destroy(p->pool);
		p->pool = NULL;
	}
	/*
	 * Do NOT call uma_zdestroy() here.  Buffers allocated from the
	 * UMA zone were released into BMan.  After BMan round-trip,
	 * XX_PhysToVirt returns DMAP addresses (0xffffa000...) instead
	 * of the original KVA addresses (0xffff0000...).  These DMAP
	 * addresses were never tracked by UMA's slab allocator, so
	 * uma_zdestroy → slab cleanup dereferences corrupted pointers
	 * and panics.  Leak the zone; memory is reclaimed on reboot.
	 */
	p->zone = NULL;
}

/* ================================================================
 * TX-confirm FQR — receives frames from FMan after reassembly
 * buffer release.
 *
 * The RX callback logs the frame and releases the buffer back to
 * the appropriate pool.
 * ================================================================ */

static e_RxStoreResponse
ipr_txc_rx_callback(t_Handle app __unused, t_Handle fqr __unused,
    t_Handle portal __unused, uint32_t fqid_off __unused,
    t_DpaaFD *frame __unused)
{

	ipr_txc_count++;
	/*
	 * Real buffer release will be implemented when
	 * fm_ehash_freebsd.c supports IPR offload.
	 * For now, just count the callback.
	 */
	return (e_RX_STORE_RESPONSE_CONTINUE);
}

static int
ipr_create_txc_fqr(void)
{
	t_Handle fqr;

	/*
	 * Create a single FQR on pool channel 1 (any portal can dequeue).
	 * Work queue 0, auto-allocated FQID, prefer in cache.
	 */
	fqr = qman_fqr_create(1,
	    e_QM_FQ_CHANNEL_POOL1, 0,	/* channel, wq */
	    false, 0,			/* no forced FQID */
	    false, false,		/* not parked, not held active */
	    true,			/* prefer in cache */
	    false, NULL,		/* no congestion avoidance */
	    0, 0);			/* no overhead accounting, no tail drop */

	if (fqr == NULL) {
		DPA_ERROR("cdx: ipr: failed to create TX-confirm FQR\n");
		return (-1);
	}

	if (qman_fqr_register_cb(fqr, ipr_txc_rx_callback, NULL) != E_OK) {
		DPA_ERROR("cdx: ipr: failed to register TX-confirm callback\n");
		qman_fqr_free(fqr);
		return (-1);
	}

	ipr_txc_fqr = fqr;
	ipr_txc_fqid = qman_fqr_get_base_fqid(fqr);

	DPA_INFO("cdx: ipr: TX-confirm FQR created — fqid=0x%x\n",
	    ipr_txc_fqid);

	return (0);
}

/* ================================================================
 * IPR timer kthread — ticks the MURAM IPR timestamp at 10 Hz
 * ================================================================ */

extern void ipr_update_timestamp(void);

static void
ipr_timer_fn(void *arg __unused)
{

	while (!ipr_timer_should_stop) {
		pause("iprtmr", hz / IPR_TIMER_FREQUENCY);
		ipr_update_timestamp();
	}

	printf("cdx: ipr: timer thread exiting\n");
	kthread_exit();
}

/* ================================================================
 * Public API — called from cdx_main_freebsd.c init path
 * ================================================================ */

int
cdx_init_ip_reassembly(void)
{
	uint16_t ctx_bufs, frag_bufs;
	uint16_t ctx_bsize, frag_bsize;
	uint32_t txc_fqid_packed;
	int error;

	/*
	 * Use IPR config from dpa_app if provided, otherwise defaults.
	 */
	ctx_bsize = (ipr_info.ipr_ctx_bsize != 0) ?
	    ipr_info.ipr_ctx_bsize : 1600;
	frag_bsize = (ipr_info.ipr_frag_bsize != 0) ?
	    ipr_info.ipr_frag_bsize : 1600;
	ctx_bufs = (ipr_info.max_contexts != 0) ?
	    ipr_info.max_contexts : IPR_CTX_POOL_BUFS;
	frag_bufs = (ipr_info.max_contexts != 0 && ipr_info.max_frags != 0) ?
	    (ipr_info.max_contexts * ipr_info.max_frags) :
	    IPR_FRAG_POOL_BUFS;

	/*
	 * Check if reassembly tables exist in the PCD configuration.
	 * If neither IPv4 nor IPv6 reassembly tables were created by
	 * dpa_app, skip all resource allocation — software reassembly
	 * in the kernel stack handles fragments.
	 */
	if (!ExternalHashReasslyTableExists(IPV4_REASSM_TABLE) &&
	    !ExternalHashReasslyTableExists(IPV6_REASSM_TABLE)) {
		DPA_INFO("cdx: ipr: no reassembly tables configured, "
		    "skipping\n");
		return (0);
	}

	DPA_INFO("cdx: ipr: init — ctx_bsize=%u frag_bsize=%u "
	    "ctx_bufs=%u frag_bufs=%u\n",
	    ctx_bsize, frag_bsize, ctx_bufs, frag_bufs);

	/*
	 * Step 1: Create BMan pool for reassembly contexts.
	 */
	error = ipr_pool_create(&ipr_ctx_pool, "ctx", ctx_bsize, ctx_bufs);
	if (error != 0)
		return (-1);

	/*
	 * Step 2: Create BMan pool for fragments.
	 */
	error = ipr_pool_create(&ipr_frag_pool, "frag", frag_bsize, frag_bufs);
	if (error != 0) {
		ipr_pool_destroy(&ipr_ctx_pool);
		return (-1);
	}

	/*
	 * Step 3: Create TX-confirm FQR for buffer release.
	 */
	error = ipr_create_txc_fqr();
	if (error != 0) {
		ipr_pool_destroy(&ipr_frag_pool);
		ipr_pool_destroy(&ipr_ctx_pool);
		return (-1);
	}

	/*
	 * Step 4: Start IPR timer kthread.
	 */
	ipr_timer_should_stop = 0;
	error = kthread_add(ipr_timer_fn, NULL, NULL,
	    &ipr_timer_td, 0, 0, "cdx_ipr_timer");
	if (error != 0) {
		DPA_ERROR("cdx: ipr: kthread_add failed: %d\n", error);
		if (ipr_txc_fqr != NULL) {
			qman_fqr_free(ipr_txc_fqr);
			ipr_txc_fqr = NULL;
		}
		ipr_pool_destroy(&ipr_frag_pool);
		ipr_pool_destroy(&ipr_ctx_pool);
		return (-1);
	}
	DPA_INFO("cdx: ipr: timer thread started at %d Hz\n",
	    IPR_TIMER_FREQUENCY);

	/*
	 * Step 5: Configure EHASH reassembly tables.
	 *
	 * Pack num_fqs (1) into upper byte of txc_fqid as expected
	 * by ExternalHashSetReasslyPool.
	 */
	txc_fqid_packed = ipr_txc_fqid | (1 << 24);

	if (ExternalHashSetReasslyPool(IPV4_REASSM_TABLE,
	    ipr_ctx_pool.bpid, ctx_bsize,
	    ipr_frag_pool.bpid, frag_bsize,
	    txc_fqid_packed, IPR_TIMER_FREQUENCY)) {
		DPA_INFO("cdx: ipr: IPv4 reassembly table not configured\n");
	}

	if (ExternalHashSetReasslyPool(IPV6_REASSM_TABLE,
	    ipr_ctx_pool.bpid, ctx_bsize,
	    ipr_frag_pool.bpid, frag_bsize,
	    txc_fqid_packed, IPR_TIMER_FREQUENCY)) {
		DPA_INFO("cdx: ipr: IPv6 reassembly table not configured\n");
	}

	return (0);
}

void
cdx_deinit_ip_reassembly(void)
{

	/* Stop the timer thread */
	if (ipr_timer_td != NULL) {
		ipr_timer_should_stop = 1;
		tsleep(__DEVOLATILE(const void *, &ipr_timer_should_stop),
		    0, "iprstop", hz * 2);
		ipr_timer_td = NULL;
	}

	/* Free the TX-confirm FQR */
	if (ipr_txc_fqr != NULL) {
		qman_fqr_free(ipr_txc_fqr);
		ipr_txc_fqr = NULL;
	}

	/* Destroy buffer pools */
	ipr_pool_destroy(&ipr_frag_pool);
	ipr_pool_destroy(&ipr_ctx_pool);

	DPA_INFO("cdx: ipr: deinitialized\n");
}

/* ================================================================
 * Stats query — called from Tier 1 FCI command handlers
 * ================================================================ */

/*
 * ipr_statistics — response structure for FCI stats query.
 * Must match what CMM expects (16-bit ack + ip_reassembly_info).
 */
struct ipr_statistics {
	uint16_t ackstats;
	struct ip_reassembly_info info;
};

int
cdx_get_ipr_v4_stats(void *resp)
{
	struct ipr_statistics *stats;

	stats = (struct ipr_statistics *)resp;

	/*
	 * get_ip_reassem_info not yet implemented in fm_ehash_freebsd.c.
	 * Return empty stats with pool info we know.
	 */
	memset(&stats->info, 0, sizeof(stats->info));
	stats->info.reassem_bpid = ipr_ctx_pool.bpid;
	stats->info.reassem_bsize = ipr_ctx_pool.buf_size;
	stats->info.frag_bpid = ipr_frag_pool.bpid;
	stats->info.frag_bsize = ipr_frag_pool.buf_size;
	stats->info.txc_fqid = ipr_txc_fqid;

	return (sizeof(struct ipr_statistics));
}

int
cdx_get_ipr_v6_stats(void *resp)
{
	struct ipr_statistics *stats;

	stats = (struct ipr_statistics *)resp;

	memset(&stats->info, 0, sizeof(stats->info));
	stats->info.reassem_bpid = ipr_ctx_pool.bpid;
	stats->info.reassem_bsize = ipr_ctx_pool.buf_size;
	stats->info.frag_bpid = ipr_frag_pool.bpid;
	stats->info.frag_bsize = ipr_frag_pool.buf_size;
	stats->info.txc_fqid = ipr_txc_fqid;

	return (sizeof(struct ipr_statistics));
}
