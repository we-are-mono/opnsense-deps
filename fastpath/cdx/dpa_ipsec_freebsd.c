/*
 * DPAA IPsec plumbing layer — FreeBSD port.
 *
 * Ported from ASK/cdx-5.03.1/dpa_ipsec.c.  Provides the DPAA
 * infrastructure for CDX inline IPsec offload:
 *   - Per-SA frame queue creation/teardown (FQ_TO_SEC, FQ_FROM_SEC, FQ_TO_CP)
 *   - IPsec OH port discovery and channel setup
 *   - Slow-path exception handler for FQ_TO_CP (decrypted miss packets)
 *   - Buffer pool info for CAAM preheader (BPID/BSIZE)
 *   - sec_descriptor allocation (64-byte aligned)
 *
 * Uses FreeBSD NCSW QMan API (qman_fqr_create_ctx, qman_fqr_create,
 * qman_fqr_register_cb, qman_fqr_free) instead of Linux SDK QMan API.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "portdefs.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "dpa_ipsec.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/netisr.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/uma.h>

/* DPAA kernel headers */
#include <dev/dpaa/qman.h>
#include <dev/dpaa/bman.h>
#include <dev/dpaa/dpaa_oh.h>

/* NCSW types */
#include <contrib/ncsw/inc/ncsw_ext.h>
#include <contrib/ncsw/inc/integrations/dpaa_integration_ext.h>

MALLOC_DECLARE(M_CDX);

#define	DPAIPSEC_CELL_INDEX	3	/* OH port cell-index for IPsec */
#define	IPSEC_WQ_ID		2	/* Work queue for per-SA FQs */

/* Buffer size for IPsec BMan pool — same as FM_PORT_BUFFER_SIZE (9600+64) */
#define	IPSEC_BUFFER_SIZE	(9600 + 64)

#define	DPAIPSEC_ERROR(fmt, ...)					\
	printf("cdx_ipsec: " fmt, ## __VA_ARGS__)
#define	DPAIPSEC_INFO(fmt, ...)						\
	printf("cdx_ipsec: " fmt, ## __VA_ARGS__)

/* ================================================================
 * Per-SA info — holds sec_descriptor + 3 FQR handles
 * ================================================================ */

struct dpa_ipsec_sainfo {
	void		*shdesc_mem;	/* raw allocation (for free) */
	struct sec_descriptor *shared_desc;	/* 64-byte aligned */
	t_Handle	fqr[NUM_FQS_PER_SA];	/* NCSW FQR handles */
	uint32_t	fqid[NUM_FQS_PER_SA];	/* resolved FQIDs */
};

/* ================================================================
 * IPsec instance singleton — one per CDX module lifetime
 * ================================================================ */

struct ipsec_info {
	uint32_t	crypto_channel_id;	/* CAAM DCP channel */
	device_t	oh_dev;			/* OH port device_t */
	uint32_t	ofport_channel;		/* OH port QMan channel */
	uint32_t	ipsec_bpid;		/* buffer pool ID for CAAM output */
	uint32_t	ipsec_buf_size;		/* buffer size in that pool */
	t_Handle	ipsec_pool;		/* BMan pool handle */
	uma_zone_t	ipsec_zone;		/* UMA zone for pool buffers */
	int		initialized;
};

static struct ipsec_info ipsecinfo;

/* Interface list from cdx_devman_freebsd.c / cdx_dpa_stub.c */
extern struct dpa_iface_info *dpa_interface_info;

/* ================================================================
 * Accessor functions — called by Tier 1 control_ipsec.c
 * ================================================================ */

void *
dpa_get_ipsec_instance(void)
{

	return (&ipsecinfo);
}

struct sec_descriptor *
get_shared_desc(void *handle)
{
	struct dpa_ipsec_sainfo *sa = (struct dpa_ipsec_sainfo *)handle;

	return (sa->shared_desc);
}

uint32_t
get_fqid_to_sec(void *handle)
{
	struct dpa_ipsec_sainfo *sa = (struct dpa_ipsec_sainfo *)handle;

	return (sa->fqid[FQ_TO_SEC]);
}

uint32_t
get_fqid_from_sec(void *handle)
{
	struct dpa_ipsec_sainfo *sa = (struct dpa_ipsec_sainfo *)handle;

	return (sa->fqid[FQ_FROM_SEC]);
}

#ifdef UNIQUE_IPSEC_CP_FQID
uint32_t
ipsec_get_to_cp_fqid(void *handle)
{
	struct dpa_ipsec_sainfo *sa = (struct dpa_ipsec_sainfo *)handle;

	return (sa->fqid[FQ_TO_CP]);
}
#endif

/* ================================================================
 * OH port table descriptor — used for classification table lookups
 * ================================================================ */

/* From cdx_devoh_freebsd.c */
extern void *get_oh_port_td(uint32_t fm_index, uint32_t port_idx,
    uint32_t type);

int
dpa_ipsec_ofport_td(struct ipsec_info *info __unused, uint32_t table_type,
    void **td, uint32_t *portid)
{
	struct dpa_iface_info *p;

	if (table_type >= MAX_MATCH_TABLES) {
		DPAIPSEC_ERROR("invalid table type %u\n", table_type);
		return (-1);
	}

	/*
	 * Walk interface list to find the IPsec OH port.
	 * Table descriptors are stored in cdx_devoh_freebsd.c's
	 * offline_port_info[][] — use get_oh_port_td() accessor.
	 */
	for (p = dpa_interface_info; p != NULL; p = p->next) {
		if ((p->if_flags & (1 << 8)) == 0)	/* IF_TYPE_OFPORT */
			continue;
		if (p->oh_info.port_idx != DPAIPSEC_CELL_INDEX)
			continue;

		*td = get_oh_port_td(p->oh_info.fman_idx,
		    p->oh_info.port_idx, table_type);
		*portid = p->oh_info.portid;
		return (0);
	}

	DPAIPSEC_ERROR("IPsec OH port not found in interface list\n");
	return (-1);
}

/* ================================================================
 * Buffer pool info — used by preheader for CAAM output buffers
 * ================================================================ */

int
cdx_dpa_get_ipsec_pool_info(uint32_t *bpid, uint32_t *buf_size)
{

	if (!ipsecinfo.initialized) {
		DPAIPSEC_ERROR("ipsec not initialized\n");
		return (-1);
	}
	*bpid = ipsecinfo.ipsec_bpid;
	*buf_size = ipsecinfo.ipsec_buf_size;
	return (0);
}

/*
 * Dedicated IPsec BMan buffer pool.
 *
 * CAAM QI acquires output buffers from BMan using the BPID in the
 * preheader.  Using a dedicated pool avoids competing with FMan RX
 * for buffers from the dtsec pool — the same starvation pattern
 * that caused the dtsec 256→2048 buffer fix.
 */
static t_Error
ipsec_pool_put_buffer(t_Handle h_BufferPool, uint8_t *buffer,
    t_Handle context __unused)
{

	uma_zfree(ipsecinfo.ipsec_zone, buffer);
	return (E_OK);
}

static uint8_t *
ipsec_pool_get_buffer(t_Handle h_BufferPool, t_Handle *context)
{

	return (uma_zalloc(ipsecinfo.ipsec_zone, M_NOWAIT));
}

static void
ipsec_pool_depleted(t_Handle h_App, bool in)
{

	if (!in)
		return;

	while (bman_count(ipsecinfo.ipsec_pool) < IPSEC_BUFCOUNT)
		bman_pool_fill(ipsecinfo.ipsec_pool, IPSEC_BUFCOUNT);
}

static int
ipsec_pool_create(struct ipsec_info *info)
{
	uint8_t bpid;

	info->ipsec_buf_size = IPSEC_BUFFER_SIZE;

	info->ipsec_zone = uma_zcreate("cdx_ipsec_bufs", IPSEC_BUFFER_SIZE,
	    NULL, NULL, NULL, NULL, 255 /* 256-byte align for DMA */, 0);
	if (info->ipsec_zone == NULL) {
		DPAIPSEC_ERROR("failed to create UMA zone\n");
		return (-1);
	}

	info->ipsec_pool = bman_pool_create(&bpid,
	    IPSEC_BUFFER_SIZE,
	    0, 0,			/* no software stockpile */
	    IPSEC_BUFCOUNT,		/* pre-seed 512 buffers */
	    ipsec_pool_get_buffer,
	    ipsec_pool_put_buffer,
	    IPSEC_BUFCOUNT / 4,		/* depletion entry threshold */
	    IPSEC_BUFCOUNT / 2,		/* depletion exit threshold */
	    0, 0,			/* no HW depletion */
	    ipsec_pool_depleted, info, NULL, NULL);
	if (info->ipsec_pool == NULL) {
		DPAIPSEC_ERROR("failed to create BMan pool\n");
		uma_zdestroy(info->ipsec_zone);
		info->ipsec_zone = NULL;
		return (-1);
	}
	info->ipsec_bpid = bpid;

	DPAIPSEC_INFO("IPsec pool: bpid %u, buf_size %u, count %u\n",
	    info->ipsec_bpid, info->ipsec_buf_size,
	    bman_count(info->ipsec_pool));
	return (0);
}

static void
ipsec_pool_destroy(struct ipsec_info *info)
{

	if (info->ipsec_pool != NULL) {
		bman_pool_destroy(info->ipsec_pool);
		info->ipsec_pool = NULL;
	}
	if (info->ipsec_zone != NULL) {
		uma_zdestroy(info->ipsec_zone);
		info->ipsec_zone = NULL;
	}
}

/* ================================================================
 * Slow-path exception handler — FQ_TO_CP callback
 *
 * Decrypted packets that don't match any fast-path flow entry
 * arrive here via the OH port's miss path.  Convert the BMan
 * buffer to an mbuf and deliver to the FreeBSD network stack.
 * ================================================================ */

static uint32_t ipsec_exception_pkt_cnt;

static e_RxStoreResponse
ipsec_exception_pkt_handler(t_Handle app __unused, t_Handle qm_fqr __unused,
    t_Handle qm_portal __unused, uint32_t fqid_offset __unused,
    t_DpaaFD *fd)
{
	struct mbuf *m;
	void *frame_va;
	uint32_t fd_status, fd_length, fd_offset;
	uint8_t fd_format;

	ipsec_exception_pkt_cnt++;

	/*
	 * Only handle short single-buffer (SBSF) frames for now.
	 * Format is in elion bits [7:5] (NCSW t_DpaaFD).
	 */
	fd_format = (fd->elion >> 5) & 0x3;
	if (fd_format != 0) {
		DPAIPSEC_ERROR("exception: unsupported FD format %u\n",
		    fd_format);
		goto release;
	}

	fd_status = fd->status;
	/* Short SBSF: length[28:20] = offset (9 bits), length[19:0] = len */
	fd_length = fd->length & 0xFFFFF;
	fd_offset = (fd->length >> 20) & 0x1FF;

	/* Check for SEC errors */
	if (fd_status & 0xFF000000) {
		DPAIPSEC_ERROR("exception: SEC error status 0x%08x\n",
		    fd_status);
		goto release;
	}

	/* Get virtual address from physical */
	frame_va = (void *)PHYS_TO_DMAP(
	    ((uint64_t)fd->addrh << 32) | fd->addrl);
	if (frame_va == NULL)
		goto release;

	/*
	 * Build an mbuf wrapping the frame data.
	 * The decrypted frame starts at frame_va + fd_offset.
	 */
	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL)
		goto release;

	/*
	 * Copy frame data into the mbuf.  For the exception path (slow
	 * path), a copy is acceptable.  The BMan buffer is released
	 * immediately after.
	 */
	if (fd_length > MHLEN) {
		if (m_cljget(m, M_NOWAIT, fd_length) == NULL) {
			m_freem(m);
			goto release;
		}
	}
	m_copyback(m, 0, fd_length, (char *)frame_va + fd_offset);
	m->m_pkthdr.len = fd_length;
	m->m_len = fd_length;

	/*
	 * Deliver the decrypted packet to the IP input path.
	 * The frame should be a raw IP packet (ESP headers stripped).
	 */
	{
		struct ip *ip;

		if (m->m_len < (int)sizeof(struct ip)) {
			m_freem(m);
			goto release;
		}
		ip = mtod(m, struct ip *);
		if (ip->ip_v == IPVERSION) {
			m->m_pkthdr.rcvif = NULL;
			netisr_dispatch(NETISR_IP, m);
		} else if (ip->ip_v == 6) {
			m->m_pkthdr.rcvif = NULL;
			netisr_dispatch(NETISR_IPV6, m);
		} else {
			DPAIPSEC_ERROR("exception: unknown IP version %u\n",
			    ip->ip_v);
			m_freem(m);
		}
	}

release:
	/* Release BMan buffer back to the IPsec pool */
	if (ipsecinfo.ipsec_pool != NULL) {
		void *buf_va;

		buf_va = (void *)PHYS_TO_DMAP(
		    ((uint64_t)fd->addrh << 32) | fd->addrl);
		if (buf_va != NULL)
			bman_put_buffer(ipsecinfo.ipsec_pool, buf_va);
	}
	return (e_RX_STORE_RESPONSE_CONTINUE);
}

/* ================================================================
 * Per-SA allocation / teardown
 * ================================================================ */

/*
 * Allocate per-SA resources: sec_descriptor + 3 FQs.
 *
 * FQ creation order (to resolve FQID dependencies):
 *   1. FQ_TO_CP    — SW portal channel, DQRR callback
 *   2. FQ_FROM_SEC — OH port channel, context_b = FQ_TO_CP FQID
 *   3. FQ_TO_SEC   — CAAM DCP channel, context_a = sec_desc phys,
 *                     context_b = FQ_FROM_SEC FQID
 */
void *
cdx_dpa_ipsecsa_alloc(struct ipsec_info *info, uint32_t handle __unused)
{
	struct dpa_ipsec_sainfo *sainfo;
	t_QmContextA context_a;
	t_QmContextB context_b;
	uint64_t desc_pa;

	if (!info || !ipsecinfo.initialized) {
		DPAIPSEC_ERROR("ipsec not initialized in sa_alloc\n");
		return (NULL);
	}

	sainfo = malloc(sizeof(*sainfo), M_CDX, M_WAITOK | M_ZERO);

	/*
	 * Allocate sec_descriptor with 64-byte alignment.
	 * Raw allocation stored for free; aligned pointer for use.
	 */
	sainfo->shdesc_mem = malloc(sizeof(struct sec_descriptor) +
	    PRE_HDR_ALIGN, M_CDX, M_WAITOK | M_ZERO);
	sainfo->shared_desc = (struct sec_descriptor *)
	    roundup2((uintptr_t)sainfo->shdesc_mem, PRE_HDR_ALIGN);

	/*
	 * Step 1: Create FQ_TO_CP — scheduled to CPU 0's SW portal.
	 * This FQ receives decrypted slow-path packets from the OH port.
	 */
	sainfo->fqr[FQ_TO_CP] = qman_fqr_create(1,
	    (e_QmFQChannel)e_QM_FQ_CHANNEL_SWPORTAL0,
	    IPSEC_WQ_ID,
	    FALSE,	/* don't force FQID */
	    0,		/* alignment */
	    FALSE,	/* not parked */
	    TRUE,	/* holdActive — keep portal affinity */
	    TRUE,	/* preferInCache */
	    FALSE,	/* no congestion avoidance */
	    NULL,	/* no CG handle */
	    0,		/* no overhead accounting */
	    0);		/* no tail drop */
	if (sainfo->fqr[FQ_TO_CP] == NULL) {
		DPAIPSEC_ERROR("failed to create FQ_TO_CP\n");
		goto err_cp;
	}
	sainfo->fqid[FQ_TO_CP] = qman_fqr_get_base_fqid(sainfo->fqr[FQ_TO_CP]);

	/* Register DQRR callback for exception packets */
	if (qman_fqr_register_cb(sainfo->fqr[FQ_TO_CP],
	    ipsec_exception_pkt_handler, NULL) != E_OK) {
		DPAIPSEC_ERROR("failed to register FQ_TO_CP callback\n");
		goto err_from;
	}

	/*
	 * Step 2: Create FQ_FROM_SEC — OH port channel.
	 *
	 * Context-A flags:
	 *   OVERRIDE_FQ  — override destination FQ with context_b FQID
	 *   A1_FIELD_VALID — enable A1 field (SEC error check)
	 *   A1 value = 2 — check SEC error status
	 *
	 * Context-B = FQ_TO_CP FQID (miss destination)
	 */
	memset(&context_a, 0, sizeof(context_a));
	context_a.res[0] =
	    (((CDX_FQD_CTX_A_OVERRIDE_FQ | CDX_FQD_CTX_A_A1_FIELD_VALID)
	      << CDX_FQD_CTX_A_SHIFT_BITS) |
	     CDX_FQD_CTX_A_A1_VAL_TO_CHECK_SECERR);
	context_b = sainfo->fqid[FQ_TO_CP];

	sainfo->fqr[FQ_FROM_SEC] = qman_fqr_create_ctx(1,
	    (e_QmFQChannel)ipsecinfo.ofport_channel,
	    IPSEC_WQ_ID,
	    FALSE,	/* don't force FQID */
	    0,		/* alignment */
	    TRUE,	/* preferInCache */
	    &context_a,
	    &context_b);
	if (sainfo->fqr[FQ_FROM_SEC] == NULL) {
		DPAIPSEC_ERROR("failed to create FQ_FROM_SEC\n");
		goto err_from;
	}
	sainfo->fqid[FQ_FROM_SEC] = qman_fqr_get_base_fqid(
	    sainfo->fqr[FQ_FROM_SEC]);

	/*
	 * Step 3: Create FQ_TO_SEC — CAAM DCP channel.
	 *
	 * Context-A = physical address of sec_descriptor (preheader + shdesc).
	 * CAAM QI reads the shared descriptor from this address.
	 *
	 * Context-B = FQ_FROM_SEC FQID (CAAM response destination).
	 */
	desc_pa = vtophys(sainfo->shared_desc);
	memset(&context_a, 0, sizeof(context_a));
	context_a.res[0] = (uint32_t)(desc_pa >> 32);
	context_a.res[1] = (uint32_t)(desc_pa);
	context_b = sainfo->fqid[FQ_FROM_SEC];

	sainfo->fqr[FQ_TO_SEC] = qman_fqr_create_ctx(1,
	    e_QM_FQ_CHANNEL_CAAM,
	    IPSEC_WQ_ID,
	    FALSE,	/* don't force FQID */
	    0,		/* alignment */
	    TRUE,	/* preferInCache */
	    &context_a,
	    &context_b);
	if (sainfo->fqr[FQ_TO_SEC] == NULL) {
		DPAIPSEC_ERROR("failed to create FQ_TO_SEC\n");
		goto err_to;
	}
	sainfo->fqid[FQ_TO_SEC] = qman_fqr_get_base_fqid(
	    sainfo->fqr[FQ_TO_SEC]);

	DPAIPSEC_INFO("SA alloc: to_sec=%u from_sec=%u to_cp=%u desc_pa=0x%lx\n",
	    sainfo->fqid[FQ_TO_SEC], sainfo->fqid[FQ_FROM_SEC],
	    sainfo->fqid[FQ_TO_CP], (unsigned long)desc_pa);

	return (sainfo);

err_to:
	qman_fqr_free(sainfo->fqr[FQ_FROM_SEC]);
err_from:
	if (sainfo->fqr[FQ_TO_CP] != NULL)
		qman_fqr_free(sainfo->fqr[FQ_TO_CP]);
err_cp:
	free(sainfo->shdesc_mem, M_CDX);
	free(sainfo, M_CDX);
	return (NULL);
}

/*
 * Retire a single per-SA FQ.
 *
 * On Linux, this calls qman_retire_fq() which transitions the FQ to
 * "retiring" state asynchronously.  On FreeBSD, NCSW qman_fqr_free()
 * does full retire+OOS synchronously.  We just free the FQ here and
 * NULL it out so cdx_dpa_ipsecsa_release() skips it.
 *
 * Returns: 0 = FQ already retired/freed, 1 = still retiring (never on NCSW).
 */
int
cdx_dpa_ipsec_retire_fq(void *handle, int fq_num)
{
	struct dpa_ipsec_sainfo *sainfo;

	if (handle == NULL)
		return (0);

	sainfo = (struct dpa_ipsec_sainfo *)handle;

	if (fq_num < 0 || fq_num >= NUM_FQS_PER_SA)
		return (0);

	if (sainfo->fqr[fq_num] != NULL) {
		qman_fqr_free(sainfo->fqr[fq_num]);
		sainfo->fqr[fq_num] = NULL;
	}

	return (0);	/* synchronous — always immediately retired */
}

/*
 * Check if a per-SA FQ is in retired state.
 *
 * On FreeBSD, qman_fqr_free() is synchronous so the FQ is always
 * fully retired (and freed) after cdx_dpa_ipsec_retire_fq().
 *
 * Returns: 0 = retired (OK to proceed), nonzero = still not retired.
 */
int
cdx_ipsec_sa_fq_check_if_retired_state(void *handle, int fq_num)
{
	struct dpa_ipsec_sainfo *sainfo;

	if (handle == NULL)
		return (0);	/* treat NULL as "already retired" */

	sainfo = (struct dpa_ipsec_sainfo *)handle;

	if (fq_num < 0 || fq_num >= NUM_FQS_PER_SA)
		return (0);

	/* If FQR is NULL, it's already freed (retired). Return 0 = OK. */
	return (sainfo->fqr[fq_num] != NULL ? 1 : 0);
}

/*
 * Release all per-SA resources: tear down FQs, free descriptor memory.
 */
int
cdx_dpa_ipsecsa_release(void *handle)
{
	struct dpa_ipsec_sainfo *sainfo;
	int ii;

	if (handle == NULL)
		return (-1);

	sainfo = (struct dpa_ipsec_sainfo *)handle;

	/* Free FQRs in reverse order */
	for (ii = NUM_FQS_PER_SA - 1; ii >= 0; ii--) {
		if (sainfo->fqr[ii] != NULL) {
			qman_fqr_free(sainfo->fqr[ii]);
			sainfo->fqr[ii] = NULL;
		}
	}

	free(sainfo->shdesc_mem, M_CDX);
	free(sainfo, M_CDX);

	return (0);
}

/* ================================================================
 * XFRM state stubs
 *
 * On Linux, these hold/release a reference to the kernel's xfrm_state
 * to keep it alive while CDX offloads the SA.  On FreeBSD there is no
 * XFRM framework — CDX manages SA lifecycle independently via FCI
 * commands from CMM.  Return a non-NULL sentinel so the Tier 1 NULL
 * check in control_ipsec.c passes.
 * ================================================================ */

#define	CDX_XFRM_SENTINEL	((void *)(uintptr_t)0x1)

void *
cdx_get_xfrm_state_of_sa(void *dev __unused, uint16_t handle __unused)
{

	return (CDX_XFRM_SENTINEL);
}

void
cdx_dpa_ipsec_xfrm_state_dec_ref_cnt(void *xfrm_state __unused)
{
}

/* ================================================================
 * SG / skb-free buffer pool stubs
 *
 * On Linux, these create dedicated BMan pools for scatter-gather
 * and skb recycling.  On FreeBSD, mbuf allocation handles this
 * natively.  Provide stub implementations that succeed.
 * ================================================================ */

int
cdx_init_scatter_gather_bpool(void)
{

	return (0);
}

int
cdx_init_skb_2bfreed_bpool(void)
{

	return (0);
}

/* ================================================================
 * Module init / exit
 * ================================================================ */

int
cdx_dpa_ipsec_init(void)
{
	device_t oh_dev;

	DPAIPSEC_INFO("initializing IPsec DPAA plumbing\n");

	memset(&ipsecinfo, 0, sizeof(ipsecinfo));

	/* CAAM DCP channel for QI submissions */
	ipsecinfo.crypto_channel_id = (uint32_t)e_QM_FQ_CHANNEL_CAAM;

	/* Discover IPsec OH port (cell-index 3) */
	oh_dev = dpaa_oh_find_port(DPAIPSEC_CELL_INDEX);
	if (oh_dev == NULL) {
		DPAIPSEC_ERROR("IPsec OH port (cell-index %d) not found\n",
		    DPAIPSEC_CELL_INDEX);
		return (-1);
	}
	ipsecinfo.oh_dev = oh_dev;
	ipsecinfo.ofport_channel = dpaa_oh_get_qman_channel(oh_dev);

	DPAIPSEC_INFO("OH port: cell-index %d, channel 0x%x\n",
	    DPAIPSEC_CELL_INDEX, ipsecinfo.ofport_channel);

	/* Create dedicated IPsec BMan buffer pool */
	if (ipsec_pool_create(&ipsecinfo) != 0) {
		DPAIPSEC_ERROR("failed to create IPsec buffer pool\n");
		return (-1);
	}

	ipsecinfo.initialized = 1;

	DPAIPSEC_INFO("IPsec DPAA plumbing initialized: "
	    "CAAM channel 0x%x, OH channel 0x%x, bpid %u, buf_size %u\n",
	    ipsecinfo.crypto_channel_id, ipsecinfo.ofport_channel,
	    ipsecinfo.ipsec_bpid, ipsecinfo.ipsec_buf_size);

	return (0);
}

void
cdx_dpa_ipsec_exit(void)
{

	DPAIPSEC_INFO("IPsec DPAA plumbing exiting\n");
	ipsecinfo.initialized = 0;
	ipsec_pool_destroy(&ipsecinfo);
}
