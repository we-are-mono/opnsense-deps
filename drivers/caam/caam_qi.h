/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM QI (Queue Interface) backend — data structures.
 *
 * QI submits crypto operations through QMan frame queues instead of Job
 * Rings, eliminating the JR spinlock for high packet-rate IPsec workloads.
 * Per-session request FQs target CAAM's Direct Connect Portal (channel
 * 0x840), and per-CPU response FQs deliver completions deterministically.
 */

#ifndef _CAAM_QI_H
#define _CAAM_QI_H

#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <contrib/ncsw/inc/Peripherals/dpaa_ext.h>
#include <contrib/ncsw/inc/Peripherals/qm_ext.h>

#include "caam_jr.h"

/* Forward declarations */
struct caam_session;
struct cryptop;

/*
 * Pool depth for QI requests — matches JR pool depth.
 */
#define CAAM_QI_DEPTH		512

/*
 * Maximum shared descriptor + preheader size in bytes.
 * Preheader = 2 words, shared desc up to 64 words = 66 words = 264 bytes.
 * Round up to 512 for alignment.
 */
#define CAAM_QI_PREHDR_SZ	512

/*
 * Per-session QI driver context.
 *
 * Holds the preheader + shared descriptor in DMA memory (FQ Context-A
 * points here), and the request FQ targeting CAAM's DCP channel.
 */
struct caam_qi_drv_ctx {
	struct caam_dma_mem	prehdr_shdesc;	/* prehdr[2] + shdesc[MAX] */
	int			shdesc_len;	/* Shared desc length (words) */
	t_Handle		req_fqr[MAXCPU]; /* Per-CPU request FQs → CAAM */
	int			ncpus;		/* Number of req FQs created */
};

/*
 * S/G entry size for compound FD: 2 entries (output + input).
 */
#define CAAM_QI_SGT_SZ		(2 * sizeof(t_DpaaSGTE))

/*
 * Per-request QI context.
 *
 * Pre-allocated in a pool.  S/G entries for the compound FD live in
 * the DMA-mapped sgt_bulk region (accessed via sgt.vaddr / sgt.paddr).
 * The request index is recovered from the response FD's address.
 */
struct caam_qi_request {
	struct cryptop		*crp;
	struct caam_session	*sess;
	struct caam_qi_drv_ctx	*drv_ctx;

	/* S/G table for compound FD (slice of sgt_bulk) */
	struct caam_dma_mem	sgt;

	/* Bounce buffer for payload I/O (slice of bulk alloc) */
	struct caam_dma_mem	bounce;

	/* Dynamic fallback for oversized payloads */
	struct caam_dma_mem	dyn_bounce;
	bool			using_dyn;

	/* Pool linkage (free list index; -1 = not in pool) */
	int			next_free;
};

/*
 * QI softc — singleton, initialized from the first JR when QI is present.
 */
struct caam_qi_softc {
	device_t		dev;		/* Parent JR device */
	int32_t			cid;		/* opencrypto driver ID */

	/* Per-CPU response FQs */
	t_Handle		rsp_fqr[MAXCPU];
	uint32_t		rsp_fqid[MAXCPU];

	/* Request pool (bulk DMA, same pattern as JR) */
	struct caam_qi_request	*requests;
	struct caam_dma_mem	sgt_bulk;	/* fd_sgt arrays */
	struct caam_dma_mem	bounce_bulk;	/* bounce buffers */
	struct mtx		pool_lock;
	int			pool_head;	/* Free list head (-1 = empty) */
	bool			blocked;	/* ERESTART returned */
};

/* Global QI softc — NULL if QI not available */
extern struct caam_qi_softc *caam_qi_sc;

/* QI-specific shared descriptor builders (caam_qi_alg.c) */
int	caam_qi_gcm_build_enc_shdesc(struct caam_session *sess, device_t dev,
	    struct caam_qi_drv_ctx *ctx);
int	caam_qi_gcm_build_dec_shdesc(struct caam_session *sess, device_t dev,
	    struct caam_qi_drv_ctx *ctx);
int	caam_qi_eta_build_enc_shdesc(struct caam_session *sess, device_t dev,
	    struct caam_qi_drv_ctx *ctx);
int	caam_qi_eta_build_dec_shdesc(struct caam_session *sess, device_t dev,
	    struct caam_qi_drv_ctx *ctx);
int	caam_qi_cipher_build_enc_shdesc(struct caam_session *sess, device_t dev,
	    struct caam_qi_drv_ctx *ctx);
int	caam_qi_cipher_build_dec_shdesc(struct caam_session *sess, device_t dev,
	    struct caam_qi_drv_ctx *ctx);
int	caam_qi_null_hmac_build_enc_shdesc(struct caam_session *sess,
	    device_t dev, struct caam_qi_drv_ctx *ctx);
int	caam_qi_null_hmac_build_dec_shdesc(struct caam_session *sess,
	    device_t dev, struct caam_qi_drv_ctx *ctx);
int	caam_qi_hash_build_shdesc(struct caam_session *sess, device_t dev,
	    struct caam_qi_drv_ctx *ctx);

#endif /* _CAAM_QI_H */
