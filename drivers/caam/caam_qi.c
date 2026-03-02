/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM QI (Queue Interface) crypto backend.
 *
 * Submits crypto operations through QMan frame queues instead of Job Rings.
 * Each session creates a request FQ targeting CAAM's DCP (channel 0x840)
 * with Context-A pointing to the preheader + shared descriptor.  Per-CPU
 * response FQs deliver completions to the originating CPU's portal.
 *
 * Compound frame descriptor format:
 *   fd.addr → fd_sgt[2] (DMA memory)
 *   fd_sgt[0] = OUTPUT buffer (CAAM writes result here)
 *   fd_sgt[1] = INPUT buffer (CAAM reads from here), F=1 (Final)
 *
 * QI shared descriptors differ from JR shared descriptors:
 *   - assoclen via SEQ LOAD (first 4 bytes of input stream)
 *   - IV via SEQ FIFO LOAD (from input stream)
 *   - KEY + OPERATION must precede SEQ FIFO LOAD with FLUSH1
 *
 * QI bounce buffer layout:
 *   [assoclen (4B, BE)] [IV (ivlen)] [AAD] [payload] [ICV for decrypt]
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/smp.h>

#include <machine/bus.h>

#include <opencrypto/cryptodev.h>

#include <contrib/ncsw/inc/Peripherals/dpaa_ext.h>
#include <contrib/ncsw/inc/integrations/dpaa_integration_ext.h>

#include <dev/ofw/ofw_bus.h>

#include <dev/dpaa/qman.h>

#include "caam.h"
#include "caam_regs.h"
#include "caam_desc.h"
#include "caam_jr.h"
#include "caam_crypto.h"
#include "caam_qi.h"

#include "cryptodev_if.h"

static MALLOC_DEFINE(M_CAAM_QI, "caam_qi", "CAAM QI crypto requests");

/* Singleton QI softc */
struct caam_qi_softc *caam_qi_sc;

/* ================================================================
 * QI Request Pool Management
 *
 * Same bulk-DMA pattern as the JR pool (caam_crypto.c).
 * S/G tables and bounce buffers are pre-allocated in bulk regions
 * and sliced into per-request chunks.
 * ================================================================ */

static int
caam_qi_pool_init(struct caam_qi_softc *qi)
{
	struct caam_qi_request *req;
	int error, i;

	qi->requests = malloc(sizeof(struct caam_qi_request) * CAAM_QI_DEPTH,
	    M_CAAM_QI, M_WAITOK | M_ZERO);

	/* Bulk DMA: S/G tables (512 * 32 = 16KB) */
	error = caam_dma_alloc(qi->dev, &qi->sgt_bulk,
	    (bus_size_t)CAAM_QI_DEPTH * CAAM_QI_SGT_SZ);
	if (error != 0)
		goto fail_requests;

	/* Bulk DMA: bounce buffers (512 * 2048 = 1MB) */
	error = caam_dma_alloc(qi->dev, &qi->bounce_bulk,
	    (bus_size_t)CAAM_QI_DEPTH * CAAM_BOUNCE_SZ);
	if (error != 0)
		goto fail_sgt;

	mtx_init(&qi->pool_lock, "caam_qi_pool", NULL, MTX_DEF);
	qi->pool_head = 0;
	qi->blocked = false;

	for (i = 0; i < CAAM_QI_DEPTH; i++) {
		req = &qi->requests[i];
		req->next_free = i + 1;

		/* S/G table slice */
		req->sgt.tag = NULL;
		req->sgt.map = NULL;
		req->sgt.vaddr = (uint8_t *)qi->sgt_bulk.vaddr +
		    i * CAAM_QI_SGT_SZ;
		req->sgt.paddr = qi->sgt_bulk.paddr +
		    i * CAAM_QI_SGT_SZ;

		/* Bounce buffer slice */
		req->bounce.tag = NULL;
		req->bounce.map = NULL;
		req->bounce.vaddr = (uint8_t *)qi->bounce_bulk.vaddr +
		    i * CAAM_BOUNCE_SZ;
		req->bounce.paddr = qi->bounce_bulk.paddr +
		    i * CAAM_BOUNCE_SZ;

		req->dyn_bounce.tag = NULL;
		req->using_dyn = false;
	}

	/* Terminate free list */
	qi->requests[CAAM_QI_DEPTH - 1].next_free = -1;

	return (0);

fail_sgt:
	caam_dma_free(&qi->sgt_bulk);
fail_requests:
	free(qi->requests, M_CAAM_QI);
	qi->requests = NULL;
	return (error);
}

static void
caam_qi_pool_fini(struct caam_qi_softc *qi)
{
	struct caam_qi_request *req;
	int i;

	if (qi->requests == NULL)
		return;

	for (i = 0; i < CAAM_QI_DEPTH; i++) {
		req = &qi->requests[i];
		if (req->using_dyn)
			caam_dma_free(&req->dyn_bounce);
	}

	caam_dma_free(&qi->bounce_bulk);
	caam_dma_free(&qi->sgt_bulk);

	mtx_destroy(&qi->pool_lock);
	free(qi->requests, M_CAAM_QI);
	qi->requests = NULL;
}

static struct caam_qi_request *
caam_qi_pool_alloc(struct caam_qi_softc *qi)
{
	struct caam_qi_request *req;
	int idx;

	mtx_lock(&qi->pool_lock);
	idx = qi->pool_head;
	if (idx < 0) {
		mtx_unlock(&qi->pool_lock);
		return (NULL);
	}
	req = &qi->requests[idx];
	qi->pool_head = req->next_free;
	req->next_free = -1;
	mtx_unlock(&qi->pool_lock);

	return (req);
}

static void
caam_qi_pool_free(struct caam_qi_softc *qi, struct caam_qi_request *req)
{
	int idx;

	if (req->using_dyn) {
		caam_dma_free(&req->dyn_bounce);
		req->using_dyn = false;
	}

	req->crp = NULL;
	req->sess = NULL;
	req->drv_ctx = NULL;

	idx = req - qi->requests;

	mtx_lock(&qi->pool_lock);
	req->next_free = qi->pool_head;
	qi->pool_head = idx;
	mtx_unlock(&qi->pool_lock);
}

/* ================================================================
 * Response FQ Callback
 *
 * Called by QMan portal polling when CAAM delivers a completed
 * frame to a per-CPU response FQ.  The response FD's addr field
 * points to the S/G table, which we map back to the request index
 * via the sgt_bulk base address.
 * ================================================================ */

static e_RxStoreResponse
caam_qi_rsp_cb(t_Handle app, t_Handle qm_fqr, t_Handle qm_portal,
    uint32_t fqid_offset, t_DpaaFD *frame)
{
	struct caam_qi_softc *qi = (struct caam_qi_softc *)app;
	struct caam_qi_request *req;
	struct cryptop *crp;
	struct caam_session *sess;
	bus_addr_t sgt_pa;
	uint32_t status, ssrc;
	uint8_t *buf;
	bool encrypt, blocked;
	int idx;

	/* Recover request from S/G table DMA address */
	sgt_pa = DPAA_FD_GET_PHYS_ADDR(frame);
	idx = (sgt_pa - qi->sgt_bulk.paddr) / CAAM_QI_SGT_SZ;

	if (__predict_false(idx < 0 || idx >= CAAM_QI_DEPTH)) {
		device_printf(qi->dev,
		    "QI: bad response sgt_pa 0x%lx (idx %d)\n",
		    (unsigned long)sgt_pa, idx);
		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

	req = &qi->requests[idx];
	crp = req->crp;
	sess = req->sess;
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);
	status = DPAA_FD_GET_STATUS(frame);

	/*
	 * QI bounce buffer layout differs from JR: QI prepends
	 * [assoclen(4)] [IV(ivlen)] before [AAD] [payload] [ICV].
	 * The "data" portion starts after the QI prefix.
	 */
	buf = req->using_dyn ? req->dyn_bounce.vaddr : req->bounce.vaddr;
	{
		int qi_prefix = 4 + sess->ivlen;
		if (sess->alg_type == CAAM_ALG_HASH ||
		    sess->alg_type == CAAM_ALG_HMAC)
			qi_prefix = 0;	/* Hash has no assoclen or IV */
		else if (sess->alg_type == CAAM_ALG_CIPHER)
			qi_prefix = sess->ivlen; /* Cipher: IV only, no assoclen */
		buf += qi_prefix;
	}

	/* Map CAAM status to error code */
	if (status == 0) {
		crp->crp_etype = 0;
	} else {
		ssrc = status & JRSTA_SSRC_MASK;
		if (ssrc == JRSTA_SSRC_JUMP_HALT_USER) {
			crp->crp_etype = 0;
		} else if (ssrc == JRSTA_SSRC_CCB_ERROR &&
		    (status & CCB_ERRID_MASK) == CCB_ERR_ICV_CHECK) {
			crp->crp_etype = EBADMSG;
		} else {
			crp->crp_etype = EIO;
			device_printf(qi->dev,
			    "QI crypto error: status 0x%08x "
			    "ssrc=0x%x errid=0x%x alg_type=%d\n",
			    status, (status >> 28) & 0xf,
			    status & 0xff, sess->alg_type);
		}
	}

	/* Copy results back on success */
	if (crp->crp_etype == 0) {
		if (sess->alg_type == CAAM_ALG_HASH ||
		    sess->alg_type == CAAM_ALG_HMAC) {
			/*
			 * Hash output is just the digest at offset 0
			 * (no payload in output — only SEQINLEN consumes it).
			 */
			if (crp->crp_op & CRYPTO_OP_VERIFY_DIGEST) {
				uint8_t expected[64];

				crypto_copydata(crp, crp->crp_digest_start,
				    sess->icvlen, expected);
				if (timingsafe_bcmp(buf, expected,
				    sess->icvlen) != 0)
					crp->crp_etype = EBADMSG;
			} else {
				crypto_copyback(crp, crp->crp_digest_start,
				    sess->icvlen, buf);
			}
		} else if (encrypt) {
			crypto_copyback(crp, crp->crp_payload_start,
			    crp->crp_payload_length,
			    buf + crp->crp_aad_length);
			crypto_copyback(crp, crp->crp_digest_start,
			    sess->icvlen,
			    buf + crp->crp_aad_length +
			    crp->crp_payload_length);
		} else {
			crypto_copyback(crp, crp->crp_payload_start,
			    crp->crp_payload_length,
			    buf + crp->crp_aad_length);
		}
	}

	caam_qi_pool_free(qi, req);

	mtx_lock(&qi->pool_lock);
	blocked = qi->blocked;
	if (blocked)
		qi->blocked = false;
	mtx_unlock(&qi->pool_lock);

	if (blocked)
		crypto_unblock(qi->cid, CRYPTO_SYMQ);

	crypto_done(crp);

	return (e_RX_STORE_RESPONSE_CONTINUE);
}

/* ================================================================
 * Response FQ Infrastructure
 * ================================================================ */

static int
caam_qi_create_rsp_fqs(struct caam_qi_softc *qi)
{
	int cpu, ncpus;
	t_Error err;

	ncpus = mp_ncpus;
	if (ncpus > MAXCPU)
		ncpus = MAXCPU;

	for (cpu = 0; cpu < ncpus; cpu++) {
		qi->rsp_fqr[cpu] = qman_fqr_create(1,
		    (e_QmFQChannel)(e_QM_FQ_CHANNEL_SWPORTAL0 + cpu),
		    3,		/* WQ 3 — same as dtsec TX confirm */
		    FALSE,	/* don't force FQID */
		    0,		/* alignment */
		    FALSE,	/* not parked */
		    FALSE,	/* no hold_active */
		    TRUE,	/* prefer_in_cache */
		    FALSE,	/* no congestion avoidance */
		    NULL,	/* no congestion group */
		    0,		/* no overhead accounting */
		    0);		/* no tail drop */

		if (qi->rsp_fqr[cpu] == NULL) {
			device_printf(qi->dev,
			    "QI: failed to create response FQ for CPU %d\n",
			    cpu);
			goto fail;
		}

		err = qman_fqr_register_cb(qi->rsp_fqr[cpu],
		    caam_qi_rsp_cb, (t_Handle)qi);
		if (err != E_OK) {
			device_printf(qi->dev,
			    "QI: failed to register cb for CPU %d: %d\n",
			    cpu, err);
			goto fail;
		}

		qi->rsp_fqid[cpu] = qman_fqr_get_base_fqid(
		    qi->rsp_fqr[cpu]);
	}

	device_printf(qi->dev,
	    "QI: %d response FQs created (FQID base %u)\n",
	    ncpus, qi->rsp_fqid[0]);

	return (0);

fail:
	for (cpu = cpu - 1; cpu >= 0; cpu--) {
		if (qi->rsp_fqr[cpu] != NULL) {
			qman_fqr_free(qi->rsp_fqr[cpu]);
			qi->rsp_fqr[cpu] = NULL;
		}
	}
	return (ENXIO);
}

static void
caam_qi_destroy_rsp_fqs(struct caam_qi_softc *qi)
{
	int cpu, ncpus;

	ncpus = mp_ncpus;
	if (ncpus > MAXCPU)
		ncpus = MAXCPU;

	for (cpu = 0; cpu < ncpus; cpu++) {
		if (qi->rsp_fqr[cpu] != NULL) {
			qman_fqr_free(qi->rsp_fqr[cpu]);
			qi->rsp_fqr[cpu] = NULL;
		}
	}
}

/* ================================================================
 * Session Lifecycle
 * ================================================================ */

/*
 * Allocate and initialize a QI driver context (preheader + shared desc
 * + request FQ).  The shared descriptor is built by the caller-supplied
 * builder function.
 */
static int
caam_qi_drv_ctx_create(struct caam_qi_softc *qi, struct caam_session *sess,
    struct caam_qi_drv_ctx **ctxp,
    int (*build_shdesc)(struct caam_session *, device_t,
    struct caam_qi_drv_ctx *))
{
	struct caam_qi_drv_ctx *ctx;
	uint32_t *prehdr;
	t_QmContextA context_a;
	t_QmContextB context_b;
	uint64_t prehdr_pa;
	int error;

	ctx = malloc(sizeof(*ctx), M_CAAM_QI, M_WAITOK | M_ZERO);

	/* Allocate DMA for preheader + shared descriptor */
	error = caam_dma_alloc(qi->dev, &ctx->prehdr_shdesc,
	    CAAM_QI_PREHDR_SZ);
	if (error != 0) {
		free(ctx, M_CAAM_QI);
		return (error);
	}

	/* Build the QI shared descriptor (populates prehdr[2..] and shdesc_len) */
	error = build_shdesc(sess, qi->dev, ctx);
	if (error != 0) {
		caam_dma_free(&ctx->prehdr_shdesc);
		free(ctx, M_CAAM_QI);
		return (error);
	}

	/*
	 * Fill preheader (2 words before the shared descriptor).
	 * Word 0: RSLS | shdesc_len
	 *   RSLS (bit 31) = Route SEQ LOAD/STORE to FD — tells the QI
	 *   hardware to route compound FD S/G data to the DECO's sequential
	 *   input/output.  Without RSLS, SEQ commands have no data source.
	 *   Linux always sets RSLS (see drivers/crypto/caam/qi.c).
	 * Word 1: ABS — absolute addressing mode
	 */
	prehdr = ctx->prehdr_shdesc.vaddr;
	prehdr[0] = cpu_to_caam32(PREHDR_RSLS | ctx->shdesc_len);
	prehdr[1] = cpu_to_caam32(PREHDR_ABS);

	/*
	 * Create per-CPU request FQs targeting CAAM's Direct Connect Portal.
	 * Context-A = DMA address of preheader (CAAM reads shdesc from here)
	 * Context-B = FQID of per-CPU response FQ (completions to submitter)
	 *
	 * Each CPU gets its own request FQ so that CAAM routes completions
	 * back to the submitting CPU's QMan portal, avoiding cross-CPU
	 * delivery overhead.
	 */
	prehdr_pa = ctx->prehdr_shdesc.paddr;
	memset(&context_a, 0, sizeof(context_a));
	context_a.res[0] = (uint32_t)(prehdr_pa >> 32);
	context_a.res[1] = (uint32_t)prehdr_pa;

	ctx->ncpus = mp_ncpus;
	if (ctx->ncpus > MAXCPU)
		ctx->ncpus = MAXCPU;

	for (int cpu = 0; cpu < ctx->ncpus; cpu++) {
		context_b = qi->rsp_fqid[cpu];

		ctx->req_fqr[cpu] = qman_fqr_create_ctx(1,
		    e_QM_FQ_CHANNEL_CAAM,
		    2,		/* WQ 2 */
		    FALSE,	/* don't force FQID */
		    0,		/* alignment */
		    TRUE,	/* prefer_in_cache */
		    &context_a,
		    &context_b);

		if (ctx->req_fqr[cpu] == NULL) {
			device_printf(qi->dev,
			    "QI: failed to create request FQ for CPU %d\n",
			    cpu);
			for (int j = cpu - 1; j >= 0; j--)
				qman_fqr_free(ctx->req_fqr[j]);
			caam_dma_free(&ctx->prehdr_shdesc);
			free(ctx, M_CAAM_QI);
			return (ENXIO);
		}
	}

	*ctxp = ctx;
	return (0);
}

static void
caam_qi_drv_ctx_destroy(struct caam_qi_drv_ctx *ctx)
{
	int cpu;

	if (ctx == NULL)
		return;

	for (cpu = 0; cpu < ctx->ncpus; cpu++) {
		if (ctx->req_fqr[cpu] != NULL)
			qman_fqr_free(ctx->req_fqr[cpu]);
	}

	/* Zero inline key material in shared descriptor before freeing */
	if (ctx->prehdr_shdesc.vaddr != NULL)
		explicit_bzero(ctx->prehdr_shdesc.vaddr, CAAM_QI_PREHDR_SZ);
	caam_dma_free(&ctx->prehdr_shdesc);
	free(ctx, M_CAAM_QI);
}

static int
caam_qi_newsession(device_t dev, crypto_session_t cses,
    const struct crypto_session_params *csp)
{
	struct caam_qi_softc *qi = caam_qi_sc;
	struct caam_session *sess;
	int error;

	sess = crypto_get_driver_session(cses);
	memset(sess, 0, sizeof(*sess));

	/* Copy cipher key */
	sess->enc_klen = csp->csp_cipher_klen;
	if (sess->enc_klen > 0 && csp->csp_cipher_key != NULL)
		memcpy(sess->enc_key, csp->csp_cipher_key, sess->enc_klen);

	switch (csp->csp_mode) {
	case CSP_MODE_AEAD:
		sess->alg_type = CAAM_ALG_GCM;
		sess->ivlen = AES_GCM_IV_LEN;
		sess->icvlen = (csp->csp_auth_mlen != 0) ?
		    csp->csp_auth_mlen : AES_GCM_TAG_LEN;
		sess->cipher_algtype = OP_ALG_ALGSEL_AES | OP_ALG_AAI_GCM;

		error = caam_qi_drv_ctx_create(qi, sess, &sess->qi_enc_ctx,
		    caam_qi_gcm_build_enc_shdesc);
		if (error != 0)
			return (error);
		error = caam_qi_drv_ctx_create(qi, sess, &sess->qi_dec_ctx,
		    caam_qi_gcm_build_dec_shdesc);
		if (error != 0) {
			caam_qi_drv_ctx_destroy(sess->qi_enc_ctx);
			sess->qi_enc_ctx = NULL;
			return (error);
		}
		break;

	case CSP_MODE_ETA:
		if (csp->csp_cipher_alg == CRYPTO_NULL_CBC)
			sess->alg_type = CAAM_ALG_NULL_HMAC;
		else
			sess->alg_type = CAAM_ALG_CBC_HMAC;

		sess->cipher_algtype = caam_cipher_algtype(
		    csp->csp_cipher_alg);
		sess->ivlen = caam_cipher_ivlen(csp->csp_cipher_alg);
		sess->icvlen = (csp->csp_auth_mlen != 0) ?
		    csp->csp_auth_mlen :
		    caam_auth_digest_len(csp->csp_auth_alg);
		sess->auth_algtype = caam_auth_algsel(csp->csp_auth_alg);
		if (sess->auth_algtype == 0)
			return (EINVAL);

		sess->auth_klen = csp->csp_auth_klen;
		memcpy(sess->auth_key, csp->csp_auth_key, sess->auth_klen);
		sess->split_key_len = caam_split_key_len(
		    sess->auth_algtype & OP_ALG_ALGSEL_MASK);
		sess->split_key_pad_len = caam_split_key_pad_len(
		    sess->auth_algtype & OP_ALG_ALGSEL_MASK);

		/* Allocate DMA buffer and derive split key via JR */
		error = caam_session_alloc_auth_key_dma(qi->dev, sess);
		if (error != 0)
			return (error);
		error = caam_gen_split_key(qi->dev, sess);
		if (error != 0) {
			caam_dma_free(&sess->auth_key_dma);
			return (error);
		}

		if (sess->alg_type == CAAM_ALG_NULL_HMAC) {
			error = caam_qi_drv_ctx_create(qi, sess,
			    &sess->qi_enc_ctx,
			    caam_qi_null_hmac_build_enc_shdesc);
			if (error != 0)
				goto qi_fail_auth_key;
			error = caam_qi_drv_ctx_create(qi, sess,
			    &sess->qi_dec_ctx,
			    caam_qi_null_hmac_build_dec_shdesc);
		} else {
			error = caam_qi_drv_ctx_create(qi, sess,
			    &sess->qi_enc_ctx,
			    caam_qi_eta_build_enc_shdesc);
			if (error != 0)
				goto qi_fail_auth_key;
			error = caam_qi_drv_ctx_create(qi, sess,
			    &sess->qi_dec_ctx,
			    caam_qi_eta_build_dec_shdesc);
		}
		if (error != 0) {
			caam_qi_drv_ctx_destroy(sess->qi_enc_ctx);
			sess->qi_enc_ctx = NULL;
		qi_fail_auth_key:
			caam_dma_free(&sess->auth_key_dma);
			return (error);
		}
		break;

	case CSP_MODE_DIGEST:
		sess->auth_algtype = caam_auth_algsel(csp->csp_auth_alg);
		if (sess->auth_algtype == 0)
			return (EINVAL);
		sess->icvlen = (csp->csp_auth_mlen != 0) ?
		    csp->csp_auth_mlen :
		    caam_auth_digest_len(csp->csp_auth_alg);
		sess->ivlen = 0;
		sess->enc_klen = 0;

		if (csp->csp_auth_klen > 0) {
			sess->alg_type = CAAM_ALG_HMAC;
			sess->auth_klen = csp->csp_auth_klen;
			sess->split_key_len = caam_split_key_len(
			    sess->auth_algtype & OP_ALG_ALGSEL_MASK);
			sess->split_key_pad_len = caam_split_key_pad_len(
			    sess->auth_algtype & OP_ALG_ALGSEL_MASK);
			memcpy(sess->auth_key, csp->csp_auth_key,
			    sess->auth_klen);

			/* Allocate DMA buffer and derive split key via JR */
			error = caam_session_alloc_auth_key_dma(qi->dev, sess);
			if (error != 0)
				return (error);
			error = caam_gen_split_key(qi->dev, sess);
			if (error != 0) {
				caam_dma_free(&sess->auth_key_dma);
				return (error);
			}
		} else {
			sess->alg_type = CAAM_ALG_HASH;
			sess->auth_klen = 0;
		}

		error = caam_qi_drv_ctx_create(qi, sess, &sess->qi_enc_ctx,
		    caam_qi_hash_build_shdesc);
		if (error != 0) {
			if (sess->alg_type == CAAM_ALG_HMAC)
				caam_dma_free(&sess->auth_key_dma);
			return (error);
		}
		/* No dec_ctx for hash — verify done in software */
		break;

	case CSP_MODE_CIPHER:
		sess->alg_type = CAAM_ALG_CIPHER;
		sess->cipher_algtype = caam_cipher_algtype(
		    csp->csp_cipher_alg);
		sess->ivlen = caam_cipher_ivlen(csp->csp_cipher_alg);
		sess->icvlen = 0;

		if (sess->cipher_algtype == 0)
			return (EINVAL);

		error = caam_qi_drv_ctx_create(qi, sess, &sess->qi_enc_ctx,
		    caam_qi_cipher_build_enc_shdesc);
		if (error != 0)
			return (error);
		error = caam_qi_drv_ctx_create(qi, sess, &sess->qi_dec_ctx,
		    caam_qi_cipher_build_dec_shdesc);
		if (error != 0) {
			caam_qi_drv_ctx_destroy(sess->qi_enc_ctx);
			sess->qi_enc_ctx = NULL;
			return (error);
		}
		break;

	default:
		return (EINVAL);
	}

	return (0);
}

static void
caam_qi_freesession(device_t dev, crypto_session_t cses)
{
	struct caam_session *sess;

	sess = crypto_get_driver_session(cses);

	/* Zero key material before freeing contexts */
	explicit_bzero(sess->enc_key, sizeof(sess->enc_key));
	explicit_bzero(sess->auth_key, sizeof(sess->auth_key));
	if (sess->auth_key_dma.vaddr != NULL)
		explicit_bzero(sess->auth_key_dma.vaddr,
		    sess->split_key_pad_len * 2);

	caam_dma_free(&sess->auth_key_dma);
	caam_qi_drv_ctx_destroy(sess->qi_enc_ctx);
	caam_qi_drv_ctx_destroy(sess->qi_dec_ctx);
	sess->qi_enc_ctx = NULL;
	sess->qi_dec_ctx = NULL;
}

/* ================================================================
 * Process — submit a crypto request via QI compound FD
 * ================================================================ */

static int
caam_qi_process(device_t dev, struct cryptop *crp, int hint)
{
	struct caam_qi_softc *qi = caam_qi_sc;
	struct caam_session *sess;
	struct caam_qi_request *req;
	struct caam_qi_drv_ctx *drv_ctx;
	t_DpaaSGTE *sgt;
	t_DpaaFD fd;
	t_Error err;
	uint8_t *buf;
	bus_addr_t bounce_pa;
	size_t total_len;
	int qi_prefix, in_len, out_len, offset;
	bool encrypt;

	sess = crypto_get_driver_session(crp->crp_session);
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);

	/* Select direction-specific context */
	if (sess->alg_type == CAAM_ALG_HASH ||
	    sess->alg_type == CAAM_ALG_HMAC) {
		drv_ctx = sess->qi_enc_ctx;	/* Hash always uses enc */
	} else {
		drv_ctx = encrypt ? sess->qi_enc_ctx : sess->qi_dec_ctx;
	}

	if (__predict_false(drv_ctx == NULL)) {
		crp->crp_etype = EINVAL;
		crypto_done(crp);
		return (0);
	}

	/* Allocate request from pool */
	req = caam_qi_pool_alloc(qi);
	if (__predict_false(req == NULL)) {
		mtx_lock(&qi->pool_lock);
		qi->blocked = true;
		mtx_unlock(&qi->pool_lock);
		return (ERESTART);
	}

	req->crp = crp;
	req->sess = sess;
	req->drv_ctx = drv_ctx;

	/*
	 * Compute QI prefix size.
	 * QI input: [assoclen(4B, BE)] [IV(ivlen)] [AAD] [payload] [ICV]
	 * Cipher-only: [IV(ivlen)] [payload]
	 * Hash: [payload] (no prefix)
	 */
	if (sess->alg_type == CAAM_ALG_HASH ||
	    sess->alg_type == CAAM_ALG_HMAC) {
		qi_prefix = 0;
	} else if (sess->alg_type == CAAM_ALG_CIPHER) {
		qi_prefix = sess->ivlen;
	} else {
		qi_prefix = 4 + sess->ivlen;	/* assoclen + IV */
	}

	total_len = (size_t)qi_prefix + (size_t)crp->crp_aad_length +
	    (size_t)crp->crp_payload_length + (size_t)sess->icvlen;

	/* Allocate bounce buffer */
	if (__predict_false(total_len > CAAM_BOUNCE_SZ)) {
		int error;

		error = caam_dma_alloc(qi->dev, &req->dyn_bounce, total_len);
		if (error != 0) {
			caam_qi_pool_free(qi, req);
			crp->crp_etype = ENOMEM;
			crypto_done(crp);
			return (0);
		}
		req->using_dyn = true;
		buf = req->dyn_bounce.vaddr;
		bounce_pa = req->dyn_bounce.paddr;
	} else {
		buf = req->bounce.vaddr;
		bounce_pa = req->bounce.paddr;
	}

	/*
	 * Fill QI input buffer.
	 */
	offset = 0;

	/* QI prefix: assoclen (4 bytes, big-endian) */
	if (qi_prefix >= 4 && sess->alg_type != CAAM_ALG_CIPHER) {
		*(uint32_t *)buf = htobe32(crp->crp_aad_length);
		offset = 4;
	}

	/* QI prefix: IV */
	if (sess->ivlen > 0) {
		crypto_read_iv(crp, buf + offset);
		offset += sess->ivlen;
	}

	/* AAD */
	if (crp->crp_aad_length > 0) {
		if (crp->crp_aad != NULL)
			memcpy(buf + offset, crp->crp_aad,
			    crp->crp_aad_length);
		else
			crypto_copydata(crp, crp->crp_aad_start,
			    crp->crp_aad_length, buf + offset);
	}
	offset += crp->crp_aad_length;

	/* Payload */
	if (crp->crp_payload_length > 0)
		crypto_copydata(crp, crp->crp_payload_start,
		    crp->crp_payload_length, buf + offset);
	offset += crp->crp_payload_length;

	/* ICV for decrypt */
	if (!encrypt && sess->alg_type != CAAM_ALG_HASH &&
	    sess->alg_type != CAAM_ALG_HMAC &&
	    sess->icvlen > 0)
		crypto_copydata(crp, crp->crp_digest_start,
		    sess->icvlen, buf + offset);

	/*
	 * Compute input and output lengths for the compound FD.
	 *
	 * Input = what CAAM reads (QI prefix + AAD + payload + ICV for decrypt)
	 * Output = what CAAM writes — NO qi_prefix.  The shdesc consumes
	 *   the prefix from SEQINLEN via SEQ LOAD/FIFO LOAD, but never
	 *   writes it to output.  Including qi_prefix in out_len would
	 *   leave SEQOUTLEN non-zero, causing CAAM to hang.
	 */
	in_len = qi_prefix + crp->crp_aad_length + crp->crp_payload_length;
	out_len = crp->crp_aad_length + crp->crp_payload_length;

	if (sess->alg_type == CAAM_ALG_HASH ||
	    sess->alg_type == CAAM_ALG_HMAC) {
		in_len = crp->crp_payload_length;
		out_len = sess->icvlen;		/* Hash output is just the digest */
	} else if (encrypt) {
		out_len += sess->icvlen;	/* Output includes ICV */
	} else {
		in_len += sess->icvlen;		/* Input includes ICV */
	}

	/*
	 * Build compound FD S/G table (2 entries in DMA memory).
	 * Entry 0: OUTPUT buffer (CAAM writes here, past QI prefix)
	 * Entry 1: INPUT buffer (CAAM reads here, includes QI prefix), F=1
	 *
	 * The output buffer starts at bounce_pa + qi_prefix because the
	 * shdesc consumes the prefix (assoclen, IV) from input only.
	 * CAAM writes output sequentially: [SKIP AAD] [data] [ICV].
	 *
	 * DPAA_SGTE_SET_* macros handle big-endian byte-swap for
	 * CAAM's DMA byte order.
	 */
	sgt = (t_DpaaSGTE *)req->sgt.vaddr;
	memset(sgt, 0, CAAM_QI_SGT_SZ);

	{
		bus_addr_t out_pa = bounce_pa + qi_prefix;

		/* Output S/G entry (past QI prefix) */
		DPAA_SGTE_SET_ADDRH(&sgt[0], (uint32_t)(out_pa >> 32));
		DPAA_SGTE_SET_ADDRL(&sgt[0], (uint32_t)out_pa);
		DPAA_SGTE_SET_LENGTH(&sgt[0], out_len);
		DPAA_SGTE_SET_FINAL(&sgt[0], 0);
		DPAA_SGTE_SET_OFFSET(&sgt[0], 0);
	}

	/* Input S/G entry (Full bounce buffer including QI prefix, Final) */
	DPAA_SGTE_SET_ADDRH(&sgt[1], (uint32_t)(bounce_pa >> 32));
	DPAA_SGTE_SET_ADDRL(&sgt[1], (uint32_t)bounce_pa);
	DPAA_SGTE_SET_LENGTH(&sgt[1], in_len);
	DPAA_SGTE_SET_FINAL(&sgt[1], 1);
	DPAA_SGTE_SET_OFFSET(&sgt[1], 0);

	/*
	 * Build compound Frame Descriptor.
	 * fd.addr = DMA address of S/G table (CPU-native; QMan portal
	 * handles byte-swap during enqueue).
	 * fd.format = COMPOUND
	 * fd.length = input length (congestion weight)
	 * fd.status = 0
	 */
	memset(&fd, 0, sizeof(fd));
	DPAA_FD_SET_ADDRH(&fd, (uint32_t)(req->sgt.paddr >> 32));
	DPAA_FD_SET_ADDRL(&fd, (uint32_t)req->sgt.paddr);
	DPAA_FD_SET_FORMAT(&fd, e_DPAA_FD_FORMAT_TYPE_COMPOUND);
	DPAA_FD_SET_LENGTH(&fd, in_len);
	DPAA_FD_SET_STATUS(&fd, 0);

	err = qman_fqr_enqueue(drv_ctx->req_fqr[curcpu % drv_ctx->ncpus],
	    0, &fd);
	if (__predict_false(err != E_OK)) {
		printf("caam_qi: enqueue failed: %d\n", err);
		caam_qi_pool_free(qi, req);
		if (err == E_BUSY) {
			mtx_lock(&qi->pool_lock);
			qi->blocked = true;
			mtx_unlock(&qi->pool_lock);
			return (ERESTART);
		}
		crp->crp_etype = EIO;
		crypto_done(crp);
		return (0);
	}

	return (0);
}

/* ================================================================
 * QI Device Driver
 * ================================================================ */

static int
caam_qi_probe(device_t dev)
{

	/*
	 * Only match the pseudo-device created by device_add_child()
	 * in caam_attach(), not the FDT jr@ children which belong to
	 * the caam_jr driver.
	 *
	 * simplebus_add_child() sets obd_node = -1 for pseudo-devices.
	 * phandle_t is uint32_t, so (phandle_t)-1 = 0xFFFFFFFF.
	 * DT children have valid phandles (positive values != -1).
	 */
	if (ofw_bus_get_node(dev) != (phandle_t)-1)
		return (ENXIO);

	device_set_desc(dev, "NXP CAAM QI crypto backend");
	return (BUS_PROBE_SPECIFIC);
}

static int
caam_qi_attach(device_t dev)
{
	struct caam_qi_softc *qi;
	int error;

	if (caam_qi_sc != NULL) {
		device_printf(dev, "QI already initialized\n");
		return (EEXIST);
	}

	qi = malloc(sizeof(*qi), M_CAAM_QI, M_WAITOK | M_ZERO);
	qi->dev = dev;
	qi->cid = -1;

	/* Create per-CPU response FQs */
	error = caam_qi_create_rsp_fqs(qi);
	if (error != 0)
		goto fail;

	/* Allocate request pool */
	error = caam_qi_pool_init(qi);
	if (error != 0) {
		caam_qi_destroy_rsp_fqs(qi);
		goto fail;
	}

	/* Register with opencrypto */
	qi->cid = crypto_get_driverid(dev,
	    sizeof(struct caam_session), CRYPTOCAP_F_HARDWARE);
	if (qi->cid < 0) {
		device_printf(dev, "QI: failed to register with opencrypto\n");
		caam_qi_pool_fini(qi);
		caam_qi_destroy_rsp_fqs(qi);
		goto fail;
	}

	caam_qi_sc = qi;

	device_printf(dev,
	    "QI: registered with opencrypto (driverid %d), "
	    "%d requests (%zuKB sgt + %zuKB bounce)\n",
	    qi->cid, CAAM_QI_DEPTH,
	    (size_t)(CAAM_QI_DEPTH * CAAM_QI_SGT_SZ / 1024),
	    (size_t)(CAAM_QI_DEPTH * CAAM_BOUNCE_SZ / 1024));

	return (0);

fail:
	free(qi, M_CAAM_QI);
	return (error);
}

static int
caam_qi_detach(device_t dev)
{
	struct caam_qi_softc *qi = caam_qi_sc;

	if (qi == NULL)
		return (0);

	if (qi->cid >= 0) {
		crypto_unregister_all(qi->cid);
		qi->cid = -1;
	}

	caam_qi_pool_fini(qi);
	caam_qi_destroy_rsp_fqs(qi);

	caam_qi_sc = NULL;
	free(qi, M_CAAM_QI);

	return (0);
}

/*
 * QI probesession: same algorithm support as JR, but higher priority
 * so opencrypto routes sessions here instead of to Job Rings.
 * CRYPTODEV_PROBE_HARDWARE is -100; returning -99 wins the tie.
 */
static int
caam_qi_probesession(device_t dev, const struct crypto_session_params *csp)
{
	int error;

	error = caam_probesession(dev, csp);
	if (error == CRYPTODEV_PROBE_HARDWARE)
		return (CRYPTODEV_PROBE_HARDWARE + 1);
	return (error);
}

static device_method_t caam_qi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		caam_qi_probe),
	DEVMETHOD(device_attach,	caam_qi_attach),
	DEVMETHOD(device_detach,	caam_qi_detach),

	/* Cryptodev interface */
	DEVMETHOD(cryptodev_probesession, caam_qi_probesession),
	DEVMETHOD(cryptodev_newsession,	  caam_qi_newsession),
	DEVMETHOD(cryptodev_freesession,  caam_qi_freesession),
	DEVMETHOD(cryptodev_process,	  caam_qi_process),

	DEVMETHOD_END
};

static driver_t caam_qi_driver = {
	"caam_qi",
	caam_qi_methods,
	0,	/* No private softc — we manage our own */
};

DRIVER_MODULE(caam_qi, caam, caam_qi_driver, 0, 0);
MODULE_VERSION(caam_qi, 1);
MODULE_DEPEND(caam_qi, caam, 1, 1, 1);
MODULE_DEPEND(caam_qi, caam_jr, 1, 1, 1);
MODULE_DEPEND(caam_qi, crypto, 1, 1, 1);
