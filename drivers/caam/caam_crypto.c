/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM opencrypto integration — connects CAAM Job Ring hardware to
 * FreeBSD's opencrypto framework for IPsec and kernel crypto.
 *
 * Architecture:
 *   opencrypto → caam_process() → bounce buffer copy → caam_jr_enqueue()
 *   caam_jr_task() → caam_crypto_done() → bounce copy-back → crypto_done()
 *
 * Supported algorithms:
 *   CSP_MODE_AEAD:  AES-GCM (128/192/256)
 *   CSP_MODE_ETA:   {AES-CBC,AES-CTR,DES-CBC,3DES-CBC} + HMAC-{SHA1,256,384,512,MD5}
 *   CSP_MODE_ETA:   NULL cipher + HMAC (auth-only)
 *   CSP_MODE_CIPHER: AES-{CBC,CTR,XTS}, DES-CBC, 3DES-CBC
 *   CSP_MODE_DIGEST: SHA-{1,224,256,384,512}, MD5, HMAC variants
 *
 * Bounce buffer strategy:
 *   Each request has a pre-mapped 2048-byte bounce buffer covering standard
 *   MTU + AAD + ICV.  For oversized payloads, a dynamic bounce buffer is
 *   allocated on demand.  Data is copied in before submission and copied
 *   back on completion.  This avoids per-request DMA mapping of mbufs.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>

#include <machine/bus.h>

#include <opencrypto/cryptodev.h>

#include "caam.h"
#include "caam_regs.h"
#include "caam_desc.h"
#include "caam_jr.h"
#include "caam_crypto.h"

static MALLOC_DEFINE(M_CAAM_CRYPTO, "caam_crypto", "CAAM crypto requests");

/* ================================================================
 * Request Pool Management
 *
 * Pre-allocated pool of CAAM_JR_DEPTH request structures.  Descriptor
 * and bounce buffers are allocated in bulk (two large DMA regions)
 * and sliced into per-request chunks.  This uses ~1.2MB per JR instead
 * of ~4MB with individual page-aligned allocations.
 *
 * Managed as a singly-linked free list indexed by next_free.
 * ================================================================ */

static int
caam_pool_init(struct caam_jr_softc *sc)
{
	struct caam_request *req;
	int error, i;

	sc->sc_requests = malloc(sizeof(struct caam_request) * CAAM_JR_DEPTH,
	    M_CAAM_CRYPTO, M_WAITOK | M_ZERO);

	/* Bulk DMA: all descriptors (512 * 256 = 128KB) */
	error = caam_dma_alloc(sc->sc_dev, &sc->sc_desc_bulk,
	    (bus_size_t)CAAM_JR_DEPTH * CAAM_DESC_MAX_BYTES);
	if (error != 0)
		goto fail_requests;

	/* Bulk DMA: all bounce buffers (512 * 2048 = 1MB) */
	error = caam_dma_alloc(sc->sc_dev, &sc->sc_bounce_bulk,
	    (bus_size_t)CAAM_JR_DEPTH * CAAM_BOUNCE_SZ);
	if (error != 0)
		goto fail_desc;

	mtx_init(&sc->sc_pool_lock, "caam_pool", NULL, MTX_DEF);
	sc->sc_pool_head = 0;
	sc->sc_blocked = false;

	for (i = 0; i < CAAM_JR_DEPTH; i++) {
		req = &sc->sc_requests[i];
		req->next_free = i + 1;

		/* Point to slice of bulk descriptor allocation */
		req->desc.tag = NULL;	/* Sentinel: sub-allocation */
		req->desc.map = NULL;
		req->desc.vaddr = (uint8_t *)sc->sc_desc_bulk.vaddr +
		    i * CAAM_DESC_MAX_BYTES;
		req->desc.paddr = sc->sc_desc_bulk.paddr +
		    i * CAAM_DESC_MAX_BYTES;

		/* Point to slice of bulk bounce allocation */
		req->bounce.tag = NULL;
		req->bounce.map = NULL;
		req->bounce.vaddr = (uint8_t *)sc->sc_bounce_bulk.vaddr +
		    i * CAAM_BOUNCE_SZ;
		req->bounce.paddr = sc->sc_bounce_bulk.paddr +
		    i * CAAM_BOUNCE_SZ;

		req->dyn_bounce.tag = NULL;
		req->using_dyn = false;
	}

	/* Terminate free list */
	sc->sc_requests[CAAM_JR_DEPTH - 1].next_free = -1;

	device_printf(sc->sc_dev,
	    "request pool: %d entries (%zuKB descs + %zuKB bounce)\n",
	    CAAM_JR_DEPTH,
	    (size_t)(CAAM_JR_DEPTH * CAAM_DESC_MAX_BYTES / 1024),
	    (size_t)(CAAM_JR_DEPTH * CAAM_BOUNCE_SZ / 1024));

	return (0);

fail_desc:
	caam_dma_free(&sc->sc_desc_bulk);
fail_requests:
	free(sc->sc_requests, M_CAAM_CRYPTO);
	sc->sc_requests = NULL;
	return (error);
}

static void
caam_pool_fini(struct caam_jr_softc *sc)
{
	struct caam_request *req;
	int i;

	if (sc->sc_requests == NULL)
		return;

	/* Free any outstanding dynamic bounces */
	for (i = 0; i < CAAM_JR_DEPTH; i++) {
		req = &sc->sc_requests[i];
		if (req->using_dyn)
			caam_dma_free(&req->dyn_bounce);
	}

	caam_dma_free(&sc->sc_bounce_bulk);
	caam_dma_free(&sc->sc_desc_bulk);

	mtx_destroy(&sc->sc_pool_lock);
	free(sc->sc_requests, M_CAAM_CRYPTO);
	sc->sc_requests = NULL;
}

static struct caam_request *
caam_pool_alloc(struct caam_jr_softc *sc)
{
	struct caam_request *req;
	int idx;

	mtx_lock(&sc->sc_pool_lock);
	idx = sc->sc_pool_head;
	if (idx < 0) {
		mtx_unlock(&sc->sc_pool_lock);
		return (NULL);
	}
	req = &sc->sc_requests[idx];
	sc->sc_pool_head = req->next_free;
	req->next_free = -1;
	mtx_unlock(&sc->sc_pool_lock);

	return (req);
}

static void
caam_pool_free(struct caam_jr_softc *sc, struct caam_request *req)
{
	int idx;

	/* Free dynamic bounce buffer if allocated */
	if (req->using_dyn) {
		caam_dma_free(&req->dyn_bounce);
		req->using_dyn = false;
	}

	req->crp = NULL;
	req->sess = NULL;
	req->sc = NULL;

	idx = req - sc->sc_requests;

	mtx_lock(&sc->sc_pool_lock);
	req->next_free = sc->sc_pool_head;
	sc->sc_pool_head = idx;
	mtx_unlock(&sc->sc_pool_lock);
}

/* ================================================================
 * Probesession — validate algorithm support
 * ================================================================ */

static bool
caam_valid_aes_klen(int klen)
{

	return (klen == 16 || klen == 24 || klen == 32);
}

int
caam_probesession(device_t dev, const struct crypto_session_params *csp)
{

	if (csp->csp_flags != 0)
		return (EINVAL);

	switch (csp->csp_mode) {
	case CSP_MODE_AEAD:
		/* AES-GCM-16 only */
		if (csp->csp_cipher_alg != CRYPTO_AES_NIST_GCM_16)
			return (EINVAL);
		if (!caam_valid_aes_klen(csp->csp_cipher_klen))
			return (EINVAL);
		if (csp->csp_ivlen != AES_GCM_IV_LEN)
			return (EINVAL);
		if (csp->csp_auth_mlen != 0 &&
		    csp->csp_auth_mlen != AES_GCM_TAG_LEN)
			return (EINVAL);
		break;

	case CSP_MODE_ETA:
		/* Cipher + HMAC (encrypt-then-authenticate) */
		switch (csp->csp_cipher_alg) {
		case CRYPTO_AES_CBC:
		case CRYPTO_AES_ICM:
			if (!caam_valid_aes_klen(csp->csp_cipher_klen))
				return (EINVAL);
			break;
		case CRYPTO_DES_CBC:
			if (csp->csp_cipher_klen != 8)
				return (EINVAL);
			break;
		case CRYPTO_3DES_CBC:
			if (csp->csp_cipher_klen != 24)
				return (EINVAL);
			break;
		case CRYPTO_NULL_CBC:
			break;
		default:
			return (EINVAL);
		}
		switch (csp->csp_auth_alg) {
		case CRYPTO_SHA1_HMAC:
		case CRYPTO_SHA2_256_HMAC:
		case CRYPTO_SHA2_384_HMAC:
		case CRYPTO_SHA2_512_HMAC:
		case CRYPTO_MD5_HMAC:
			break;
		default:
			return (EINVAL);
		}
		if (csp->csp_auth_klen > CAAM_MAX_SPLIT_KEY_LEN)
			return (EINVAL);
		break;

	case CSP_MODE_DIGEST:
		/* Standalone hash or HMAC */
		switch (csp->csp_auth_alg) {
		case CRYPTO_SHA1:
		case CRYPTO_SHA2_224:
		case CRYPTO_SHA2_256:
		case CRYPTO_SHA2_384:
		case CRYPTO_SHA2_512:
		case CRYPTO_MD5:
			/* Plain hash — no key allowed */
			if (csp->csp_auth_klen != 0)
				return (EINVAL);
			break;
		case CRYPTO_SHA1_HMAC:
		case CRYPTO_SHA2_224_HMAC:
		case CRYPTO_SHA2_256_HMAC:
		case CRYPTO_SHA2_384_HMAC:
		case CRYPTO_SHA2_512_HMAC:
		case CRYPTO_MD5_HMAC:
			/* HMAC — key required, bounded by auth_key buffer */
			if (csp->csp_auth_klen == 0 ||
			    csp->csp_auth_klen > CAAM_MAX_SPLIT_KEY_LEN)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
		break;

	case CSP_MODE_CIPHER:
		switch (csp->csp_cipher_alg) {
		case CRYPTO_AES_CBC:
		case CRYPTO_AES_ICM:
			if (!caam_valid_aes_klen(csp->csp_cipher_klen))
				return (EINVAL);
			break;
		case CRYPTO_AES_XTS:
			/* XTS uses double key: enc_key || tweak_key */
			if (csp->csp_cipher_klen != 32 &&
			    csp->csp_cipher_klen != 64)
				return (EINVAL);
			break;
		case CRYPTO_DES_CBC:
			if (csp->csp_cipher_klen != 8)
				return (EINVAL);
			break;
		case CRYPTO_3DES_CBC:
			if (csp->csp_cipher_klen != 24)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
		break;

	default:
		return (EINVAL);
	}

	return (CRYPTODEV_PROBE_HARDWARE);
}

/* ================================================================
 * Newsession / Freesession — session lifecycle
 * ================================================================ */

/*
 * Map FreeBSD cipher algorithm to CAAM algorithm selector + AAI.
 */
uint32_t
caam_cipher_algtype(int cipher_alg)
{

	switch (cipher_alg) {
	case CRYPTO_AES_CBC:
		return (OP_ALG_ALGSEL_AES | OP_ALG_AAI_CBC);
	case CRYPTO_AES_ICM:
		return (OP_ALG_ALGSEL_AES | OP_ALG_AAI_CTR_MOD128);
	case CRYPTO_AES_XTS:
		return (OP_ALG_ALGSEL_AES | OP_ALG_AAI_XTS);
	case CRYPTO_DES_CBC:
		return (OP_ALG_ALGSEL_DES | OP_ALG_AAI_CBC);
	case CRYPTO_3DES_CBC:
		return (OP_ALG_ALGSEL_3DES | OP_ALG_AAI_CBC);
	case CRYPTO_NULL_CBC:
		return (0);	/* No cipher operation */
	default:
		return (0);
	}
}

/*
 * IV length for cipher algorithms.
 */
int
caam_cipher_ivlen(int cipher_alg)
{

	switch (cipher_alg) {
	case CRYPTO_AES_CBC:
	case CRYPTO_AES_XTS:
		return (AES_BLOCK_LEN);	/* 16 */
	case CRYPTO_AES_ICM:
		return (AES_BLOCK_LEN);	/* 16-byte CTR IV/nonce */
	case CRYPTO_DES_CBC:
	case CRYPTO_3DES_CBC:
		return (8);		/* DES block = 8 */
	default:
		return (0);
	}
}

/*
 * Map FreeBSD hash/HMAC algorithm ID to CAAM algorithm selector.
 */
uint32_t
caam_auth_algsel(int auth_alg)
{

	switch (auth_alg) {
	case CRYPTO_SHA1:
	case CRYPTO_SHA1_HMAC:
		return (OP_ALG_ALGSEL_SHA1);
	case CRYPTO_SHA2_224:
	case CRYPTO_SHA2_224_HMAC:
		return (OP_ALG_ALGSEL_SHA224);
	case CRYPTO_SHA2_256:
	case CRYPTO_SHA2_256_HMAC:
		return (OP_ALG_ALGSEL_SHA256);
	case CRYPTO_SHA2_384:
	case CRYPTO_SHA2_384_HMAC:
		return (OP_ALG_ALGSEL_SHA384);
	case CRYPTO_SHA2_512:
	case CRYPTO_SHA2_512_HMAC:
		return (OP_ALG_ALGSEL_SHA512);
	case CRYPTO_MD5:
	case CRYPTO_MD5_HMAC:
		return (OP_ALG_ALGSEL_MD5);
	default:
		return (0);
	}
}

/*
 * Full hash digest length for the given hash/HMAC algorithm.
 */
int
caam_auth_digest_len(int auth_alg)
{

	switch (auth_alg) {
	case CRYPTO_MD5:
	case CRYPTO_MD5_HMAC:
		return (16);
	case CRYPTO_SHA1:
	case CRYPTO_SHA1_HMAC:
		return (20);
	case CRYPTO_SHA2_224:
	case CRYPTO_SHA2_224_HMAC:
		return (28);
	case CRYPTO_SHA2_256:
	case CRYPTO_SHA2_256_HMAC:
		return (32);
	case CRYPTO_SHA2_384:
	case CRYPTO_SHA2_384_HMAC:
		return (48);
	case CRYPTO_SHA2_512:
	case CRYPTO_SHA2_512_HMAC:
		return (64);
	default:
		return (0);
	}
}

/*
 * Allocate DMA buffer for pre-computed split key.
 * Buffer will be filled by caam_gen_split_key() after allocation.
 * Must be called after sess->split_key_pad_len is set.
 */
int
caam_session_alloc_auth_key_dma(device_t dev, struct caam_session *sess)
{
	int error;

	error = caam_dma_alloc(dev, &sess->auth_key_dma,
	    sess->split_key_pad_len);
	if (error != 0)
		return (error);

	/* Buffer is zero-filled by BUS_DMA_ZERO in caam_dma_alloc() */
	return (0);
}

/*
 * Derive HMAC split key via a standalone Job Ring submission.
 *
 * Builds a job descriptor that:
 *   1. Loads the raw HMAC key inline (KEY CLASS2 IMM)
 *   2. Runs HMAC INIT to derive ipad||opad (OPERATION CLASS2 HMAC INIT)
 *   3. Stores the split key to auth_key_dma (FIFO STORE SPLIT_KEK)
 *
 * This replaces DKP pointer mode which causes DECO watchdog timeouts
 * on LS1046A ERA 8.  Matches Linux's gen_split_key() approach used
 * for ERA < 6 and as a fallback.
 *
 * Must be called after caam_session_alloc_auth_key_dma().
 * dev must be a JR device (caam_jr_softc).
 */
struct caam_splitkey_result {
	volatile int	done;
	uint32_t	status;
};

static void
caam_splitkey_done(uint32_t status, void *arg)
{
	struct caam_splitkey_result *res = arg;

	res->status = status;
	res->done = 1;
	wakeup(res);
}

int
caam_gen_split_key(device_t dev, struct caam_session *sess)
{
	struct caam_softc *csc;
	struct caam_jr_softc *sc;
	struct caam_dma_mem desc_mem;
	struct caam_splitkey_result result;
	uint32_t *desc;
	device_t jr_dev;
	int error;

	/*
	 * Find a JR device to submit the split key descriptor.
	 * When called from a JR newsession, dev is the JR device itself.
	 * When called from QI newsession, dev is the QI device —
	 * look up the admin JR via the parent CAAM controller.
	 */
	csc = device_get_softc(device_get_parent(dev));
	jr_dev = csc->sc_admin_jr;
	if (jr_dev == NULL) {
		device_printf(dev,
		    "gen_split_key: no JR device available\n");
		return (ENXIO);
	}
	sc = device_get_softc(jr_dev);

	error = caam_dma_alloc(jr_dev, &desc_mem, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = desc_mem.vaddr;

	/*
	 * Derive HMAC split key (ipad || opad partial hashes).
	 * Matches Linux key_gen.c gen_split_key() exactly:
	 *
	 *   KEY CLASS2 keylen PTR(auth_key_dma)
	 *   OPERATION CLASS2_ALG algsel HMAC INIT DECRYPT
	 *   FIFO_LOAD CLASS2 MSG LAST2 IMM len=0
	 *   FIFO_STORE CLASS2KEY SPLIT_KEK split_key_len PTR(auth_key_dma)
	 *
	 * The raw key is first copied into auth_key_dma.  CAAM loads it
	 * via DMA, derives the split key internally, and stores the
	 * result back to the same DMA buffer via FIFO STORE.
	 */
	memcpy(sess->auth_key_dma.vaddr, sess->auth_key, sess->auth_klen);

	caam_desc_init(desc);

	/* KEY: load raw key into Class 2 key register via DMA pointer */
	caam_desc_add_word(desc,
	    CMD_KEY | KEY_CLASS2 | sess->auth_klen);
	caam_desc_add_ptr(desc, sess->auth_key_dma.paddr);

	/* OPERATION: HMAC INIT DECRYPT — triggers ipad/opad expansion */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS2_ALG |
	    (sess->auth_algtype & OP_ALG_ALGSEL_MASK) |
	    OP_ALG_AAI_HMAC | OP_ALG_AS_INIT | OP_ALG_DECRYPT);

	/* FIFO LOAD: 0 bytes, CLASS2, MSG, LAST2, IMM — finalize */
	caam_desc_add_word(desc,
	    CMD_FIFO_LOAD | FIFOLD_CLASS_CLASS2 | FIFOLD_IMM |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/* FIFO STORE: extract split key to DMA buffer */
	caam_desc_add_word(desc,
	    CMD_FIFO_STORE | FIFOST_CLASS_CLASS2KEY |
	    FIFOST_TYPE_SPLIT_KEK | sess->split_key_len);
	caam_desc_add_ptr(desc, sess->auth_key_dma.paddr);

	result.done = 0;
	result.status = 0;

	error = caam_jr_enqueue(sc, desc, desc_mem.paddr,
	    caam_desc_len(desc) * sizeof(uint32_t),
	    caam_splitkey_done, &result);
	if (error != 0) {
		caam_dma_free(&desc_mem);
		return (error);
	}

	/* Wait for completion (split key derivation is sub-millisecond) */
	while (!result.done) {
		error = tsleep(&result, 0, "caamsk", 5 * hz);
		if (error != 0 && !result.done) {
			device_printf(dev,
			    "split key derivation timed out\n");
			caam_dma_free(&desc_mem);
			return (ETIMEDOUT);
		}
	}

	caam_dma_free(&desc_mem);

	if (result.status != 0) {
		device_printf(dev,
		    "split key derivation failed: status 0x%08x\n",
		    result.status);
		return (EIO);
	}

	return (0);
}

int
caam_newsession(device_t dev, crypto_session_t cses,
    const struct crypto_session_params *csp)
{
	struct caam_session *sess;
	int error;

	sess = crypto_get_driver_session(cses);

	/* Copy cipher key (if present) */
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

		error = caam_gcm_build_enc_shdesc(sess, dev);
		if (error != 0)
			return (error);
		error = caam_gcm_build_dec_shdesc(sess, dev);
		if (error != 0) {
			caam_dma_free(&sess->enc_shdesc);
			return (error);
		}
		break;

	case CSP_MODE_ETA:
		if (csp->csp_cipher_alg == CRYPTO_NULL_CBC) {
			sess->alg_type = CAAM_ALG_NULL_HMAC;
		} else {
			sess->alg_type = CAAM_ALG_CBC_HMAC;
		}
		sess->cipher_algtype = caam_cipher_algtype(
		    csp->csp_cipher_alg);
		sess->ivlen = caam_cipher_ivlen(csp->csp_cipher_alg);
		sess->icvlen = (csp->csp_auth_mlen != 0) ?
		    csp->csp_auth_mlen :
		    caam_auth_digest_len(csp->csp_auth_alg);
		sess->auth_algtype = caam_auth_algsel(csp->csp_auth_alg);

		if (sess->auth_algtype == 0)
			return (EINVAL);

		/*
		 * Store raw auth key for split key derivation.
		 * The split key (ipad||opad) is pre-derived via a
		 * standalone JR job during session setup, then loaded
		 * in the shared descriptor via KEY CLASS2 MDHA_SPLIT.
		 */
		sess->auth_klen = csp->csp_auth_klen;
		memcpy(sess->auth_key, csp->csp_auth_key, sess->auth_klen);
		sess->split_key_len = caam_split_key_len(
		    sess->auth_algtype & OP_ALG_ALGSEL_MASK);
		sess->split_key_pad_len = caam_split_key_pad_len(
		    sess->auth_algtype & OP_ALG_ALGSEL_MASK);

		/* Allocate DMA buffer and derive split key via JR */
		error = caam_session_alloc_auth_key_dma(dev, sess);
		if (error != 0)
			return (error);
		error = caam_gen_split_key(dev, sess);
		if (error != 0) {
			caam_dma_free(&sess->auth_key_dma);
			return (error);
		}

		if (sess->alg_type == CAAM_ALG_NULL_HMAC) {
			error = caam_null_hmac_build_enc_shdesc(sess, dev);
			if (error != 0)
				goto fail_auth_key;
			error = caam_null_hmac_build_dec_shdesc(sess, dev);
		} else {
			error = caam_eta_build_enc_shdesc(sess, dev);
			if (error != 0)
				goto fail_auth_key;
			error = caam_eta_build_dec_shdesc(sess, dev);
		}
		if (error != 0) {
			caam_dma_free(&sess->enc_shdesc);
		fail_auth_key:
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
			/* HMAC */
			sess->alg_type = CAAM_ALG_HMAC;
			sess->auth_klen = csp->csp_auth_klen;
			sess->split_key_len = caam_split_key_len(
			    sess->auth_algtype & OP_ALG_ALGSEL_MASK);
			sess->split_key_pad_len = caam_split_key_pad_len(
			    sess->auth_algtype & OP_ALG_ALGSEL_MASK);
			memcpy(sess->auth_key, csp->csp_auth_key,
			    sess->auth_klen);

			/* Allocate DMA buffer and derive split key via JR */
			error = caam_session_alloc_auth_key_dma(dev, sess);
			if (error != 0)
				return (error);
			error = caam_gen_split_key(dev, sess);
			if (error != 0) {
				caam_dma_free(&sess->auth_key_dma);
				return (error);
			}
		} else {
			/* Plain hash */
			sess->alg_type = CAAM_ALG_HASH;
			sess->auth_klen = 0;
		}

		error = caam_hash_build_shdesc(sess, dev);
		if (error != 0) {
			if (sess->alg_type == CAAM_ALG_HMAC)
				caam_dma_free(&sess->auth_key_dma);
			return (error);
		}
		/* No separate dec_shdesc — verify done in software */
		break;

	case CSP_MODE_CIPHER:
		sess->alg_type = CAAM_ALG_CIPHER;
		sess->cipher_algtype = caam_cipher_algtype(csp->csp_cipher_alg);
		sess->ivlen = caam_cipher_ivlen(csp->csp_cipher_alg);
		sess->icvlen = 0;	/* No authentication */

		if (sess->cipher_algtype == 0)
			return (EINVAL);

		error = caam_cipher_build_enc_shdesc(sess, dev);
		if (error != 0)
			return (error);
		error = caam_cipher_build_dec_shdesc(sess, dev);
		if (error != 0) {
			caam_dma_free(&sess->enc_shdesc);
			return (error);
		}
		break;

	default:
		return (EINVAL);
	}

	return (0);
}

void
caam_freesession(device_t dev, crypto_session_t cses)
{
	struct caam_session *sess;

	sess = crypto_get_driver_session(cses);

	/* Zero key material before freeing DMA descriptors */
	explicit_bzero(sess->enc_key, sizeof(sess->enc_key));
	explicit_bzero(sess->auth_key, sizeof(sess->auth_key));
	if (sess->auth_key_dma.vaddr != NULL)
		explicit_bzero(sess->auth_key_dma.vaddr,
		    sess->split_key_pad_len);
	if (sess->enc_shdesc.vaddr != NULL)
		explicit_bzero(sess->enc_shdesc.vaddr, CAAM_DESC_MAX_BYTES);
	if (sess->dec_shdesc.vaddr != NULL)
		explicit_bzero(sess->dec_shdesc.vaddr, CAAM_DESC_MAX_BYTES);

	caam_dma_free(&sess->auth_key_dma);
	caam_dma_free(&sess->enc_shdesc);
	caam_dma_free(&sess->dec_shdesc);
}

/* ================================================================
 * Completion callback — invoked from caam_jr_task() for each
 * completed job descriptor.
 *
 * Maps CAAM hardware status to crp_etype, copies results back
 * from the bounce buffer, returns the request to the pool,
 * unblocks opencrypto if needed, and calls crypto_done().
 * ================================================================ */

static void
caam_crypto_done(uint32_t status, void *arg)
{
	struct caam_request *req = arg;
	struct caam_jr_softc *sc = req->sc;
	struct cryptop *crp = req->crp;
	struct caam_session *sess = req->sess;
	uint8_t *buf;
	bool encrypt, blocked;
	uint32_t ssrc;

	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);
	buf = req->using_dyn ? req->dyn_bounce.vaddr : req->bounce.vaddr;

	/* Map CAAM status to error code */
	if (status == 0) {
		crp->crp_etype = 0;
	} else {
		ssrc = status & JRSTA_SSRC_MASK;
		if (ssrc == JRSTA_SSRC_JUMP_HALT_USER) {
			/* Informational condition code, not an error */
			crp->crp_etype = 0;
		} else if (ssrc == JRSTA_SSRC_CCB_ERROR &&
		    (status & CCB_ERRID_MASK) == CCB_ERR_ICV_CHECK) {
			crp->crp_etype = EBADMSG;
		} else {
			crp->crp_etype = EIO;
			device_printf(sc->sc_dev,
			    "crypto error: status 0x%08x "
			    "(SSRC=%u, detail=0x%04x) "
			    "payload=%u aad=%u op=%s alg=%d\n",
			    status,
			    (status >> JRSTA_SSRC_SHIFT) & 0xf,
			    status & 0xffff,
			    crp->crp_payload_length,
			    crp->crp_aad_length,
			    CRYPTO_OP_IS_ENCRYPT(crp->crp_op) ?
			        "encrypt" : "decrypt",
			    sess->alg_type);
			/* Dump JD for post-mortem analysis */
			{
				uint32_t *jd = req->desc.vaddr;
				int i, nw = caam_desc_len(jd);

				device_printf(sc->sc_dev,
				    "  JD (%d words, PA 0x%jx):\n",
				    nw, (uintmax_t)req->desc.paddr);
				for (i = 0; i < nw; i++)
					device_printf(sc->sc_dev,
					    "    [%2d] 0x%08x\n",
					    i, caam_to_cpu32(jd[i]));
			}
		}
	}

	/* Copy results back on success */
	if (crp->crp_etype == 0) {
		if (sess->alg_type == CAAM_ALG_HASH ||
		    sess->alg_type == CAAM_ALG_HMAC) {
			/*
			 * Digest mode: computed hash is at
			 * buf[payload_length..payload_length + icvlen].
			 */
			if (crp->crp_op & CRYPTO_OP_VERIFY_DIGEST) {
				uint8_t expected[64]; /* max SHA-512 */

				crypto_copydata(crp, crp->crp_digest_start,
				    sess->icvlen, expected);
				if (timingsafe_bcmp(
				    buf + crp->crp_payload_length,
				    expected, sess->icvlen) != 0)
					crp->crp_etype = EBADMSG;
			} else {
				crypto_copyback(crp, crp->crp_digest_start,
				    sess->icvlen,
				    buf + crp->crp_payload_length);
			}
		} else if (encrypt) {
			/* Ciphertext at bounce[aad_length..] */
			crypto_copyback(crp, crp->crp_payload_start,
			    crp->crp_payload_length,
			    buf + crp->crp_aad_length);
			/* ICV/tag at bounce[aad_length + payload_length..] */
			crypto_copyback(crp, crp->crp_digest_start,
			    sess->icvlen,
			    buf + crp->crp_aad_length +
			    crp->crp_payload_length);
		} else {
			/* Plaintext at bounce[aad_length..] */
			crypto_copyback(crp, crp->crp_payload_start,
			    crp->crp_payload_length,
			    buf + crp->crp_aad_length);
		}
	}

	/* Return request to pool */
	caam_pool_free(sc, req);

	/* Unblock opencrypto if we were resource-constrained */
	mtx_lock(&sc->sc_pool_lock);
	blocked = sc->sc_blocked;
	if (blocked)
		sc->sc_blocked = false;
	mtx_unlock(&sc->sc_pool_lock);

	if (blocked)
		crypto_unblock(sc->sc_cid, CRYPTO_SYMQ);

	/* Notify opencrypto framework */
	crypto_done(crp);
}

/* ================================================================
 * Process — submit a crypto request to the CAAM Job Ring
 *
 * 1. Allocate request from pre-allocated pool
 * 2. Copy AAD + payload (+ ICV for decrypt) into bounce buffer
 * 3. Build the per-request job descriptor
 * 4. Submit to the JR hardware via caam_jr_enqueue()
 *
 * Returns 0 if the request was accepted (errors reported via
 * crp_etype + crypto_done).  Returns ERESTART if the pool or
 * ring is temporarily full — opencrypto will retry later.
 * ================================================================ */

int
caam_process(device_t dev, struct cryptop *crp, int hint)
{
	struct caam_jr_softc *sc;
	struct caam_session *sess;
	struct caam_request *req;
	uint32_t *desc;
	uint8_t *buf;
	size_t total_len;
	int error;
	bool encrypt;

	sc = device_get_softc(dev);
	sess = crypto_get_driver_session(crp->crp_session);
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);

	/* Allocate request from pool */
	req = caam_pool_alloc(sc);
	if (__predict_false(req == NULL)) {
		mtx_lock(&sc->sc_pool_lock);
		sc->sc_blocked = true;
		mtx_unlock(&sc->sc_pool_lock);
		return (ERESTART);
	}

	req->crp = crp;
	req->sess = sess;
	req->sc = sc;

	/*
	 * Determine bounce buffer size.
	 * Max of input and output is always aad + payload + icvlen.
	 * Use size_t to avoid signed integer overflow.
	 */
	total_len = (size_t)crp->crp_aad_length +
	    (size_t)crp->crp_payload_length + (size_t)sess->icvlen;

	if (__predict_false(total_len > CAAM_BOUNCE_SZ)) {
		/* Oversized: allocate dynamic bounce */
		error = caam_dma_alloc(sc->sc_dev, &req->dyn_bounce,
		    total_len);
		if (error != 0) {
			caam_pool_free(sc, req);
			crp->crp_etype = ENOMEM;
			crypto_done(crp);
			return (0);
		}
		req->using_dyn = true;
		buf = req->dyn_bounce.vaddr;
	} else {
		buf = req->bounce.vaddr;
	}

	/*
	 * Copy data into the bounce buffer.
	 *
	 * Layout: [AAD (aad_length)] [payload (payload_length)] [ICV (icvlen)]
	 *
	 * For encrypt input:  AAD + plaintext
	 * For decrypt input:  AAD + ciphertext + ICV
	 */
	if (crp->crp_aad_length > 0) {
		if (crp->crp_aad != NULL)
			memcpy(buf, crp->crp_aad, crp->crp_aad_length);
		else
			crypto_copydata(crp, crp->crp_aad_start,
			    crp->crp_aad_length, buf);
	}

	if (crp->crp_payload_length > 0)
		crypto_copydata(crp, crp->crp_payload_start,
		    crp->crp_payload_length,
		    buf + crp->crp_aad_length);

	if (!encrypt && sess->alg_type != CAAM_ALG_HASH &&
	    sess->alg_type != CAAM_ALG_HMAC)
		crypto_copydata(crp, crp->crp_digest_start,
		    sess->icvlen,
		    buf + crp->crp_aad_length + crp->crp_payload_length);

	/* Build the per-request job descriptor */
	if (sess->alg_type == CAAM_ALG_GCM)
		error = caam_gcm_build_job(sc, req, crp);
	else if (sess->alg_type == CAAM_ALG_CIPHER)
		error = caam_cipher_build_job(sc, req, crp);
	else if (sess->alg_type == CAAM_ALG_NULL_HMAC)
		error = caam_null_hmac_build_job(sc, req, crp);
	else if (sess->alg_type == CAAM_ALG_HASH ||
	    sess->alg_type == CAAM_ALG_HMAC)
		error = caam_hash_build_job(sc, req, crp);
	else
		error = caam_eta_build_job(sc, req, crp);

	if (__predict_false(error != 0)) {
		caam_pool_free(sc, req);
		crp->crp_etype = error;
		crypto_done(crp);
		return (0);
	}

	/* Submit to the Job Ring */
	desc = req->desc.vaddr;
	error = caam_jr_enqueue(sc, desc, req->desc.paddr,
	    caam_desc_len(desc) * sizeof(uint32_t),
	    caam_crypto_done, req);

	if (__predict_false(error == ENOSPC)) {
		/* Ring full — tell opencrypto to retry */
		caam_pool_free(sc, req);
		mtx_lock(&sc->sc_pool_lock);
		sc->sc_blocked = true;
		mtx_unlock(&sc->sc_pool_lock);
		return (ERESTART);
	}
	if (__predict_false(error != 0)) {
		caam_pool_free(sc, req);
		crp->crp_etype = error;
		crypto_done(crp);
		return (0);
	}

	return (0);
}

/* ================================================================
 * Init / Detach — called from caam_jr attach/detach
 * ================================================================ */

int
caam_crypto_init(struct caam_jr_softc *sc)
{
	int error;

	/* Allocate request pool with bulk DMA buffers */
	error = caam_pool_init(sc);
	if (error != 0)
		return (error);

	/* Register with opencrypto framework */
	sc->sc_cid = crypto_get_driverid(sc->sc_dev,
	    sizeof(struct caam_session), CRYPTOCAP_F_HARDWARE);
	if (sc->sc_cid < 0) {
		device_printf(sc->sc_dev,
		    "failed to register with opencrypto\n");
		caam_pool_fini(sc);
		return (ENXIO);
	}

	device_printf(sc->sc_dev,
	    "registered with opencrypto (driverid %d)\n", sc->sc_cid);

	return (0);
}

void
caam_crypto_detach(struct caam_jr_softc *sc)
{

	if (sc->sc_cid >= 0) {
		crypto_unregister_all(sc->sc_cid);
		sc->sc_cid = -1;
	}
	caam_pool_fini(sc);
}
