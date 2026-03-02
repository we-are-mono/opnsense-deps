/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM opencrypto integration — per-session and per-request structures.
 */

#ifndef _CAAM_CRYPTO_H
#define _CAAM_CRYPTO_H

#include <sys/types.h>
#include <opencrypto/cryptodev.h>
#include "caam_jr.h"

/* Forward declaration */
struct caam_qi_drv_ctx;

/* Algorithm types */
#define CAAM_ALG_GCM		1	/* AES-GCM (AEAD) */
#define CAAM_ALG_CBC_HMAC	2	/* Cipher + HMAC-SHA (ETA) */
#define CAAM_ALG_CIPHER		3	/* Standalone cipher (no auth) */
#define CAAM_ALG_NULL_HMAC	4	/* NULL cipher + HMAC (auth-only) */
#define CAAM_ALG_HASH		5	/* Standalone hash (SHA, MD5) */
#define CAAM_ALG_HMAC		6	/* Standalone HMAC */

/* Maximum key sizes */
#define CAAM_MAX_KEY_LEN	64	/* AES-256-XTS = 2*32 */
#define CAAM_MAX_SPLIT_KEY_LEN	128	/* SHA-512 split key */

/* AES-GCM constants */
#define AES_GCM_IV_LEN		12
#define AES_GCM_TAG_LEN		16

/* Bounce buffer for small payloads (covers standard MTU + AAD + ICV) */
#define CAAM_BOUNCE_SZ		2048

/*
 * Per-session data, stored by the opencrypto framework.
 * Allocated as part of crypto_session; retrieved via
 * crypto_get_driver_session().
 */
struct caam_session {
	int			alg_type;	/* CAAM_ALG_GCM or CAAM_ALG_CBC_HMAC */
	int			ivlen;
	int			icvlen;
	int			enc_klen;	/* Cipher key length (bytes) */

	/* Pre-built shared descriptors (DMA-mapped, CAAM byte order) */
	struct caam_dma_mem	enc_shdesc;
	struct caam_dma_mem	dec_shdesc;
	int			enc_shdesc_len;	/* Words */
	int			dec_shdesc_len;

	/* Cipher key (CPU byte order, converted when building shdesc) */
	uint8_t			enc_key[CAAM_MAX_KEY_LEN];

	/* Raw HMAC key (CPU copy, for reference) */
	uint8_t			auth_key[CAAM_MAX_SPLIT_KEY_LEN];
	int			auth_klen;

	/*
	 * DMA buffer for pre-derived HMAC split key (ipad||opad).
	 * Derived by caam_gen_split_key() during session setup.
	 * Size = split_key_pad_len bytes.
	 */
	struct caam_dma_mem	auth_key_dma;

	/* Split key dimensions */
	int			split_key_len;
	int			split_key_pad_len;

	/* Algorithm type for OPERATION command (CAAM encoding) */
	uint32_t		cipher_algtype;	/* e.g. AES | GCM */
	uint32_t		auth_algtype;	/* e.g. SHA256 | HMAC_PRECOMP */

	/* QI backend: driver contexts (NULL for JR sessions) */
	struct caam_qi_drv_ctx	*qi_enc_ctx;
	struct caam_qi_drv_ctx	*qi_dec_ctx;
};

/*
 * Per-request context for in-flight crypto operations.
 * Pre-allocated in a pool of CAAM_JR_DEPTH entries.
 */
struct caam_request {
	struct caam_jr_softc	*sc;		/* Owning JR (for callback) */
	struct cryptop		*crp;
	struct caam_session	*sess;

	/* Job descriptor (pre-mapped DMA, 256 bytes = 64 words max) */
	struct caam_dma_mem	desc;

	/* Bounce buffer for payload I/O (pre-mapped DMA) */
	struct caam_dma_mem	bounce;

	/* Dynamic fallback for oversized payloads */
	struct caam_dma_mem	dyn_bounce;
	bool			using_dyn;

	/* Pool linkage (free list index; -1 = not in pool) */
	int			next_free;
};

/* Split key length for given hash algorithm selector */
int	caam_split_key_len(uint32_t algsel);
int	caam_split_key_pad_len(uint32_t algsel);

/* Shared descriptor builders */
int	caam_gcm_build_enc_shdesc(struct caam_session *sess, device_t dev);
int	caam_gcm_build_dec_shdesc(struct caam_session *sess, device_t dev);
int	caam_eta_build_enc_shdesc(struct caam_session *sess, device_t dev);
int	caam_eta_build_dec_shdesc(struct caam_session *sess, device_t dev);
int	caam_cipher_build_enc_shdesc(struct caam_session *sess, device_t dev);
int	caam_cipher_build_dec_shdesc(struct caam_session *sess, device_t dev);
int	caam_null_hmac_build_enc_shdesc(struct caam_session *sess, device_t dev);
int	caam_null_hmac_build_dec_shdesc(struct caam_session *sess, device_t dev);

/* Job descriptor builders */
int	caam_gcm_build_job(struct caam_jr_softc *sc,
	    struct caam_request *req, struct cryptop *crp);
int	caam_eta_build_job(struct caam_jr_softc *sc,
	    struct caam_request *req, struct cryptop *crp);
int	caam_cipher_build_job(struct caam_jr_softc *sc,
	    struct caam_request *req, struct cryptop *crp);
int	caam_null_hmac_build_job(struct caam_jr_softc *sc,
	    struct caam_request *req, struct cryptop *crp);

/* Hash/HMAC descriptor builders (caam_hash.c) */
int	caam_hash_build_shdesc(struct caam_session *sess, device_t dev);
int	caam_hash_build_job(struct caam_jr_softc *sc,
	    struct caam_request *req, struct cryptop *crp);

/* Opencrypto DEVMETHOD implementations (referenced from caam_jr_methods[]) */
int	caam_probesession(device_t dev,
	    const struct crypto_session_params *csp);
int	caam_newsession(device_t dev, crypto_session_t cses,
	    const struct crypto_session_params *csp);
void	caam_freesession(device_t dev, crypto_session_t cses);
int	caam_process(device_t dev, struct cryptop *crp, int hint);

/* Opencrypto lifecycle (called from caam_jr attach/detach) */
int	caam_crypto_init(struct caam_jr_softc *sc);
void	caam_crypto_detach(struct caam_jr_softc *sc);

/* DMA helpers (defined in caam_jr.c, used by crypto code) */
int	caam_dma_alloc(device_t dev, struct caam_dma_mem *mem, bus_size_t size);
void	caam_dma_free(struct caam_dma_mem *mem);

/* Algorithm mapping helpers (defined in caam_crypto.c, shared by QI) */
uint32_t caam_cipher_algtype(int cipher_alg);
int	caam_cipher_ivlen(int cipher_alg);
uint32_t caam_auth_algsel(int auth_alg);
int	caam_auth_digest_len(int auth_alg);

/* Auth key DMA and split key derivation (shared by JR and QI) */
int	caam_session_alloc_auth_key_dma(device_t dev,
	    struct caam_session *sess);
int	caam_gen_split_key(device_t dev, struct caam_session *sess);

#endif /* _CAAM_CRYPTO_H */
