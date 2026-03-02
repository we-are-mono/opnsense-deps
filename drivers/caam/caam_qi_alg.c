/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM QI shared descriptor builders.
 *
 * QI shared descriptors differ from JR versions in two ways:
 *   1. Parameters (assoclen, IV) read via SEQ LOAD from the input stream
 *      (replacing the JD body which runs first with HDR_REVERSE in JR mode)
 *   2. No per-request job descriptor — everything is in the shared descriptor
 *
 * Instruction ordering: KEY and OPERATION must come before SEQ FIFO LOAD
 * with FLUSH1 — the CHA must be initialized before it can accept flushed
 * data.  Violating this causes a DECO pipeline deadlock.
 *
 * QI input stream layout (compound FD input S/G → bounce buffer):
 *   AEAD:   [assoclen(4B,BE)] [IV(ivlen)] [AAD] [payload] [ICV for decrypt]
 *   ETA:    [assoclen(4B,BE)] [IV(ivlen)] [AAD] [payload] [ICV for decrypt]
 *   Cipher: [IV(ivlen)] [payload]
 *   Hash:   [payload]
 *
 * The shared descriptor is written at offset 8 (after the 2-word preheader)
 * in ctx->prehdr_shdesc DMA memory.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>

#include <machine/bus.h>

#include <opencrypto/cryptodev.h>

#include "caam.h"
#include "caam_regs.h"
#include "caam_desc.h"
#include "caam_jr.h"
#include "caam_crypto.h"
#include "caam_qi.h"

/*
 * Start address for shdesc within the preheader+shdesc DMA buffer.
 * Preheader occupies words [0] and [1]; shdesc starts at word [2].
 */
#define QI_SHDESC_OFFSET	(2 * sizeof(uint32_t))

static uint32_t *
qi_shdesc_ptr(struct caam_qi_drv_ctx *ctx)
{

	return ((uint32_t *)((uint8_t *)ctx->prehdr_shdesc.vaddr +
	    QI_SHDESC_OFFSET));
}

/*
 * Prepend JUMP NIFP to shared descriptor.
 * Tests NIFP (No Input Frame Pending) condition:
 *   - If set (no frame), jump to self (busy-wait)
 *   - If clear (frame ready), fall through
 */
static void
qi_shdesc_add_nifp(uint32_t *desc)
{

	caam_desc_add_word(desc,
	    CMD_JUMP | JUMP_TEST_ALL | JUMP_COND_NIFP | 1);
}

/*
 * Pipeline barrier after SEQ LOAD into MATH register.
 * Ensures the DECO pipeline drains before MATH operations
 * read the loaded value.  Matches Linux's wait_load_cmd pattern.
 */
static void
qi_shdesc_add_load_barrier(uint32_t *desc)
{

	caam_desc_add_word(desc,
	    CMD_JUMP | JUMP_TEST_ALL |
	    JUMP_COND_CALM | JUMP_COND_NCP | JUMP_COND_NOP |
	    JUMP_COND_NIP | JUMP_COND_NIFP | 1);
}

/* ================================================================
 * AES-GCM QI Shared Descriptors
 *
 * Input stream: [assoclen(4B)] [IV(12B)] [AAD] [payload] [ICV]
 * ================================================================ */

int
caam_qi_gcm_build_enc_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump, *zero_assoc_jump1, *zero_assoc_jump2,
		 *zero_payload_jump;

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

	/* Load AES key (inline) */
	caam_desc_add_word(desc,
	    CMD_KEY | KEY_CLASS1 | KEY_DEST_CLASS_REG |
	    KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	caam_desc_set_jump_target(desc, key_jump);

	/*
	 * OPERATION: AES-GCM encrypt, init+final.
	 * MUST be before SEQ FIFO LOAD IV — the GCM CHA must be
	 * initialized before it can accept IV data via FLUSH1.
	 */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS1_ALG |
	    OP_ALG_ALGSEL_AES | OP_ALG_AAI_GCM |
	    OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* Read assoclen (4 bytes, BE) from input stream → REG3 lower half */
	caam_desc_add_word(desc,
	    CMD_SEQ_LOAD | LDST_CLASS_DECO |
	    LDST_SRCDST_WORD_DECO_MATH3 |
	    (4 << LDST_OFFSET_SHIFT) | sizeof(uint32_t));
	qi_shdesc_add_load_barrier(desc);

	/* Read IV (12 bytes) from input stream into Class 1 FIFO */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 |
	    FIFOLD_TYPE_IV | FIFOLD_TYPE_FLUSH1 | AES_GCM_IV_LEN);

	/* --- Same processing body as JR shdesc --- */

	/* VARSEQOUTLEN = SEQINLEN - REG0(=0) */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_SUB |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* If total length is zero, skip to ICV write */
	zero_assoc_jump2 = caam_desc_add_jump(desc,
	    JUMP_TEST_ALL | JUMP_COND_MATH_Z);

	/* VARSEQINLEN = REG3 (= assoclen) */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_REG3 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* If assoclen is zero, skip AAD */
	zero_assoc_jump1 = caam_desc_add_jump(desc,
	    JUMP_TEST_ALL | JUMP_COND_MATH_Z);

	/* VARSEQOUTLEN = REG3 */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_REG3 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* Skip AAD in output */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_SKIP | FIFOLDST_VLF);

	/* cryptlen = SEQINLEN - REG3 */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_SUB |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG3 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* If cryptlen is zero, jump to zero-payload path */
	zero_payload_jump = caam_desc_add_jump(desc,
	    JUMP_TEST_ALL | JUMP_COND_MATH_Z);

	/* Read AAD (CLASS1, AAD, FLUSH1) */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
	    FIFOLD_TYPE_AAD | FIFOLD_TYPE_FLUSH1);

	caam_desc_set_jump_target(desc, zero_assoc_jump1);

	/* VARSEQINLEN = SEQINLEN - REG0 (remaining = cryptlen) */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_SUB |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* Write encrypted payload */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_VLF);

	/* Read plaintext (CLASS1, MSG, LAST1) */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);

	/* Jump past zero-payload path */
	caam_desc_add_word(desc, CMD_JUMP | JUMP_TEST_ALL | 2);

	/* Zero-payload: read AAD only (AAD | LAST1) */
	caam_desc_set_jump_target(desc, zero_payload_jump);
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
	    FIFOLD_TYPE_AAD | FIFOLD_TYPE_LAST1);

	/* Zero-total-length target */
	caam_desc_set_jump_target(desc, zero_assoc_jump2);

	/* Write ICV */
	caam_desc_add_word(desc,
	    CMD_SEQ_STORE | LDST_CLASS_1_CCB |
	    LDST_SRCDST_BYTE_CONTEXT | sess->icvlen);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}

int
caam_qi_gcm_build_dec_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump, *zero_assoc_jump1, *zero_payload_jump;

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL);

	/* Key loading */
	key_jump = caam_desc_add_jump(desc,
	    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

	caam_desc_add_word(desc,
	    CMD_KEY | KEY_CLASS1 | KEY_DEST_CLASS_REG |
	    KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	caam_desc_set_jump_target(desc, key_jump);

	/* OPERATION before IV FIFO LOAD — GCM CHA must be initialized first */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS1_ALG |
	    OP_ALG_ALGSEL_AES | OP_ALG_AAI_GCM |
	    OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT | OP_ALG_ICV_ON);

	/* Read assoclen → REG3 lower half */
	caam_desc_add_word(desc,
	    CMD_SEQ_LOAD | LDST_CLASS_DECO |
	    LDST_SRCDST_WORD_DECO_MATH3 |
	    (4 << LDST_OFFSET_SHIFT) | sizeof(uint32_t));
	qi_shdesc_add_load_barrier(desc);

	/* Read IV from input stream */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 |
	    FIFOLD_TYPE_IV | FIFOLD_TYPE_FLUSH1 | AES_GCM_IV_LEN);

	/* --- Same processing body as JR dec shdesc --- */

	/* VARSEQINLEN = REG3 */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_REG3 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	zero_assoc_jump1 = caam_desc_add_jump(desc,
	    JUMP_TEST_ALL | JUMP_COND_MATH_Z);

	/* VARSEQOUTLEN = REG3 */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_REG3 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* Skip AAD in output */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_SKIP | FIFOLDST_VLF);

	/* Read AAD */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
	    FIFOLD_TYPE_AAD | FIFOLD_TYPE_FLUSH1);

	caam_desc_set_jump_target(desc, zero_assoc_jump1);

	/* cryptlen = SEQOUTLEN - REG0 */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_SUB |
	    MATH_SRC0_SEQOUTLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	zero_payload_jump = caam_desc_add_jump(desc,
	    JUMP_TEST_ALL | JUMP_COND_MATH_Z);

	/* VARSEQOUTLEN = SEQOUTLEN - REG0 */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_SUB |
	    MATH_SRC0_SEQOUTLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* Write decrypted payload */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_VLF);

	/* Read ciphertext */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_FLUSH1);

	caam_desc_set_jump_target(desc, zero_payload_jump);

	/* Read ICV for verification */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 |
	    FIFOLD_TYPE_ICV | FIFOLD_TYPE_LAST1 | sess->icvlen);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * ETA (Cipher + HMAC) QI Shared Descriptors
 *
 * Input stream: [assoclen(4B)] [IV(ivlen)] [AAD] [payload] [ICV]
 * ================================================================ */

int
caam_qi_eta_build_enc_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump;

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL | HDR_SAVECTX);

	/* Key loading first (matches Linux QI ETA order) */
	key_jump = caam_desc_add_jump(desc,
	    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

	caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
	    sess->auth_key_dma.paddr);

	caam_desc_add_word(desc,
	    CMD_KEY | KEY_CLASS1 | KEY_DEST_CLASS_REG |
	    KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	caam_desc_set_jump_target(desc, key_jump);

	/* Read assoclen → REG3 lower half → DPOVRD */
	caam_desc_add_word(desc,
	    CMD_SEQ_LOAD | LDST_CLASS_DECO |
	    LDST_SRCDST_WORD_DECO_MATH3 |
	    (4 << LDST_OFFSET_SHIFT) | sizeof(uint32_t));
	qi_shdesc_add_load_barrier(desc);

	/* Copy REG3 → DPOVRD (ETA uses DPOVRD for assoclen) */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_REG3 |
	    MATH_DEST_DPOVRD | MATH_LEN_4BYTE);

	/* Read IV from input stream → Class 1 context register */
	if (sess->ivlen > 0) {
		int ctx1_iv_off = 0;

		if ((sess->cipher_algtype & OP_ALG_AAI_MASK) ==
		    OP_ALG_AAI_CTR_MOD128)
			ctx1_iv_off = 16;

		caam_desc_add_word(desc,
		    CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (ctx1_iv_off << LDST_OFFSET_SHIFT) | sess->ivlen);
	}

	/* --- Same processing body as JR ETA enc shdesc --- */

	/* Class 2 OPERATION: HMAC encrypt */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype | OP_ALG_AAI_HMAC_PRECOMP |
	    OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* VARSEQINLEN = DPOVRD = assoclen */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_DPOVRD |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* VARSEQOUTLEN = DPOVRD */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_DPOVRD |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* Skip AAD in output */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_SKIP | FIFOLDST_VLF);

	/* Read AAD for HMAC (CLASS2, MSG) */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS2 |
	    FIFOLD_TYPE_MSG | FIFOLDST_VLF);

	/* Class 1 OPERATION: cipher encrypt */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS1_ALG |
	    sess->cipher_algtype | OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* cryptlen = SEQINLEN + REG0(=0) */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* Read plaintext and write ciphertext (both classes, MSG1OUT2) */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_VLF);
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_BOTH | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG1OUT2 | FIFOLD_TYPE_LASTBOTH);

	/* Write HMAC ICV */
	caam_desc_add_word(desc,
	    CMD_SEQ_STORE | LDST_CLASS_2_CCB |
	    LDST_SRCDST_BYTE_CONTEXT | sess->icvlen);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}

int
caam_qi_eta_build_dec_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump;

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL | HDR_SAVECTX);

	/* Key loading first (matches Linux QI ETA order) */
	key_jump = caam_desc_add_jump(desc,
	    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

	caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
	    sess->auth_key_dma.paddr);

	caam_desc_add_word(desc,
	    CMD_KEY | KEY_CLASS1 | KEY_DEST_CLASS_REG |
	    KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	caam_desc_set_jump_target(desc, key_jump);

	/* Read assoclen → REG3 lower half → DPOVRD */
	caam_desc_add_word(desc,
	    CMD_SEQ_LOAD | LDST_CLASS_DECO |
	    LDST_SRCDST_WORD_DECO_MATH3 |
	    (4 << LDST_OFFSET_SHIFT) | sizeof(uint32_t));
	qi_shdesc_add_load_barrier(desc);

	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_REG3 |
	    MATH_DEST_DPOVRD | MATH_LEN_4BYTE);

	/* Read IV from input stream → Class 1 context register */
	if (sess->ivlen > 0) {
		int ctx1_iv_off = 0;

		if ((sess->cipher_algtype & OP_ALG_AAI_MASK) ==
		    OP_ALG_AAI_CTR_MOD128)
			ctx1_iv_off = 16;

		caam_desc_add_word(desc,
		    CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (ctx1_iv_off << LDST_OFFSET_SHIFT) | sess->ivlen);
	}

	/* --- Same processing body as JR ETA dec shdesc --- */

	/* Class 2 OPERATION: HMAC verify */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype | OP_ALG_AAI_HMAC_PRECOMP |
	    OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT | OP_ALG_ICV_ON);

	/* VARSEQINLEN = DPOVRD */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_DPOVRD |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* VARSEQOUTLEN = DPOVRD */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_ZERO | MATH_SRC1_DPOVRD |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* Skip AAD in output */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_SKIP | FIFOLDST_VLF);

	/* Read AAD for HMAC */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS2 |
	    FIFOLD_TYPE_MSG | FIFOLDST_VLF);

	/* Class 1 OPERATION: cipher decrypt */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS1_ALG |
	    sess->cipher_algtype | OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT);

	/* cryptlen = SEQOUTLEN + REG0(=0) */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQOUTLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQOUTLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/*
	 * Read ciphertext and write plaintext.
	 * LASTBOTH finalizes both Class 1 (cipher) and Class 2 (HMAC)
	 * message streams.  The subsequent ICV load provides the reference
	 * hash for comparison.
	 */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_VLF);
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_BOTH | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_LASTBOTH);

	/* Read ICV for verification */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS2 |
	    FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV | sess->icvlen);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * Standalone Cipher QI Shared Descriptors
 *
 * Input stream: [IV(ivlen)] [payload]
 * ================================================================ */

static bool
qi_cipher_is_xts(const struct caam_session *sess)
{

	return ((sess->cipher_algtype & OP_ALG_AAI_MASK) == OP_ALG_AAI_XTS);
}

int
caam_qi_cipher_build_enc_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump;

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL);

	/* Key loading first (matches Linux QI cipher order) */
	key_jump = caam_desc_add_jump(desc,
	    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

	caam_desc_add_word(desc,
	    CMD_KEY | KEY_CLASS1 | KEY_DEST_CLASS_REG |
	    KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	if (qi_cipher_is_xts(sess)) {
		static const uint8_t sector_size[8] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00
		};
		caam_desc_add_word(desc,
		    CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (0x28 << LDST_OFFSET_SHIFT) | 8);
		caam_desc_add_key_imm(desc, sector_size, 8);
	}

	caam_desc_set_jump_target(desc, key_jump);

	/* Read IV from input stream → Class 1 context register */
	if (qi_cipher_is_xts(sess)) {
		/*
		 * XTS: load 16-byte tweak as two 8-byte halves
		 * into CONTEXT1 at offsets 0x20 and 0x30.
		 */
		caam_desc_add_word(desc,
		    CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (0x20 << LDST_OFFSET_SHIFT) | 8);
		caam_desc_add_word(desc,
		    CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (0x30 << LDST_OFFSET_SHIFT) | 8);
	} else if (sess->ivlen > 0) {
		int ctx1_iv_off = 0;

		if ((sess->cipher_algtype & OP_ALG_AAI_MASK) ==
		    OP_ALG_AAI_CTR_MOD128)
			ctx1_iv_off = 16;

		caam_desc_add_word(desc,
		    CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (ctx1_iv_off << LDST_OFFSET_SHIFT) | sess->ivlen);
	}

	/* OPERATION: cipher encrypt */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS1_ALG |
	    sess->cipher_algtype | OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* --- Same processing as JR cipher enc shdesc --- */

	/* VARSEQOUTLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* VARSEQINLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* Read plaintext and write ciphertext */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_VLF);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}

int
caam_qi_cipher_build_dec_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump;
	uint32_t algtype;

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL);

	/* Key loading first (matches Linux QI cipher order) */
	key_jump = caam_desc_add_jump(desc,
	    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

	caam_desc_add_word(desc,
	    CMD_KEY | KEY_CLASS1 | KEY_DEST_CLASS_REG |
	    KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	if (qi_cipher_is_xts(sess)) {
		static const uint8_t sector_size[8] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00
		};
		caam_desc_add_word(desc,
		    CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (0x28 << LDST_OFFSET_SHIFT) | 8);
		caam_desc_add_key_imm(desc, sector_size, 8);
	}

	caam_desc_set_jump_target(desc, key_jump);

	/* Read IV from input stream → Class 1 context register */
	if (qi_cipher_is_xts(sess)) {
		/*
		 * XTS: load 16-byte tweak as two 8-byte halves
		 * into CONTEXT1 at offsets 0x20 and 0x30.
		 */
		caam_desc_add_word(desc,
		    CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (0x20 << LDST_OFFSET_SHIFT) | 8);
		caam_desc_add_word(desc,
		    CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (0x30 << LDST_OFFSET_SHIFT) | 8);
	} else if (sess->ivlen > 0) {
		int ctx1_iv_off = 0;

		if ((sess->cipher_algtype & OP_ALG_AAI_MASK) ==
		    OP_ALG_AAI_CTR_MOD128)
			ctx1_iv_off = 16;

		caam_desc_add_word(desc,
		    CMD_SEQ_LOAD | LDST_CLASS_1_CCB |
		    LDST_SRCDST_BYTE_CONTEXT |
		    (ctx1_iv_off << LDST_OFFSET_SHIFT) | sess->ivlen);
	}

	/* OPERATION: cipher decrypt (with DK optimization for AES) */
	algtype = sess->cipher_algtype;
	if ((algtype & OP_ALG_ALGSEL_MASK) == OP_ALG_ALGSEL_AES &&
	    (algtype & OP_ALG_AAI_MASK) != OP_ALG_AAI_CTR_MOD128) {
		uint32_t *dk_jump, *skip_jump;

		dk_jump = caam_desc_add_jump(desc,
		    JUMP_TEST_ALL | JUMP_COND_SHRD);

		caam_desc_add_word(desc,
		    CMD_OPERATION | OP_TYPE_CLASS1_ALG |
		    algtype | OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT);

		skip_jump = caam_desc_add_jump(desc, JUMP_TEST_ALL);

		caam_desc_set_jump_target(desc, dk_jump);
		caam_desc_add_word(desc,
		    CMD_OPERATION | OP_TYPE_CLASS1_ALG |
		    algtype | OP_ALG_AS_INITFINAL |
		    OP_ALG_DECRYPT | OP_ALG_AAI_DK);

		caam_desc_set_jump_target(desc, skip_jump);
	} else {
		caam_desc_add_word(desc,
		    CMD_OPERATION | OP_TYPE_CLASS1_ALG |
		    algtype | OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT);
	}

	/* --- Same processing as JR cipher dec shdesc --- */

	/* VARSEQOUTLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* VARSEQINLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* Read ciphertext and write plaintext */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS1 | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_MESSAGE_DATA | FIFOLDST_VLF);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * NULL cipher + HMAC QI Shared Descriptors
 *
 * Input stream: [assoclen(4B)] [AAD] [payload] [ICV for decrypt]
 * (no IV — NULL cipher has no IV)
 * ================================================================ */

int
caam_qi_null_hmac_build_enc_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump;

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL | HDR_SAVECTX);

	/* Key loading first (matches Linux QI null+hmac order) */
	key_jump = caam_desc_add_jump(desc,
	    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

	caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
	    sess->auth_key_dma.paddr);

	caam_desc_set_jump_target(desc, key_jump);

	/* Read assoclen from input stream → REG3 lower half */
	caam_desc_add_word(desc,
	    CMD_SEQ_LOAD | LDST_CLASS_DECO |
	    LDST_SRCDST_WORD_DECO_MATH3 |
	    (4 << LDST_OFFSET_SHIFT) | sizeof(uint32_t));
	qi_shdesc_add_load_barrier(desc);

	/* --- Same processing as JR null_hmac enc shdesc --- */

	/* OPERATION: HMAC encrypt */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype | OP_ALG_AAI_HMAC_PRECOMP |
	    OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* VARSEQINLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* VARSEQOUTLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* Skip passthrough in output */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_SKIP | FIFOLDST_VLF);

	/* Feed all data to HMAC */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS2 | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/* Write HMAC ICV */
	caam_desc_add_word(desc,
	    CMD_SEQ_STORE | LDST_CLASS_2_CCB |
	    LDST_SRCDST_BYTE_CONTEXT | sess->icvlen);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}

int
caam_qi_null_hmac_build_dec_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump;

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL | HDR_SAVECTX);

	/* Key loading first (matches Linux QI null+hmac order) */
	key_jump = caam_desc_add_jump(desc,
	    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

	caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
	    sess->auth_key_dma.paddr);

	caam_desc_set_jump_target(desc, key_jump);

	/* Read assoclen from input stream → REG3 lower half */
	caam_desc_add_word(desc,
	    CMD_SEQ_LOAD | LDST_CLASS_DECO |
	    LDST_SRCDST_WORD_DECO_MATH3 |
	    (4 << LDST_OFFSET_SHIFT) | sizeof(uint32_t));
	qi_shdesc_add_load_barrier(desc);

	/* --- Same processing as JR null_hmac dec shdesc --- */

	/* OPERATION: HMAC verify */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype | OP_ALG_AAI_HMAC_PRECOMP |
	    OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT | OP_ALG_ICV_ON);

	/* Data length = SEQOUTLEN (excludes ICV) */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQOUTLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQOUTLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQOUTLEN | MATH_LEN_4BYTE);

	/* Skip passthrough in output */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_STORE | FIFOST_TYPE_SKIP | FIFOLDST_VLF);

	/* Feed data to HMAC (no LAST2 yet — ICV follows) */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS2 | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG);

	/* Read ICV for verification */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS2 |
	    FIFOLD_TYPE_ICV | FIFOLD_TYPE_LAST2 | sess->icvlen);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * Hash/HMAC QI Shared Descriptor
 *
 * Input stream: [payload] (no prefix — hash has no assoclen or IV)
 * ================================================================ */

int
caam_qi_hash_build_shdesc(struct caam_session *sess, device_t dev,
    struct caam_qi_drv_ctx *ctx)
{
	uint32_t *desc;
	uint32_t *key_jump;
	bool is_hmac;

	is_hmac = (sess->alg_type == CAAM_ALG_HMAC);

	desc = qi_shdesc_ptr(ctx);
	caam_shdesc_init(desc, HDR_SHARE_SERIAL);

	if (is_hmac) {
		key_jump = caam_desc_add_jump(desc,
		    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

		caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
		    sess->auth_key_dma.paddr);

		caam_desc_set_jump_target(desc, key_jump);
	}

	/* --- Same processing as JR hash shdesc --- */

	/* OPERATION: hash/HMAC compute */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype |
	    (is_hmac ? OP_ALG_AAI_HMAC_PRECOMP : 0) |
	    OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/* VARSEQINLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* Feed all data to Class 2 */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS2 | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/* Store digest */
	caam_desc_add_word(desc,
	    CMD_SEQ_STORE | LDST_CLASS_2_CCB |
	    LDST_SRCDST_BYTE_CONTEXT | sess->icvlen);

	ctx->shdesc_len = caam_shdesc_len(desc);
	return (0);
}
