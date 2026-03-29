/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM algorithm descriptor builders for all supported modes.
 *
 * Shared descriptors are built once per session and stored in DMA memory.
 * Job descriptors are built per-request and reference the shared descriptor.
 *
 * Descriptor sequences inspired by the NXP SEC v5.x reference manual and
 * NXP's CAAM SDK examples, adapted for FreeBSD's opencrypto buffer model.
 *
 * Job descriptor layout uses CAAM_HDR_SHARE_DEFER | CAAM_HDR_REVERSE so the JD body
 * (REG3 load, IV load, SEQ IN/OUT PTR) executes BEFORE the shared
 * descriptor.  start_idx = shdesc_len following the combined descriptor
 * interleaving model.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <machine/bus.h>

#include <opencrypto/cryptodev.h>

#include "caam.h"
#include "caam_regs.h"
#include "caam_desc.h"
#include "caam_jr.h"
#include "caam_crypto.h"

/*
 * Split key lengths for HMAC algorithms.
 *
 * The split key is the ipad || opad partial digests concatenated.
 * Each half is the MDHA internal state size (NOT the truncated digest
 * size).  SHA-224 and SHA-384 share internal state sizes with SHA-256
 * and SHA-512 respectively.  Values derived from the MDHA internal state sizes in the
 * NXP SEC reference manual.
 */
int
caam_split_key_len(uint32_t algsel)
{

	switch (algsel) {
	case CAAM_OP_ALG_ALGSEL_SHA1:
		return (40);	/* 2 * 20 (160-bit state) */
	case CAAM_OP_ALG_ALGSEL_SHA224:
		return (64);	/* 2 * 32 (256-bit state, same as SHA-256) */
	case CAAM_OP_ALG_ALGSEL_SHA256:
		return (64);	/* 2 * 32 (256-bit state) */
	case CAAM_OP_ALG_ALGSEL_SHA384:
		return (128);	/* 2 * 64 (512-bit state, same as SHA-512) */
	case CAAM_OP_ALG_ALGSEL_SHA512:
		return (128);	/* 2 * 64 (512-bit state) */
	case CAAM_OP_ALG_ALGSEL_MD5:
		return (32);	/* 2 * 16 (128-bit state) */
	default:
		return (0);
	}
}

int
caam_split_key_pad_len(uint32_t algsel)
{

	/* Round up to the next multiple of 16 for CAAM DMA alignment */
	return ((caam_split_key_len(algsel) + 15) & ~15);
}

/* ================================================================
 * AES-GCM Shared Descriptors
 *
 * GCM uses Class 1 only (AES in GCM mode is a combined cipher+auth).
 * The shared descriptor loads the key and sets up the OPERATION.
 * Job descriptors provide:
 *   - REG3 = assoclen (via MATH ADD IMM, runs first with CAAM_HDR_REVERSE)
 *   - IV via FIFO LOAD IMM (12 bytes, Class 1)
 *   - SEQ IN PTR / SEQ OUT PTR for bounce buffer
 *
 * Data layout in bounce buffer:
 *   Encrypt input:  [AAD (assoclen bytes)] [plaintext (cryptlen bytes)]
 *   Encrypt output: [AAD (assoclen bytes)] [ciphertext] [ICV (16 bytes)]
 *   Decrypt input:  [AAD (assoclen bytes)] [ciphertext] [ICV (16 bytes)]
 *   Decrypt output: [AAD (assoclen bytes)] [plaintext]
 * ================================================================ */

int
caam_gcm_build_enc_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump, *zero_assoc_jump1, *zero_assoc_jump2,
		 *zero_payload_jump;
	int error;

	error = caam_dma_alloc(dev, &sess->enc_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->enc_shdesc.vaddr;
	caam_shdesc_init(desc, CAAM_HDR_SHARE_SERIAL);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_JSL | CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

	/* Load AES key (inline in descriptor) */
	caam_desc_add_word(desc,
	    CAAM_CMD_KEY | CAAM_KEY_CLASS1 | CAAM_KEY_DEST_CLASS_REG |
	    CAAM_KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	caam_desc_set_jump_target(desc, key_jump);

	/* OPERATION: AES-GCM encrypt, init+final */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
	    CAAM_OP_ALG_ALGSEL_AES | CAAM_OP_ALG_AAI_GCM |
	    CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_ENCRYPT);

	/*
	 * VARSEQOUTLEN = SEQINLEN - REG0
	 * REG0 is zero at job start, so VARSEQOUTLEN = total input length.
	 * If zero, no data to process — skip to ICV write.
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_SUB |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* If total length (assoclen + cryptlen) is zero, skip to ICV write */
	zero_assoc_jump2 = caam_desc_add_jump(desc,
	    CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_MATH_Z);

	/* VARSEQINLEN = REG3 (= assoclen, loaded by job desc) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_REG3 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	/* If assoclen is zero, skip AAD processing */
	zero_assoc_jump1 = caam_desc_add_jump(desc,
	    CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_MATH_Z);

	/* VARSEQOUTLEN = REG3 (for skipping AAD in output) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_REG3 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* Skip AAD bytes in output */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_SKIP | CAAM_FIFOLDST_VLF);

	/* cryptlen = SEQINLEN - REG3 (subtract assoclen from remaining) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_SUB |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG3 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* If cryptlen is zero, jump to zero-payload path */
	zero_payload_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_MATH_Z);

	/* Read AAD data (Class 1, AAD type, FLUSH1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_AAD | CAAM_FIFOLD_TYPE_FLUSH1);

	caam_desc_set_jump_target(desc, zero_assoc_jump1);

	/* VARSEQINLEN = SEQINLEN - REG0 (remaining = cryptlen) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_SUB |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	/* Write encrypted payload */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_MESSAGE_DATA | CAAM_FIFOLDST_VLF);

	/* Read plaintext payload (CLASS1, MSG, LAST1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_MSG | CAAM_FIFOLD_TYPE_LAST1);

	/* Jump past zero-payload path to ICV write */
	caam_desc_add_word(desc, CAAM_CMD_JUMP | CAAM_JUMP_TEST_ALL | 2);

	/* Zero-payload: read AAD only (AAD | LAST1) */
	caam_desc_set_jump_target(desc, zero_payload_jump);
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_AAD | CAAM_FIFOLD_TYPE_LAST1);

	/* Zero-total-length target */
	caam_desc_set_jump_target(desc, zero_assoc_jump2);

	/* Write ICV (tag) from Class 1 context register */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_STORE | CAAM_LDST_CLASS_1_CCB |
	    CAAM_LDST_SRCDST_BYTE_CONTEXT | sess->icvlen);

	sess->enc_shdesc_len = caam_shdesc_len(desc);
	return (0);
}

int
caam_gcm_build_dec_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump, *zero_assoc_jump1, *zero_payload_jump;
	int error;

	error = caam_dma_alloc(dev, &sess->dec_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->dec_shdesc.vaddr;
	caam_shdesc_init(desc, CAAM_HDR_SHARE_SERIAL);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_JSL | CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

	/* Load AES key */
	caam_desc_add_word(desc,
	    CAAM_CMD_KEY | CAAM_KEY_CLASS1 | CAAM_KEY_DEST_CLASS_REG |
	    CAAM_KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	caam_desc_set_jump_target(desc, key_jump);

	/* OPERATION: AES-GCM decrypt with ICV check */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
	    CAAM_OP_ALG_ALGSEL_AES | CAAM_OP_ALG_AAI_GCM |
	    CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_DECRYPT | CAAM_OP_ALG_ICV_ON);

	/* VARSEQINLEN = REG3 (= assoclen) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_REG3 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	/* If assoclen is zero, skip AAD */
	zero_assoc_jump1 = caam_desc_add_jump(desc,
	    CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_MATH_Z);

	/* VARSEQOUTLEN = REG3 */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_REG3 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* Skip AAD in output */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_SKIP | CAAM_FIFOLDST_VLF);

	/* Read AAD (CLASS1, AAD, FLUSH1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_AAD | CAAM_FIFOLD_TYPE_FLUSH1);

	caam_desc_set_jump_target(desc, zero_assoc_jump1);

	/* cryptlen = SEQOUTLEN - REG0 (= remaining output size) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_SUB |
	    CAAM_MATH_SRC0_SEQOUTLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	/* If cryptlen is zero, jump to ICV read */
	zero_payload_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_MATH_Z);

	/* VARSEQOUTLEN = SEQOUTLEN - REG0 */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_SUB |
	    CAAM_MATH_SRC0_SEQOUTLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* Write decrypted payload */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_MESSAGE_DATA | CAAM_FIFOLDST_VLF);

	/* Read ciphertext (CLASS1, MSG, FLUSH1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_MSG | CAAM_FIFOLD_TYPE_FLUSH1);

	/* Zero-payload target */
	caam_desc_set_jump_target(desc, zero_payload_jump);

	/* Read ICV for verification (CLASS1, ICV | LAST1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 |
	    CAAM_FIFOLD_TYPE_ICV | CAAM_FIFOLD_TYPE_LAST1 | sess->icvlen);

	sess->dec_shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * AES-CBC + HMAC-SHA Shared Descriptors (ETA mode)
 *
 * Uses both Class 1 (AES-CBC) and Class 2 (HMAC-SHA).
 * ================================================================ */

int
caam_eta_build_enc_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump;
	int error;

	error = caam_dma_alloc(dev, &sess->enc_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->enc_shdesc.vaddr;
	caam_shdesc_init(desc, CAAM_HDR_SHARE_SERIAL | CAAM_HDR_SAVECTX);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_JSL | CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

	/* Load pre-derived HMAC split key (pointer mode, 3 words) */
	caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
	    sess->auth_key_dma.paddr);

	/* Load AES cipher key (Class 1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_KEY | CAAM_KEY_CLASS1 | CAAM_KEY_DEST_CLASS_REG |
	    CAAM_KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	caam_desc_set_jump_target(desc, key_jump);

	/* Class 2 OPERATION: HMAC with pre-computed split key */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype | CAAM_OP_ALG_AAI_HMAC_PRECOMP |
	    CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_ENCRYPT);

	/*
	 * Read assoclen from DPOVRD (set by job descriptor, era >= 3).
	 * VARSEQINLEN = DPOVRD = assoclen
	 * VARSEQOUTLEN = DPOVRD = assoclen
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_DPOVRD |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_DPOVRD |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* Skip assoc data in output */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_SKIP | CAAM_FIFOLDST_VLF);

	/* Read assoc data for HMAC (CLASS2, MSG) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS2 |
	    CAAM_FIFOLD_TYPE_MSG | CAAM_FIFOLDST_VLF);

	/* Class 1 OPERATION: AES-CBC encrypt */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
	    sess->cipher_algtype | CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_ENCRYPT);

	/*
	 * Remaining input = SEQINLEN (live counter after AAD consumed).
	 * VARSEQINLEN = SEQINLEN + REG0(=0) = cryptlen
	 * VARSEQOUTLEN = SEQINLEN + REG0(=0) = cryptlen
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/*
	 * Read plaintext (both classes) and write ciphertext.
	 * MSG1OUT2: Class 1 encrypts, Class 2 authenticates the ciphertext.
	 * LASTBOTH: finalize both Class 1 (cipher) and Class 2 (HMAC).
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_MESSAGE_DATA | CAAM_FIFOLDST_VLF);
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_BOTH | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_MSG1OUT2 | CAAM_FIFOLD_TYPE_LASTBOTH);

	/* Write HMAC ICV from Class 2 context */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_STORE | CAAM_LDST_CLASS_2_CCB |
	    CAAM_LDST_SRCDST_BYTE_CONTEXT | sess->icvlen);

	sess->enc_shdesc_len = caam_shdesc_len(desc);

	return (0);
}

int
caam_eta_build_dec_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump;
	int error;

	error = caam_dma_alloc(dev, &sess->dec_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->dec_shdesc.vaddr;
	caam_shdesc_init(desc, CAAM_HDR_SHARE_SERIAL | CAAM_HDR_SAVECTX);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_JSL | CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

	/* Load pre-derived HMAC split key (pointer mode, 3 words) */
	caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
	    sess->auth_key_dma.paddr);

	/* Load AES cipher key (Class 1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_KEY | CAAM_KEY_CLASS1 | CAAM_KEY_DEST_CLASS_REG |
	    CAAM_KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	caam_desc_set_jump_target(desc, key_jump);

	/* Class 2 OPERATION: HMAC verify (DECRYPT + ICV_ON) */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype | CAAM_OP_ALG_AAI_HMAC_PRECOMP |
	    CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_DECRYPT | CAAM_OP_ALG_ICV_ON);

	/* VARSEQINLEN = DPOVRD (= assoclen, set by job desc, era >= 3) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_DPOVRD |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	/* VARSEQOUTLEN = DPOVRD */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_DPOVRD |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* Skip assoc data in output */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_SKIP | CAAM_FIFOLDST_VLF);

	/* Read assoc data for HMAC (CLASS2, MSG) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS2 |
	    CAAM_FIFOLD_TYPE_MSG | CAAM_FIFOLDST_VLF);

	/* Class 1 OPERATION: AES-CBC decrypt */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
	    sess->cipher_algtype | CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_DECRYPT);

	/*
	 * For decrypt, use SEQOUTLEN (output remaining) to determine
	 * cryptlen.
	 * VARSEQINLEN = SEQOUTLEN + REG0(=0) = cryptlen
	 * VARSEQOUTLEN = SEQOUTLEN + REG0(=0) = cryptlen
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQOUTLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQOUTLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/*
	 * Read ciphertext and write plaintext.
	 * LASTBOTH finalizes both Class 1 (cipher) and Class 2 (HMAC)
	 * message streams.  The subsequent ICV load provides the reference
	 * hash for comparison (HMAC is already complete at that point).
	 * Using LAST1 alone would leave Class 2 waiting for more data,
	 * causing a DECO watchdog timeout.
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_MESSAGE_DATA | CAAM_FIFOLDST_VLF);
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_BOTH | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_MSG | CAAM_FIFOLD_TYPE_LASTBOTH);

	/* Read ICV for verification (CLASS2, ICV | LAST2) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS2 |
	    CAAM_FIFOLD_TYPE_LAST2 | CAAM_FIFOLD_TYPE_ICV | sess->icvlen);

	sess->dec_shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * Job Descriptor Builders
 *
 * Job descriptors use CAAM_HDR_SHARE_DEFER | CAAM_HDR_REVERSE so the JD body
 * executes BEFORE the shared descriptor.  This allows the JD to
 * set up REG3 (GCM) or DPOVRD (ETA, era >= 3) for the shared
 * descriptor to use.
 *
 * Combined descriptor model (DECO internal view):
 *   [0]             JD header
 *   [1..shlen]      Shared descriptor (loaded from DMA)
 *   [shlen+1..end]  JD body (from words after shdesc pointer in JD)
 *
 * start_idx = shlen + 1: tells DECO where JD body begins.
 * With CAAM_HDR_REVERSE: JD body runs first, then shared descriptor.
 *
 * JD memory layout:
 *   [0]    JD header
 *   [1-2]  Shared descriptor DMA pointer (64-bit)
 *   [3..]  JD body commands (MATH, LOAD IV, SEQ IN/OUT PTR)
 * ================================================================ */

int
caam_gcm_build_job(struct caam_jr_softc *sc, struct caam_request *req,
    struct cryptop *crp)
{
	struct caam_session *sess;
	uint32_t *desc;
	bus_addr_t buf_pa;
	uint32_t assoclen, input_len, output_len;
	bool encrypt;
	int shdesc_len;
	uint8_t iv[AES_GCM_IV_LEN];

	sess = req->sess;
	desc = req->desc.vaddr;
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);
	buf_pa = req->using_dyn ? req->dyn_bounce.paddr : req->bounce.paddr;

	assoclen = crp->crp_aad_length;
	shdesc_len = encrypt ? sess->enc_shdesc_len : sess->dec_shdesc_len;

	if (encrypt) {
		input_len = assoclen + crp->crp_payload_length;
		output_len = assoclen + crp->crp_payload_length + sess->icvlen;
	} else {
		input_len = assoclen + crp->crp_payload_length + sess->icvlen;
		output_len = assoclen + crp->crp_payload_length;
	}

	/* Read IV from the crypto request */
	crypto_read_iv(crp, iv);

	/* Build job descriptor */
	caam_desc_init(desc);

	/* Set start index and share mode */
	{
		uint32_t hdr = caam_to_cpu32(desc[0]);

		hdr |= CAAM_HDR_SHARED | CAAM_HDR_SHARE_DEFER | CAAM_HDR_REVERSE;
		hdr |= (shdesc_len << CAAM_HDR_START_IDX_SHIFT);
		desc[0] = cpu_to_caam32(hdr);
	}

	/* Shared descriptor pointer (64-bit) */
	if (encrypt)
		caam_desc_add_ptr(desc, sess->enc_shdesc.paddr);
	else
		caam_desc_add_ptr(desc, sess->dec_shdesc.paddr);

	/* === JD body (runs FIRST with CAAM_HDR_REVERSE) === */

	/* REG3 = assoclen (MATH ADD: ZERO + IMM → REG3) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_IMM |
	    CAAM_MATH_DEST_REG3 | CAAM_MATH_LEN_4BYTE);
	caam_desc_add_word(desc, assoclen);

	/*
	 * Load GCM IV (12 bytes, inline) into Class 1 FIFO.
	 * CAAM AES-GCM expects the 12-byte IV; it auto-appends counter=1.
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 | CAAM_FIFOLD_IMM |
	    CAAM_FIFOLD_TYPE_IV | CAAM_FIFOLD_TYPE_FLUSH1 | AES_GCM_IV_LEN);
	caam_desc_add_key_imm(desc, iv, AES_GCM_IV_LEN);

	/* SEQ IN PTR: input data */
	caam_desc_add_seq_in_ptr(desc, buf_pa, input_len);

	/* SEQ OUT PTR: output data */
	caam_desc_add_seq_out_ptr(desc, buf_pa, output_len);

	return (0);
}

int
caam_eta_build_job(struct caam_jr_softc *sc, struct caam_request *req,
    struct cryptop *crp)
{
	struct caam_session *sess;
	uint32_t *desc;
	bus_addr_t buf_pa;
	uint32_t assoclen, input_len, output_len;
	bool encrypt;
	int shdesc_len;
	uint8_t iv[AES_BLOCK_LEN];	/* Max IV: 16 bytes (AES) */

	sess = req->sess;
	desc = req->desc.vaddr;
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);
	buf_pa = req->using_dyn ? req->dyn_bounce.paddr : req->bounce.paddr;

	assoclen = crp->crp_aad_length;
	shdesc_len = encrypt ? sess->enc_shdesc_len : sess->dec_shdesc_len;

	if (encrypt) {
		input_len = assoclen + crp->crp_payload_length;
		output_len = assoclen + crp->crp_payload_length + sess->icvlen;
	} else {
		input_len = assoclen + crp->crp_payload_length + sess->icvlen;
		output_len = assoclen + crp->crp_payload_length;
	}

	/* Build job descriptor */
	caam_desc_init(desc);

	{
		uint32_t hdr = caam_to_cpu32(desc[0]);

		hdr |= CAAM_HDR_SHARED | CAAM_HDR_SHARE_DEFER | CAAM_HDR_REVERSE;
		hdr |= (shdesc_len << CAAM_HDR_START_IDX_SHIFT);
		desc[0] = cpu_to_caam32(hdr);
	}

	/* Shared descriptor pointer */
	if (encrypt)
		caam_desc_add_ptr(desc, sess->enc_shdesc.paddr);
	else
		caam_desc_add_ptr(desc, sess->dec_shdesc.paddr);

	/* === JD body (runs FIRST with CAAM_HDR_REVERSE) === */

	/* DPOVRD = assoclen (MATH ADD: ZERO + IMM -> DPOVRD, era >= 3) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_ZERO | CAAM_MATH_SRC1_IMM |
	    CAAM_MATH_DEST_DPOVRD | CAAM_MATH_LEN_4BYTE);
	caam_desc_add_word(desc, assoclen);

	/*
	 * Load cipher IV into Class 1 context register.
	 * AES-CTR: 16 bytes at CONTEXT1[16] (ctx1_iv_off = 16).
	 * AES-CBC / DES-CBC: at CONTEXT1[0].
	 */
	if (sess->ivlen > 0) {
		int ctx1_iv_off = 0;

		if ((sess->cipher_algtype & CAAM_OP_ALG_AAI_MASK) ==
		    CAAM_OP_ALG_AAI_CTR_MOD128)
			ctx1_iv_off = 16;

		crypto_read_iv(crp, iv);
		caam_desc_add_word(desc,
		    CAAM_CMD_LOAD | CAAM_LDST_CLASS_1_CCB | CAAM_LDST_IMM |
		    CAAM_LDST_SRCDST_BYTE_CONTEXT |
		    (ctx1_iv_off << CAAM_LDST_OFFSET_SHIFT) | sess->ivlen);
		caam_desc_add_key_imm(desc, iv, sess->ivlen);
	}

	/* SEQ IN PTR */
	caam_desc_add_seq_in_ptr(desc, buf_pa, input_len);

	/* SEQ OUT PTR */
	caam_desc_add_seq_out_ptr(desc, buf_pa, output_len);

	return (0);
}

/* ================================================================
 * Standalone Cipher Shared Descriptors
 *
 * Class 1 only (no authentication).  Supports AES-CBC, AES-CTR,
 * AES-ECB, AES-XTS, DES-CBC, and 3DES-CBC.
 *
 * Key is loaded inline.  IV is provided by the job descriptor via
 * LOAD IMM into CONTEXT1 (runs first with CAAM_HDR_REVERSE).
 *
 * XTS requires special handling: double key, sector size in
 * CONTEXT1+0x28, and IV (tweak) loaded as two 8-byte halves
 * at CONTEXT1+0x20 and 0x30.
 * ================================================================ */

static bool
caam_cipher_is_xts(const struct caam_session *sess)
{

	return ((sess->cipher_algtype & CAAM_OP_ALG_AAI_MASK) == CAAM_OP_ALG_AAI_XTS);
}

int
caam_cipher_build_enc_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump;
	int error;

	error = caam_dma_alloc(dev, &sess->enc_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->enc_shdesc.vaddr;
	caam_shdesc_init(desc, CAAM_HDR_SHARE_SERIAL);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_JSL | CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

	/* Load cipher key (inline, Class 1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_KEY | CAAM_KEY_CLASS1 | CAAM_KEY_DEST_CLASS_REG |
	    CAAM_KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	if (caam_cipher_is_xts(sess)) {
		/*
		 * XTS: load sector size (2^15 = 32768) at CONTEXT1+0x28.
		 * This effectively disables sector-based segmentation,
		 * processing the entire input as one unit.
		 */
		static const uint8_t sector_size[8] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00
		};
		caam_desc_add_word(desc,
		    CAAM_CMD_LOAD | CAAM_LDST_CLASS_1_CCB | CAAM_LDST_IMM |
		    CAAM_LDST_SRCDST_BYTE_CONTEXT |
		    (0x28 << CAAM_LDST_OFFSET_SHIFT) | 8);
		caam_desc_add_key_imm(desc, sector_size, 8);
	}

	caam_desc_set_jump_target(desc, key_jump);

	/* OPERATION: cipher encrypt, init+final */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
	    sess->cipher_algtype | CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_ENCRYPT);

	/* VARSEQOUTLEN = SEQINLEN (total input → total output) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* VARSEQINLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	/* Read plaintext and write ciphertext */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_MSG | CAAM_FIFOLD_TYPE_LAST1);
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_MESSAGE_DATA | CAAM_FIFOLDST_VLF);

	sess->enc_shdesc_len = caam_shdesc_len(desc);
	return (0);
}

int
caam_cipher_build_dec_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump;
	uint32_t algtype;
	int error;

	error = caam_dma_alloc(dev, &sess->dec_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->dec_shdesc.vaddr;
	caam_shdesc_init(desc, CAAM_HDR_SHARE_SERIAL);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_JSL | CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

	/* Load cipher key (inline, Class 1) */
	caam_desc_add_word(desc,
	    CAAM_CMD_KEY | CAAM_KEY_CLASS1 | CAAM_KEY_DEST_CLASS_REG |
	    CAAM_KEY_IMM | sess->enc_klen);
	caam_desc_add_key_imm(desc, sess->enc_key, sess->enc_klen);

	if (caam_cipher_is_xts(sess)) {
		/* XTS: sector size at CONTEXT1+0x28 */
		static const uint8_t sector_size[8] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00
		};
		caam_desc_add_word(desc,
		    CAAM_CMD_LOAD | CAAM_LDST_CLASS_1_CCB | CAAM_LDST_IMM |
		    CAAM_LDST_SRCDST_BYTE_CONTEXT |
		    (0x28 << CAAM_LDST_OFFSET_SHIFT) | 8);
		caam_desc_add_key_imm(desc, sector_size, 8);
	}

	caam_desc_set_jump_target(desc, key_jump);

	/*
	 * OPERATION: cipher decrypt.
	 *
	 * For AES, use the DK (Derived Key) optimization:
	 * - First run (key not yet shared): plain INITFINAL + DECRYPT
	 *   computes the decrypt key schedule from the raw key.
	 * - Subsequent runs (key shared): INITFINAL + DECRYPT + DK
	 *   reuses the pre-computed decrypt key schedule.
	 * CTR mode doesn't need DK (same key schedule for enc/dec).
	 * DES/3DES doesn't support DK.
	 */
	algtype = sess->cipher_algtype;
	if ((algtype & CAAM_OP_ALG_ALGSEL_MASK) == CAAM_OP_ALG_ALGSEL_AES &&
	    (algtype & CAAM_OP_ALG_AAI_MASK) != CAAM_OP_ALG_AAI_CTR_MOD128) {
		uint32_t *dk_jump, *skip_jump;

		/* If shared, jump to DK path */
		dk_jump = caam_desc_add_jump(desc,
		    CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

		/* First run: derive decrypt key from raw key */
		caam_desc_add_word(desc,
		    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
		    algtype | CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_DECRYPT);

		skip_jump = caam_desc_add_jump(desc, CAAM_JUMP_TEST_ALL);

		/* DK path: reuse pre-computed decrypt key */
		caam_desc_set_jump_target(desc, dk_jump);
		caam_desc_add_word(desc,
		    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
		    algtype | CAAM_OP_ALG_AS_INITFINAL |
		    CAAM_OP_ALG_DECRYPT | CAAM_OP_ALG_AAI_DK);

		caam_desc_set_jump_target(desc, skip_jump);
	} else {
		/* CTR, DES, 3DES: plain decrypt */
		caam_desc_add_word(desc,
		    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS1_ALG |
		    algtype | CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_DECRYPT);
	}

	/* VARSEQOUTLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* VARSEQINLEN = SEQINLEN */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	/* Read ciphertext and write plaintext */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS1 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_MSG | CAAM_FIFOLD_TYPE_LAST1);
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_MESSAGE_DATA | CAAM_FIFOLDST_VLF);

	sess->dec_shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * NULL cipher + HMAC Shared Descriptors (auth-only ETA)
 *
 * Class 2 only — no cipher engine.  All data (AAD + payload) is
 * fed to HMAC as message data.  Since our bounce buffer uses the
 * same address for input and output, the "passthrough" is implicit:
 * data is already in the output buffer.  We just skip the output
 * sequence, feed data to Class 2, and write/verify the ICV.
 *
 * This avoids the complex self-modifying MOVE descriptor pattern
 * that would be needed for separate source/destination buffers.
 * ================================================================ */

int
caam_null_hmac_build_enc_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump;
	int error;

	error = caam_dma_alloc(dev, &sess->enc_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->enc_shdesc.vaddr;
	caam_shdesc_init(desc, CAAM_HDR_SHARE_SERIAL | CAAM_HDR_SAVECTX);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_JSL | CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

	/* Load pre-derived HMAC split key (pointer mode, 3 words) */
	caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
	    sess->auth_key_dma.paddr);

	caam_desc_set_jump_target(desc, key_jump);

	/* Class 2 OPERATION: HMAC init+final, encrypt (generate ICV) */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype | CAAM_OP_ALG_AAI_HMAC_PRECOMP |
	    CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_ENCRYPT);

	/*
	 * VARSEQINLEN = SEQINLEN (= assoclen + cryptlen).
	 * All input data is fed to HMAC — no AAD/payload split needed
	 * since there is no cipher to separate them.
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	/* VARSEQOUTLEN = SEQINLEN (skip passthrough in output) */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQINLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* Skip passthrough data in output (bounce buffer already has it) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_SKIP | CAAM_FIFOLDST_VLF);

	/* Feed all data to Class 2 HMAC (LAST2 for finalization) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS2 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_MSG | CAAM_FIFOLD_TYPE_LAST2);

	/* Write HMAC ICV from Class 2 context */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_STORE | CAAM_LDST_CLASS_2_CCB |
	    CAAM_LDST_SRCDST_BYTE_CONTEXT | sess->icvlen);

	sess->enc_shdesc_len = caam_shdesc_len(desc);
	return (0);
}

int
caam_null_hmac_build_dec_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump;
	int error;

	error = caam_dma_alloc(dev, &sess->dec_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->dec_shdesc.vaddr;
	caam_shdesc_init(desc, CAAM_HDR_SHARE_SERIAL | CAAM_HDR_SAVECTX);

	/* Skip key loading if already shared */
	key_jump = caam_desc_add_jump(desc,
	    CAAM_JUMP_JSL | CAAM_JUMP_TEST_ALL | CAAM_JUMP_COND_SHRD);

	/* Load pre-derived HMAC split key (pointer mode, 3 words) */
	caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
	    sess->auth_key_dma.paddr);

	caam_desc_set_jump_target(desc, key_jump);

	/* Class 2 OPERATION: HMAC verify (decrypt + ICV check) */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype | CAAM_OP_ALG_AAI_HMAC_PRECOMP |
	    CAAM_OP_ALG_AS_INITFINAL | CAAM_OP_ALG_DECRYPT | CAAM_OP_ALG_ICV_ON);

	/*
	 * Data length = SEQOUTLEN (= assoclen + cryptlen, excludes ICV).
	 * SEQINLEN includes ICV; SEQOUTLEN does not.
	 */
	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQOUTLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQINLEN | CAAM_MATH_LEN_4BYTE);

	caam_desc_add_word(desc,
	    CAAM_CMD_MATH | CAAM_MATH_FUN_ADD |
	    CAAM_MATH_SRC0_SEQOUTLEN | CAAM_MATH_SRC1_REG0 |
	    CAAM_MATH_DEST_VARSEQOUTLEN | CAAM_MATH_LEN_4BYTE);

	/* Skip passthrough data in output (bounce buffer already has it) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_STORE | CAAM_FIFOST_TYPE_SKIP | CAAM_FIFOLDST_VLF);

	/* Feed data to Class 2 HMAC (no LAST2 yet — ICV follows) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS2 | CAAM_FIFOLDST_VLF |
	    CAAM_FIFOLD_TYPE_MSG);

	/* Read ICV for verification (Class 2, ICV | LAST2) */
	caam_desc_add_word(desc,
	    CAAM_CMD_SEQ_FIFO_LOAD | CAAM_FIFOLD_CLASS_CLASS2 |
	    CAAM_FIFOLD_TYPE_ICV | CAAM_FIFOLD_TYPE_LAST2 | sess->icvlen);

	sess->dec_shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * NULL+HMAC Job Descriptor
 *
 * Simpler than regular ETA — no cipher IV, no DPOVRD needed.
 * The shared descriptor uses SEQINLEN/SEQOUTLEN directly.
 * ================================================================ */

int
caam_null_hmac_build_job(struct caam_jr_softc *sc,
    struct caam_request *req, struct cryptop *crp)
{
	struct caam_session *sess;
	uint32_t *desc;
	bus_addr_t buf_pa;
	uint32_t input_len, output_len;
	bool encrypt;
	int shdesc_len;

	sess = req->sess;
	desc = req->desc.vaddr;
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);
	buf_pa = req->using_dyn ? req->dyn_bounce.paddr : req->bounce.paddr;

	shdesc_len = encrypt ? sess->enc_shdesc_len : sess->dec_shdesc_len;

	if (encrypt) {
		input_len = crp->crp_aad_length + crp->crp_payload_length;
		output_len = crp->crp_aad_length + crp->crp_payload_length +
		    sess->icvlen;
	} else {
		input_len = crp->crp_aad_length + crp->crp_payload_length +
		    sess->icvlen;
		output_len = crp->crp_aad_length + crp->crp_payload_length;
	}

	/* Build job descriptor */
	caam_desc_init(desc);

	{
		uint32_t hdr = caam_to_cpu32(desc[0]);

		hdr |= CAAM_HDR_SHARED | CAAM_HDR_SHARE_DEFER | CAAM_HDR_REVERSE;
		hdr |= (shdesc_len << CAAM_HDR_START_IDX_SHIFT);
		desc[0] = cpu_to_caam32(hdr);
	}

	/* Shared descriptor pointer */
	if (encrypt)
		caam_desc_add_ptr(desc, sess->enc_shdesc.paddr);
	else
		caam_desc_add_ptr(desc, sess->dec_shdesc.paddr);

	/* === JD body (runs FIRST with CAAM_HDR_REVERSE) === */

	/* SEQ IN PTR */
	caam_desc_add_seq_in_ptr(desc, buf_pa, input_len);

	/* SEQ OUT PTR */
	caam_desc_add_seq_out_ptr(desc, buf_pa, output_len);

	return (0);
}

/* ================================================================
 * Cipher Job Descriptor
 *
 * Layout:
 *   [0]    JD header (SHARED | SHARE_DEFER | REVERSE)
 *   [1-2]  Shared descriptor pointer (64-bit)
 *   [3..]  JD body: LOAD IV (inline), SEQ IN PTR, SEQ OUT PTR
 *
 * For XTS: IV loaded as two 8-byte halves at CONTEXT1+0x20 and 0x30.
 * For CBC/DES: IV loaded at CONTEXT1+0x00.
 * For CTR: IV (full counter block) loaded at CONTEXT1+0x00.
 * For ECB: no IV.
 * ================================================================ */

int
caam_cipher_build_job(struct caam_jr_softc *sc, struct caam_request *req,
    struct cryptop *crp)
{
	struct caam_session *sess;
	uint32_t *desc;
	bus_addr_t buf_pa;
	uint32_t cryptlen;
	bool encrypt;
	int shdesc_len;
	uint8_t iv[AES_BLOCK_LEN];

	sess = req->sess;
	desc = req->desc.vaddr;
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);
	buf_pa = req->using_dyn ? req->dyn_bounce.paddr : req->bounce.paddr;

	cryptlen = crp->crp_payload_length;
	shdesc_len = encrypt ? sess->enc_shdesc_len : sess->dec_shdesc_len;

	/* Build job descriptor */
	caam_desc_init(desc);

	{
		uint32_t hdr = caam_to_cpu32(desc[0]);

		hdr |= CAAM_HDR_SHARED | CAAM_HDR_SHARE_DEFER | CAAM_HDR_REVERSE;
		hdr |= (shdesc_len << CAAM_HDR_START_IDX_SHIFT);
		desc[0] = cpu_to_caam32(hdr);
	}

	/* Shared descriptor pointer */
	if (encrypt)
		caam_desc_add_ptr(desc, sess->enc_shdesc.paddr);
	else
		caam_desc_add_ptr(desc, sess->dec_shdesc.paddr);

	/* === JD body (runs FIRST with CAAM_HDR_REVERSE) === */

	/* Load IV if applicable */
	if (sess->ivlen > 0) {
		crypto_read_iv(crp, iv);

		if (caam_cipher_is_xts(sess)) {
			/*
			 * XTS: load 16-byte tweak as two 8-byte halves
			 * into CONTEXT1 at offsets 0x20 and 0x30.
			 */
			caam_desc_add_word(desc,
			    CAAM_CMD_LOAD | CAAM_LDST_CLASS_1_CCB | CAAM_LDST_IMM |
			    CAAM_LDST_SRCDST_BYTE_CONTEXT |
			    (0x20 << CAAM_LDST_OFFSET_SHIFT) | 8);
			caam_desc_add_key_imm(desc, iv, 8);

			caam_desc_add_word(desc,
			    CAAM_CMD_LOAD | CAAM_LDST_CLASS_1_CCB | CAAM_LDST_IMM |
			    CAAM_LDST_SRCDST_BYTE_CONTEXT |
			    (0x30 << CAAM_LDST_OFFSET_SHIFT) | 8);
			caam_desc_add_key_imm(desc, iv + 8, 8);
		} else {
			/*
			 * CBC/DES: IV at CONTEXT1+0x00.
			 * CTR: IV at CONTEXT1+0x10 (counter block).
			 */
			int ctx1_iv_off = 0;

			if ((sess->cipher_algtype & CAAM_OP_ALG_AAI_MASK) ==
			    CAAM_OP_ALG_AAI_CTR_MOD128)
				ctx1_iv_off = 16;

			caam_desc_add_word(desc,
			    CAAM_CMD_LOAD | CAAM_LDST_CLASS_1_CCB | CAAM_LDST_IMM |
			    CAAM_LDST_SRCDST_BYTE_CONTEXT |
			    (ctx1_iv_off << CAAM_LDST_OFFSET_SHIFT) |
			    sess->ivlen);
			caam_desc_add_key_imm(desc, iv, sess->ivlen);
		}
	}

	/* SEQ IN PTR: input data (cipher-only, no AAD) */
	caam_desc_add_seq_in_ptr(desc, buf_pa, cryptlen);

	/* SEQ OUT PTR: output data (same size, no ICV) */
	caam_desc_add_seq_out_ptr(desc, buf_pa, cryptlen);

	return (0);
}
