/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM hash/HMAC descriptor builders for CSP_MODE_DIGEST.
 *
 * Standalone hash (SHA, MD5) and HMAC use Class 2 (MDHA) only.
 * A single shared descriptor covers both compute and verify —
 * CAAM always computes the hash; verification (digest comparison)
 * is done in software in the completion callback.
 *
 * Bounce buffer layout:
 *   [payload data (payload_length bytes)] [digest output (icvlen bytes)]
 *   SEQ IN PTR  → buf_pa, payload_length
 *   SEQ OUT PTR → buf_pa + payload_length, icvlen
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

/* ================================================================
 * Hash/HMAC Shared Descriptor
 *
 * For plain hash:
 *   OPERATION (algtype | INITFINAL | ENCRYPT)
 *   MATH ADD (VARSEQINLEN = SEQINLEN)
 *   SEQ FIFO LOAD (CLASS2, MSG, LAST2, VLF)
 *   SEQ STORE (icvlen, CLASS_2_CCB, BYTE_CONTEXT)
 *
 * For HMAC:
 *   JUMP (skip key if shared)
 *   DKP (derive split key inline)
 *   [jump target]
 *   OPERATION (algtype | HMAC_PRECOMP | INITFINAL | ENCRYPT)
 *   MATH ADD (VARSEQINLEN = SEQINLEN)
 *   SEQ FIFO LOAD (CLASS2, MSG, LAST2, VLF)
 *   SEQ STORE (icvlen, CLASS_2_CCB, BYTE_CONTEXT)
 * ================================================================ */

int
caam_hash_build_shdesc(struct caam_session *sess, device_t dev)
{
	uint32_t *desc;
	uint32_t *key_jump;
	int error;
	bool is_hmac;

	is_hmac = (sess->alg_type == CAAM_ALG_HMAC);

	error = caam_dma_alloc(dev, &sess->enc_shdesc, CAAM_DESC_MAX_BYTES);
	if (error != 0)
		return (error);

	desc = sess->enc_shdesc.vaddr;
	caam_shdesc_init(desc, HDR_SHARE_SERIAL);

	if (is_hmac) {
		/* Skip key loading if already shared */
		key_jump = caam_desc_add_jump(desc,
		    JUMP_JSL | JUMP_TEST_ALL | JUMP_COND_SHRD);

		/* Load pre-derived HMAC split key (pointer mode, 3 words) */
		caam_desc_add_split_key_ptr(desc, sess->split_key_pad_len,
		    sess->auth_key_dma.paddr);

		caam_desc_set_jump_target(desc, key_jump);
	}

	/* OPERATION: hash/HMAC init+final, always "encrypt" (compute) */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_CLASS2_ALG |
	    sess->auth_algtype |
	    (is_hmac ? OP_ALG_AAI_HMAC_PRECOMP : 0) |
	    OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

	/*
	 * VARSEQINLEN = SEQINLEN + 0.
	 * SEQINLEN is set by the SEQ IN PTR command in the JD body
	 * (which runs first due to HDR_REVERSE).  REG0 is always zero
	 * at descriptor start.  Matches Linux cnstr_shdsc_ahash().
	 */
	caam_desc_add_word(desc,
	    CMD_MATH | MATH_FUN_ADD |
	    MATH_SRC0_SEQINLEN | MATH_SRC1_REG0 |
	    MATH_DEST_VARSEQINLEN | MATH_LEN_4BYTE);

	/* Feed all data to Class 2 (LAST2 for finalization) */
	caam_desc_add_word(desc,
	    CMD_SEQ_FIFO_LOAD | FIFOLD_CLASS_CLASS2 | FIFOLDST_VLF |
	    FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/* Store digest from Class 2 context register */
	caam_desc_add_word(desc,
	    CMD_SEQ_STORE | LDST_CLASS_2_CCB |
	    LDST_SRCDST_BYTE_CONTEXT | sess->icvlen);

	sess->enc_shdesc_len = caam_shdesc_len(desc);
	return (0);
}

/* ================================================================
 * Hash/HMAC Job Descriptor
 *
 * Layout (always-EXT, matching Linux):
 *   [0]     JD header (SHARED | SHARE_DEFER | REVERSE)
 *   [1-2]   Shared descriptor pointer (64-bit)
 *   [3]     SEQ IN PTR | EXT (payload data)
 *   [4-5]   Input DMA pointer (64-bit)
 *   [6]     Input length (extended)
 *   [7]     SEQ OUT PTR | EXT (digest output)
 *   [8-9]   Output DMA pointer (64-bit)
 *   [10]    Output length (extended)
 *
 * Total: 11 words (constant for all payload sizes).
 * ================================================================ */

int
caam_hash_build_job(struct caam_jr_softc *sc, struct caam_request *req,
    struct cryptop *crp)
{
	struct caam_session *sess;
	uint32_t *desc;
	bus_addr_t buf_pa;
	uint32_t data_len;
	int shdesc_len;

	sess = req->sess;
	desc = req->desc.vaddr;
	buf_pa = req->using_dyn ? req->dyn_bounce.paddr : req->bounce.paddr;

	data_len = crp->crp_payload_length;
	shdesc_len = sess->enc_shdesc_len;

	/* Build job descriptor */
	caam_desc_init(desc);

	{
		uint32_t hdr = caam_to_cpu32(desc[0]);

		hdr |= HDR_SHARED | HDR_SHARE_DEFER | HDR_REVERSE;
		hdr |= (shdesc_len << HDR_START_IDX_SHIFT);
		desc[0] = cpu_to_caam32(hdr);
	}

	/* Shared descriptor pointer */
	caam_desc_add_ptr(desc, sess->enc_shdesc.paddr);

	/* === JD body (runs FIRST with HDR_REVERSE) === */

	/* SEQ IN PTR: data to hash (always EXT mode) */
	caam_desc_add_seq_in_ptr(desc, buf_pa, data_len);

	/* SEQ OUT PTR: digest output (immediately after input data) */
	caam_desc_add_seq_out_ptr(desc, buf_pa + data_len, sess->icvlen);

	return (0);
}
