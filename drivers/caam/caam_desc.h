/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM descriptor command word definitions and construction helpers.
 * Field encodings from the NXP SEC v5.x descriptor format specification
 * (document SECMCRM, LS1046A variant).
 *
 * Descriptors are arrays of uint32_t words in DMA memory, accessed by
 * CAAM directly.  All words are stored in CAAM byte order (BE on LS1046A).
 * Construction helpers handle the byte-swap transparently.
 */

#ifndef _CAAM_DESC_H
#define _CAAM_DESC_H

#include "caam.h"

#define CAAM_DESC_MAX_WORDS	64	/* Max descriptor size in 32-bit words */
#define CAAM_DESC_MAX_BYTES	(CAAM_DESC_MAX_WORDS * sizeof(uint32_t))

/*
 * Descriptor Command Types (bits 31:27)
 */
#define CAAM_CMD_SHIFT		27
#define CAAM_CMD_MASK		(0x1fU << CAAM_CMD_SHIFT)

#define CAAM_CMD_KEY			(0x00U << CAAM_CMD_SHIFT)	/* KEY command */
#define CAAM_CMD_SEQ_KEY		(0x01U << CAAM_CMD_SHIFT)	/* SEQ KEY */
#define CAAM_CMD_LOAD		(0x02U << CAAM_CMD_SHIFT)	/* LOAD command */
#define CAAM_CMD_SEQ_LOAD		(0x03U << CAAM_CMD_SHIFT)
#define CAAM_CMD_FIFO_LOAD		(0x04U << CAAM_CMD_SHIFT)	/* FIFO LOAD */
#define CAAM_CMD_SEQ_FIFO_LOAD	(0x05U << CAAM_CMD_SHIFT)
#define CAAM_CMD_STORE		(0x0aU << CAAM_CMD_SHIFT)	/* STORE command */
#define CAAM_CMD_SEQ_STORE		(0x0bU << CAAM_CMD_SHIFT)
#define CAAM_CMD_FIFO_STORE		(0x0cU << CAAM_CMD_SHIFT)	/* FIFO STORE */
#define CAAM_CMD_SEQ_FIFO_STORE	(0x0dU << CAAM_CMD_SHIFT)
#define CAAM_CMD_MOVE		(0x0fU << CAAM_CMD_SHIFT)
#define CAAM_CMD_OPERATION		(0x10U << CAAM_CMD_SHIFT)	/* OPERATION command */
#define CAAM_CMD_SIGNATURE		(0x12U << CAAM_CMD_SHIFT)
#define CAAM_CMD_JUMP		(0x14U << CAAM_CMD_SHIFT)
#define CAAM_CMD_MATH		(0x15U << CAAM_CMD_SHIFT)
#define CAAM_CMD_DESC_HDR		(0x16U << CAAM_CMD_SHIFT)	/* Job Descriptor Header */
#define CAAM_CMD_SH_DESC_HDR		(0x17U << CAAM_CMD_SHIFT)	/* Shared Descriptor Hdr */
#define CAAM_CMD_SEQ_IN_PTR		(0x1eU << CAAM_CMD_SHIFT)	/* Seq Input Pointer */
#define CAAM_CMD_SEQ_OUT_PTR		(0x1fU << CAAM_CMD_SHIFT)	/* Seq Output Pointer */

/*
 * Job Descriptor Header (word 0)
 *
 * Bits 31:27 = 0x16 (CAAM_CMD_DESC_HDR)
 * Bit  23    = ONE (must be set)
 * Bits 21:16 = Start Index
 * Bit  12    = SHARED (next item is shared desc pointer)
 * Bits 11:8  = SHARE type
 * Bits  6:0  = Descriptor length in words
 */
#define CAAM_HDR_ONE			(1U << 23)
#define CAAM_HDR_START_IDX_SHIFT	16
#define CAAM_HDR_START_IDX_MASK	(0x3fU << CAAM_HDR_START_IDX_SHIFT)
#define CAAM_HDR_DESCLEN_MASK	0x0000007f
#define CAAM_HDR_JD_LENGTH_MASK	CAAM_HDR_DESCLEN_MASK
#define CAAM_HDR_SHARED		(1U << 12)	/* JD: shared desc ptr follows */
#define CAAM_HDR_SAVECTX		CAAM_HDR_SHARED	/* SH_DESC: save context */
#define CAAM_HDR_REVERSE		(1U << 11)

/*
 * SHR (Sharing domain) field — bits 10:8 (JD) / 9:8 (shared desc).
 * Controls how the DECO caches the shared descriptor across invocations.
 * Share field starts at bit 8 per SEC descriptor format spec.
 */
#define CAAM_HDR_SHARE_SHIFT		8
#define CAAM_HDR_SHARE_MASK		(0x07U << CAAM_HDR_SHARE_SHIFT)
#define CAAM_HDR_SHARE_NEVER		(0x00U << CAAM_HDR_SHARE_SHIFT)
#define CAAM_HDR_SHARE_WAIT		(0x01U << CAAM_HDR_SHARE_SHIFT)
#define CAAM_HDR_SHARE_SERIAL	(0x02U << CAAM_HDR_SHARE_SHIFT)
#define CAAM_HDR_SHARE_ALWAYS	(0x03U << CAAM_HDR_SHARE_SHIFT)
#define CAAM_HDR_SHARE_DEFER		(0x04U << CAAM_HDR_SHARE_SHIFT)

/* Shared Descriptor Header */
#define CAAM_SHR_HDR_DESCLEN_MASK	0x0000003f
#define CAAM_SHR_HDR_START_IDX_SHIFT	16

/*
 * KEY Command (bits 31:27 = 0x00)
 *
 * Bit  26    = SGF
 * Bits 25:24 = CLASS (00=none, 01=class1, 10=class2, 11=both)
 * Bit  23    = IMM (key inline in descriptor)
 * Bit  22    = ENC (encrypted key)
 * Bits 21:20 = TK (key encryption type: 00=ECB, 01=TKEK, 10=KDKEK, 11=TDKEK)
 * Bits 17:16 = KDEST (00=class reg, 01=PKHA_E, 10=AFHA_SBOX, 11=MDHA split)
 * Bits 9:0   = Key length
 */
#define CAAM_KEY_CLASS_SHIFT		25
#define CAAM_KEY_CLASS1		(0x01U << CAAM_KEY_CLASS_SHIFT) /* 0x02000000 */
#define CAAM_KEY_CLASS2		(0x02U << CAAM_KEY_CLASS_SHIFT) /* 0x04000000 */
#define CAAM_KEY_IMM			(1U << 23)
#define CAAM_KEY_ENC			(1U << 22)
#define CAAM_KEY_DEST_SHIFT		16
#define CAAM_KEY_DEST_CLASS_REG	(0x00U << CAAM_KEY_DEST_SHIFT) /* Class key register */
#define CAAM_KEY_DEST_PKHA_E		(0x01U << CAAM_KEY_DEST_SHIFT) /* PKHA E register */
#define CAAM_KEY_DEST_AFHA_SBOX	(0x02U << CAAM_KEY_DEST_SHIFT) /* AFHA S-box */
#define CAAM_KEY_DEST_MDHA_SPLIT	(0x03U << CAAM_KEY_DEST_SHIFT) /* MDHA split key */
#define CAAM_KEY_LENGTH_MASK		0x000003ff

/*
 * LOAD / SEQ LOAD / STORE / SEQ STORE commands
 *
 * Bits 26:25 = CLASS (00=ind CCB, 01=class1, 10=class2, 11=DECO)
 * Bit  23    = IMM (immediate data follows)
 * Bits 22:16 = SRCDST (source or destination register)
 * Bits 15:8  = OFFSET (byte offset within register)
 * Bits  7:0  = LENGTH (byte count)
 */
#define CAAM_LDST_CLASS_SHIFT	25
#define CAAM_LDST_CLASS_IND_CCB	(0x00U << CAAM_LDST_CLASS_SHIFT)
#define CAAM_LDST_CLASS_1_CCB	(0x01U << CAAM_LDST_CLASS_SHIFT)
#define CAAM_LDST_CLASS_2_CCB	(0x02U << CAAM_LDST_CLASS_SHIFT)
#define CAAM_LDST_CLASS_DECO		(0x03U << CAAM_LDST_CLASS_SHIFT)

#define CAAM_LDST_IMM		(1U << 23)

#define CAAM_LDST_SRCDST_SHIFT	16
#define CAAM_LDST_SRCDST_BYTE_CONTEXT  (0x20U << CAAM_LDST_SRCDST_SHIFT) /* Context reg */
#define CAAM_LDST_SRCDST_BYTE_KEY	  (0x40U << CAAM_LDST_SRCDST_SHIFT) /* Key reg */

/* DECO register destinations (used with CAAM_LDST_CLASS_DECO) */
#define CAAM_LDST_SRCDST_WORD_CLRW	       (0x08U << CAAM_LDST_SRCDST_SHIFT)
#define CAAM_LDST_SRCDST_WORD_DECO_MATH0   (0x08U << CAAM_LDST_SRCDST_SHIFT)
#define CAAM_LDST_SRCDST_WORD_DECO_MATH1   (0x09U << CAAM_LDST_SRCDST_SHIFT)
#define CAAM_LDST_SRCDST_WORD_DECO_MATH2   (0x0aU << CAAM_LDST_SRCDST_SHIFT)
#define CAAM_LDST_SRCDST_WORD_DECO_MATH3   (0x0bU << CAAM_LDST_SRCDST_SHIFT)
#define CAAM_LDST_SRCDST_WORD_DECO_AAD_SZ  CAAM_LDST_SRCDST_WORD_DECO_MATH3

#define CAAM_LDST_OFFSET_SHIFT	8
#define CAAM_LDST_OFFSET_MASK	(0xffU << CAAM_LDST_OFFSET_SHIFT)

#define CAAM_LDST_LEN_SHIFT		0
#define CAAM_LDST_LEN_MASK		0x000000ff

/*
 * OPERATION Command (bits 31:27 = 0x10)
 */
#define CAAM_OP_TYPE_SHIFT		24
#define CAAM_OP_TYPE_MASK		(0x07U << CAAM_OP_TYPE_SHIFT)
#define CAAM_OP_TYPE_CLASS1		(0x02U << CAAM_OP_TYPE_SHIFT)
#define CAAM_OP_TYPE_CLASS2		(0x04U << CAAM_OP_TYPE_SHIFT)
#define CAAM_OP_TYPE_UNI_PROTOCOL	(0x00U << CAAM_OP_TYPE_SHIFT)
#define CAAM_OP_TYPE_CLASS1_ALG	CAAM_OP_TYPE_CLASS1
#define CAAM_OP_TYPE_CLASS2_ALG	CAAM_OP_TYPE_CLASS2

/* Algorithm selectors (bits 23:16) */
#define CAAM_OP_ALG_ALGSEL_SHIFT	16
#define CAAM_OP_ALG_ALGSEL_MASK	(0xffU << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_SUBMASK	(0x0fU << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_AES	(0x10U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_DES	(0x20U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_3DES	(0x21U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_MD5	(0x40U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_SHA1	(0x41U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_SHA224	(0x42U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_SHA256	(0x43U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_SHA384	(0x44U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_SHA512	(0x45U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_RNG	(0x50U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_CHACHA20	(0xd0U << CAAM_OP_ALG_ALGSEL_SHIFT)
#define CAAM_OP_ALG_ALGSEL_POLY1305	(0xe0U << CAAM_OP_ALG_ALGSEL_SHIFT)

/* Additional Algorithm Info (AAI) — bits 12:4 */
#define CAAM_OP_ALG_AAI_SHIFT	4
#define CAAM_OP_ALG_AAI_MASK		(0x1ffU << CAAM_OP_ALG_AAI_SHIFT)

/* AES modes */
#define CAAM_OP_ALG_AAI_CTR_MOD128	(0x00U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_CBC		(0x10U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_ECB		(0x20U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_CFB		(0x30U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_OFB		(0x40U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_XTS		(0x50U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_CMAC		(0x60U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_CCM		(0x80U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_GCM		(0x90U << CAAM_OP_ALG_AAI_SHIFT)

/* Hash modes */
#define CAAM_OP_ALG_AAI_HASH		(0x00U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_HMAC		(0x01U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_SMAC		(0x02U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_HMAC_PRECOMP	(0x04U << CAAM_OP_ALG_AAI_SHIFT)

/* Decrypt key derivation */
#define CAAM_OP_ALG_AAI_DK		(0x100U << CAAM_OP_ALG_AAI_SHIFT)

/* RNG modes */
#define CAAM_OP_ALG_AAI_RNG		(0x00U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_RNG4_SH_0	(0x00U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_RNG4_SH_1	(0x01U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_RNG4_PS	(0x40U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_RNG4_AI	(0x80U << CAAM_OP_ALG_AAI_SHIFT)
#define CAAM_OP_ALG_AAI_RNG4_SK	(0x100U << CAAM_OP_ALG_AAI_SHIFT)

/*
 * Derived Key Protocol (DKP) — protocol info for CAAM_OP_TYPE_UNI_PROTOCOL.
 * Used on ERA >= 6 to compute HMAC split keys inline in the descriptor.
 */
#define OP_PCL_DKP_SRC_IMM	(0U << 14)	/* Source key inline */
#define OP_PCL_DKP_SRC_PTR	(1U << 14)	/* Source key via DMA pointer */
#define OP_PCL_DKP_DST_IMM	(0U << 12)	/* Derived key inline */
#define OP_PCL_DKP_DST_PTR	(1U << 12)	/* Derived key via DMA pointer */

/* Algorithm State (bits 3:2) */
#define CAAM_OP_ALG_AS_SHIFT		2
#define CAAM_OP_ALG_AS_MASK		(0x03U << CAAM_OP_ALG_AS_SHIFT)
#define CAAM_OP_ALG_AS_UPDATE	(0x00U << CAAM_OP_ALG_AS_SHIFT)
#define CAAM_OP_ALG_AS_INIT		(0x01U << CAAM_OP_ALG_AS_SHIFT)
#define CAAM_OP_ALG_AS_FINALIZE	(0x02U << CAAM_OP_ALG_AS_SHIFT)
#define CAAM_OP_ALG_AS_INITFINAL	(0x03U << CAAM_OP_ALG_AS_SHIFT)

/* ICV check / Prediction Resistance (bit 1 — context-dependent) */
#define CAAM_OP_ALG_ICV_OFF		(0U << 1)
#define CAAM_OP_ALG_ICV_ON		(1U << 1)
#define CAAM_OP_ALG_PR_ON		(1U << 1)	/* RNG: prediction resistance */

/* Direction (bit 0) */
#define CAAM_OP_ALG_DECRYPT		0
#define CAAM_OP_ALG_ENCRYPT		1

/*
 * SEQ IN PTR / SEQ OUT PTR Commands
 */
#define SQIN_RBS		(1U << 26)
#define SQIN_INL		(1U << 25)
#define SQIN_SGF		(1U << 24)
#define SQIN_PRE		(1U << 23)
#define SQIN_EXT		(1U << 22)
#define SQIN_RTO		(1U << 21)
#define SQIN_LEN_MASK		0x0000ffff

#define SQOUT_SGF		(1U << 24)
#define SQOUT_PRE		(1U << 23)
#define SQOUT_EXT		(1U << 22)
#define SQOUT_LEN_MASK		0x0000ffff

/*
 * FIFO LOAD / SEQ FIFO LOAD commands
 *
 * Bits 26:25 = CLASS (00=skip, 01=class1, 10=class2, 11=both)
 * Bit  24    = SGF/VLF (variable length flag for SEQ FIFO)
 * Bit  23    = IMM (immediate data follows)
 * Bit  22    = EXT (extended length in next word)
 * Bits 21:16 = TYPE (data type + action bits)
 * Bits 15:0  = LENGTH
 *
 * TYPE field (6 bits, split into data type [21:19] and action [18:16]):
 *   Data types: MSG=010, IV=100, AAD=110, ICV=111
 *   Actions:    FLUSH1=001, LAST1=010, LAST2=100, etc.
 */
#define CAAM_FIFOLD_CLASS_SHIFT	25
#define CAAM_FIFOLD_CLASS_SKIP	(0x00U << CAAM_FIFOLD_CLASS_SHIFT)
#define CAAM_FIFOLD_CLASS_CLASS1	(0x01U << CAAM_FIFOLD_CLASS_SHIFT)
#define CAAM_FIFOLD_CLASS_CLASS2	(0x02U << CAAM_FIFOLD_CLASS_SHIFT)
#define CAAM_FIFOLD_CLASS_BOTH	(0x03U << CAAM_FIFOLD_CLASS_SHIFT)

#define CAAM_FIFOLDST_VLF		(1U << 24)	/* Variable length (SEQ FIFO) */
#define CAAM_FIFOLDST_SGF		CAAM_FIFOLDST_VLF	/* Alias */
#define CAAM_FIFOLD_IMM		(1U << 23)
#define CAAM_FIFOLDST_EXT		(1U << 22)

#define CAAM_FIFOLD_TYPE_SHIFT	16
#define CAAM_FIFOLD_TYPE_MASK	(0x3fU << CAAM_FIFOLD_TYPE_SHIFT)

/* Data types (upper 3 bits of TYPE) */
#define CAAM_FIFOLD_TYPE_MSG		(0x10U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_MSG1OUT2	(0x18U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_IV		(0x20U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_BITDATA	(0x28U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_AAD		(0x30U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_ICV		(0x38U << CAAM_FIFOLD_TYPE_SHIFT)

/* Action bits (lower 3 bits of TYPE, OR'd with data type) */
#define CAAM_FIFOLD_TYPE_NOACTION	(0x00U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_FLUSH1	(0x01U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_LAST1	(0x02U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_LAST2FLUSH	(0x03U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_LAST2	(0x04U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_LAST2FLUSH1	(0x05U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_LASTBOTH	(0x06U << CAAM_FIFOLD_TYPE_SHIFT)
#define CAAM_FIFOLD_TYPE_LASTBOTHFL	(0x07U << CAAM_FIFOLD_TYPE_SHIFT)

#define CAAM_FIFOLDST_LEN_MASK	0x0000ffff

/*
 * FIFO STORE / SEQ FIFO STORE commands
 *
 * Bits 26:25 = CLASS (00=normal, 01=class1key, 10=class2key)
 * Bit  24    = SGF/VLF
 * Bit  22    = EXT
 * Bits 21:16 = TYPE
 * Bits 15:0  = LENGTH
 */
#define CAAM_FIFOST_CLASS_SHIFT	25
#define CAAM_FIFOST_CLASS_NORMAL	(0x00U << CAAM_FIFOST_CLASS_SHIFT)
#define CAAM_FIFOST_CLASS_CLASS1KEY	(0x01U << CAAM_FIFOST_CLASS_SHIFT)
#define CAAM_FIFOST_CLASS_CLASS2KEY	(0x02U << CAAM_FIFOST_CLASS_SHIFT)

#define CAAM_FIFOST_TYPE_SHIFT	16
#define CAAM_FIFOST_TYPE_MASK	(0x3fU << CAAM_FIFOST_TYPE_SHIFT)
#define CAAM_FIFOST_TYPE_MESSAGE_DATA (0x30U << CAAM_FIFOST_TYPE_SHIFT)
#define CAAM_FIFOST_TYPE_RNGSTORE	(0x34U << CAAM_FIFOST_TYPE_SHIFT)
#define CAAM_FIFOST_TYPE_RNGFIFO	(0x35U << CAAM_FIFOST_TYPE_SHIFT)
#define CAAM_FIFOST_TYPE_SPLIT_KEK	(0x26U << CAAM_FIFOST_TYPE_SHIFT)
#define CAAM_FIFOST_TYPE_SKIP	(0x3fU << CAAM_FIFOST_TYPE_SHIFT)

/*
 * JUMP Command
 *
 * Bits 26:25 = CLASS
 * Bit  24    = JSL (jump save link — used for condition codes)
 * Bits 23:22 = TYPE (00=local, 01=nonlocal, 10=halt, 11=halt_user)
 * Bits 17:16 = TEST (00=all, 01=invall, 10=any, 11=invany)
 * Bits 15:8  = COND (condition flags)
 * Bits  7:0  = OFFSET (signed)
 */
#define CAAM_JUMP_CLASS_SHIFT	25
#define CAAM_JUMP_CLASS_NONE		0
#define CAAM_JUMP_CLASS_CLASS1	(1U << CAAM_JUMP_CLASS_SHIFT)
#define CAAM_JUMP_CLASS_CLASS2	(2U << CAAM_JUMP_CLASS_SHIFT)
#define CAAM_JUMP_CLASS_BOTH		(3U << CAAM_JUMP_CLASS_SHIFT)

#define CAAM_JUMP_JSL		(1U << 24)

#define CAAM_JUMP_TYPE_SHIFT		22
#define CAAM_JUMP_TYPE_LOCAL		(0x00U << CAAM_JUMP_TYPE_SHIFT)
#define CAAM_JUMP_TYPE_NONLOCAL	(0x01U << CAAM_JUMP_TYPE_SHIFT)
#define CAAM_JUMP_TYPE_HALT		(0x02U << CAAM_JUMP_TYPE_SHIFT)
#define CAAM_JUMP_TYPE_HALT_USER	(0x03U << CAAM_JUMP_TYPE_SHIFT)

#define CAAM_JUMP_TEST_SHIFT		16
#define CAAM_JUMP_TEST_ALL		(0x00U << CAAM_JUMP_TEST_SHIFT)
#define CAAM_JUMP_TEST_INVALL	(0x01U << CAAM_JUMP_TEST_SHIFT)
#define CAAM_JUMP_TEST_ANY		(0x02U << CAAM_JUMP_TEST_SHIFT)
#define CAAM_JUMP_TEST_INVANY	(0x03U << CAAM_JUMP_TEST_SHIFT)

/* Condition codes (bits 15:8) — plain conditions (without JSL) */
#define CAAM_JUMP_COND_SHIFT		8
#define CAAM_JUMP_COND_MATH_N	(0x08U << CAAM_JUMP_COND_SHIFT)
#define CAAM_JUMP_COND_MATH_Z	(0x04U << CAAM_JUMP_COND_SHIFT)
#define CAAM_JUMP_COND_MATH_C	(0x02U << CAAM_JUMP_COND_SHIFT)
#define CAAM_JUMP_COND_MATH_NV	(0x01U << CAAM_JUMP_COND_SHIFT)

/* Condition codes that include JSL (per SEC descriptor format spec) */
#define CAAM_JUMP_COND_JRP		((0x80U << CAAM_JUMP_COND_SHIFT) | CAAM_JUMP_JSL)
#define CAAM_JUMP_COND_SHRD		((0x40U << CAAM_JUMP_COND_SHIFT) | CAAM_JUMP_JSL)
#define CAAM_JUMP_COND_SELF		((0x20U << CAAM_JUMP_COND_SHIFT) | CAAM_JUMP_JSL)
#define CAAM_JUMP_COND_CALM		((0x10U << CAAM_JUMP_COND_SHIFT) | CAAM_JUMP_JSL)
#define CAAM_JUMP_COND_NIP		((0x08U << CAAM_JUMP_COND_SHIFT) | CAAM_JUMP_JSL)
#define CAAM_JUMP_COND_NIFP		((0x04U << CAAM_JUMP_COND_SHIFT) | CAAM_JUMP_JSL)
#define CAAM_JUMP_COND_NOP		((0x02U << CAAM_JUMP_COND_SHIFT) | CAAM_JUMP_JSL)
#define CAAM_JUMP_COND_NCP		((0x01U << CAAM_JUMP_COND_SHIFT) | CAAM_JUMP_JSL)

#define CAAM_JUMP_OFFSET_SHIFT	0
#define CAAM_JUMP_OFFSET_MASK	0x000000ff

/*
 * MATH Command
 *
 * Bits 26    = IFB (immediate four bytes)
 * Bit  25    = NFU
 * Bit  24    = STL (store result to MATH register)
 * Bits 23:20 = FUN (function: add, sub, or, and, xor, etc.)
 * Bits 19:16 = SRC0
 * Bits 15:12 = SRC1
 * Bits 11:8  = DEST
 * Bits  3:0  = LEN (1, 2, 4, or 8 bytes)
 */
#define CAAM_MATH_IFB		(1U << 26)

#define CAAM_MATH_FUN_SHIFT		20
#define CAAM_MATH_FUN_ADD		(0x00U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_ADDC		(0x01U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_SUB		(0x02U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_SUBB		(0x03U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_OR		(0x04U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_AND		(0x05U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_XOR		(0x06U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_LSHIFT		(0x07U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_RSHIFT		(0x08U << CAAM_MATH_FUN_SHIFT)
#define CAAM_MATH_FUN_ZBYT		(0x0aU << CAAM_MATH_FUN_SHIFT)

#define CAAM_MATH_SRC0_SHIFT		16
#define CAAM_MATH_SRC0_REG0		(0x00U << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_REG1		(0x01U << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_REG2		(0x02U << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_REG3		(0x03U << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_IMM		(0x04U << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_DPOVRD	(0x07U << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_SEQINLEN	(0x08U << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_SEQOUTLEN	(0x09U << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_VARSEQINLEN	(0x0aU << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_VARSEQOUTLEN	(0x0bU << CAAM_MATH_SRC0_SHIFT)
#define CAAM_MATH_SRC0_ZERO		(0x0cU << CAAM_MATH_SRC0_SHIFT)

#define CAAM_MATH_SRC1_SHIFT		12
#define CAAM_MATH_SRC1_REG0		(0x00U << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_REG1		(0x01U << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_REG2		(0x02U << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_REG3		(0x03U << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_IMM		(0x04U << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_DPOVRD	(0x07U << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_INFIFO	(0x0aU << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_OUTFIFO	(0x0bU << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_ONE		(0x0cU << CAAM_MATH_SRC1_SHIFT)
#define CAAM_MATH_SRC1_ZERO		(0x0fU << CAAM_MATH_SRC1_SHIFT)

#define CAAM_MATH_DEST_SHIFT		8
#define CAAM_MATH_DEST_REG0		(0x00U << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_REG1		(0x01U << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_REG2		(0x02U << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_REG3		(0x03U << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_DPOVRD	(0x07U << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_SEQINLEN	(0x08U << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_SEQOUTLEN	(0x09U << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_VARSEQINLEN	(0x0aU << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_VARSEQOUTLEN	(0x0bU << CAAM_MATH_DEST_SHIFT)
#define CAAM_MATH_DEST_NONE		(0x0fU << CAAM_MATH_DEST_SHIFT)

#define CAAM_MATH_LEN_SHIFT		0
#define CAAM_MATH_LEN_1BYTE		0x01
#define CAAM_MATH_LEN_2BYTE		0x02
#define CAAM_MATH_LEN_4BYTE		0x04
#define CAAM_MATH_LEN_8BYTE		0x08

/*
 * MOVE Command
 */
#define CAAM_MOVE_SRC_SHIFT		20
#define CAAM_MOVE_SRC_CLASS1CTX	(0x04U << CAAM_MOVE_SRC_SHIFT)
#define CAAM_MOVE_SRC_CLASS2CTX	(0x05U << CAAM_MOVE_SRC_SHIFT)
#define CAAM_MOVE_SRC_OUTFIFO	(0x06U << CAAM_MOVE_SRC_SHIFT)

#define CAAM_MOVE_DEST_SHIFT		16
#define CAAM_MOVE_DEST_CLASS1CTX	(0x04U << CAAM_MOVE_DEST_SHIFT)
#define CAAM_MOVE_DEST_CLASS2CTX	(0x05U << CAAM_MOVE_DEST_SHIFT)
#define CAAM_MOVE_DEST_CLASS2INFIFO	(0x07U << CAAM_MOVE_DEST_SHIFT)

#define CAAM_MOVE_OFFSET_SHIFT	8
#define CAAM_MOVE_LEN_SHIFT		0

/*
 * SEC4 Scatter-Gather Table Entry
 *
 * Used when data spans multiple non-contiguous DMA buffers.
 * Fields in CAAM byte order.
 */
struct sec4_sg_entry {
	uint64_t	ptr;		/* DMA address of buffer */
	uint32_t	len;		/* Buffer length + flags */
#define SEC4_SG_OFFSET_MASK	0x00001fff
#define SEC4_SG_LEN_MASK	0x3fffffff
#define SEC4_SG_LEN_FIN	0x40000000	/* Final entry */
#define SEC4_SG_LEN_EXT	0x80000000	/* Extension (points to more SG) */
	uint32_t	bpid_offset;	/* Buffer Pool ID + offset */
} __packed;

/*
 * CCB error codes from job status (when SSRC=CCB_ERROR).
 * Lower 16 bits: bits 15:8 = index, bits 7:4 = CHA ID, bits 3:0 = error ID.
 */
#define CCB_ERRID_MASK		0x0f	/* Error ID in bits 3:0 */
#define CCB_ERR_ICV_CHECK	0x0a	/* ICV verification failed */

/* ================================================================
 * Descriptor construction helpers.
 *
 * All words are stored in CAAM byte order (BE on LS1046A ARM64).
 * The helpers handle conversion transparently — callers pass native
 * CPU-endian values and addresses.
 * ================================================================ */

/* Get descriptor length in words (reads header from CAAM byte order) */
static __inline int
caam_desc_len(const uint32_t *desc)
{

	return (caam_to_cpu32(desc[0]) & CAAM_HDR_DESCLEN_MASK);
}

/* Get shared descriptor length in words */
static __inline int
caam_shdesc_len(const uint32_t *desc)
{

	return (caam_to_cpu32(desc[0]) & CAAM_SHR_HDR_DESCLEN_MASK);
}

/*
 * Initialize a job descriptor header.
 * Sets CAAM_CMD_DESC_HDR + CAAM_HDR_ONE + length=1 (the header word itself).
 */
static __inline void
caam_desc_init(uint32_t *desc)
{

	desc[0] = cpu_to_caam32(CAAM_CMD_DESC_HDR | CAAM_HDR_ONE | 1);
}

/*
 * Initialize a shared descriptor header.
 * Sets CAAM_CMD_SH_DESC_HDR + CAAM_HDR_ONE + options + length=1.
 */
static __inline void
caam_shdesc_init(uint32_t *desc, uint32_t options)
{

	/*
	 * Shared descriptor header: CAAM_CMD_SH_DESC_HDR + CAAM_HDR_ONE + options + 1.
	 * CAAM_HDR_ONE (bit 23) is set in both JD and SD headers per the SEC
	 * reference manual; always ORed into descriptor headers.
	 */
	desc[0] = cpu_to_caam32(CAAM_CMD_SH_DESC_HDR | CAAM_HDR_ONE | options | 1);
}

/* Append a command/data word to the descriptor (with byte-swap) */
static __inline void
caam_desc_add_word(uint32_t *desc, uint32_t word)
{
	uint32_t hdr;
	int len;

	hdr = caam_to_cpu32(desc[0]);
	len = hdr & CAAM_HDR_DESCLEN_MASK;
	KASSERT(len < CAAM_DESC_MAX_WORDS,
	    ("caam_desc_add_word: descriptor overflow (%d words)", len));
	desc[len] = cpu_to_caam32(word);
	desc[0] = cpu_to_caam32((hdr & ~CAAM_HDR_DESCLEN_MASK) | (len + 1));
}

/*
 * Append a raw 32-bit value without byte-swap.
 * Used for inline key material that is already in CAAM byte order.
 */
static __inline void
caam_desc_add_raw(uint32_t *desc, uint32_t raw)
{
	uint32_t hdr;
	int len;

	hdr = caam_to_cpu32(desc[0]);
	len = hdr & CAAM_HDR_DESCLEN_MASK;
	KASSERT(len < CAAM_DESC_MAX_WORDS,
	    ("caam_desc_add_raw: descriptor overflow (%d words)", len));
	desc[len] = raw;
	desc[0] = cpu_to_caam32((hdr & ~CAAM_HDR_DESCLEN_MASK) | (len + 1));
}

/*
 * Append a 64-bit pointer (as two 32-bit words).
 * Word order follows CAAM endianness:
 *   BE: high 32 first, low 32 second
 *   LE: low 32 first, high 32 second
 */
static __inline void
caam_desc_add_ptr(uint32_t *desc, uint64_t ptr)
{
	uint32_t hdr;
	int len;

	hdr = caam_to_cpu32(desc[0]);
	len = hdr & CAAM_HDR_DESCLEN_MASK;
	KASSERT(len + 1 < CAAM_DESC_MAX_WORDS,
	    ("caam_desc_add_ptr: descriptor overflow (%d words)", len));
	if (caam_big_endian) {
		desc[len]     = htobe32((uint32_t)(ptr >> 32));
		desc[len + 1] = htobe32((uint32_t)ptr);
	} else {
		desc[len]     = (uint32_t)ptr;
		desc[len + 1] = (uint32_t)(ptr >> 32);
	}
	desc[0] = cpu_to_caam32((hdr & ~CAAM_HDR_DESCLEN_MASK) | (len + 2));
}

/*
 * Return a pointer to the current append position and advance length.
 * Used for jump target patching: save the position, then later
 * set the offset to reach the target.
 */
static __inline uint32_t *
caam_desc_add_jump(uint32_t *desc, uint32_t options)
{
	uint32_t hdr;
	int len;
	uint32_t *jump_word;

	hdr = caam_to_cpu32(desc[0]);
	len = hdr & CAAM_HDR_DESCLEN_MASK;
	jump_word = &desc[len];
	desc[len] = cpu_to_caam32(CAAM_CMD_JUMP | options);
	desc[0] = cpu_to_caam32((hdr & ~CAAM_HDR_DESCLEN_MASK) | (len + 1));
	return (jump_word);
}

/*
 * Patch a JUMP command's offset to jump to the current descriptor end.
 * jump_cmd: pointer returned by caam_desc_add_jump()
 */
static __inline void
caam_desc_set_jump_target(uint32_t *desc, uint32_t *jump_cmd)
{
	int jump_idx, cur_len;
	uint32_t jcmd;

	/* Index of the jump command within the descriptor */
	jump_idx = jump_cmd - desc;
	cur_len = caam_desc_len(desc);
	/* Offset is relative: how many words to skip from the jump command */
	jcmd = caam_to_cpu32(*jump_cmd);
	jcmd = (jcmd & ~CAAM_JUMP_OFFSET_MASK) | (cur_len - jump_idx);
	*jump_cmd = cpu_to_caam32(jcmd);
}

/*
 * Append inline byte data (key, IV, etc.) to the descriptor.
 *
 * Data bytes are copied verbatim into the descriptor buffer without
 * byte-swapping.  CAAM reads the inline data as raw bytes from the
 * descriptor in DMA memory, regardless of register endianness.
 * Uses memcpy to append raw bytes into the descriptor buffer.
 *
 * key_len is rounded up to 4 for word alignment; callers must ensure
 * the key command's length field reflects the actual byte count.
 */
static __inline void
caam_desc_add_key_imm(uint32_t *desc, const uint8_t *key, int key_len)
{
	int nwords = (key_len + 3) / 4;
	uint32_t w;
	int i;

	for (i = 0; i < nwords; i++) {
		memcpy(&w, key + i * 4, sizeof(w));
		caam_desc_add_raw(desc, w);
	}
}

/*
 * Append a Derived Key Protocol (DKP) OPERATION for HMAC split key.
 * Used on ERA >= 6 instead of KEY + CAAM_KEY_ENC for split key loading.
 *
 * The DKP computes the HMAC split key from the raw HMAC key at DECO
 * runtime and loads it into the Class 2 key register.  This replaces
 * the pre-computed split key + CAAM_KEY_DEST_MDHA_SPLIT approach used on
 * earlier ERAs.
 *
 * algtype:      algorithm selector (e.g. CAAM_OP_ALG_ALGSEL_SHA256)
 * key:          raw HMAC key bytes
 * keylen:       raw HMAC key length in bytes
 * split_key_len: split key length = 2 * MDHA_pad (determines DECO IP
 *               advancement and inline reservation).  Must be the
 *               UNPADDED split_key_len, NOT split_key_pad_len.
 *               KEY length field = unpadded split_key_len per SEC RM.
 *
 * When keylen > split_key_len, inline source would cause the DECO to
 * skip fewer words than the key occupies, executing key data as
 * instructions.  In that case we MUST NOT inline both.  This
 * implementation rejects keylen > split_key_len; callers must limit
 * auth_klen in probesession.  (SRC_PTR mode with a DMA pointer
 * could be used for large keys but is not implemented here.)
 */
static __inline void
caam_desc_add_proto_dkp(uint32_t *desc, uint32_t algtype,
    const uint8_t *key, int keylen, int split_key_len)
{
	uint32_t protid, hdr;
	int words, len;

	/*
	 * Translate CAAM_OP_ALG_ALGSEL_SHA* to OP_PCLID_DKP_SHA*.
	 * DKP protocol IDs are 0x2n where n = low nibble of ALGSEL.
	 */
	protid = (algtype & CAAM_OP_ALG_ALGSEL_SUBMASK) |
	    (0x20U << CAAM_OP_ALG_ALGSEL_SHIFT);

	KASSERT(keylen <= split_key_len,
	    ("caam DKP: keylen %d > split_key_len %d, need SRC_PTR mode",
	    keylen, split_key_len));

	/* OPERATION: DKP with inline source and inline destination */
	caam_desc_add_word(desc,
	    CAAM_CMD_OPERATION | CAAM_OP_TYPE_UNI_PROTOCOL | protid |
	    OP_PCL_DKP_SRC_IMM | OP_PCL_DKP_DST_IMM | keylen);

	/* Append raw key inline */
	caam_desc_add_key_imm(desc, key, keylen);

	/*
	 * Reserve space for derived key output.
	 * DKP writes split_key_len bytes starting at the inline key
	 * position and advances the DECO IP past ALIGN(split_key_len, 4)
	 * words.  If split_key_len > keylen, we need extra words so the
	 * next instruction aligns with where the DECO lands.
	 */
	words = (roundup2(split_key_len, 4) - roundup2(keylen, 4)) / 4;
	if (words > 0) {
		hdr = caam_to_cpu32(desc[0]);
		len = hdr & CAAM_HDR_DESCLEN_MASK;
		desc[0] = cpu_to_caam32((hdr & ~CAAM_HDR_DESCLEN_MASK) |
		    (len + words));
	}
}

/*
 * Load a pre-computed HMAC split key via pointer mode.
 *
 * Uses KEY CLASS2 with MDHA_SPLIT destination and ENC flag, which
 * tells the DECO that the data is the pre-derived ipad||opad split
 * key (not a raw key requiring HMAC key schedule processing).
 *
 * Total: 3 words (1 KEY cmd + 2 pointer), same space savings as
 * DKP pointer mode but using well-tested KEY command primitives.
 *
 * split_key_pad_len: padded split key length (bytes, multiple of 16)
 * key_pa:            DMA address of pre-derived split key buffer
 */
static __inline void
caam_desc_add_split_key_ptr(uint32_t *desc, int split_key_pad_len,
    bus_addr_t key_pa)
{

	caam_desc_add_word(desc,
	    CAAM_CMD_KEY | CAAM_KEY_CLASS2 | CAAM_KEY_DEST_MDHA_SPLIT | CAAM_KEY_ENC |
	    split_key_pad_len);
	caam_desc_add_ptr(desc, key_pa);
}

/*
 * Append a SEQ IN PTR command.  Always uses EXT mode (extended 32-bit
 * length in a separate word after the pointer).
 *
 * EXT mode is always used for SEQ IN/OUT PTR on 64-bit platforms — the
 * the extlen variant unconditionally.  We match this behavior to ensure
 * the JD body word count is constant regardless of data size, which
 * avoids DECO descriptor caching issues when the same shared descriptor
 * is used with varying payload sizes.
 *
 * Format: [CMD | EXT | options] [ptr_hi] [ptr_lo] [ext_length]
 */
static __inline void
caam_desc_add_seq_in_ptr(uint32_t *desc, bus_addr_t pa, uint32_t len)
{

	caam_desc_add_word(desc, CAAM_CMD_SEQ_IN_PTR | SQIN_EXT);
	caam_desc_add_ptr(desc, pa);
	caam_desc_add_word(desc, len);
}

/*
 * Append a SEQ OUT PTR command.  Always uses EXT mode to match
 * SEQ IN PTR and keep JD body size constant.
 */
static __inline void
caam_desc_add_seq_out_ptr(uint32_t *desc, bus_addr_t pa, uint32_t len)
{

	caam_desc_add_word(desc, CAAM_CMD_SEQ_OUT_PTR | SQOUT_EXT);
	caam_desc_add_ptr(desc, pa);
	caam_desc_add_word(desc, len);
}

/*
 * QI Preheader Constants
 *
 * Two 32-bit words placed before the shared descriptor in DMA memory.
 * FQ Context-A points to prehdr[0].  CAAM QI uses these to configure
 * shared descriptor execution for compound frame processing.
 */
#define PREHDR_RSLS		(1U << 31)	/* Route SEQ LOAD/STORE to FD */
#define PREHDR_ABS		(1U << 25)	/* Absolute addressing mode */

/*
 * Build a minimal NOP Job Descriptor (for testing ring operation).
 * Header + JUMP HALT — the DECO halts immediately with status 0.
 */
static __inline void
caam_desc_build_nop(uint32_t *desc)
{

	caam_desc_init(desc);
	caam_desc_add_word(desc, CAAM_CMD_JUMP | CAAM_JUMP_TYPE_HALT);
}

#endif /* _CAAM_DESC_H */
