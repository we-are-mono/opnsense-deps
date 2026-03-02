/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * CAAM descriptor command word definitions and construction helpers.
 * Based on the NXP SEC v4.x/v5.x descriptor format specification.
 * Field encodings match Linux drivers/crypto/caam/desc.h for LS1046A.
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
#define CMD_SHIFT		27
#define CMD_MASK		(0x1fU << CMD_SHIFT)

#define CMD_KEY			(0x00U << CMD_SHIFT)	/* KEY command */
#define CMD_SEQ_KEY		(0x01U << CMD_SHIFT)	/* SEQ KEY */
#define CMD_LOAD		(0x02U << CMD_SHIFT)	/* LOAD command */
#define CMD_SEQ_LOAD		(0x03U << CMD_SHIFT)
#define CMD_FIFO_LOAD		(0x04U << CMD_SHIFT)	/* FIFO LOAD */
#define CMD_SEQ_FIFO_LOAD	(0x05U << CMD_SHIFT)
#define CMD_STORE		(0x0aU << CMD_SHIFT)	/* STORE command */
#define CMD_SEQ_STORE		(0x0bU << CMD_SHIFT)
#define CMD_FIFO_STORE		(0x0cU << CMD_SHIFT)	/* FIFO STORE */
#define CMD_SEQ_FIFO_STORE	(0x0dU << CMD_SHIFT)
#define CMD_MOVE		(0x0fU << CMD_SHIFT)
#define CMD_OPERATION		(0x10U << CMD_SHIFT)	/* OPERATION command */
#define CMD_SIGNATURE		(0x12U << CMD_SHIFT)
#define CMD_JUMP		(0x14U << CMD_SHIFT)
#define CMD_MATH		(0x15U << CMD_SHIFT)
#define CMD_DESC_HDR		(0x16U << CMD_SHIFT)	/* Job Descriptor Header */
#define CMD_SH_DESC_HDR		(0x17U << CMD_SHIFT)	/* Shared Descriptor Hdr */
#define CMD_SEQ_IN_PTR		(0x1eU << CMD_SHIFT)	/* Seq Input Pointer */
#define CMD_SEQ_OUT_PTR		(0x1fU << CMD_SHIFT)	/* Seq Output Pointer */

/*
 * Job Descriptor Header (word 0)
 *
 * Bits 31:27 = 0x16 (CMD_DESC_HDR)
 * Bit  23    = ONE (must be set)
 * Bits 21:16 = Start Index
 * Bit  12    = SHARED (next item is shared desc pointer)
 * Bits 11:8  = SHARE type
 * Bits  6:0  = Descriptor length in words
 */
#define HDR_ONE			(1U << 23)
#define HDR_START_IDX_SHIFT	16
#define HDR_START_IDX_MASK	(0x3fU << HDR_START_IDX_SHIFT)
#define HDR_DESCLEN_MASK	0x0000007f
#define HDR_JD_LENGTH_MASK	HDR_DESCLEN_MASK
#define HDR_SHARED		(1U << 12)	/* JD: shared desc ptr follows */
#define HDR_SAVECTX		HDR_SHARED	/* SH_DESC: save context */
#define HDR_REVERSE		(1U << 11)

/*
 * SHR (Sharing domain) field — bits 10:8 (JD) / 9:8 (shared desc).
 * Controls how the DECO caches the shared descriptor across invocations.
 * Matches Linux drivers/crypto/caam/desc.h HDR_SD_SHARE_SHIFT = 8.
 */
#define HDR_SHARE_SHIFT		8
#define HDR_SHARE_MASK		(0x07U << HDR_SHARE_SHIFT)
#define HDR_SHARE_NEVER		(0x00U << HDR_SHARE_SHIFT)
#define HDR_SHARE_WAIT		(0x01U << HDR_SHARE_SHIFT)
#define HDR_SHARE_SERIAL	(0x02U << HDR_SHARE_SHIFT)
#define HDR_SHARE_ALWAYS	(0x03U << HDR_SHARE_SHIFT)
#define HDR_SHARE_DEFER		(0x04U << HDR_SHARE_SHIFT)

/* Shared Descriptor Header */
#define SHR_HDR_DESCLEN_MASK	0x0000003f
#define SHR_HDR_START_IDX_SHIFT	16

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
#define KEY_CLASS_SHIFT		25
#define KEY_CLASS1		(0x01U << KEY_CLASS_SHIFT) /* 0x02000000 */
#define KEY_CLASS2		(0x02U << KEY_CLASS_SHIFT) /* 0x04000000 */
#define KEY_IMM			(1U << 23)
#define KEY_ENC			(1U << 22)
#define KEY_DEST_SHIFT		16
#define KEY_DEST_CLASS_REG	(0x00U << KEY_DEST_SHIFT) /* Class key register */
#define KEY_DEST_PKHA_E		(0x01U << KEY_DEST_SHIFT) /* PKHA E register */
#define KEY_DEST_AFHA_SBOX	(0x02U << KEY_DEST_SHIFT) /* AFHA S-box */
#define KEY_DEST_MDHA_SPLIT	(0x03U << KEY_DEST_SHIFT) /* MDHA split key */
#define KEY_LENGTH_MASK		0x000003ff

/*
 * LOAD / SEQ LOAD / STORE / SEQ STORE commands
 *
 * Bits 26:25 = CLASS (00=ind CCB, 01=class1, 10=class2, 11=DECO)
 * Bit  23    = IMM (immediate data follows)
 * Bits 22:16 = SRCDST (source or destination register)
 * Bits 15:8  = OFFSET (byte offset within register)
 * Bits  7:0  = LENGTH (byte count)
 */
#define LDST_CLASS_SHIFT	25
#define LDST_CLASS_IND_CCB	(0x00U << LDST_CLASS_SHIFT)
#define LDST_CLASS_1_CCB	(0x01U << LDST_CLASS_SHIFT)
#define LDST_CLASS_2_CCB	(0x02U << LDST_CLASS_SHIFT)
#define LDST_CLASS_DECO		(0x03U << LDST_CLASS_SHIFT)

#define LDST_IMM		(1U << 23)

#define LDST_SRCDST_SHIFT	16
#define LDST_SRCDST_BYTE_CONTEXT  (0x20U << LDST_SRCDST_SHIFT) /* Context reg */
#define LDST_SRCDST_BYTE_KEY	  (0x40U << LDST_SRCDST_SHIFT) /* Key reg */

/* DECO register destinations (used with LDST_CLASS_DECO) */
#define LDST_SRCDST_WORD_CLRW	       (0x08U << LDST_SRCDST_SHIFT)
#define LDST_SRCDST_WORD_DECO_MATH0   (0x08U << LDST_SRCDST_SHIFT)
#define LDST_SRCDST_WORD_DECO_MATH1   (0x09U << LDST_SRCDST_SHIFT)
#define LDST_SRCDST_WORD_DECO_MATH2   (0x0aU << LDST_SRCDST_SHIFT)
#define LDST_SRCDST_WORD_DECO_MATH3   (0x0bU << LDST_SRCDST_SHIFT)
#define LDST_SRCDST_WORD_DECO_AAD_SZ  LDST_SRCDST_WORD_DECO_MATH3

#define LDST_OFFSET_SHIFT	8
#define LDST_OFFSET_MASK	(0xffU << LDST_OFFSET_SHIFT)

#define LDST_LEN_SHIFT		0
#define LDST_LEN_MASK		0x000000ff

/*
 * OPERATION Command (bits 31:27 = 0x10)
 */
#define OP_TYPE_SHIFT		24
#define OP_TYPE_MASK		(0x07U << OP_TYPE_SHIFT)
#define OP_TYPE_CLASS1		(0x02U << OP_TYPE_SHIFT)
#define OP_TYPE_CLASS2		(0x04U << OP_TYPE_SHIFT)
#define OP_TYPE_UNI_PROTOCOL	(0x00U << OP_TYPE_SHIFT)
#define OP_TYPE_CLASS1_ALG	OP_TYPE_CLASS1
#define OP_TYPE_CLASS2_ALG	OP_TYPE_CLASS2

/* Algorithm selectors (bits 23:16) */
#define OP_ALG_ALGSEL_SHIFT	16
#define OP_ALG_ALGSEL_MASK	(0xffU << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_SUBMASK	(0x0fU << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_AES	(0x10U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_DES	(0x20U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_3DES	(0x21U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_MD5	(0x40U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_SHA1	(0x41U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_SHA224	(0x42U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_SHA256	(0x43U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_SHA384	(0x44U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_SHA512	(0x45U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_RNG	(0x50U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_CHACHA20	(0xd0U << OP_ALG_ALGSEL_SHIFT)
#define OP_ALG_ALGSEL_POLY1305	(0xe0U << OP_ALG_ALGSEL_SHIFT)

/* Additional Algorithm Info (AAI) — bits 12:4 */
#define OP_ALG_AAI_SHIFT	4
#define OP_ALG_AAI_MASK		(0x1ffU << OP_ALG_AAI_SHIFT)

/* AES modes */
#define OP_ALG_AAI_CTR_MOD128	(0x00U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_CBC		(0x10U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_ECB		(0x20U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_CFB		(0x30U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_OFB		(0x40U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_XTS		(0x50U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_CMAC		(0x60U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_CCM		(0x80U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_GCM		(0x90U << OP_ALG_AAI_SHIFT)

/* Hash modes */
#define OP_ALG_AAI_HASH		(0x00U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_HMAC		(0x01U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_SMAC		(0x02U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_HMAC_PRECOMP	(0x04U << OP_ALG_AAI_SHIFT)

/* Decrypt key derivation */
#define OP_ALG_AAI_DK		(0x100U << OP_ALG_AAI_SHIFT)

/* RNG modes */
#define OP_ALG_AAI_RNG		(0x00U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_RNG4_SH_0	(0x00U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_RNG4_SH_1	(0x01U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_RNG4_PS	(0x40U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_RNG4_AI	(0x80U << OP_ALG_AAI_SHIFT)
#define OP_ALG_AAI_RNG4_SK	(0x100U << OP_ALG_AAI_SHIFT)

/*
 * Derived Key Protocol (DKP) — protocol info for OP_TYPE_UNI_PROTOCOL.
 * Used on ERA >= 6 to compute HMAC split keys inline in the descriptor.
 */
#define OP_PCL_DKP_SRC_IMM	(0U << 14)	/* Source key inline */
#define OP_PCL_DKP_SRC_PTR	(1U << 14)	/* Source key via DMA pointer */
#define OP_PCL_DKP_DST_IMM	(0U << 12)	/* Derived key inline */
#define OP_PCL_DKP_DST_PTR	(1U << 12)	/* Derived key via DMA pointer */

/* Algorithm State (bits 3:2) */
#define OP_ALG_AS_SHIFT		2
#define OP_ALG_AS_MASK		(0x03U << OP_ALG_AS_SHIFT)
#define OP_ALG_AS_UPDATE	(0x00U << OP_ALG_AS_SHIFT)
#define OP_ALG_AS_INIT		(0x01U << OP_ALG_AS_SHIFT)
#define OP_ALG_AS_FINALIZE	(0x02U << OP_ALG_AS_SHIFT)
#define OP_ALG_AS_INITFINAL	(0x03U << OP_ALG_AS_SHIFT)

/* ICV check / Prediction Resistance (bit 1 — context-dependent) */
#define OP_ALG_ICV_OFF		(0U << 1)
#define OP_ALG_ICV_ON		(1U << 1)
#define OP_ALG_PR_ON		(1U << 1)	/* RNG: prediction resistance */

/* Direction (bit 0) */
#define OP_ALG_DECRYPT		0
#define OP_ALG_ENCRYPT		1

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
#define FIFOLD_CLASS_SHIFT	25
#define FIFOLD_CLASS_SKIP	(0x00U << FIFOLD_CLASS_SHIFT)
#define FIFOLD_CLASS_CLASS1	(0x01U << FIFOLD_CLASS_SHIFT)
#define FIFOLD_CLASS_CLASS2	(0x02U << FIFOLD_CLASS_SHIFT)
#define FIFOLD_CLASS_BOTH	(0x03U << FIFOLD_CLASS_SHIFT)

#define FIFOLDST_VLF		(1U << 24)	/* Variable length (SEQ FIFO) */
#define FIFOLDST_SGF		FIFOLDST_VLF	/* Alias */
#define FIFOLD_IMM		(1U << 23)
#define FIFOLDST_EXT		(1U << 22)

#define FIFOLD_TYPE_SHIFT	16
#define FIFOLD_TYPE_MASK	(0x3fU << FIFOLD_TYPE_SHIFT)

/* Data types (upper 3 bits of TYPE) */
#define FIFOLD_TYPE_MSG		(0x10U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_MSG1OUT2	(0x18U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_IV		(0x20U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_BITDATA	(0x28U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_AAD		(0x30U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_ICV		(0x38U << FIFOLD_TYPE_SHIFT)

/* Action bits (lower 3 bits of TYPE, OR'd with data type) */
#define FIFOLD_TYPE_NOACTION	(0x00U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_FLUSH1	(0x01U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_LAST1	(0x02U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_LAST2FLUSH	(0x03U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_LAST2	(0x04U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_LAST2FLUSH1	(0x05U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_LASTBOTH	(0x06U << FIFOLD_TYPE_SHIFT)
#define FIFOLD_TYPE_LASTBOTHFL	(0x07U << FIFOLD_TYPE_SHIFT)

#define FIFOLDST_LEN_MASK	0x0000ffff

/*
 * FIFO STORE / SEQ FIFO STORE commands
 *
 * Bits 26:25 = CLASS (00=normal, 01=class1key, 10=class2key)
 * Bit  24    = SGF/VLF
 * Bit  22    = EXT
 * Bits 21:16 = TYPE
 * Bits 15:0  = LENGTH
 */
#define FIFOST_CLASS_SHIFT	25
#define FIFOST_CLASS_NORMAL	(0x00U << FIFOST_CLASS_SHIFT)
#define FIFOST_CLASS_CLASS1KEY	(0x01U << FIFOST_CLASS_SHIFT)
#define FIFOST_CLASS_CLASS2KEY	(0x02U << FIFOST_CLASS_SHIFT)

#define FIFOST_TYPE_SHIFT	16
#define FIFOST_TYPE_MASK	(0x3fU << FIFOST_TYPE_SHIFT)
#define FIFOST_TYPE_MESSAGE_DATA (0x30U << FIFOST_TYPE_SHIFT)
#define FIFOST_TYPE_RNGSTORE	(0x34U << FIFOST_TYPE_SHIFT)
#define FIFOST_TYPE_RNGFIFO	(0x35U << FIFOST_TYPE_SHIFT)
#define FIFOST_TYPE_SPLIT_KEK	(0x26U << FIFOST_TYPE_SHIFT)
#define FIFOST_TYPE_SKIP	(0x3fU << FIFOST_TYPE_SHIFT)

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
#define JUMP_CLASS_SHIFT	25
#define JUMP_CLASS_NONE		0
#define JUMP_CLASS_CLASS1	(1U << JUMP_CLASS_SHIFT)
#define JUMP_CLASS_CLASS2	(2U << JUMP_CLASS_SHIFT)
#define JUMP_CLASS_BOTH		(3U << JUMP_CLASS_SHIFT)

#define JUMP_JSL		(1U << 24)

#define JUMP_TYPE_SHIFT		22
#define JUMP_TYPE_LOCAL		(0x00U << JUMP_TYPE_SHIFT)
#define JUMP_TYPE_NONLOCAL	(0x01U << JUMP_TYPE_SHIFT)
#define JUMP_TYPE_HALT		(0x02U << JUMP_TYPE_SHIFT)
#define JUMP_TYPE_HALT_USER	(0x03U << JUMP_TYPE_SHIFT)

#define JUMP_TEST_SHIFT		16
#define JUMP_TEST_ALL		(0x00U << JUMP_TEST_SHIFT)
#define JUMP_TEST_INVALL	(0x01U << JUMP_TEST_SHIFT)
#define JUMP_TEST_ANY		(0x02U << JUMP_TEST_SHIFT)
#define JUMP_TEST_INVANY	(0x03U << JUMP_TEST_SHIFT)

/* Condition codes (bits 15:8) — plain conditions (without JSL) */
#define JUMP_COND_SHIFT		8
#define JUMP_COND_MATH_N	(0x08U << JUMP_COND_SHIFT)
#define JUMP_COND_MATH_Z	(0x04U << JUMP_COND_SHIFT)
#define JUMP_COND_MATH_C	(0x02U << JUMP_COND_SHIFT)
#define JUMP_COND_MATH_NV	(0x01U << JUMP_COND_SHIFT)

/* Condition codes that include JSL (per Linux desc.h encoding) */
#define JUMP_COND_JRP		((0x80U << JUMP_COND_SHIFT) | JUMP_JSL)
#define JUMP_COND_SHRD		((0x40U << JUMP_COND_SHIFT) | JUMP_JSL)
#define JUMP_COND_SELF		((0x20U << JUMP_COND_SHIFT) | JUMP_JSL)
#define JUMP_COND_CALM		((0x10U << JUMP_COND_SHIFT) | JUMP_JSL)
#define JUMP_COND_NIP		((0x08U << JUMP_COND_SHIFT) | JUMP_JSL)
#define JUMP_COND_NIFP		((0x04U << JUMP_COND_SHIFT) | JUMP_JSL)
#define JUMP_COND_NOP		((0x02U << JUMP_COND_SHIFT) | JUMP_JSL)
#define JUMP_COND_NCP		((0x01U << JUMP_COND_SHIFT) | JUMP_JSL)

#define JUMP_OFFSET_SHIFT	0
#define JUMP_OFFSET_MASK	0x000000ff

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
#define MATH_IFB		(1U << 26)

#define MATH_FUN_SHIFT		20
#define MATH_FUN_ADD		(0x00U << MATH_FUN_SHIFT)
#define MATH_FUN_ADDC		(0x01U << MATH_FUN_SHIFT)
#define MATH_FUN_SUB		(0x02U << MATH_FUN_SHIFT)
#define MATH_FUN_SUBB		(0x03U << MATH_FUN_SHIFT)
#define MATH_FUN_OR		(0x04U << MATH_FUN_SHIFT)
#define MATH_FUN_AND		(0x05U << MATH_FUN_SHIFT)
#define MATH_FUN_XOR		(0x06U << MATH_FUN_SHIFT)
#define MATH_FUN_LSHIFT		(0x07U << MATH_FUN_SHIFT)
#define MATH_FUN_RSHIFT		(0x08U << MATH_FUN_SHIFT)
#define MATH_FUN_ZBYT		(0x0aU << MATH_FUN_SHIFT)

#define MATH_SRC0_SHIFT		16
#define MATH_SRC0_REG0		(0x00U << MATH_SRC0_SHIFT)
#define MATH_SRC0_REG1		(0x01U << MATH_SRC0_SHIFT)
#define MATH_SRC0_REG2		(0x02U << MATH_SRC0_SHIFT)
#define MATH_SRC0_REG3		(0x03U << MATH_SRC0_SHIFT)
#define MATH_SRC0_IMM		(0x04U << MATH_SRC0_SHIFT)
#define MATH_SRC0_DPOVRD	(0x07U << MATH_SRC0_SHIFT)
#define MATH_SRC0_SEQINLEN	(0x08U << MATH_SRC0_SHIFT)
#define MATH_SRC0_SEQOUTLEN	(0x09U << MATH_SRC0_SHIFT)
#define MATH_SRC0_VARSEQINLEN	(0x0aU << MATH_SRC0_SHIFT)
#define MATH_SRC0_VARSEQOUTLEN	(0x0bU << MATH_SRC0_SHIFT)
#define MATH_SRC0_ZERO		(0x0cU << MATH_SRC0_SHIFT)

#define MATH_SRC1_SHIFT		12
#define MATH_SRC1_REG0		(0x00U << MATH_SRC1_SHIFT)
#define MATH_SRC1_REG1		(0x01U << MATH_SRC1_SHIFT)
#define MATH_SRC1_REG2		(0x02U << MATH_SRC1_SHIFT)
#define MATH_SRC1_REG3		(0x03U << MATH_SRC1_SHIFT)
#define MATH_SRC1_IMM		(0x04U << MATH_SRC1_SHIFT)
#define MATH_SRC1_DPOVRD	(0x07U << MATH_SRC1_SHIFT)
#define MATH_SRC1_INFIFO	(0x0aU << MATH_SRC1_SHIFT)
#define MATH_SRC1_OUTFIFO	(0x0bU << MATH_SRC1_SHIFT)
#define MATH_SRC1_ONE		(0x0cU << MATH_SRC1_SHIFT)
#define MATH_SRC1_ZERO		(0x0fU << MATH_SRC1_SHIFT)

#define MATH_DEST_SHIFT		8
#define MATH_DEST_REG0		(0x00U << MATH_DEST_SHIFT)
#define MATH_DEST_REG1		(0x01U << MATH_DEST_SHIFT)
#define MATH_DEST_REG2		(0x02U << MATH_DEST_SHIFT)
#define MATH_DEST_REG3		(0x03U << MATH_DEST_SHIFT)
#define MATH_DEST_DPOVRD	(0x07U << MATH_DEST_SHIFT)
#define MATH_DEST_SEQINLEN	(0x08U << MATH_DEST_SHIFT)
#define MATH_DEST_SEQOUTLEN	(0x09U << MATH_DEST_SHIFT)
#define MATH_DEST_VARSEQINLEN	(0x0aU << MATH_DEST_SHIFT)
#define MATH_DEST_VARSEQOUTLEN	(0x0bU << MATH_DEST_SHIFT)
#define MATH_DEST_NONE		(0x0fU << MATH_DEST_SHIFT)

#define MATH_LEN_SHIFT		0
#define MATH_LEN_1BYTE		0x01
#define MATH_LEN_2BYTE		0x02
#define MATH_LEN_4BYTE		0x04
#define MATH_LEN_8BYTE		0x08

/*
 * MOVE Command
 */
#define MOVE_SRC_SHIFT		20
#define MOVE_SRC_CLASS1CTX	(0x04U << MOVE_SRC_SHIFT)
#define MOVE_SRC_CLASS2CTX	(0x05U << MOVE_SRC_SHIFT)
#define MOVE_SRC_OUTFIFO	(0x06U << MOVE_SRC_SHIFT)

#define MOVE_DEST_SHIFT		16
#define MOVE_DEST_CLASS1CTX	(0x04U << MOVE_DEST_SHIFT)
#define MOVE_DEST_CLASS2CTX	(0x05U << MOVE_DEST_SHIFT)
#define MOVE_DEST_CLASS2INFIFO	(0x07U << MOVE_DEST_SHIFT)

#define MOVE_OFFSET_SHIFT	8
#define MOVE_LEN_SHIFT		0

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

	return (caam_to_cpu32(desc[0]) & HDR_DESCLEN_MASK);
}

/* Get shared descriptor length in words */
static __inline int
caam_shdesc_len(const uint32_t *desc)
{

	return (caam_to_cpu32(desc[0]) & SHR_HDR_DESCLEN_MASK);
}

/*
 * Initialize a job descriptor header.
 * Sets CMD_DESC_HDR + HDR_ONE + length=1 (the header word itself).
 */
static __inline void
caam_desc_init(uint32_t *desc)
{

	desc[0] = cpu_to_caam32(CMD_DESC_HDR | HDR_ONE | 1);
}

/*
 * Initialize a shared descriptor header.
 * Sets CMD_SH_DESC_HDR + HDR_ONE + options + length=1.
 */
static __inline void
caam_shdesc_init(uint32_t *desc, uint32_t options)
{

	/*
	 * Shared descriptor header: CMD_SH_DESC_HDR + HDR_ONE + options + 1.
	 * HDR_ONE (bit 23) is set in both JD and SD headers per the SEC
	 * reference manual.  Matches Linux init_sh_desc → init_desc which
	 * always ORs HDR_ONE.
	 */
	desc[0] = cpu_to_caam32(CMD_SH_DESC_HDR | HDR_ONE | options | 1);
}

/* Append a command/data word to the descriptor (with byte-swap) */
static __inline void
caam_desc_add_word(uint32_t *desc, uint32_t word)
{
	uint32_t hdr;
	int len;

	hdr = caam_to_cpu32(desc[0]);
	len = hdr & HDR_DESCLEN_MASK;
	KASSERT(len < CAAM_DESC_MAX_WORDS,
	    ("caam_desc_add_word: descriptor overflow (%d words)", len));
	desc[len] = cpu_to_caam32(word);
	desc[0] = cpu_to_caam32((hdr & ~HDR_DESCLEN_MASK) | (len + 1));
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
	len = hdr & HDR_DESCLEN_MASK;
	KASSERT(len < CAAM_DESC_MAX_WORDS,
	    ("caam_desc_add_raw: descriptor overflow (%d words)", len));
	desc[len] = raw;
	desc[0] = cpu_to_caam32((hdr & ~HDR_DESCLEN_MASK) | (len + 1));
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
	len = hdr & HDR_DESCLEN_MASK;
	KASSERT(len + 1 < CAAM_DESC_MAX_WORDS,
	    ("caam_desc_add_ptr: descriptor overflow (%d words)", len));
	if (caam_big_endian) {
		desc[len]     = htobe32((uint32_t)(ptr >> 32));
		desc[len + 1] = htobe32((uint32_t)ptr);
	} else {
		desc[len]     = (uint32_t)ptr;
		desc[len + 1] = (uint32_t)(ptr >> 32);
	}
	desc[0] = cpu_to_caam32((hdr & ~HDR_DESCLEN_MASK) | (len + 2));
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
	len = hdr & HDR_DESCLEN_MASK;
	jump_word = &desc[len];
	desc[len] = cpu_to_caam32(CMD_JUMP | options);
	desc[0] = cpu_to_caam32((hdr & ~HDR_DESCLEN_MASK) | (len + 1));
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
	jcmd = (jcmd & ~JUMP_OFFSET_MASK) | (cur_len - jump_idx);
	*jump_cmd = cpu_to_caam32(jcmd);
}

/*
 * Append inline byte data (key, IV, etc.) to the descriptor.
 *
 * Data bytes are copied verbatim into the descriptor buffer without
 * byte-swapping.  CAAM reads the inline data as raw bytes from the
 * descriptor in DMA memory, regardless of register endianness.
 * This matches Linux's append_data() which uses memcpy.
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
 * Used on ERA >= 6 instead of KEY + KEY_ENC for split key loading.
 *
 * The DKP computes the HMAC split key from the raw HMAC key at DECO
 * runtime and loads it into the Class 2 key register.  This replaces
 * the pre-computed split key + KEY_DEST_MDHA_SPLIT approach used on
 * earlier ERAs.
 *
 * algtype:      algorithm selector (e.g. OP_ALG_ALGSEL_SHA256)
 * key:          raw HMAC key bytes
 * keylen:       raw HMAC key length in bytes
 * split_key_len: split key length = 2 * MDHA_pad (determines DECO IP
 *               advancement and inline reservation).  Must be the
 *               UNPADDED split_key_len, NOT split_key_pad_len.
 *               Matches Linux adata->keylen_pad = split_key_len().
 *
 * When keylen > split_key_len, inline source would cause the DECO to
 * skip fewer words than the key occupies, executing key data as
 * instructions.  In that case we MUST NOT inline both.  This
 * implementation rejects keylen > split_key_len; callers must limit
 * auth_klen in probesession.  (Linux uses SRC_PTR mode with a DMA
 * pointer for large keys.)
 */
static __inline void
caam_desc_add_proto_dkp(uint32_t *desc, uint32_t algtype,
    const uint8_t *key, int keylen, int split_key_len)
{
	uint32_t protid, hdr;
	int words, len;

	/*
	 * Translate OP_ALG_ALGSEL_SHA* to OP_PCLID_DKP_SHA*.
	 * DKP protocol IDs are 0x2n where n = low nibble of ALGSEL.
	 */
	protid = (algtype & OP_ALG_ALGSEL_SUBMASK) |
	    (0x20U << OP_ALG_ALGSEL_SHIFT);

	KASSERT(keylen <= split_key_len,
	    ("caam DKP: keylen %d > split_key_len %d, need SRC_PTR mode",
	    keylen, split_key_len));

	/* OPERATION: DKP with inline source and inline destination */
	caam_desc_add_word(desc,
	    CMD_OPERATION | OP_TYPE_UNI_PROTOCOL | protid |
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
		len = hdr & HDR_DESCLEN_MASK;
		desc[0] = cpu_to_caam32((hdr & ~HDR_DESCLEN_MASK) |
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
	    CMD_KEY | KEY_CLASS2 | KEY_DEST_MDHA_SPLIT | KEY_ENC |
	    split_key_pad_len);
	caam_desc_add_ptr(desc, key_pa);
}

/*
 * Append a SEQ IN PTR command.  Always uses EXT mode (extended 32-bit
 * length in a separate word after the pointer).
 *
 * Linux's append_seq_in_ptr() also always uses EXT mode — the compile-
 * time sizeof(u32) > sizeof(u16) check in APPEND_CMD_PTR_LEN selects
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

	caam_desc_add_word(desc, CMD_SEQ_IN_PTR | SQIN_EXT);
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

	caam_desc_add_word(desc, CMD_SEQ_OUT_PTR | SQOUT_EXT);
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
	caam_desc_add_word(desc, CMD_JUMP | JUMP_TYPE_HALT);
}

#endif /* _CAAM_DESC_H */
