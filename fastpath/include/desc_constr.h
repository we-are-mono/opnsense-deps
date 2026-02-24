/*
 * CAAM descriptor construction helper functions — FreeBSD port.
 *
 * Ported from Linux drivers/crypto/caam/desc_constr.h.  Provides
 * inline functions for building CAAM shared and job descriptors.
 *
 * Adaptations for FreeBSD:
 *   - Linux u32/u64/u8 → uint32_t/uint64_t/uint8_t
 *   - Linux dma_addr_t → uint64_t
 *   - Linux cpu_to_caam32/caam32_to_cpu → htobe32/be32toh
 *     (LS1046A CAAM is big-endian, confirmed)
 *   - CAAM pointer size hardcoded to 8 (LS1046A uses 36-bit addrs)
 *   - caam_little_end hardcoded to false (LS1046A CAAM is BE)
 *   - PRINT_POS → no-op
 *   - ALIGN → roundup2
 *   - IS_ENABLED → 0
 *
 * Copyright 2008-2012 Freescale Semiconductor, Inc.
 * Copyright 2019 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef DESC_CONSTR_H
#define DESC_CONSTR_H

#include "desc.h"

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/param.h>		/* roundup2 */
#else
#include <stdint.h>
#include <string.h>
#include <endian.h>
#endif

/*
 * Endianness conversion — LS1046A CAAM is big-endian.
 * Descriptor words and DMA addresses are stored in BE format.
 */
static inline uint32_t cpu_to_caam32(uint32_t val)
{
	return htobe32(val);
}

static inline uint32_t caam32_to_cpu(uint32_t val)
{
	return be32toh(val);
}

static inline uint64_t cpu_to_caam64(uint64_t val)
{
	return htobe64(val);
}

static inline uint64_t cpu_to_caam_dma(uint64_t val)
{
	return htobe64(val);
}

static inline uint64_t caam_dma_to_cpu(uint64_t val)
{
	return be64toh(val);
}

#ifndef lower_32_bits
#define lower_32_bits(x)	((uint32_t)(x))
#endif
#ifndef upper_32_bits
#define upper_32_bits(x)	((uint32_t)((uint64_t)(x) >> 32))
#endif

#ifndef roundup2
#define roundup2(x, y)	(((x) + ((y) - 1)) & ~((y) - 1))
#endif

#define IMMEDIATE	(1 << 23)
#define CAAM_CMD_SZ	sizeof(uint32_t)
#define CAAM_PTR_SZ	sizeof(uint64_t)	/* LS1046A: 8-byte pointers */
#define CAAM_PTR_SZ_MAX	sizeof(uint64_t)
#define CAAM_PTR_SZ_MIN	sizeof(uint32_t)
#define CAAM_DESC_BYTES_MAX (CAAM_CMD_SZ * MAX_CAAM_DESCSIZE)

#define __DESC_JOB_IO_LEN(n)	(CAAM_CMD_SZ * 5 + (n) * 3)
#define DESC_JOB_IO_LEN		__DESC_JOB_IO_LEN(CAAM_PTR_SZ)
#define DESC_JOB_IO_LEN_MAX	__DESC_JOB_IO_LEN(CAAM_PTR_SZ_MAX)
#define DESC_JOB_IO_LEN_MIN	__DESC_JOB_IO_LEN(CAAM_PTR_SZ_MIN)

/*
 * Max shared descriptor length for QI-based descriptors.
 * QI job descriptor overhead: HEADER + shdesc_ptr + SEQ_OUT_PTR +
 * out_ptr + out_len + SEQ_IN_PTR + in_ptr + in_len = 8-11 words.
 */
#define MAX_SDLEN	((CAAM_DESC_BYTES_MAX - DESC_JOB_IO_LEN_MIN) / CAAM_CMD_SZ)

#define PRINT_POS

#define SET_OK_NO_PROP_ERRORS	(IMMEDIATE | LDST_CLASS_DECO | \
				 LDST_SRCDST_WORD_DECOCTRL | \
				 (LDOFF_CHG_SHARE_OK_NO_PROP << \
				  LDST_OFFSET_SHIFT))
#define DISABLE_AUTO_INFO_FIFO	(IMMEDIATE | LDST_CLASS_DECO | \
				 LDST_SRCDST_WORD_DECOCTRL | \
				 (LDOFF_DISABLE_AUTO_NFIFO << LDST_OFFSET_SHIFT))
#define ENABLE_AUTO_INFO_FIFO	(IMMEDIATE | LDST_CLASS_DECO | \
				 LDST_SRCDST_WORD_DECOCTRL | \
				 (LDOFF_ENABLE_AUTO_NFIFO << LDST_OFFSET_SHIFT))

static inline int desc_len(uint32_t * const desc)
{
	return caam32_to_cpu(*desc) & HDR_DESCLEN_MASK;
}

static inline int desc_bytes(void * const desc)
{
	return desc_len(desc) * CAAM_CMD_SZ;
}

static inline uint32_t *desc_end(uint32_t * const desc)
{
	return desc + desc_len(desc);
}

static inline void *sh_desc_pdb(uint32_t * const desc)
{
	return desc + 1;
}

static inline void init_desc(uint32_t * const desc, uint32_t options)
{
	*desc = cpu_to_caam32((options | HDR_ONE) + 1);
}

static inline void init_sh_desc(uint32_t * const desc, uint32_t options)
{
	PRINT_POS;
	init_desc(desc, CMD_SHARED_DESC_HDR | options);
}

static inline void init_sh_desc_pdb(uint32_t * const desc, uint32_t options,
				    size_t pdb_bytes)
{
	uint32_t pdb_len = (pdb_bytes + CAAM_CMD_SZ - 1) / CAAM_CMD_SZ;

	init_sh_desc(desc, (((pdb_len + 1) << HDR_START_IDX_SHIFT) + pdb_len) |
		     options);
}

static inline void init_job_desc(uint32_t * const desc, uint32_t options)
{
	init_desc(desc, CMD_DESC_HDR | options);
}

static inline void init_job_desc_pdb(uint32_t * const desc, uint32_t options,
				     size_t pdb_bytes)
{
	uint32_t pdb_len = (pdb_bytes + CAAM_CMD_SZ - 1) / CAAM_CMD_SZ;

	init_job_desc(desc, (((pdb_len + 1) << HDR_START_IDX_SHIFT)) | options);
}

static inline void append_ptr(uint32_t * const desc, uint64_t ptr)
{
	uint64_t *offset = (uint64_t *)desc_end(desc);

	*offset = cpu_to_caam_dma(ptr);

	(*desc) = cpu_to_caam32(caam32_to_cpu(*desc) +
				CAAM_PTR_SZ / CAAM_CMD_SZ);
}

static inline void init_job_desc_shared(uint32_t * const desc, uint64_t ptr,
					int len, uint32_t options)
{
	PRINT_POS;
	init_job_desc(desc, HDR_SHARED | options |
		      (len << HDR_START_IDX_SHIFT));
	append_ptr(desc, ptr);
}

static inline void append_data(uint32_t * const desc, const void *data,
			       int len)
{
	uint32_t *offset = desc_end(desc);

	if (data)
		memcpy(offset, data, len);

	(*desc) = cpu_to_caam32(caam32_to_cpu(*desc) +
				(len + CAAM_CMD_SZ - 1) / CAAM_CMD_SZ);
}

static inline void append_cmd(uint32_t * const desc, uint32_t command)
{
	uint32_t *cmd = desc_end(desc);

	*cmd = cpu_to_caam32(command);

	(*desc) = cpu_to_caam32(caam32_to_cpu(*desc) + 1);
}

#define append_u32 append_cmd

static inline void append_u64(uint32_t * const desc, uint64_t data)
{
	uint32_t *offset = desc_end(desc);

	/* LS1046A CAAM is big-endian */
	*offset = cpu_to_caam32(upper_32_bits(data));
	*(++offset) = cpu_to_caam32(lower_32_bits(data));

	(*desc) = cpu_to_caam32(caam32_to_cpu(*desc) + 2);
}

/* Write command without affecting header, and return pointer to next word */
static inline uint32_t *write_cmd(uint32_t * const desc, uint32_t command)
{
	*desc = cpu_to_caam32(command);
	return desc + 1;
}

static inline void append_cmd_ptr(uint32_t * const desc, uint64_t ptr,
				  int len, uint32_t command)
{
	append_cmd(desc, command | len);
	append_ptr(desc, ptr);
}

/* Write length after pointer, rather than inside command */
static inline void append_cmd_ptr_extlen(uint32_t * const desc, uint64_t ptr,
					 unsigned int len, uint32_t command)
{
	append_cmd(desc, command);
	if (!(command & (SQIN_RTO | SQIN_PRE)))
		append_ptr(desc, ptr);
	append_cmd(desc, len);
}

static inline void append_cmd_data(uint32_t * const desc, const void *data,
				   int len, uint32_t command)
{
	append_cmd(desc, command | IMMEDIATE | len);
	append_data(desc, data, len);
}

#define APPEND_CMD_RET(cmd, op) \
static inline uint32_t *append_##cmd(uint32_t * const desc, uint32_t options) \
{ \
	uint32_t *cmd = desc_end(desc); \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | options); \
	return cmd; \
}
APPEND_CMD_RET(jump, JUMP)
APPEND_CMD_RET(move, MOVE)
APPEND_CMD_RET(move_len, MOVE_LEN)
APPEND_CMD_RET(moveb, MOVEB)

static inline void set_jump_tgt_here(uint32_t * const desc,
				     uint32_t *jump_cmd)
{
	*jump_cmd = cpu_to_caam32(caam32_to_cpu(*jump_cmd) |
				  (desc_len(desc) - (jump_cmd - desc)));
}

static inline void set_move_tgt_here(uint32_t * const desc,
				     uint32_t *move_cmd)
{
	uint32_t val = caam32_to_cpu(*move_cmd);

	val &= ~MOVE_OFFSET_MASK;
	val |= (desc_len(desc) << (MOVE_OFFSET_SHIFT + 2)) & MOVE_OFFSET_MASK;
	*move_cmd = cpu_to_caam32(val);
}

#define APPEND_CMD(cmd, op) \
static inline void append_##cmd(uint32_t * const desc, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | options); \
}
APPEND_CMD(operation, OPERATION)

#define APPEND_CMD_LEN(cmd, op) \
static inline void append_##cmd(uint32_t * const desc, unsigned int len, \
				uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | len | options); \
}

APPEND_CMD_LEN(seq_load, SEQ_LOAD)
APPEND_CMD_LEN(seq_store, SEQ_STORE)
APPEND_CMD_LEN(seq_fifo_load, SEQ_FIFO_LOAD)
APPEND_CMD_LEN(seq_fifo_store, SEQ_FIFO_STORE)

#define APPEND_CMD_PTR(cmd, op) \
static inline void append_##cmd(uint32_t * const desc, uint64_t ptr, \
				unsigned int len, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd_ptr(desc, ptr, len, CMD_##op | options); \
}
APPEND_CMD_PTR(key, KEY)
APPEND_CMD_PTR(load, LOAD)
APPEND_CMD_PTR(fifo_load, FIFO_LOAD)
APPEND_CMD_PTR(fifo_store, FIFO_STORE)

static inline void append_store(uint32_t * const desc, uint64_t ptr,
				unsigned int len, uint32_t options)
{
	uint32_t cmd_src;

	cmd_src = options & LDST_SRCDST_MASK;

	append_cmd(desc, CMD_STORE | options | len);

	/* The following options do not require pointer */
	if (!(cmd_src == LDST_SRCDST_WORD_DESCBUF_SHARED ||
	      cmd_src == LDST_SRCDST_WORD_DESCBUF_JOB    ||
	      cmd_src == LDST_SRCDST_WORD_DESCBUF_JOB_WE ||
	      cmd_src == LDST_SRCDST_WORD_DESCBUF_SHARED_WE))
		append_ptr(desc, ptr);
}

#define APPEND_SEQ_PTR_INTLEN(cmd, op) \
static inline void append_seq_##cmd##_ptr_intlen(uint32_t * const desc, \
						 uint64_t ptr, \
						 unsigned int len, \
						 uint32_t options) \
{ \
	PRINT_POS; \
	if (options & (SQIN_RTO | SQIN_PRE)) \
		append_cmd(desc, CMD_SEQ_##op##_PTR | len | options); \
	else \
		append_cmd_ptr(desc, ptr, len, CMD_SEQ_##op##_PTR | options); \
}
APPEND_SEQ_PTR_INTLEN(in, IN)
APPEND_SEQ_PTR_INTLEN(out, OUT)

#define APPEND_CMD_PTR_TO_IMM(cmd, op) \
static inline void append_##cmd##_as_imm(uint32_t * const desc, \
					 const void *data, \
					 unsigned int len, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd_data(desc, data, len, CMD_##op | options); \
}
APPEND_CMD_PTR_TO_IMM(load, LOAD)
APPEND_CMD_PTR_TO_IMM(fifo_load, FIFO_LOAD)

#define APPEND_CMD_PTR_EXTLEN(cmd, op) \
static inline void append_##cmd##_extlen(uint32_t * const desc, \
					 uint64_t ptr, \
					 unsigned int len, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd_ptr_extlen(desc, ptr, len, CMD_##op | SQIN_EXT | options); \
}
APPEND_CMD_PTR_EXTLEN(seq_in_ptr, SEQ_IN_PTR)
APPEND_CMD_PTR_EXTLEN(seq_out_ptr, SEQ_OUT_PTR)

/*
 * 2nd variant for commands whose specified immediate length differs
 * from length of immediate data provided, e.g., split keys
 */
#define APPEND_CMD_PTR_TO_IMM2(cmd, op) \
static inline void append_##cmd##_as_imm(uint32_t * const desc, \
					 const void *data, \
					 unsigned int data_len, \
					 unsigned int len, uint32_t options) \
{ \
	PRINT_POS; \
	append_cmd(desc, CMD_##op | IMMEDIATE | len | options); \
	append_data(desc, data, data_len); \
}
APPEND_CMD_PTR_TO_IMM2(key, KEY)

#define APPEND_CMD_RAW_IMM(cmd, op, type) \
static inline void append_##cmd##_imm_##type(uint32_t * const desc, \
					     type immediate, \
					     uint32_t options) \
{ \
	PRINT_POS; \
	if (options & LDST_LEN_MASK) \
		append_cmd(desc, CMD_##op | IMMEDIATE | options); \
	else \
		append_cmd(desc, CMD_##op | IMMEDIATE | options | \
			   sizeof(type)); \
	append_cmd(desc, immediate); \
}
APPEND_CMD_RAW_IMM(load, LOAD, uint32_t)

/*
 * Append math command. Only the last part of destination and source need to
 * be specified
 */
#define APPEND_MATH(op, desc, dest, src_0, src_1, len) \
append_cmd(desc, CMD_MATH | MATH_FUN_##op | MATH_DEST_##dest | \
	MATH_SRC0_##src_0 | MATH_SRC1_##src_1 | (uint32_t)len);

#define append_math_add(desc, dest, src0, src1, len) \
	APPEND_MATH(ADD, desc, dest, src0, src1, len)
#define append_math_sub(desc, dest, src0, src1, len) \
	APPEND_MATH(SUB, desc, dest, src0, src1, len)
#define append_math_add_c(desc, dest, src0, src1, len) \
	APPEND_MATH(ADDC, desc, dest, src0, src1, len)
#define append_math_sub_b(desc, dest, src0, src1, len) \
	APPEND_MATH(SUBB, desc, dest, src0, src1, len)
#define append_math_and(desc, dest, src0, src1, len) \
	APPEND_MATH(AND, desc, dest, src0, src1, len)
#define append_math_or(desc, dest, src0, src1, len) \
	APPEND_MATH(OR, desc, dest, src0, src1, len)
#define append_math_xor(desc, dest, src0, src1, len) \
	APPEND_MATH(XOR, desc, dest, src0, src1, len)
#define append_math_lshift(desc, dest, src0, src1, len) \
	APPEND_MATH(LSHIFT, desc, dest, src0, src1, len)
#define append_math_rshift(desc, dest, src0, src1, len) \
	APPEND_MATH(RSHIFT, desc, dest, src0, src1, len)
#define append_math_ldshift(desc, dest, src0, src1, len) \
	APPEND_MATH(SHLD, desc, dest, src0, src1, len)

/* Exactly one source is IMM. Data is passed in as uint32_t value */
#define APPEND_MATH_IMM_u32(op, desc, dest, src_0, src_1, data) \
do { \
	APPEND_MATH(op, desc, dest, src_0, src_1, CAAM_CMD_SZ); \
	append_cmd(desc, data); \
} while (0)

#define append_math_add_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(ADD, desc, dest, src0, src1, data)
#define append_math_sub_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(SUB, desc, dest, src0, src1, data)
#define append_math_add_c_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(ADDC, desc, dest, src0, src1, data)
#define append_math_sub_b_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(SUBB, desc, dest, src0, src1, data)
#define append_math_and_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(AND, desc, dest, src0, src1, data)
#define append_math_or_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(OR, desc, dest, src0, src1, data)
#define append_math_xor_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(XOR, desc, dest, src0, src1, data)
#define append_math_lshift_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(LSHIFT, desc, dest, src0, src1, data)
#define append_math_rshift_imm_u32(desc, dest, src0, src1, data) \
	APPEND_MATH_IMM_u32(RSHIFT, desc, dest, src0, src1, data)

/**
 * struct alginfo - Container for algorithm details
 * @algtype: algorithm selector
 * @keylen: length of the provided algorithm key, in bytes
 * @keylen_pad: padded length of the provided algorithm key, in bytes
 * @key_dma: DMA (bus) address where algorithm key resides
 * @key_virt: virtual address where algorithm key resides
 * @key_inline: true - key can be inlined in the descriptor
 * @key_real_len: size of the key to be loaded by the CAAM
 * @key_cmd_opt: optional parameters for KEY command
 */
struct alginfo {
	uint32_t algtype;
	unsigned int keylen;
	unsigned int keylen_pad;
	uint64_t key_dma;
	const void *key_virt;
	int key_inline;		/* bool — avoid C++ keyword issues */
	uint32_t key_real_len;
	uint32_t key_cmd_opt;
};

/**
 * desc_inline_query() - Provide indications on which data items can be inlined
 *                       and which shall be referenced in a shared descriptor.
 */
static inline int desc_inline_query(unsigned int sd_base_len,
				    unsigned int jd_len,
				    unsigned int *data_len,
				    uint32_t *inl_mask,
				    unsigned int count)
{
	int rem_bytes = (int)(CAAM_DESC_BYTES_MAX - sd_base_len - jd_len);
	unsigned int i;

	*inl_mask = 0;
	for (i = 0; (i < count) && (rem_bytes > 0); i++) {
		if (rem_bytes - (int)(data_len[i] +
			(count - i - 1) * CAAM_PTR_SZ) >= 0) {
			rem_bytes -= data_len[i];
			*inl_mask |= (1 << i);
		} else {
			rem_bytes -= CAAM_PTR_SZ;
		}
	}

	return (rem_bytes >= 0) ? 0 : -1;
}

/**
 * append_proto_dkp - Derived Key Protocol (DKP): key -> split key
 */
static inline void append_proto_dkp(uint32_t * const desc,
				    struct alginfo *adata)
{
	uint32_t protid;

	/*
	 * Quick & dirty translation from OP_ALG_ALGSEL_{MD5, SHA*}
	 * to OP_PCLID_DKP_{MD5, SHA*}
	 */
	protid = (adata->algtype & OP_ALG_ALGSEL_SUBMASK) |
		 (0x20 << OP_ALG_ALGSEL_SHIFT);

	if (adata->key_inline) {
		int words;

		if (adata->keylen > adata->keylen_pad) {
			append_operation(desc, OP_TYPE_UNI_PROTOCOL | protid |
					 OP_PCL_DKP_SRC_PTR |
					 OP_PCL_DKP_DST_IMM | adata->keylen);
			append_ptr(desc, adata->key_dma);

			words = (roundup2(adata->keylen_pad, CAAM_CMD_SZ) -
				 CAAM_PTR_SZ) / CAAM_CMD_SZ;
		} else {
			append_operation(desc, OP_TYPE_UNI_PROTOCOL | protid |
					 OP_PCL_DKP_SRC_IMM |
					 OP_PCL_DKP_DST_IMM | adata->keylen);
			append_data(desc, adata->key_virt, adata->keylen);

			words = (roundup2(adata->keylen_pad, CAAM_CMD_SZ) -
				 roundup2(adata->keylen, CAAM_CMD_SZ)) /
				CAAM_CMD_SZ;
		}

		/* Reserve space in descriptor buffer for the derived key */
		if (words)
			(*desc) = cpu_to_caam32(caam32_to_cpu(*desc) + words);
	} else {
		append_operation(desc, OP_TYPE_UNI_PROTOCOL | protid |
				 OP_PCL_DKP_SRC_PTR | OP_PCL_DKP_DST_PTR |
				 adata->keylen);
		append_ptr(desc, adata->key_dma);
	}
}

#endif /* DESC_CONSTR_H */
