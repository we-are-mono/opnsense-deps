/*
 * DPA IPSec offload header — FreeBSD port.
 *
 * Ported from ASK/cdx-5.03.1/dpa_ipsec.h.  Provides the sec_descriptor
 * layout, per-SA frame queue constants, FQD Context-A flags, and function
 * declarations for the DPAA plumbing layer.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "pdb.h"

#ifndef DPA_IPSEC_H
#define DPA_IPSEC_H

#define UNIQUE_IPSEC_CP_FQID

/*
 * FQD Context-A flags — set in the MSB of context_a.hi to control
 * the OH port's handling of frames arriving from SEC.
 */
#define CDX_FQD_CTX_A_OVERRIDE_FQ	0x80
#define CDX_FQD_CTX_A_IGNORE_CMD	0x40
#define CDX_FQD_CTX_A_A1_FIELD_VALID	0x20
#define CDX_FQD_CTX_A_A2_FIELD_VALID	0x10
#define CDX_FQD_CTX_A_A0_FIELD_VALID	0x08
#define CDX_FQD_CTX_A_B0_FIELD_VALID	0x04
#define CDX_FQD_CTX_A_OVERRIDE_OMB	0x02
#define CDX_FQD_CTX_A_SHIFT_BITS	24

/* A1 field value: 2 = check SEC error status */
#define CDX_FQD_CTX_A_A1_VAL_TO_CHECK_SECERR	2

/*
 * Shared descriptor layout — preheader + descriptor body.
 * The CAAM QI reads the preheader from FQ Context-A, then fetches
 * the shared descriptor that follows.
 */
#define MAX_SHARED_DESC_SIZE	62
#define PRE_HDR_ALIGN		64

/* Per-SA frame queue indices */
#define FQ_FROM_SEC		0
#define FQ_TO_SEC		1
#ifdef UNIQUE_IPSEC_CP_FQID
#define FQ_TO_CP		2
#endif

#ifdef UNIQUE_IPSEC_CP_FQID
#define NUM_FQS_PER_SA		3
#else
#define NUM_FQS_PER_SA		2
#endif

#define IPSEC_FMAN_IDX		0
#define DEFA_WQ_ID		0

/*
 * desc_hdr — shared descriptor header word + PDB.
 * The PDB (Protocol Data Block) immediately follows the shared
 * descriptor header word.
 */
struct desc_hdr {
	uint32_t	sd_hdr;
	union {
		struct ipsec_encap_pdb	pdb_encrypt;
		struct ipsec_decap_pdb	pdb_decrypt;
	};
};

/*
 * GCM/CCM salt and option constants
 */
#define AES_GCM_SALT_LEN	4
#define AES_CCM_SALT_LEN	3
#define AES_CCM_INIT_COUNTER	0x0
#define AES_CCM_ICV8_IV_FLAG	0x5B
#define AES_CCM_ICV12_IV_FLAG	0x6B
#define AES_CCM_ICV16_IV_FLAG	0x7B
#define AES_CCM_CTR_FLAG	0x03

/*
 * sec_descriptor — the preheader + shared descriptor.
 * CAAM QI reads this from the DMA address in FQ Context-A.
 * Must be 64-byte aligned (PRE_HDR_ALIGN).
 */
struct sec_descriptor {
	uint64_t	preheader;
	union {
		uint32_t	shared_desc[MAX_SHARED_DESC_SIZE];
		struct desc_hdr	desc_hdr;
#define hdr_word	desc_hdr.sd_hdr
#define pdb_en		desc_hdr.pdb_encrypt
#define pdb_dec		desc_hdr.pdb_decrypt
	};
};

/*
 * Buffer pool constants.
 * IPSEC_BUFCOUNT: number of buffers pre-seeded in the IPSec BMan pool.
 * THRESHOLD_IPSEC_BPOOL_REFILL: refill when count drops below this.
 */
#define IPSEC_BUFCOUNT			512
#define THRESHOLD_IPSEC_BPOOL_REFILL	16

/*
 * Forward declarations
 */
struct ipsec_info;

/*
 * DPAA plumbing API — implemented in dpa_ipsec_freebsd.c
 */
void *	dpa_get_ipsec_instance(void);
void *	cdx_dpa_ipsecsa_alloc(struct ipsec_info *info, uint32_t handle);
int	dpa_ipsec_ofport_td(struct ipsec_info *info, uint32_t table_type,
	    void **td, uint32_t *portid);
int	cdx_dpa_ipsecsa_release(void *handle);
uint32_t get_fqid_to_sec(void *handle);
uint32_t get_fqid_from_sec(void *handle);
#ifdef UNIQUE_IPSEC_CP_FQID
uint32_t ipsec_get_to_cp_fqid(void *handle);
#endif
struct sec_descriptor *get_shared_desc(void *handle);

int	cdx_dpa_get_ipsec_pool_info(uint32_t *bpid, uint32_t *buf_size);
int	cdx_dpa_ipsec_init(void);
void	cdx_dpa_ipsec_exit(void);

int	cdx_init_scatter_gather_bpool(void);
int	cdx_init_skb_2bfreed_bpool(void);

#endif /* DPA_IPSEC_H */
