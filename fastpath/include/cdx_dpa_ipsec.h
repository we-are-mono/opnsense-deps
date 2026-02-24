/*
 * CDX DPA IPsec offload — algorithm constants and function declarations.
 *
 * Ported from ASK/cdx-5.03.1/cdx_dpa_ipsec.h.  Provides CAAM IPsec
 * protocol descriptor algorithm codes, tunnel mode options, preheader
 * macros, and the function declarations for the descriptor building
 * and classification table layers.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CDX_DPA_IPSEC_H
#define CDX_DPA_IPSEC_H

#include "dpa_ipsec.h"

#define MAX_NUM_OF_SA		1000
#define MAX_CIPHER_KEY_LEN	100
#define MAX_AUTH_KEY_LEN	256
#define MAX_BUFFER_POOL_ID	63

/*
 * If CAAM used with QI the maximum shared descriptor length is 50 words.
 * QI job descriptor consumes 8-11 words of the 64-word DECO buffer;
 * the shared descriptor must fit in the remaining space.
 */
#define MAX_CAAM_SHARED_DESCSIZE	50

/* 4 words allocated for per-SA stats (2 words packets, 2 words bytes) */
#define CDX_DPA_IPSEC_STATS_LEN	4

/* Maximum length (in bytes) for CAAM extra descriptor commands */
#define MAX_EXTRA_DESC_COMMANDS		(64 * sizeof(uint32_t))

/*
 * IPsec protocol cipher algorithm codes (OP_PCLID_IPSEC protinfo)
 *
 * These duplicate the ones in desc.h but cdx_dpa_ipsec.c references
 * them without the desc.h include path, so keep them here too.
 */
#define OP_PCL_IPSEC_CIPHER_MASK		 0xff00
#define OP_PCL_IPSEC_AUTH_MASK			 0x00ff

#define OP_PCL_IPSEC_DES_IV64			 0x0100
#define OP_PCL_IPSEC_DES			 0x0200
#define OP_PCL_IPSEC_3DES			 0x0300
#define OP_PCL_IPSEC_NULL_ENC			 0x0b00
#define OP_PCL_IPSEC_AES_CBC			 0x0c00
#define OP_PCL_IPSEC_AES_CTR			 0x0d00
#define OP_PCL_IPSEC_AES_XTS			 0x1600
#define OP_PCL_IPSEC_AES_CCM8			 0x0e00
#define OP_PCL_IPSEC_AES_CCM12			 0x0f00
#define OP_PCL_IPSEC_AES_CCM16			 0x1000
#define OP_PCL_IPSEC_AES_GCM8			 0x1200
#define OP_PCL_IPSEC_AES_GCM12			 0x1300
#define OP_PCL_IPSEC_AES_GCM16			 0x1400
#define OP_PCL_IPSEC_AES_GMAC			 0x1500

#define OP_PCL_IPSEC_HMAC_NULL			 0x0000
#define OP_PCL_IPSEC_HMAC_MD5_96		 0x0001
#define OP_PCL_IPSEC_HMAC_SHA1_96		 0x0002
#define OP_PCL_IPSEC_AES_XCBC_MAC_96		 0x0005
#define OP_PCL_IPSEC_HMAC_MD5_128		 0x0006
#define OP_PCL_IPSEC_HMAC_SHA1_160		 0x0007
#define OP_PCL_IPSEC_HMAC_SHA2_256_128		 0x000c
#define OP_PCL_IPSEC_HMAC_SHA2_384_192		 0x000d
#define OP_PCL_IPSEC_HMAC_SHA2_512_256		 0x000e

/*
 * Tunnel mode options — used with OP_PCLID_IPSEC protocol descriptors.
 * OP_PCLID_IPSEC_TUNNEL sets tunnel mode (vs transport mode).
 * Requires OP_PCLID_SHIFT from desc.h.
 */
#include "desc.h"

#define PDBOPTS_ETU			0x01
#define PDBOPTS_TECN			0x20
#define OP_PCLID_IPSEC_TUNNEL		(0x11 << OP_PCLID_SHIFT)
#define PDBOPTS_OIHI_FROM_INPUT		0x04
#define PDBOPTS_OIHI_FROM_PDB		0x0C
#define PDBOPTS_OIHI_FROM_PDB_REF	0x08
#define PDBOPTS_NAT			0x02
#define PDBOPTS_NAT_UDP_CHECKSM		0x01

/*
 * DSCP / fragmentation / DPOVRD flags for CDX IPsec control plane.
 */
#define DSCP_FQ_MAP_ENABLE		(1 << 0)
#define DSCP_FQ_MAP_DISABLE		(0 << 0)
#define IPSEC_DPOVRD_ENABLE		(1 << 1)
#define IPSEC_DPOVRD_DISABLE		(0 << 1)
#define IPSEC_IPV4_ENCAPSULATION	(0 << 2)
#define IPSEC_IPV6_ENCAPSULATION	(1 << 2)
#define FRAG_DISABLE			(1 << 3)

/* SA direction constants */
#define CDX_DPA_IPSEC_INBOUND		1
#define CDX_DPA_IPSEC_OUTBOUND		0
#define IPV4_HDR_SIZE			20

/*
 * Preheader field preparation macros.
 * The preheader is the first 8 bytes of sec_descriptor, read by CAAM QI.
 * Two-argument form: OR the value into the preheader variable.
 */
#define PREHEADER_PREP_IDLEN(prehdr, val)	\
	((prehdr) |= ((uint64_t)(val) << 48))
#define PREHEADER_PREP_BPID(prehdr, val)	\
	((prehdr) |= ((uint64_t)(val) << 32))
#define PREHEADER_PREP_BSIZE(prehdr, val)	\
	((prehdr) |= ((uint64_t)(val) << 16))
#define PREHEADER_PREP_OFFSET(prehdr, val)	\
	((prehdr) |= ((uint64_t)(val)))

/*
 * Forward declarations — full definitions are in control_ipsec.h
 * (Tier 1 header from cdx-5.03.1/).
 */
struct auth_params;
struct cipher_params;

/* Forward declaration: SA entry from control_ipsec.h */
struct _tSAEntry;
typedef struct _tSAEntry *PSAEntry;

/* Forward declaration: connection entry from cdx.h */
struct _tCtEntry;
typedef struct _tCtEntry *PCtEntry;

/* Forward declaration: classification entry info */
struct ins_entry_info;

/*
 * CDX DPA IPsec API — implemented in cdx_dpa_ipsec_freebsd.c
 *
 * These functions are called from Tier 1 control_ipsec.c when
 * DPA_IPSEC_OFFLOAD is defined.
 */

/* Module init/exit — called from CDX module load/unload */
int	cdx_ipsec_init(void);

/* Get OH port table descriptor for classification table operations */
int	cdx_ipsec_get_of_port_tbl_id(PCtEntry entry,
	    struct ins_entry_info *info);

/* SA context allocation/free for sec_descriptor + keys */
void	*cdx_ipsec_sec_sa_context_alloc(uint32_t);
void	cdx_ipsec_sec_sa_context_free(void *pdpa_sec_context);

/* Determine SA direction (inbound/outbound) */
int	cdx_dpa_ipsec_find_sa_direction(PSAEntry sa);

/* Add/delete classification table entries for ESP flow matching */
int	cdx_ipsec_add_classification_table_entry(PSAEntry sa);
int	cdx_ipsec_process_udp_classification_table_entry(PSAEntry sa);
int	cdx_ipsec_delete_fp_entry(PSAEntry pSA);

/* Build CAAM shared descriptor for a given SA */
int	cdx_ipsec_create_shareddescriptor(PSAEntry sa, uint32_t bytes_to_copy);

/* Generate HMAC split key via CAAM Job Ring */
int	cdx_ipsec_generate_split_key(struct auth_params *auth_param);

/* Release all HW resources associated with an SA */
void	cdx_ipsec_release_sa_resources(PSAEntry pSA);

/* Get L2/L3 header info for tunnel mode encapsulation */
int	dpa_get_l2l3_info_by_itf_id(uint32_t itf_id,
	    struct dpa_l2hdr_info *l2_info,
	    struct dpa_l3hdr_info *l3_info, uint32_t dir_in);

/* Inbound SPI → SAGD lookup for exception-path packets */
int	cdx_ipsec_handle_get_inbound_sagd(uint32_t spi, uint16_t *sagd);

/* Fill classification table actions for IPsec flow entries */
int	fill_ipsec_actions(PSAEntry entry, struct ins_entry_info *info,
	    uint32_t sa_dir_in);

/* Fill SEC info for connection entry (fast-path flow with IPsec) */
int	cdx_ipsec_fill_sec_info(PCtEntry entry, struct ins_entry_info *info);

/* Read per-SA statistics from CAAM descriptor */
void	get_stats_from_sa(PSAEntry sa, uint32_t *pkts, uint64_t *bytes,
	    uint8_t *pSeqOverflow);

#endif /* CDX_DPA_IPSEC_H */
