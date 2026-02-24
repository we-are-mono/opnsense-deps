/*
 * CDX DPA IPsec descriptor building and classification — FreeBSD port.
 *
 * Ported from ASK/cdx-5.03.1/cdx_dpa_ipsec.c.  Provides:
 *   - CAAM IPsec protocol descriptor (shared descriptor + PDB) building
 *   - CAAM preheader setup for QI-based descriptor submission
 *   - Per-SA context allocation/teardown (cipher key, auth key, split key)
 *   - FMan enhanced hash table entry programming for ESP flow matching
 *   - Per-SA inline statistics (packet/byte counters in descriptor)
 *   - Split key generation via CAAM Job Ring
 *
 * Key differences from Linux:
 *   - struct iphdr → struct ip (FreeBSD <netinet/ip.h>)
 *   - struct ipv6hdr → struct ip6_hdr (FreeBSD <netinet/ip6.h>)
 *   - ip_fast_csum() → in_cksum_hdr() (FreeBSD in_cksum.h)
 *   - dma_map_single() → vtophys() (LS1046A is DMA-coherent via CCI-400)
 *   - kzalloc/kfree → malloc/free with M_CDX
 *   - caam_jr_alloc()/caam_jr_enqueue() → FreeBSD CAAM JR API
 *   - cpu_to_caam32/64 → htobe32/htobe64 (via desc_constr.h)
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifdef DPA_IPSEC_OFFLOAD

#include "portdefs.h"
#include "cdx.h"
#include "cdx_common.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_pppoe.h"
#include "control_socket.h"
#include "layer2.h"
#include "control_ipsec.h"

#include "cdx_dpa_ipsec.h"
#include "fm_ehash.h"

/* FreeBSD CAAM descriptor construction (desc.h + desc_constr.h) */
#include "pdb.h"
#include "desc.h"
#include "desc_constr.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/endian.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <machine/in_cksum.h>
#include <vm/vm.h>
#include <vm/pmap.h>

MALLOC_DECLARE(M_CDX);

/* Suppress warnings for vendor-style code */
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/*
 * SEC failure stats query command — mirrors fpp.h definition.
 * en_SEC_failure_stats is from fm_ehash.h (already included above).
 */
typedef struct fpp_sec_failure_stats_query_cmd {
	uint16_t		action;
	en_SEC_failure_stats	SEC_failure_stats;
} __attribute__((__packed__)) fpp_sec_failure_stats_query_cmd_t;

/* Forward declarations — implemented in dpa_ipsec_freebsd.c */
extern int cdx_ipsec_sa_fq_check_if_retired_state(void *handle, int fq_num);
extern int cdx_dpa_ipsec_retire_fq(void *handle, int fq_num);

/* ================================================================
 * Constants
 * ================================================================ */

#define CLASS_SHIFT		25
#define CLASS_MASK		(0x03 << CLASS_SHIFT)
#define CLASS_NONE		(0x00 << CLASS_SHIFT)
#define CLASS_1			(0x01 << CLASS_SHIFT)
#define CLASS_2			(0x02 << CLASS_SHIFT)
#define CLASS_BOTH		(0x03 << CLASS_SHIFT)

#define SEQ_NUM_HI_MASK		0xFFFFFFFF00000000ULL
#define SEQ_NUM_LOW_MASK	0x00000000FFFFFFFFULL

#define POST_SEC_OUT_DATA_OFFSET	128	/* bytes, multiple of 64 */
#define POST_SEC_IN_DATA_OFFSET		128

#define ETH_HDR_LEN		14
#define UDP_HEADER_LEN		8

#define PROTO_IPV4		2	/* AF_INET */
#define PROTO_IPV6		10	/* AF_INET6 (Linux value) */

extern int gIPSecStatQueryTimer;

/*
 * Max packets forwarded per second — used for seq num soft limit.
 */
#define MAX_IPSEC_PKTS_FWD_PSEC		1300000
#define SEQ_NUM_SOFT_LIMIT	\
	(0xFFFFFFFF - (MAX_IPSEC_PKTS_FWD_PSEC * gIPSecStatQueryTimer))
#define SEQ_NUM_ESN_SOFT_LIMIT	\
	(0xFFFFFFFFFFFFFFFFULL - \
	 ((uint64_t)MAX_IPSEC_PKTS_FWD_PSEC * gIPSecStatQueryTimer))

/* ================================================================
 * Globals
 * ================================================================ */

static struct ipsec_info *ipsec_instance;
static int sec_era;
static uint64_t post_sec_out_data_off;
static uint64_t post_sec_in_data_off;

/* ================================================================
 * Module init
 * ================================================================ */

int
cdx_ipsec_init(void)
{

	DPA_INFO("%s\n", __func__);
	ipsec_instance = dpa_get_ipsec_instance();
	sec_era = 4;
	post_sec_out_data_off = (uint64_t)POST_SEC_OUT_DATA_OFFSET / 64;
	post_sec_in_data_off = (uint64_t)POST_SEC_IN_DATA_OFFSET / 64;

	DPA_INFO("%s: initialized (sec_era=%d)\n", __func__, sec_era);
	return (0);
}

/* ================================================================
 * Fill SEC info for connection entries (fast-path flows with IPsec)
 * ================================================================ */

int
cdx_ipsec_fill_sec_info(PCtEntry entry, struct ins_entry_info *info)
{
	int i;
	PSAEntry sa;

	for (i = 0; i < SA_MAX_OP; i++) {
		sa = M_ipsec_sa_cache_lookup_by_h(entry->hSAEntry[i]);
		if (sa == NULL)
			continue;

		if (sa->direction == CDX_DPA_IPSEC_OUTBOUND) {
			info->to_sec_fqid =
			    sa->pSec_sa_context->to_sec_fqid;
			info->sa_family = sa->family;
			info->tnl_hdr_size =
			    (sa->dev_mtu - sa->mtu);
		} else {
			info->l3_info.ipsec_inbound_flow = 1;
			dpa_ipsec_ofport_td(ipsec_instance,
			    info->tbl_type, &info->td, &info->port_id);
		}
	}
	return (0);
}

/* ================================================================
 * SA context allocation / free
 * ================================================================ */

void
cdx_ipsec_sec_sa_context_free(void *arg)
{
	PDpaSecSAContext pdpa_sec_context = (PDpaSecSAContext)arg;

	if (pdpa_sec_context == NULL)
		return;

	if (pdpa_sec_context->dpa_ipsecsa_handle)
		cdx_dpa_ipsecsa_release(pdpa_sec_context->dpa_ipsecsa_handle);
	if (pdpa_sec_context->cipher_data.cipher_key)
		free(pdpa_sec_context->cipher_data.cipher_key, M_CDX);
	if (pdpa_sec_context->auth_data.auth_key)
		free(pdpa_sec_context->auth_data.auth_key, M_CDX);
	if (pdpa_sec_context->auth_data.split_key)
		free(pdpa_sec_context->auth_data.split_key, M_CDX);
	if (pdpa_sec_context->sec_desc_extra_cmds_unaligned)
		free(pdpa_sec_context->sec_desc_extra_cmds_unaligned, M_CDX);
	if (pdpa_sec_context->rjob_desc_unaligned)
		free(pdpa_sec_context->rjob_desc_unaligned, M_CDX);
	free(pdpa_sec_context, M_CDX);
}

void *
cdx_ipsec_sec_sa_context_alloc(uint32_t handle)
{
	PDpaSecSAContext ctx;

	ctx = malloc(sizeof(DpaSecSAContext), M_CDX, M_WAITOK | M_ZERO);

	ctx->cipher_data.cipher_key =
	    malloc(MAX_CIPHER_KEY_LEN, M_CDX, M_WAITOK | M_ZERO);

	ctx->auth_data.auth_key =
	    malloc(MAX_AUTH_KEY_LEN, M_CDX, M_WAITOK | M_ZERO);

	ctx->auth_data.split_key =
	    malloc(MAX_AUTH_KEY_LEN, M_CDX, M_WAITOK | M_ZERO);

	/*
	 * Allocate space for extra descriptor commands (extended descriptor).
	 * Aligned to CORE_CACHELINE_SIZE (64 bytes).
	 */
	ctx->sec_desc_extra_cmds_unaligned =
	    malloc(2 * MAX_EXTRA_DESC_COMMANDS + 64, M_CDX,
	    M_WAITOK | M_ZERO);
	ctx->sec_desc_extra_cmds =
	    (uint32_t *)roundup2(
	    (uintptr_t)ctx->sec_desc_extra_cmds_unaligned, 64);
	if (ctx->sec_desc_extra_cmds_unaligned ==
	    (uint32_t *)(void *)ctx->sec_desc_extra_cmds)
		ctx->sec_desc_extra_cmds += 64 / 4;

	/*
	 * Allocate space for the SEC replacement job descriptor.
	 * Requires 64-byte alignment.
	 */
	ctx->rjob_desc_unaligned =
	    malloc(MAX_CAAM_DESCSIZE * sizeof(uint32_t) + 64, M_CDX,
	    M_WAITOK | M_ZERO);
	ctx->rjob_desc =
	    (uint32_t *)roundup2((uintptr_t)ctx->rjob_desc_unaligned, 64);

	/* Allocate per-SA FQs + sec_descriptor via DPAA plumbing */
	ctx->dpa_ipsecsa_handle = cdx_dpa_ipsecsa_alloc(NULL, handle);
	if (ctx->dpa_ipsecsa_handle == NULL) {
		DPA_ERROR("%s: failed to allocate DPAA SA resources\n",
		    __func__);
		cdx_ipsec_sec_sa_context_free(ctx);
		return (NULL);
	}

	ctx->sec_desc = get_shared_desc(ctx->dpa_ipsecsa_handle);
	ctx->to_sec_fqid = get_fqid_to_sec(ctx->dpa_ipsecsa_handle);
	ctx->from_sec_fqid = get_fqid_from_sec(ctx->dpa_ipsecsa_handle);
#ifdef UNIQUE_IPSEC_CP_FQID
	ctx->to_cp_fqid = ipsec_get_to_cp_fqid(ctx->dpa_ipsecsa_handle);
#endif

	DPA_INFO("%s: to_sec=%u from_sec=%u to_cp=%u\n", __func__,
	    ctx->to_sec_fqid, ctx->from_sec_fqid, ctx->to_cp_fqid);

	return (ctx);
}

/* ================================================================
 * SA delete / resource release
 * ================================================================ */

int
cdx_ipsec_delete_fp_entry(PSAEntry pSA)
{
	struct hw_ct *hwct;

	DPA_INFO("%s: dir=%s handle=%x fqid=%x\n", __func__,
	    (pSA->direction) ? "INBOUND" : "OUTBOUND",
	    pSA->handle,
	    pSA->pSec_sa_context ? pSA->pSec_sa_context->to_sec_fqid : 0);

	/*
	 * NAT-T multi-SPI handling: if multiple SAs share the same
	 * hash table entry, decrement refcount and return.
	 */
	if (IS_NATT_SA(pSA) && pSA->ct && pSA->ct->handle) {
		if (pSA->direction == CDX_DPA_IPSEC_OUTBOUND &&
		    pSA->ct->natt_out_refcnt > 1) {
			pSA->ct->natt_out_refcnt--;
			pSA->ct = NULL;
			return (0);
		} else if (pSA->direction == CDX_DPA_IPSEC_INBOUND &&
		    pSA->ct->natt_in_refcnt > 1) {
			pSA->ct->natt_in_refcnt--;
			pSA->ct = NULL;
			return (0);
		}
	}

	if (pSA->ct != NULL && pSA->ct->handle != NULL) {
		if (ExternalHashTableDeleteKey(pSA->ct->td,
		    pSA->ct->index, pSA->ct->handle)) {
			DPA_ERROR("%s: unable to remove hash table entry\n",
			    __func__);
			return (-1);
		}
		ExternalHashTableEntryFree(pSA->ct->handle);
		pSA->ct->handle = NULL;
		hwct = pSA->ct;
		pSA->ct = NULL;
		free(hwct, M_CDX);
	}
	return (0);
}

static void
cdx_ipsec_delete_fp_hash_entry(PSAEntry pSA)
{
	struct hw_ct *hwct;

	if (pSA->ct != NULL && pSA->ct->handle != NULL) {
		ExternalHashTableEntryFree(pSA->ct->handle);
		pSA->ct->handle = NULL;
		hwct = pSA->ct;
		pSA->ct = NULL;
		free(hwct, M_CDX);
	}
}

/*
 * Timer callback for deferred SA resource release.
 * Checks that all per-SA FQs have been retired before freeing.
 */
static int
cdx_ipsec_release_sa_ctx_cbk(struct timer_entry_t *entry)
{
	PSAEntry pSA;
	PDpaSecSAContext sa_context;
	int ii, ret;

	pSA = container_of(entry, SAEntry, deletion_timer);
	cdx_timer_del(entry);

	/* Check frame queue states */
	for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {
		if (pSA->flags & (SA_FQ_WAIT_B4_FREE << ii)) {
			ret = cdx_ipsec_sa_fq_check_if_retired_state(
			    pSA->pSec_sa_context->dpa_ipsecsa_handle, ii);
			if (ret) {
				DPA_ERROR("%s: FQ %d not yet retired\n",
				    __func__, ii);
				cdx_timer_init(
				    (TIMER_ENTRY *)&pSA->deletion_timer,
				    cdx_ipsec_release_sa_ctx_cbk);
				cdx_timer_add(
				    (TIMER_ENTRY *)&pSA->deletion_timer,
				    SA_CTX_RELEASE_TIMER_VAL);
				return (0);
			}
			pSA->flags &= ~(SA_FQ_WAIT_B4_FREE << ii);
		}
	}

	/* Free hash table entry if needed */
	if (pSA->flags & SA_FREE_HASH_ENTRY)
		cdx_ipsec_delete_fp_hash_entry(pSA);

	/* Remove from FQID lookup list */
	sa_remove_from_list_fqid(pSA);

	/* Free SA context and SA entry */
	sa_context = pSA->pSec_sa_context;
	cdx_ipsec_sec_sa_context_free(sa_context);
	pSA->pSec_sa_context = NULL;
	sa_free(pSA);
	return (0);
}

void
cdx_ipsec_release_sa_resources(PSAEntry pSA)
{
	int ii, ret;

	pSA->flags |= SA_DELETE;

	/* Delete hash table entry */
	if (cdx_ipsec_delete_fp_entry(pSA))
		pSA->flags |= SA_FREE_HASH_ENTRY;

	/* Retire frame queues */
	if (pSA->pSec_sa_context != NULL &&
	    pSA->pSec_sa_context->dpa_ipsecsa_handle != NULL) {
		for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {
			ret = cdx_dpa_ipsec_retire_fq(
			    pSA->pSec_sa_context->dpa_ipsecsa_handle, ii);
			if (ret == 1)
				pSA->flags |= (SA_FQ_WAIT_B4_FREE << ii);
		}
	}

	/* Defer resource release via timer */
	cdx_timer_init((TIMER_ENTRY *)&pSA->deletion_timer,
	    cdx_ipsec_release_sa_ctx_cbk);
	cdx_timer_add((TIMER_ENTRY *)&pSA->deletion_timer,
	    SA_CTX_RELEASE_TIMER_VAL);
}

/* ================================================================
 * Inline statistics descriptor commands
 *
 * 4 words reserved in the descriptor for per-SA statistics:
 *   [0] padding (unused)
 *   [1] packet count (big-endian uint32_t)
 *   [2..3] byte count (big-endian uint64_t)
 * ================================================================ */

static void
build_stats_descriptor_part(PSAEntry sa, size_t pdb_len)
{
	uint32_t *desc;
	uint32_t stats_offset;
	PDpaSecSAContext ctx;

	ctx = sa->pSec_sa_context;
	desc = (uint32_t *)ctx->sec_desc->shared_desc;

	stats_offset = sizeof(ctx->sec_desc->hdr_word) + pdb_len -
	    CDX_DPA_IPSEC_STATS_LEN * sizeof(uint32_t);
	sa->stats_offset = stats_offset;
	memset((uint8_t *)desc + stats_offset, 0,
	    CDX_DPA_IPSEC_STATS_LEN * sizeof(uint32_t));

	/* Copy packet count from descriptor to MATH REG 0 */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 |
	    MOVE_WAITCOMP |
	    (stats_offset << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	/* Increment packet counter by 1 */
	append_math_add_imm_u32(desc, REG0, REG0, IMM, 1);

	/* Store packet count back to descriptor */
	append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF |
	    MOVE_WAITCOMP |
	    (stats_offset << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	/* Copy byte count from descriptor to MATH REG 0 */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 |
	    MOVE_WAITCOMP |
	    ((stats_offset + 8) << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	if (sa->direction == CDX_DPA_IPSEC_INBOUND) {
		/* Inbound: getting decrypted data size + padded bytes */
		append_math_add(desc, REG0, VARSEQINLEN, REG0,
		    MATH_LEN_8BYTE);
		/* Get padded bytes */
		append_math_add_imm_u32(desc, REG2, VARSEQOUTLEN, IMM, 0);
		/* Subtract padding */
		append_math_sub(desc, REG0, REG0, REG2, MATH_LEN_8BYTE);
	} else {
		append_math_add(desc, REG0, SEQINLEN, REG0,
		    MATH_LEN_8BYTE);
	}

	/* Store byte count back to descriptor */
	append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF |
	    MOVE_WAITCOMP |
	    ((stats_offset + 8) << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));
}

void
get_stats_from_sa(PSAEntry sa, uint32_t *pkts, uint64_t *bytes,
    uint8_t *pSeqOverflow)
{
	uint32_t *desc, *stats_desc;
	uint64_t *bytes_desc;
	uint64_t cur_seq;
	PDpaSecSAContext ctx;

	ctx = sa->pSec_sa_context;
	desc = (uint32_t *)ctx->sec_desc->shared_desc;
	stats_desc = desc + sa->stats_offset / 4;

	/* Packet count is at offset +1 word */
	stats_desc++;
	*pkts = be32toh(*stats_desc);

	/* Check sequence number for overflow soft limit */
	if (pSeqOverflow != NULL && !sa->seq_overflow) {
		if (sa->direction == CDX_DPA_IPSEC_OUTBOUND) {
			cur_seq = be32toh(
			    ctx->sec_desc->pdb_en.seq_num_ext_hi);
			cur_seq <<= 32;
			cur_seq |= be32toh(ctx->sec_desc->pdb_en.seq_num);
		} else {
			cur_seq = be32toh(
			    ctx->sec_desc->pdb_dec.seq_num_ext_hi);
			cur_seq <<= 32;
			cur_seq |= be32toh(ctx->sec_desc->pdb_dec.seq_num);
		}

		if (sa->flags & SA_ALLOW_EXT_SEQ_NUM) {
			if (cur_seq > SEQ_NUM_ESN_SOFT_LIMIT) {
				*pSeqOverflow = 1;
				sa->seq_overflow = 1;
			}
		} else {
			if (cur_seq > SEQ_NUM_SOFT_LIMIT) {
				*pSeqOverflow = 1;
				sa->seq_overflow = 1;
			}
		}
	}

	/* Byte count is at offset +2 words (uint64_t) */
	stats_desc++;
	bytes_desc = (uint64_t *)stats_desc;
	*bytes = be64toh(*bytes_desc);
}

static inline void
save_stats_in_external_mem(PSAEntry sa)
{
	uint32_t *desc;
	uint32_t stats_offset;

	desc = (uint32_t *)sa->pSec_sa_context->sec_desc->shared_desc;
	stats_offset = sa->stats_offset;

	/*
	 * STORE command: write stats from descriptor buffer to itself.
	 * Length is in 4-byte words for Descriptor Buffer, offset in words.
	 */
	append_store(desc, 0, CDX_DPA_IPSEC_STATS_LEN,
	    LDST_CLASS_DECO |
	    ((stats_offset / 4) << LDST_OFFSET_SHIFT) |
	    LDST_SRCDST_WORD_DESCBUF_SHARED);

	/* JUMP CALM to ensure previous operation completed */
	append_jump(desc, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));
}

/* ================================================================
 * PDB builders
 * ================================================================ */

int
cdx_ipsec_build_in_sa_pdb(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	PDpaSecSAContext ctx;
	struct decap_ccm_opt *ccm_opt;
	uint8_t *salt;

	ctx = sa->pSec_sa_context;
	sec_desc = ctx->sec_desc;
	memset(&sec_desc->pdb_dec, 0, sizeof(sec_desc->pdb_dec));

	sec_desc->pdb_dec.seq_num =
	    cpu_to_caam32(sa->seq & SEQ_NUM_LOW_MASK);

	if (sa->flags & SA_ALLOW_EXT_SEQ_NUM) {
		sec_desc->pdb_dec.seq_num_ext_hi =
		    cpu_to_caam32((sa->seq & SEQ_NUM_HI_MASK) >> 32);
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_ESN;
	}

	if (sa->flags & SA_ALLOW_SEQ_ROLL) {
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARSNONE;
	} else {
		/* Default anti-replay window of 64 */
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARS64;
	}

	if (sa->mode == SA_MODE_TUNNEL) {
		/* Offset in frame where encrypted payload starts */
		sec_desc->pdb_dec.options |=
		    (sa->header_len << PDBHDRLEN_ESP_DECAP_SHIFT);

		if (sa->natt.sport && sa->natt.dport) {
			/* NAT-T: also strip the UDP header */
			sec_desc->pdb_dec.options &= 0xf000ffff;
			sec_desc->pdb_dec.options |=
			    ((sa->header_len + UDP_HEADER_LEN) <<
			     PDBHDRLEN_ESP_DECAP_SHIFT);
		}

		/* By default, copy DSCP from outer to inner */
		sec_desc->pdb_dec.options |= PDBHMO_ESP_DIFFSERV;

		if (sa->hdr_flags) {
			if (sa->hdr_flags & SA_HDR_DEC_TTL)
				sec_desc->pdb_dec.options |=
				    PDBHMO_ESP_DECAP_DEC_TTL;
		}
	} else {
		/* Transport mode */
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_OUTFMT;
		if (sec_era > 4)
			sec_desc->pdb_dec.options |= PDBOPTS_ESP_AOFL;

		if (sa->family == PROTO_IPV4) {
			sec_desc->pdb_dec.options |=
			    (sizeof(ipv4_hdr_t) <<
			     PDBHDRLEN_ESP_DECAP_SHIFT);
			sec_desc->pdb_dec.options |=
			    PDBOPTS_ESP_VERIFY_CSUM;
		} else {
			sec_desc->pdb_dec.options |=
			    (sizeof(ipv6_hdr_t) <<
			     PDBHDRLEN_ESP_DECAP_SHIFT);
			sec_desc->pdb_dec.options |= PDBOPTS_ESP_IPVSN;
		}
		sec_desc->pdb_dec.options |=
		    (0x01 << PDB_NH_OFFSET_SHIFT);
	}

	/* Convert options to CAAM byte order */
	sec_desc->pdb_dec.options =
	    cpu_to_caam32(sec_desc->pdb_dec.options);

	/* Fill salt for GCM / CCM */
	salt = ctx->cipher_data.cipher_key + ctx->cipher_data.cipher_key_len;

	if (ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM8 ||
	    ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM12 ||
	    ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM16 ||
	    ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GMAC) {
		memcpy(sec_desc->pdb_dec.gcm.salt, salt, AES_GCM_SALT_LEN);
	} else if (ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM8) {
		memcpy(&sec_desc->pdb_dec.ccm.salt[1], salt,
		    AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)
		    &sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV8_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	} else if (ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM12) {
		memcpy(&sec_desc->pdb_dec.ccm.salt[1], salt,
		    AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)
		    &sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV12_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	} else if (ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM16) {
		memcpy(&sec_desc->pdb_dec.ccm.salt[1], salt,
		    AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)
		    &sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV16_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}

	return (0);
}

int
cdx_ipsec_build_out_sa_pdb(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	PDpaSecSAContext ctx;
	struct ip *outer_ip4;
	struct ip6_hdr *outer_ip6;
	struct encap_ccm_opt *ccm_opt;
	uint8_t *salt;

	ctx = sa->pSec_sa_context;
	sec_desc = ctx->sec_desc;
	memset(&sec_desc->pdb_en, 0, sizeof(sec_desc->pdb_en));

	/* SPI is already in network byte order */
	sec_desc->pdb_en.spi = sa->id.spi;

	if (sa->flags & SA_ALLOW_EXT_SEQ_NUM) {
		sec_desc->pdb_en.seq_num_ext_hi =
		    cpu_to_caam32((sa->seq & SEQ_NUM_HI_MASK) >> 32);
		sec_desc->pdb_en.options |= PDBOPTS_ESP_ESN;
	}
	sec_desc->pdb_en.seq_num =
	    cpu_to_caam32(sa->seq & SEQ_NUM_LOW_MASK);

	/* IV from internal random generator */
	sec_desc->pdb_en.options |= PDBOPTS_ESP_IVSRC;

	if (sa->mode == SA_MODE_TUNNEL) {
		sec_desc->pdb_en.options |= PDBOPTS_OIHI_FROM_PDB;

		if (sa->hdr_flags) {
			if (sa->hdr_flags & SA_HDR_DEC_TTL)
				sec_desc->pdb_en.options |=
				    PDBHMO_ESP_ENCAP_DEC_TTL;
			if ((sa->hdr_flags & SA_HDR_COPY_DF) &&
			    sa->family == PROTO_IPV4)
				sec_desc->pdb_en.options |=
				    PDBHMO_ESP_DFBIT;
		}

		/* Copy the outer IP header from SA tunnel info */
		memcpy(&sec_desc->pdb_en.ip_hdr[0],
		    &sa->tunnel.ip4, sa->header_len);
		sec_desc->pdb_en.ip_hdr_len = sa->header_len;

		/* NAT-T: append UDP header to PDB */
		if (sa->natt.sport && sa->natt.dport) {
			struct udphdr *udp;
			uint8_t *tmp;

			tmp = (uint8_t *)&sec_desc->pdb_en.ip_hdr[0];
			udp = (struct udphdr *)(tmp + sa->header_len);
			udp->uh_sport = htons(sa->natt.sport);
			udp->uh_dport = htons(sa->natt.dport);
			udp->uh_sum = 0;
			udp->uh_ulen = 0;
			sec_desc->pdb_en.ip_hdr_len += UDP_HEADER_LEN;
			sec_desc->pdb_en.options |= PDBOPTS_NAT;
			sec_desc->pdb_en.options |= PDBOPTS_NAT_UDP_CHECKSM;

			if (sa->header_len == IPV4_HDR_SIZE) {
				outer_ip4 = (struct ip *)
				    &sec_desc->pdb_en.ip_hdr[0];
				outer_ip4->ip_p = IPPROTO_UDP;
			} else {
				outer_ip6 = (struct ip6_hdr *)
				    &sec_desc->pdb_en.ip_hdr[0];
				outer_ip6->ip6_nxt = IPPROTO_UDP;
			}
		}

		/* Convert ip_hdr_len to CAAM byte order */
		sec_desc->pdb_en.ip_hdr_len =
		    cpu_to_caam32(sec_desc->pdb_en.ip_hdr_len);

		if (sa->family == PROTO_IPV4) {
			outer_ip4 = (struct ip *)
			    &sec_desc->pdb_en.ip_hdr[0];
			if (!sa->natt.sport && !sa->natt.dport)
				outer_ip4->ip_p = IPPROTO_ESP;
			/*
			 * Set total length from ip_hdr_len.
			 * ip_hdr_len is in CAAM BE format at this point.
			 */
			outer_ip4->ip_len =
			    ((sec_desc->pdb_en.ip_hdr_len >> 16) & 0xffff);
			outer_ip4->ip_sum = 0;
			outer_ip4->ip_sum = in_cksum_hdr(outer_ip4);
		} else {
			outer_ip6 = (struct ip6_hdr *)
			    &sec_desc->pdb_en.ip_hdr[0];
			if (!sa->natt.sport && !sa->natt.dport)
				outer_ip6->ip6_nxt = IPPROTO_ESP;
		}
	} else {
		/* Transport mode */
		sec_desc->pdb_en.options |= PDBOPTS_ESP_INCIPHDR;

		if (sa->family == PROTO_IPV4) {
			sec_desc->pdb_en.ip_hdr_len = sizeof(ipv4_hdr_t);
			sec_desc->pdb_en.options |= PDBOPTS_ESP_UPDATE_CSUM;
		} else {
			sec_desc->pdb_en.ip_hdr_len = sizeof(ipv6_hdr_t);
			sec_desc->pdb_en.options |= PDBOPTS_ESP_IPV6;
		}
		sec_desc->pdb_en.options |= (0x01 << PDB_NH_OFFSET_SHIFT);
		sec_desc->pdb_en.options |=
		    (IPPROTO_ESP << PDBNH_ESP_ENCAP_SHIFT);
		sec_desc->pdb_en.ip_hdr_len =
		    cpu_to_caam32(sec_desc->pdb_en.ip_hdr_len);
	}

	/* Convert options to CAAM byte order */
	sec_desc->pdb_en.options = cpu_to_caam32(sec_desc->pdb_en.options);

	/* Fill salt for GCM / CCM */
	salt = ctx->cipher_data.cipher_key + ctx->cipher_data.cipher_key_len;

	if (ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM8 ||
	    ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM12 ||
	    ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM16 ||
	    ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GMAC) {
		memcpy(sec_desc->pdb_en.gcm.salt, salt, AES_GCM_SALT_LEN);
	} else if (ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM8) {
		memcpy(&sec_desc->pdb_en.ccm.salt[1], salt,
		    AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)
		    &sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV8_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	} else if (ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM12) {
		memcpy(&sec_desc->pdb_en.ccm.salt[1], salt,
		    AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)
		    &sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV12_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	} else if (ctx->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM16) {
		memcpy(&sec_desc->pdb_en.ccm.salt[1], salt,
		    AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)
		    &sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV16_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}

	return (0);
}

/* ================================================================
 * Shared descriptor builder
 *
 * Builds the CAAM protocol shared descriptor for an IPsec SA.
 * The descriptor layout:
 *   [header word]
 *   [PDB (encap or decap)]
 *   [stats words (4)]
 *   [key jump]
 *   [auth key (split or normal)]
 *   [cipher key]
 *   [L2 header copy commands]
 *   [stats update commands]
 *   [OPERATION (IPsec protocol)]
 *   [save stats to external mem]
 * ================================================================ */

int
cdx_ipsec_build_shared_descriptor(PSAEntry sa,
    uint64_t auth_key_dma, uint64_t crypto_key_dma,
    uint32_t bytes_to_copy)
{
	uint32_t *desc, *key_jump_cmd;
	int opthdrsz;
	size_t pdb_len = 0;
	uint32_t sa_op;
	PDpaSecSAContext ctx;

	ctx = sa->pSec_sa_context;
	desc = (uint32_t *)ctx->sec_desc->shared_desc;

	/* Reserve 4 words for statistics */
	pdb_len = CDX_DPA_IPSEC_STATS_LEN * sizeof(uint32_t);

	if (sa->direction == CDX_DPA_IPSEC_OUTBOUND) {
		/*
		 * Compute optional header size, rounded up to
		 * descriptor word size.
		 */
		opthdrsz =
		    (caam32_to_cpu(ctx->sec_desc->pdb_en.ip_hdr_len) +
		    3) & ~3;
		pdb_len += sizeof(struct ipsec_encap_pdb) + opthdrsz;
		init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL,
		    pdb_len);
		sa_op = OP_TYPE_ENCAP_PROTOCOL;
	} else {
		pdb_len += sizeof(struct ipsec_decap_pdb);
		init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL,
		    pdb_len);
		sa_op = OP_TYPE_DECAP_PROTOCOL;
	}

	/* Key jump — skip keys if already loaded (shared descriptor) */
	if ((ctx->auth_data.split_key_len ||
	     ctx->auth_data.auth_key_len) &&
	    ctx->cipher_data.cipher_key_len)
		key_jump_cmd = append_jump(desc, CLASS_BOTH |
		    JUMP_TEST_ALL | JUMP_COND_SHRD | JUMP_COND_SELF);
	else if (ctx->cipher_data.cipher_key_len)
		key_jump_cmd = append_jump(desc, CLASS_1 |
		    JUMP_TEST_ALL | JUMP_COND_SHRD | JUMP_COND_SELF);
	else
		key_jump_cmd = append_jump(desc, CLASS_2 |
		    JUMP_TEST_ALL | JUMP_COND_SHRD | JUMP_COND_SELF);

	/* Append authentication key (split or normal) */
	if (ctx->auth_data.split_key_len)
		append_key(desc, auth_key_dma,
		    ctx->auth_data.split_key_len,
		    CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else if (ctx->auth_data.auth_key_len)
		append_key(desc, auth_key_dma,
		    ctx->auth_data.auth_key_len,
		    CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	if (ctx->cipher_data.cipher_key_len)
		append_key(desc, crypto_key_dma,
		    ctx->cipher_data.cipher_key_len,
		    CLASS_1 | KEY_DEST_CLASS_REG);

	set_jump_tgt_here(desc, key_jump_cmd);

	/* Copy L2 header from original to outer packet */
	if (bytes_to_copy != 0) {
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

		append_seq_fifo_load(desc, bytes_to_copy,
		    FIFOLD_TYPE_MSG | FIFOLD_CLASS_BOTH |
		    FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_LAST2 |
		    FIFOLD_TYPE_FLUSH1);

		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

		append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO |
		    bytes_to_copy);

		append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA,
		    bytes_to_copy);
	}

	/* Build stats for outbound before OPERATION */
	if (sa->direction != CDX_DPA_IPSEC_INBOUND)
		build_stats_descriptor_part(sa, pdb_len);

	/* Protocol-specific OPERATION */
	if (sa->mode == SA_MODE_TUNNEL)
		append_operation(desc, OP_PCLID_IPSEC_TUNNEL | sa_op |
		    ctx->cipher_data.cipher_type |
		    ctx->auth_data.auth_type);
	else
		append_operation(desc, OP_PCLID_IPSEC | sa_op |
		    ctx->cipher_data.cipher_type |
		    ctx->auth_data.auth_type);

	/* Build stats for inbound after OPERATION */
	if (sa->direction == CDX_DPA_IPSEC_INBOUND)
		build_stats_descriptor_part(sa, pdb_len);

	/* Save stats to external memory */
	save_stats_in_external_mem(sa);

	/* Check descriptor length fits in QI shared descriptor limit */
	if (desc_len(desc) >= MAX_CAAM_SHARED_DESCSIZE) {
		DPA_ERROR("%s: descriptor too long (%d words, max %d)\n",
		    __func__, desc_len(desc), MAX_CAAM_SHARED_DESCSIZE);
		memset((uint8_t *)desc + sa->stats_offset, 0,
		    MAX_CAAM_DESCSIZE * sizeof(uint32_t) -
		    sa->stats_offset);
		return (-EPERM);
	}

	return (0);
}

/* ================================================================
 * Shared descriptor orchestrator
 *
 * Builds PDB, maps keys, calls build_shared_descriptor,
 * sets up preheader for QI.
 * ================================================================ */

int
cdx_ipsec_create_shareddescriptor(PSAEntry sa, uint32_t bytes_to_copy)
{
	struct sec_descriptor *sec_desc;
	uint64_t auth_key_dma = 0;
	uint64_t crypto_key_dma;
	int ret;
	uint32_t bpid, buf_size;
	PDpaSecSAContext ctx;

	if (cdx_dpa_get_ipsec_pool_info(&bpid, &buf_size))
		return (-EIO);

	ctx = sa->pSec_sa_context;

	/* Build the PDB */
	if (sa->direction == CDX_DPA_IPSEC_OUTBOUND)
		cdx_ipsec_build_out_sa_pdb(sa);
	else
		cdx_ipsec_build_in_sa_pdb(sa);

	/*
	 * Map keys for DMA.
	 * LS1046A is DMA-coherent via CCI-400, so vtophys() suffices.
	 */
	if (ctx->auth_data.split_key_len) {
		auth_key_dma = vtophys(ctx->auth_data.split_key);
	} else if (ctx->auth_data.auth_key_len) {
		auth_key_dma = vtophys(ctx->auth_data.auth_key);
	}

	crypto_key_dma = vtophys(ctx->cipher_data.cipher_key);

	/* Build the shared descriptor */
	ret = cdx_ipsec_build_shared_descriptor(sa, auth_key_dma,
	    crypto_key_dma, bytes_to_copy);

	if (ret == -EPERM) {
		/*
		 * Descriptor too long — extended descriptors would be
		 * needed.  Not yet implemented on FreeBSD.
		 */
		DPA_ERROR("%s: extended descriptors not supported\n",
		    __func__);
		return (-EFAULT);
	} else if (ret != 0) {
		DPA_ERROR("%s: failed to build shared descriptor "
		    "(spi %u, ret %d)\n", __func__, sa->id.spi, ret);
		return (-EFAULT);
	}

	/* Setup preheader for CAAM QI */
	sec_desc = ctx->sec_desc;
	sec_desc->preheader = 0;

	PREHEADER_PREP_IDLEN(sec_desc->preheader,
	    desc_len(sec_desc->shared_desc));
	PREHEADER_PREP_BPID(sec_desc->preheader, bpid);
	PREHEADER_PREP_BSIZE(sec_desc->preheader, buf_size);

	if (sa->direction == CDX_DPA_IPSEC_INBOUND)
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
		    post_sec_in_data_off);
	else
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
		    post_sec_out_data_off);

	/* Convert preheader to CAAM byte order */
	sec_desc->preheader = cpu_to_caam64(sec_desc->preheader);

	DPA_INFO("%s: shdesc built, %d words, dir=%s\n", __func__,
	    desc_len(sec_desc->shared_desc),
	    (sa->direction == CDX_DPA_IPSEC_OUTBOUND) ? "out" : "in");

	return (0);
}

/* ================================================================
 * Split key generation
 *
 * Generates HMAC split key via CAAM Job Ring.
 * Required for AES-CBC+HMAC-SHA algorithms.
 * Not needed for AES-GCM (combined cipher+auth).
 * ================================================================ */

/* Map auth algorithm type to CAAM algorithm selector + split key length */
int
cdx_ipsec_get_split_key_info(struct auth_params *auth_param,
    uint32_t *hmac_alg)
{
	/*
	 * Running digest sizes for MDHA pads:
	 * MD5=16, SHA1=20, SHA224=32, SHA256=32, SHA384=64, SHA512=64
	 */
	static const uint8_t mdpadlen[] = {16, 20, 32, 32, 64, 64};

	switch (auth_param->auth_type) {
	case OP_PCL_IPSEC_HMAC_MD5_96:
	case OP_PCL_IPSEC_HMAC_MD5_128:
		*hmac_alg = OP_ALG_ALGSEL_MD5;
		break;
	case OP_PCL_IPSEC_HMAC_SHA1_96:
	case OP_PCL_IPSEC_HMAC_SHA1_160:
		*hmac_alg = OP_ALG_ALGSEL_SHA1;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_256_128:
		*hmac_alg = OP_ALG_ALGSEL_SHA256;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_384_192:
		*hmac_alg = OP_ALG_ALGSEL_SHA384;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_512_256:
		*hmac_alg = OP_ALG_ALGSEL_SHA512;
		break;
	case OP_PCL_IPSEC_AES_XCBC_MAC_96:
		*hmac_alg = 0;
		auth_param->split_key_len = 0;
		break;
	default:
		/*
		 * For GCM and other combined modes, auth_type is 0
		 * and no split key is needed.
		 */
		if (auth_param->auth_type == OP_PCL_IPSEC_HMAC_NULL) {
			*hmac_alg = 0;
			auth_param->split_key_len = 0;
			return (0);
		}
		DPA_ERROR("%s: unsupported auth algorithm %u\n",
		    __func__, auth_param->auth_type);
		return (-EINVAL);
	}

	if (*hmac_alg)
		auth_param->split_key_len =
		    mdpadlen[(*hmac_alg & OP_ALG_ALGSEL_SUBMASK) >>
		    OP_ALG_ALGSEL_SHIFT] * 2;

	return (0);
}

int
cdx_ipsec_generate_split_key(struct auth_params *auth_param)
{
	uint32_t alg_sel = 0;
	int ret;
	uint32_t *desc;
	uint64_t dma_addr_in, dma_addr_out;

	ret = cdx_ipsec_get_split_key_info(auth_param, &alg_sel);
	/* Exit if error or no split key needed (GCM, XCBC-MAC) */
	if (ret < 0 || alg_sel == 0)
		return (ret);

	auth_param->split_key_pad_len =
	    (auth_param->split_key_len + 15) & ~15;

	/*
	 * Build a Job Ring descriptor for split key generation.
	 *
	 * Descriptor sequence:
	 *   HEADER
	 *   KEY (auth key, CLASS 2)
	 *   OPERATION (HMAC INIT, CLASS 2)
	 *   FIFO LOAD (zero-length, triggers internal key expansion)
	 *   FIFO STORE (split key output)
	 *
	 * On LS1046A, DMA is coherent via CCI-400, so vtophys() works.
	 */
	desc = malloc(CAAM_CMD_SZ * 8 + CAAM_PTR_SZ * 2, M_CDX,
	    M_WAITOK | M_ZERO);

	dma_addr_in = vtophys(auth_param->auth_key);
	dma_addr_out = vtophys(auth_param->split_key);

	init_job_desc(desc, 0);
	append_key(desc, dma_addr_in, auth_param->auth_key_len,
	    CLASS_2 | KEY_DEST_CLASS_REG);
	append_operation(desc, OP_ALG_TYPE_CLASS2 | alg_sel |
	    OP_ALG_AAI_HMAC | OP_ALG_DECRYPT | OP_ALG_AS_INIT);
	append_fifo_load_as_imm(desc, NULL, 0,
	    LDST_CLASS_2_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);
	append_fifo_store(desc, dma_addr_out, auth_param->split_key_len,
	    LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);

	/*
	 * Submit the descriptor to a CAAM Job Ring.
	 *
	 * TODO: Currently there is no public JR submission API exported
	 * from the CAAM JR driver for out-of-tree modules.  For GCM
	 * (which is the primary target), no split key is needed.
	 * For CBC+HMAC support, we need to either:
	 *   (a) Export caam_jr_enqueue() from the kernel JR driver, or
	 *   (b) Use the DKP (Derived Key Protocol) inline in the shdesc
	 *
	 * For now, print a warning and return error for non-GCM algorithms
	 * that require split keys.
	 */
	DPA_ERROR("%s: JR-based split key generation not yet available "
	    "for out-of-tree modules (alg_sel=0x%x). "
	    "Use AES-GCM which does not require split keys.\n",
	    __func__, alg_sel);

	free(desc, M_CDX);
	return (-ENOTSUP);
}

/* ================================================================
 * SA direction helper
 * ================================================================ */

int
cdx_dpa_ipsec_find_sa_direction(PSAEntry sa)
{

	return (sa->direction);
}

/* cdx_ipsec_handle_get_inbound_sagd: provided by Tier 1 control_ipsec.c */

/* ================================================================
 * Classification table entry operations
 *
 * Programs FMan enhanced hash table entries for ESP flow matching.
 * Inbound: WAN port ESP table, key = {dst_ip, proto, SPI}
 * Outbound: IPsec OH port ESP table, key = {dst_ip, proto, SPI}
 * ================================================================ */

static int
get_tbl_type(PSAEntry sa)
{

	if (IS_NATT_SA(sa)) {
		if (sa->family == PROTO_IPV4)
			return (IPV4_UDP_TABLE);
		else
			return (IPV6_UDP_TABLE);
	} else {
		if (sa->family == PROTO_IPV4)
			return (ESP_IPV4_TABLE);
		else
			return (ESP_IPV6_TABLE);
	}
}

static int
fill_ipsec_key_info(PSAEntry sa, struct en_exthash_tbl_entry *tbl_entry,
    uint32_t port_id)
{
	union dpa_key *key;
	uint32_t key_size;
	uint32_t ii;
	uint8_t *sptr;

	key = (union dpa_key *)&tbl_entry->hashentry.key[0];
	key->portid = port_id;
	key_size = 1;

	if (sa->family == PROTO_IPV4) {
		key_size += sizeof(struct ipv4_esp_key);
		key->ipv4_esp_key.ipv4_daddr = sa->id.daddr.a6[0];
		key->ipv4_esp_key.ipv4_protocol = IPPROTOCOL_ESP;
		key->ipv4_esp_key.spi = sa->id.spi;
	} else {
		key_size += sizeof(struct ipv6_esp_key);
		sptr = (uint8_t *)&sa->id.daddr;
		for (ii = 0; ii < 16; ii++)
			key->ipv6_tcpudp_key.ipv6_saddr[ii] = *(sptr + ii);
		key->ipv6_esp_key.ipv6_protocol = IPPROTOCOL_ESP;
		key->ipv6_esp_key.spi = sa->id.spi;
	}
	return (key_size);
}

static int
fill_natt_key_info(PSAEntry sa, struct en_exthash_tbl_entry *tbl_entry,
    uint32_t port_id)
{
	union dpa_key *key;
	unsigned char *saddr, *daddr;
	uint32_t key_size;
	int i;

	key = (union dpa_key *)&tbl_entry->hashentry.key[0];
	key->portid = port_id;

	if (sa->family == PROTO_IPV4) {
		key_size = sizeof(struct ipv4_tcpudp_key) + 1;
		key->ipv4_tcpudp_key.ipv4_saddr = sa->id.saddr[0];
		key->ipv4_tcpudp_key.ipv4_daddr = sa->id.daddr.a6[0];
		key->ipv4_tcpudp_key.ipv4_protocol = IPPROTO_UDP;
		key->ipv4_tcpudp_key.ipv4_sport =
		    htobe16(sa->natt.sport);
		key->ipv4_tcpudp_key.ipv4_dport =
		    htobe16(sa->natt.dport);
	} else {
		saddr = (unsigned char *)&sa->id.saddr[0];
		daddr = (unsigned char *)&sa->id.daddr.a6[0];
		key_size = sizeof(struct ipv6_tcpudp_key) + 1;
		for (i = 0; i < 16; i++)
			key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
		for (i = 0; i < 16; i++)
			key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];
		key->ipv6_tcpudp_key.ipv6_protocol = IPPROTO_UDP;
		key->ipv6_tcpudp_key.ipv6_sport =
		    htobe16(sa->natt.sport);
		key->ipv6_tcpudp_key.ipv6_dport =
		    htobe16(sa->natt.dport);
	}
	return (key_size);
}

int
cdx_ipsec_add_classification_table_entry(PSAEntry sa)
{
	int retval;
	uint32_t flags;
	uint8_t *ptr;
	uint32_t key_size;
	int tbl_type;
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	uint32_t sa_dir_in = 0;
	uint32_t itf_id = 0;
	uint32_t bytes_to_copy = ETH_HDR_LEN;

	info = malloc(sizeof(struct ins_entry_info), M_CDX,
	    M_WAITOK | M_ZERO);
	tbl_entry = NULL;

	/* Allocate hw connection tracker entry */
	sa->ct = malloc(sizeof(struct hw_ct), M_CDX, M_WAITOK | M_ZERO);

	/* FMAN index for IPsec (single FMAN on LS1046A) */
	info->fm_idx = IPSEC_FMAN_IDX;

	/* Get PCD handle for this FMAN */
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (info->fm_pcd == NULL) {
		DPA_ERROR("%s: unable to get PCD handle for fman %u\n",
		    __func__, info->fm_idx);
		goto err_ret;
	}

	flags = 0;
	tbl_type = get_tbl_type(sa);
	if (tbl_type == -1) {
		DPA_ERROR("%s: unable to determine table type\n", __func__);
		goto err_ret;
	}

	/* Get port and table info based on direction */
	if (sa->direction == CDX_DPA_IPSEC_INBOUND) {
		sa_dir_in = 1;

		/* Inbound: look up WAN port by destination IP */
		if (dpa_get_iface_info_by_ipaddress(sa->family,
		    &sa->id.daddr.a6[0], NULL, &itf_id, &info->port_id,
		    &sa->netdev, (uint32_t)sa->handle) != SUCCESS) {
			DPA_ERROR("%s: dpa_get_iface_info_by_ipaddress "
			    "failed\n", __func__);
			goto err_ret;
		}

		/* Get table descriptor for this port and table type */
		sa->ct->td = dpa_get_tdinfo(info->fm_idx, info->port_id,
		    tbl_type);
		if (sa->ct->td == NULL) {
			DPA_ERROR("%s: unable to get td for port %u, "
			    "type %d\n", __func__, info->port_id, tbl_type);
			goto err_ret;
		}

		info->sa_itf_id = itf_id;
		dpa_get_l2l3_info_by_itf_id(itf_id, &info->l2_info,
		    &info->l3_info, sa_dir_in);
	} else {
		/* Outbound: use IPsec OH port ESP table */
		sa_dir_in = 0;
		dpa_ipsec_ofport_td(ipsec_instance, tbl_type,
		    &sa->ct->td, &info->port_id);

		if (dpa_get_iface_info_by_ipaddress(sa->family,
		    &sa->id.saddr[0], NULL, NULL, NULL,
		    &sa->netdev, (uint32_t)sa->handle) != SUCCESS) {
			DPA_ERROR("%s: dpa_get_iface_info_by_ipaddress "
			    "failed (outbound)\n", __func__);
			goto err_ret;
		}

		if (dpa_get_out_tx_info_by_itf_id(sa->pRtEntry,
		    &info->l2_info, &info->l3_info)) {
			DPA_ERROR("%s: dpa_get_out_tx_info_by_itf_id "
			    "failed\n", __func__);
			goto err_ret;
		}
	}

	/* Build shared descriptor if not already done */
	if (!(sa->flags & SA_SH_DESC_BUILT)) {
		if (cdx_ipsec_create_shareddescriptor(sa, bytes_to_copy)) {
			DPA_ERROR("%s: unable to create shared desc\n",
			    __func__);
			goto err_ret;
		}
		sa->flags |= SA_SH_DESC_BUILT;
	}

	/* Get table descriptor for hash table operations */
	info->td = sa->ct->td;

	/* Allocate hash table entry */
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (tbl_entry == NULL) {
		DPA_ERROR("%s: unable to alloc hash table memory\n",
		    __func__);
		goto err_ret;
	}

	if (info->td == NULL) {
		DPA_ERROR("%s: NULL table descriptor\n", __func__);
		goto err_ret;
	}

	/* Fill key information from SA */
	if (IS_NATT_SA(sa))
		key_size = fill_natt_key_info(sa, tbl_entry, info->port_id);
	else
		key_size = fill_ipsec_key_info(sa, tbl_entry, info->port_id);

	if (key_size == 0) {
		DPA_ERROR("%s: unable to compose key\n", __func__);
		goto err_ret;
	}

	/* Set up opcode and parameter pointers in entry */
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
	ptr += roundup2(key_size, TBLENTRY_OPC_ALIGN);
	info->opcptr = ptr;
	ptr += MAX_OPCODES;
	flags = 0;

#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter =
	    htobe32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = htobe32(JIFFIES32);
	sa->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif

	SET_OPC_OFFSET(flags,
	    (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	SET_PARAM_OFFSET(flags,
	    (uint32_t)(ptr - (uint8_t *)tbl_entry));
	tbl_entry->hashentry.flags = htobe16(flags);
	info->paramptr = ptr;
	info->param_size = MAX_EN_EHASH_ENTRY_SIZE -
	    GET_PARAM_OFFSET(flags);

	/* Fix FQID and MTU for inbound packets to SEC */
	if (sa_dir_in) {
		info->l2_info.fqid = sa->pSec_sa_context->to_sec_fqid;
		info->l2_info.mtu = 0xffff;
		info->to_sec_fqid = sa->pSec_sa_context->to_sec_fqid;
	}

	/* Fill protocol-specific actions (opcodes) */
	if (fill_ipsec_actions(sa, info, sa_dir_in)) {
		DPA_ERROR("%s: unable to fill actions\n", __func__);
		goto err_ret;
	}

	/* Set result pointer based on SA type */
	if (IS_NATT_SA(sa) && sa_dir_in)
		tbl_entry->ipsec_preempt_params = info->preempt_params;
	else
		tbl_entry->enqueue_params = info->enqueue_params;

	sa->ct->handle = tbl_entry;

	/* Insert entry into hash table */
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry);
	if (retval == -1) {
		DPA_ERROR("%s: unable to add entry in hash table\n",
		    __func__);
		goto err_ret;
	}
	sa->ct->index = (uint16_t)retval;

	free(info, M_CDX);
	return (SUCCESS);

err_ret:
	if (sa->ct != NULL) {
		free(sa->ct, M_CDX);
		sa->ct = NULL;
	}
	if (tbl_entry != NULL)
		ExternalHashTableEntryFree(tbl_entry);
	free(info, M_CDX);
	return (FAILURE);
}

/*
 * NAT-T classification table entry processing.
 * Checks for existing NAT-T entries with the same 5-tuple and
 * updates the SPI array if found.
 */
int
cdx_ipsec_process_udp_classification_table_entry(PSAEntry sa)
{
	PSAEntry natt_sa;
	int arr_index;
	struct en_exthash_tbl_entry *natt_tbl_entry;
	struct en_ehash_ipsec_preempt_op *ipsec_preempt_params;
	uint32_t *sa_addr;
	uint32_t bytes_to_copy = ETH_HDR_LEN;

	natt_sa = M_ipsec_get_matched_natt_tunnel(sa);

	if (natt_sa != NULL && natt_sa->ct != NULL) {
		if (sa->direction == CDX_DPA_IPSEC_INBOUND)
			sa_addr = &sa->id.daddr.a6[0];
		else
			sa_addr = &sa->id.saddr[0];

		if (dpa_get_iface_info_by_ipaddress(sa->family, sa_addr,
		    NULL, NULL, NULL, &sa->netdev,
		    (uint32_t)sa->handle) != SUCCESS) {
			DPA_ERROR("%s: dpa_get_iface_info_by_ipaddress "
			    "failed\n", __func__);
			goto err_ret;
		}

		if (!(sa->flags & SA_SH_DESC_BUILT)) {
			if (cdx_ipsec_create_shareddescriptor(sa,
			    bytes_to_copy)) {
				DPA_ERROR("%s: unable to create shared "
				    "desc\n", __func__);
				goto err_ret;
			}
			sa->flags |= SA_SH_DESC_BUILT;
		}

		sa->ct = natt_sa->ct;

		if (sa->direction == CDX_DPA_IPSEC_INBOUND) {
			natt_tbl_entry = (struct en_exthash_tbl_entry *)
			    sa->ct->handle;
			ipsec_preempt_params =
			    (struct en_ehash_ipsec_preempt_op *)
			    natt_tbl_entry->ipsec_preempt_params;
			arr_index = 0;
			while (arr_index < MAX_SPI_PER_FLOW &&
			    (be16toh(ipsec_preempt_params->natt_arr_mask) &
			     (1 << arr_index)))
				arr_index++;
			if (arr_index > MAX_SPI_PER_FLOW)
				goto err_ret;
			sa->ct->natt_in_refcnt++;
			ipsec_preempt_params->spi_param[arr_index].spi =
			    sa->id.spi;
			ipsec_preempt_params->spi_param[arr_index].fqid =
			    htobe32(sa->pSec_sa_context->to_sec_fqid);
			ipsec_preempt_params->natt_arr_mask |=
			    htobe16(1 << arr_index);
			sa->natt_arr_index = arr_index;
		} else {
			sa->ct->natt_out_refcnt++;
		}
	} else {
		cdx_ipsec_add_classification_table_entry(sa);
		if (sa->direction == CDX_DPA_IPSEC_INBOUND)
			sa->ct->natt_in_refcnt = 1;
		else
			sa->ct->natt_out_refcnt = 1;
	}

	return (SUCCESS);
err_ret:
	return (FAILURE);
}

/* ================================================================
 * SEC failure stats (delegated to external hash layer)
 * ================================================================ */

int
IPsec_get_SEC_failure_stats(uint16_t *pcmd, uint16_t cmd_len)
{
	fpp_sec_failure_stats_query_cmd_t *pStats;
	int retval;

	if (cmd_len < sizeof(fpp_sec_failure_stats_query_cmd_t))
		return (ERR_WRONG_COMMAND_SIZE);

	pStats = (fpp_sec_failure_stats_query_cmd_t *)pcmd;
	retval = ExternalHashGetSECfailureStats(&pStats->SEC_failure_stats);

	if (retval)
		return (ERR_WRONG_COMMAND_PARAM);

	return (cmd_len);
}

int
IPsec_reset_SEC_failure_stats(uint16_t *pcmd, uint16_t cmd_len)
{

	ExternalHashResetSECfailureStats();
	return (0);
}

#endif /* DPA_IPSEC_OFFLOAD */
