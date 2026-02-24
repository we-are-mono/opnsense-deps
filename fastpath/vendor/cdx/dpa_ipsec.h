/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "pdb.h"

#ifndef DPA_IPSEC_H
#define DPA_IPSEC_H

#define  UNIQUE_IPSEC_CP_FQID


/* following flags are used to set in context A field of FQD */
#define CDX_FQD_CTX_A_OVERRIDE_FQ	0x80
#define CDX_FQD_CTX_A_IGNORE_CMD	0x40
#define CDX_FQD_CTX_A_A1_FIELD_VALID	0x20
#define CDX_FQD_CTX_A_A2_FIELD_VALID	0x10
#define CDX_FQD_CTX_A_A0_FIELD_VALID	0x08
#define CDX_FQD_CTX_A_B0_FIELD_VALID	0x04
#define CDX_FQD_CTX_A_OVERRIDE_OMB	0x02
#define CDX_FQD_CTX_A_SHIFT_BITS	24 /* the above flags are set in most
					significant byte of context A field */

/* A1 field setting in context A field of FQD */
#define CDX_FQD_CTX_A_A1_VAL_TO_CHECK_SECERR 2

#define MAX_SHARED_DESC_SIZE 	62	
#define PRE_HDR_ALIGN		64

#define FQ_FROM_SEC		0
#define FQ_TO_SEC		1
#ifdef UNIQUE_IPSEC_CP_FQID
#define FQ_TO_CP		2 /* creating a frame queue to receive a packet to CP */
#endif


#ifdef UNIQUE_IPSEC_CP_FQID
/*If we have to avoid adding sagd in packet, we need to use this
  logic, currently some issue with this ,
  so adding this code under a macro */
#define NUM_FQS_PER_SA	3 /* creating 3 frame queues per SA */
#else
#define NUM_FQS_PER_SA	2 /* creating 2 frame queues per SA */
#endif


#define IPSEC_FMAN_IDX		0
#define DEFA_WQ_ID              0
struct desc_hdr {
        uint32_t sd_hdr;
        union {
                struct ipsec_encap_pdb pdb_encrypt;
                struct ipsec_decap_pdb pdb_decrypt;
        };
};

#define AES_GCM_SALT_LEN	4
#define AES_CCM_SALT_LEN	3
#define AES_CCM_INIT_COUNTER	0x0
#define AES_CCM_ICV8_IV_FLAG	0x5B
#define AES_CCM_ICV12_IV_FLAG	0x6B
#define AES_CCM_ICV16_IV_FLAG	0x7B
#define AES_CCM_CTR_FLAG	0x03
struct encap_ccm_opt {
	u8 b0_flags;
	u8 ctr_flags;
	u16 ctr_initial;
};
struct decap_ccm_opt {
	u8 b0_flags;
	u8 ctr_flags;
	u16 ctr_initial;
};
struct sec_descriptor {
        uint64_t preheader;
        /* SEC Shared Descriptor */
        union {
                uint32_t shared_desc[MAX_SHARED_DESC_SIZE];
                struct desc_hdr desc_hdr;
#define hdr_word        desc_hdr.sd_hdr
#define pdb_en          desc_hdr.pdb_encrypt
#define pdb_dec         desc_hdr.pdb_decrypt
        };
};

/* For all Buffer pools using the ethernet driver seed routine,
 * we'll be using the same   BPOOL size */
#define IPSEC_BUFSIZE	dpa_bp_size(x)
#define IPSEC_BUFCOUNT  512
#define	THRESHOLD_IPSEC_BPOOL_REFILL 16

struct ipsec_info; 
void *  dpa_get_ipsec_instance(void);
void *cdx_dpa_ipsecsa_alloc(struct ipsec_info *info, uint32_t handle); 
int dpa_ipsec_ofport_td(struct ipsec_info *info, uint32_t table_type, void **td, 
			uint32_t* portid);
int cdx_dpa_ipsecsa_release(void *handle) ;
uint32_t get_fqid_to_sec(void *handle);
uint32_t get_fqid_from_sec(void *handle);
#ifdef UNIQUE_IPSEC_CP_FQID
uint32_t ipsec_get_to_cp_fqid(void *handle);
#endif /* UNIQUE_IPSEC_CP_FQID */

struct sec_descriptor *get_shared_desc(void *handle);

struct qman_fq *get_to_sec_fq(void *handle);
struct qman_fq *get_from_sec_fq(void *handle);

int cdx_dpa_get_ipsec_pool_info(uint32_t *bpid, uint32_t *buf_size);
int cdx_dpa_ipsec_init(void);
void cdx_dpa_ipsec_exit(void);

int cdx_init_scatter_gather_bpool(void);
int cdx_init_skb_2bfreed_bpool(void);

void print_ipsec_offload_pkt_count(void);
void display_fq_info(void *handle);
int cdx_init_fqid_procfs(void);

#endif

