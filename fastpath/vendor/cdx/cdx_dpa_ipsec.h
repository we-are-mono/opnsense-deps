/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */



#ifndef CDX_DPA_IPSEC_H
#define CDX_DPA_IPSEC_H

#include "dpa_ipsec.h"

#define MAX_NUM_OF_SA       1000
#define MAX_CIPHER_KEY_LEN  100
#define MAX_AUTH_KEY_LEN    256
#define MAX_BUFFER_POOL_ID  63

#define MAX_CAAM_SHARED_DESCSIZE 50     /* If CAAM used with QI the maximum
                                         * shared descriptor length is 50 words
                                         */
#define CDX_DPA_IPSEC_STATS_LEN  4	/* 4 words are allocated for stats 
					* 2 words for packets
					* 2 words for bytes
					*/
/* The maximum length (in bytes) for the CAAM extra commands */
#define MAX_EXTRA_DESC_COMMANDS         (64 * sizeof(U32))



/* for OP_PCLID_IPSEC */
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


/*#define  ESP_TRANSPORT_LEGACY_TUNNEL_MODE 1  */
#define PDBOPTS_ETU  				0x01
#define PDBOPTS_TECN  				0x20
#define OP_PCLID_IPSEC_TUNNEL          		(0x11 << OP_PCLID_SHIFT)
#define PDBOPTS_OIHI_FROM_INPUT  		0x04
#define PDBOPTS_OIHI_FROM_PDB  			0x0C
#define PDBOPTS_OIHI_FROM_PDB_REF  		0x08
#define PDBOPTS_NAT  				0x02
#define PDBOPTS_NAT_UDP_CHECKSM  		0x01

#define DSCP_FQ_MAP_ENABLE			(1<<0) /* 0th bit */
#define DSCP_FQ_MAP_DISABLE			(0<<0) /* 0th bit */
#define IPSEC_DPOVRD_ENABLE			(1<<1) /* 1st bit */
#define IPSEC_DPOVRD_DISABLE			(0<<1) /* 1st bit */
#define IPSEC_IPV4_ENCAPSULATION		(0<<2) /* 2nd bit */
#define IPSEC_IPV6_ENCAPSULATION		(1<<2) /* 2nd bit */
#define FRAG_DISABLE				(1<<3)

#if 0
struct desc_hdr {
        uint32_t hdr_word;
        union {
                struct ipsec_encap_pdb pdb_en;
                struct ipsec_decap_pdb pdb_dec;
        };
};

struct sec_descriptor {
        u64     preheader;
        /* SEC Shared Descriptor */
        union {
                uint32_t desc[MAX_CAAM_DESCSIZE];
                struct desc_hdr desc_hdr;
#define hdr_word        desc_hdr.hdr_word
#define pdb_en          desc_hdr.pdb_en
#define pdb_dec         desc_hdr.pdb_dec
        };
};

#endif

/* defined in fpp.h */
typedef struct fpp_sec_failure_stats_query_cmd {
	uint16_t	action;
	en_SEC_failure_stats	SEC_failure_stats;
} __attribute__((__packed__)) fpp_sec_failure_stats_query_cmd_t;

int cdx_ipsec_init(void);
int cdx_ipsec_get_of_port_tbl_id ( PCtEntry entry, struct ins_entry_info *info);

PDpaSecSAContext  cdx_ipsec_sec_sa_context_alloc (uint32_t);
void cdx_ipsec_sec_sa_context_free(PDpaSecSAContext pdpa_sec_context ) ;

int cdx_dpa_ipsec_find_sa_direction(PSAEntry sa);
int  cdx_ipsec_add_classification_table_entry(PSAEntry sa);
int  cdx_ipsec_process_udp_classification_table_entry(PSAEntry sa);
int  cdx_ipsec_create_shareddescriptor(PSAEntry sa, u32 bytes_to_copy);
int cdx_ipsec_generate_split_key(struct auth_params *auth_param);
void cdx_ipsec_release_sa_resources(PSAEntry pSA);
int dpa_get_l2l3_info_by_itf_id(uint32_t itf_id, 
				struct dpa_l2hdr_info *l2_info,
				struct dpa_l3hdr_info *l3_info, uint32_t dir_in);
int cdx_ipsec_handle_get_inbound_sagd(U32 spi, U16 * sagd );
int fill_ipsec_actions(PSAEntry entry, struct ins_entry_info *info, 
			uint32_t sa_dir_in);
int cdx_ipsec_fill_sec_info( PCtEntry entry, struct ins_entry_info *info);
int cdx_ipsec_delete_fp_entry(PSAEntry pSA);
void get_stats_from_sa(PSAEntry sa, u32* pkts, u64* bytes, u8* pSeqOverflow);
#endif
