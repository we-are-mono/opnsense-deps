/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifdef DPA_IPSEC_OFFLOAD 
#include <linux/delay.h>
#include <linux/udp.h>
#include "error.h"
#include "desc.h"
#include "jr.h"
#include "pdb.h"
#include "desc_constr.h"

#include "misc.h"
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
#include "dpa_control_mc.h"
#include "fe.h"

//#define CDX_DPA_DEBUG	1

#define CLASS_SHIFT		25
#define CLASS_MASK		(0x03 << CLASS_SHIFT)

#define CLASS_NONE		(0x00 << CLASS_SHIFT)
#define CLASS_1			(0x01 << CLASS_SHIFT)
#define CLASS_2			(0x02 << CLASS_SHIFT)
#define CLASS_BOTH		(0x03 << CLASS_SHIFT)

#define PREHDR_IDLEN_SHIFT	32
#define PREHDR_OFFSET_SHIFT	26
#define PREHDR_BPID_SHIFT	16
#define PREHDR_ADDBUF_SHIFT	24
#define PREHDR_ABS_SHIFT	25
#define PREHDR_BSIZE_SHIFT	0
#define PREHDR_TBPID_SHIFT      40
#define PREHDR_TBP_SIZE_SHIFT   48


#define PREHDR_IDLEN_MASK	GENMASK_ULL(39,32)
#define PREHDR_OFFSET_MASK	GENMASK_ULL(27,26)
#define PREHDR_BPID_MASK	GENMASK_ULL(23,16)
#define PREHDR_ADDBUF_MASK	GENMASK_ULL(24,24)
#define PREHDR_ABS_MASK		GENMASK_ULL(25,25)
#define PREHDR_BSIZE_MASK	GENMASK_ULL(15,0)
#define PREHDR_TBPID_MASK	GENMASK_ULL(47,40)
#define PREHDR_TBP_SIZE_MASK 	GENMASK_ULL(48,50)


#define PREHEADER_PREP_IDLEN(preh, idlen) \
	(preh) |= ((u64)(idlen) << PREHDR_IDLEN_SHIFT) & PREHDR_IDLEN_MASK

#define PREHEADER_PREP_BPID(preh, bpid) \
	(preh) |= ((u64)(bpid) << PREHDR_BPID_SHIFT) & PREHDR_BPID_MASK

#define PREHEADER_PREP_ADDBUF(preh, addbuf) \
	(preh) |= ((u64)(addbuf) << PREHDR_ADDBUF_SHIFT) & PREHDR_ADDBUF_MASK

#define PREHEADER_PREP_ABS(preh, abs) \
	(preh) |= ((u64)(abs) << PREHDR_ABS_SHIFT) & PREHDR_ABS_MASK

#define PREHEADER_PREP_BSIZE(preh, bufsize) \
	(preh) |= ((u64)(bufsize) << PREHDR_BSIZE_SHIFT) & PREHDR_BSIZE_MASK

// setting the table buffer pool ID
#define PREHEADER_PREP_TBPID(preh, bpid) \
	(preh) |= ((u64)(bpid) << PREHDR_TBPID_SHIFT) & PREHDR_TBPID_MASK

// setting the table buffer pool size
#define PREHEADER_PREP_TBP_SIZE(preh, tbpsz) \
	(preh) |= ((u64)(tbpsz) << 48) & 0x0007000000000000 ; 

#define PREHEADER_PREP_OFFSET(preh, offs) \
	(preh) |= ((u64)(offs) << PREHDR_OFFSET_SHIFT) & PREHDR_OFFSET_MASK



/*
 * to retrieve a 256 byte aligned buffer address from an address
 * we need to copy only the first 7 bytes
 */
#define ALIGNED_PTR_ADDRESS_SZ  (CAAM_PTR_SZ - 1)

#define JOB_DESC_HDR_LEN        CAAM_CMD_SZ
#define SEQ_OUT_PTR_SGF_MASK    0x01000000;

#define SEQ_NUM_HI_MASK         0xFFFFFFFF00000000
#define SEQ_NUM_LOW_MASK        0x00000000FFFFFFFF

#define POST_SEC_OUT_DATA_OFFSET 128 //bytes multiple of 64
#define POST_SEC_IN_DATA_OFFSET  128 //bytes multiple of 64

/* relative offset where the input pointer should be updated in the descriptor*/
#define IN_PTR_REL_OFF          4 /* words from current location */

/* dummy pointer value */
#define DUMMY_PTR_VAL           0x00000000
#define PTR_LEN                 2       /* Descriptor is created only for 8 byte
                                         * pointer. PTR_LEN is in words. */
#define ETH_HDR_LEN		14 
#define PPPOE_HDR_LEN		8 
#define UDP_HEADER_LEN          8

extern int gIPSecStatQueryTimer;
/*Here 1300000 value came based on 128 packet size max packets getting fastforwarded
 * is 921828. On safe side increased it to 1300000.
 */
#define MAX_IPSEC_PKTS_FWD_PSEC	1300000
#define SEQ_NUM_SOFT_LIMIT	(0xFFFFFFFF - (MAX_IPSEC_PKTS_FWD_PSEC * gIPSecStatQueryTimer))
#define SEQ_NUM_ESN_SOFT_LIMIT	(0xFFFFFFFFFFFFFFFF - (MAX_IPSEC_PKTS_FWD_PSEC * gIPSecStatQueryTimer))

struct ipsec_info *ipsec_instance;
int sec_era;
U64 post_sec_out_data_off;
U64 post_sec_in_data_off;

struct device *jrdev_g;

extern void cdx_dpa_ipsec_xfrm_state_dec_ref_cnt(void *xfrm_state);

extern int cdx_ipsec_sa_fq_check_if_retired_state(void *dpa_ipsecsa_handle, int fq_num);

extern int cdx_dpa_ipsec_retire_fq(void *handle, int fq_num);

/* #define PRINT_DESC  */
#ifdef PRINT_DESC
void cdx_ipsec_print_desc ( U32 *desc,const char* function, int line)
{
	int  desc_length,ii;
	desc_length = desc_len(desc);
	printk(KERN_ERR "\n%s(%d) -  Desc length: %d,  dump: \n",function,line, desc_length);
	for ( ii=0; ii< desc_length; ii++){ 
		printk(KERN_ERR "0x%08x \n", caam32_to_cpu(desc[ii]));
	}


}
#endif

int cdx_ipsec_init(void)
{
	printk(KERN_INFO "%s\n", __func__);
	ipsec_instance = dpa_get_ipsec_instance();
	sec_era = 4 ;
	post_sec_out_data_off = ((uint64_t )POST_SEC_OUT_DATA_OFFSET /64);
	post_sec_in_data_off = ((uint64_t )POST_SEC_IN_DATA_OFFSET / 64);
	/* get the jr device  */
	jrdev_g  = caam_jr_alloc();
	if (!jrdev_g) {
		log_err("Failed to get the job ring device, check the dts\n");
		return -EINVAL;
	}
	printk(KERN_INFO "%s job ring device= %p\n", __func__,jrdev_g);
	return 0;
}


int cdx_ipsec_fill_sec_info( PCtEntry entry, struct ins_entry_info *info)
{
	int i;
	PSAEntry sa;
  
	for (i=0;i < SA_MAX_OP;i++)
	{ 
		if((sa = M_ipsec_sa_cache_lookup_by_h(entry->hSAEntry[i])) 
					!= NULL)
		{ 
			if(sa->direction == CDX_DPA_IPSEC_OUTBOUND )
			{
				info->to_sec_fqid = 
				sa->pSec_sa_context->to_sec_fqid;
				info->sa_family = sa->family ;
				info->tnl_hdr_size = (sa->dev_mtu - sa->mtu); /* Gives you the header expansion size */
#ifdef CDX_DPA_DEBUG	
				printk(KERN_CRIT "%s OutBound SA info->to_sec_fqid  = %d\n", __func__,info->to_sec_fqid );
#endif				
			}else{
				info->l3_info.ipsec_inbound_flow = 1;
				dpa_ipsec_ofport_td(ipsec_instance, 
					info->tbl_type, &info->td, &info->port_id );
#ifdef CDX_DPA_DEBUG	
//			printk(KERN_CRIT "%s InBound SA info->td  = %d\n", __func__,info->td );
#endif
			}
		}
	}
	return 0;
}

void cdx_ipsec_sec_sa_context_free(PDpaSecSAContext pdpa_sec_context ) 
{

	if(pdpa_sec_context->dpa_ipsecsa_handle)
		cdx_dpa_ipsecsa_release(pdpa_sec_context->dpa_ipsecsa_handle);
	if(pdpa_sec_context->cipher_data.cipher_key)
		kfree(pdpa_sec_context->cipher_data.cipher_key);
	if(pdpa_sec_context->auth_data.auth_key)
		kfree(pdpa_sec_context->auth_data.auth_key);
	if(pdpa_sec_context->auth_data.split_key)
		kfree(pdpa_sec_context->auth_data.split_key); 
	if(pdpa_sec_context->sec_desc_extra_cmds_unaligned)
		kfree(pdpa_sec_context->sec_desc_extra_cmds_unaligned);
	if(pdpa_sec_context->rjob_desc_unaligned)
		kfree(pdpa_sec_context->rjob_desc_unaligned);
	kfree(pdpa_sec_context);

}

/* natt_arr_mask enables bits according to the number of spi
 * entries per 5 tuple. This function returns the free index
 * bit index available in the mask */
static int get_free_natt_arr_index(uint16_t natt_arr_mask)
{
	int i = 0;
	while(i < MAX_SPI_PER_FLOW)
	{
		if (!(natt_arr_mask & (1 << i)))
			break;
		i++;
	}
	return i;	
}

/* This function sets the corresponding bit in the array mask
 * to mark it as being used */
static inline void set_natt_arr_mask(uint16_t* natt_arr_mask,int index)
{
	*natt_arr_mask |= cpu_to_be16(1<<index);
}


/* This function resets the corresponding bit in the array mask
 * to make it available */
static inline void reset_natt_arr_mask(uint16_t *natt_arr_mask,int index)
{
	*natt_arr_mask &= ~cpu_to_be16(1<<index);
}

int cdx_ipsec_delete_fp_entry(PSAEntry pSA)
{
	struct hw_ct *hwct;
	struct en_exthash_tbl_entry *natt_tbl_entry;
	struct en_ehash_ipsec_preempt_op *ipsec_preempt_params;

	DPA_INFO("%s(%d) dir: %s , handle %x fqid %x\n",
		__FUNCTION__,__LINE__,(pSA->direction)?"INBOUND":"OUTBOUND",
		pSA->handle,
		pSA->pSec_sa_context ? pSA->pSec_sa_context->to_sec_fqid : 0);
	/* WE need to lock below section of code */
	if (IS_NATT_SA(pSA) && pSA->ct && (pSA->ct->handle))
	{
		natt_tbl_entry = pSA->ct->handle;
		if ( (pSA->direction == CDX_DPA_IPSEC_OUTBOUND) && (pSA->ct->natt_out_refcnt > 1))
		{
			pSA->ct->natt_out_refcnt--;
			pSA->ct = NULL;
			return 0;
		}
		else if ((pSA->direction == CDX_DPA_IPSEC_INBOUND) && (pSA->ct->natt_in_refcnt > 1))
		{
			ipsec_preempt_params = ( struct en_ehash_ipsec_preempt_op *)natt_tbl_entry->ipsec_preempt_params;
			pSA->ct->natt_in_refcnt--;
			reset_natt_arr_mask(&ipsec_preempt_params->natt_arr_mask, pSA->natt_arr_index);
			ipsec_preempt_params->spi_param[pSA->natt_arr_index].spi = 0;
			ipsec_preempt_params->spi_param[pSA->natt_arr_index].fqid = 0;
			pSA->ct = NULL;
			return 0;
		}
			
	}
	if ((pSA->ct) && (pSA->ct->handle)) {
		if (ExternalHashTableDeleteKey(pSA->ct->td, 
			pSA->ct->index, pSA->ct->handle)) {
			DPA_ERROR("%s::unable to remove entry from hash table\n", __FUNCTION__);
			return -1;
		}
		ExternalHashTableEntryFree(pSA->ct->handle);
		pSA->ct->handle =  NULL;
		hwct = pSA->ct;
		pSA->ct = NULL;
		kfree(hwct);
	}	 
	return 0;
}

void cdx_ipsec_delete_fp_hash_entry(PSAEntry pSA)
{
	struct hw_ct *hwct;

	if ((pSA->ct) && (pSA->ct->handle)) {
		ExternalHashTableEntryFree(pSA->ct->handle);
		pSA->ct->handle =  NULL;
		hwct = pSA->ct;
		pSA->ct = NULL;
		kfree(hwct);
	}	 
	return;
}


static int cdx_ipsec_release_sa_ctx_cbk(struct timer_entry_t *entry)
{
	PSAEntry         pSA;
	PDpaSecSAContext sa_context;
	int32_t ii, ret;

	pSA  = container_of(entry, SAEntry, deletion_timer);
	cdx_timer_del(entry);
	/* check frame queues states */
	for (ii=0; ii<NUM_FQS_PER_SA; ii++)
	{
		if (pSA->flags & (SA_FQ_WAIT_B4_FREE << ii))
		{
			ret = cdx_ipsec_sa_fq_check_if_retired_state(pSA->pSec_sa_context->dpa_ipsecsa_handle, ii);
			/* if fq is not in retired state, restart timer */
			if (ret)
			{
				DPA_ERROR("%s::Failed to change state \n", 
				__FUNCTION__);
				cdx_timer_init((TIMER_ENTRY *)&pSA->deletion_timer,
					cdx_ipsec_release_sa_ctx_cbk);
				cdx_timer_add((TIMER_ENTRY *)&pSA->deletion_timer,
					SA_CTX_RELEASE_TIMER_VAL);
				return 0;
			}
			pSA->flags &= ~((SA_FQ_WAIT_B4_FREE << ii));
		}
	}
	/* free hash table entry if rqd */
	if (pSA->flags & SA_FREE_HASH_ENTRY)
	{
		cdx_ipsec_delete_fp_hash_entry(pSA);
	}
	/* delete from list_fq */
	sa_remove_from_list_fqid(pSA);

	/* remove xfrm_state */
	if (pSA->xfrm_state)
		cdx_dpa_ipsec_xfrm_state_dec_ref_cnt(pSA->xfrm_state);
	sa_context = pSA->pSec_sa_context;
	cdx_ipsec_sec_sa_context_free(sa_context);
	pSA->pSec_sa_context = NULL;
	/* free sa memory */
	sa_free(pSA);
	return 0;
}

void cdx_ipsec_release_sa_resources(PSAEntry pSA)
{
	int ii,ret;
	pSA->flags |= SA_DELETE;
	/* delete hash table entry */
	if (cdx_ipsec_delete_fp_entry(pSA) ) {
		/* if fails free hash entry memory in timer context */
		pSA->flags |= SA_FREE_HASH_ENTRY;
	}

	/* change frame queues states */
	if ((pSA->pSec_sa_context) &&
	    (pSA->pSec_sa_context->dpa_ipsecsa_handle))
	{
		for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {
			ret = cdx_dpa_ipsec_retire_fq(pSA->pSec_sa_context->dpa_ipsecsa_handle, ii);

			if (ret == 1)
				pSA->flags |= (SA_FQ_WAIT_B4_FREE << ii);

		}
	}

	/* defer resource release */
	cdx_timer_init((TIMER_ENTRY *)&pSA->deletion_timer,
			cdx_ipsec_release_sa_ctx_cbk);
	cdx_timer_add((TIMER_ENTRY *)&pSA->deletion_timer,
			SA_CTX_RELEASE_TIMER_VAL);
	return;
}

PDpaSecSAContext  cdx_ipsec_sec_sa_context_alloc(uint32_t handle)
{

	PDpaSecSAContext pdpa_sec_context; 
	pdpa_sec_context = Heap_Alloc(sizeof( DpaSecSAContext));
	if(!pdpa_sec_context )
	{
		return NULL;
	}  	
	memset(pdpa_sec_context , 0, sizeof(DpaSecSAContext));
	pdpa_sec_context->cipher_data.cipher_key =
		kzalloc(MAX_CIPHER_KEY_LEN, GFP_KERNEL);
	if (!pdpa_sec_context->cipher_data.cipher_key) {
		log_err("Could not allocate memory for cipher key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	memset(pdpa_sec_context->cipher_data.cipher_key, 0, MAX_CIPHER_KEY_LEN);
	pdpa_sec_context->auth_data.auth_key =
		kzalloc(MAX_AUTH_KEY_LEN, GFP_KERNEL);
	if (!pdpa_sec_context->auth_data.auth_key) {
		log_err("Could not allocate memory for authentication key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	memset(pdpa_sec_context->auth_data.auth_key, 0, MAX_AUTH_KEY_LEN);

	pdpa_sec_context->auth_data.split_key =
		kzalloc(MAX_AUTH_KEY_LEN, GFP_KERNEL);
	if (!pdpa_sec_context->auth_data.split_key) {
		log_err("Could not allocate memory for authentication split key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	memset(pdpa_sec_context->auth_data.split_key, 0, MAX_AUTH_KEY_LEN);

	/* Allocate space for extra material space in case when the
	 * descriptor is greater than 64 words */
	pdpa_sec_context->sec_desc_extra_cmds_unaligned =
		kzalloc(2 * MAX_EXTRA_DESC_COMMANDS + L1_CACHE_BYTES,
				GFP_KERNEL);
	if (!pdpa_sec_context->sec_desc_extra_cmds_unaligned) {
		log_err("Allocation failed for CAAM extra commands\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	memset(pdpa_sec_context->sec_desc_extra_cmds_unaligned, 0,(2* MAX_EXTRA_DESC_COMMANDS + L1_CACHE_BYTES));

	pdpa_sec_context->sec_desc_extra_cmds =
		PTR_ALIGN(pdpa_sec_context->sec_desc_extra_cmds_unaligned,
				L1_CACHE_BYTES);
	if (pdpa_sec_context->sec_desc_extra_cmds_unaligned ==
			pdpa_sec_context->sec_desc_extra_cmds)
		pdpa_sec_context->sec_desc_extra_cmds += L1_CACHE_BYTES / 4;

	/*
	 * Allocate space for the SEC replacement job descriptor
	 * Required 64 byte alignment
	 */
	pdpa_sec_context->rjob_desc_unaligned =
		kzalloc(MAX_CAAM_DESCSIZE * sizeof(U32) + 64,
				GFP_KERNEL);
	if (!pdpa_sec_context->rjob_desc_unaligned) {
		log_err("No memory for replacement job descriptor\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	memset(pdpa_sec_context->rjob_desc_unaligned, 0,(MAX_CAAM_DESCSIZE * sizeof(U32)+64));
	pdpa_sec_context->rjob_desc = 
		PTR_ALIGN(pdpa_sec_context->rjob_desc_unaligned, 64);
	pdpa_sec_context->dpa_ipsecsa_handle  = cdx_dpa_ipsecsa_alloc(NULL, handle); 
	if(pdpa_sec_context->dpa_ipsecsa_handle){
		pdpa_sec_context->sec_desc = 
			get_shared_desc(pdpa_sec_context->dpa_ipsecsa_handle);
		pdpa_sec_context->to_sec_fqid = 
			get_fqid_to_sec(pdpa_sec_context->dpa_ipsecsa_handle);	
		pdpa_sec_context->from_sec_fqid = 
			get_fqid_from_sec(pdpa_sec_context->dpa_ipsecsa_handle);
#ifdef UNIQUE_IPSEC_CP_FQID
		pdpa_sec_context->to_cp_fqid =
			ipsec_get_to_cp_fqid(pdpa_sec_context->dpa_ipsecsa_handle);
#ifdef CDX_DPA_DEBUG	
		printk("%s::fqid_to_sec %x(%d), fqid_from_sec %x(%d), to_cp_fqid %x(%d)\n",
				__FUNCTION__, pdpa_sec_context->to_sec_fqid,
				pdpa_sec_context->to_sec_fqid,
				pdpa_sec_context->from_sec_fqid,
				pdpa_sec_context->from_sec_fqid,
				pdpa_sec_context->to_cp_fqid,
				pdpa_sec_context->to_cp_fqid);
#endif
#endif
	}
	else {
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	return pdpa_sec_context;	
}

static inline int get_cipher_params(U16 cipher_alg,
                                    uint32_t *iv_length, uint32_t *icv_length,
                                    uint32_t *max_pad_length)
{
	switch (cipher_alg) {
#if 0
		case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_MD5_128:
		case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_SHA_160:
			*iv_length = 8;
			*max_pad_length = 8;
			*icv_length = 12;
			break;
		case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_MD5_128:
			*iv_length = 8;
			*max_pad_length = 8;
			*icv_length = 16;
			break;
		case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_160:
		case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_256_128:
			*iv_length = 8;
			*max_pad_length = 8;
			*icv_length = 20;
			break;
		case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_384_192:
			*iv_length = 8;
			*max_pad_length = 8;
			*icv_length = 24;
			break;
		case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_512_256:
			*iv_length = 8;
			*max_pad_length = 8;
			*icv_length = 32;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_MD5_128:
		case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_SHA_160:
		case DPA_IPSEC_CIPHER_ALG_AES_CBC_AES_XCBC_MAC_96:
			*iv_length = 16;
			*max_pad_length = 16;
			*icv_length = 12;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_MD5_128:
		case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_256_128:
			*iv_length = 16;
			*max_pad_length = 16;
			*icv_length = 16;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_160:
			*iv_length = 16;
			*max_pad_length = 16;
			*icv_length = 20;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_384_192:
			*iv_length = 16;
			*max_pad_length = 16;
			*icv_length = 24;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_512_256:
			*iv_length = 16;
			*max_pad_length = 16;
			*icv_length = 32;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_MD5_128:
		case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_SHA_160:
		case DPA_IPSEC_CIPHER_ALG_AES_CTR_AES_XCBC_MAC_96:
			*iv_length = 16;
			*max_pad_length = 16;
			*icv_length = 12;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_MD5_128:
		case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_256_128:
			*iv_length = 8;
			*max_pad_length = 4;
			*icv_length = 16;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_160:
			*iv_length = 8;
			*max_pad_length = 4;
			*icv_length = 20;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_384_192:
			*iv_length = 8;
			*max_pad_length = 4;
			*icv_length = 24;
			break;
		case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_512_256:
			*iv_length = 8;
			*max_pad_length = 4;
			*icv_length = 32;
			break;
#endif
		default:
			*iv_length = 0;
			*icv_length = 0;
			*max_pad_length = 0;
			log_err("Unsupported cipher suite %d\n", cipher_alg);
			return -EINVAL;
	}

	return 0;
}


static  void build_stats_descriptor_part(PSAEntry sa, size_t pdb_len)
{
	uint32_t *desc;
	uint32_t stats_offset;
	PDpaSecSAContext pSec_sa_context ; 


	BUG_ON(!sa);

	pSec_sa_context= sa->pSec_sa_context;
	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;

	stats_offset = sizeof(pSec_sa_context->sec_desc->hdr_word) + pdb_len - CDX_DPA_IPSEC_STATS_LEN * sizeof(u32);
	sa->stats_offset = stats_offset;
	memset((u8 *)desc + stats_offset, 0, CDX_DPA_IPSEC_STATS_LEN * sizeof(u32));

	/* Copy from descriptor to MATH REG 0 the current statistics */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
			(stats_offset << MOVE_OFFSET_SHIFT) | sizeof(u64));

	/* increment REG0 by 1 */
	append_math_add_imm_u32(desc, REG0, REG0, IMM, 1);

	/* Store in the descriptor but not in external memory */
	append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP |
			(stats_offset << MOVE_OFFSET_SHIFT) | sizeof(u64));

	/* Copy from descriptor to MATH REG 0 the current statistics */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
			((stats_offset + 8) << MOVE_OFFSET_SHIFT) | sizeof(u64));

	// inbound 
	if (sa->direction  == CDX_DPA_IPSEC_INBOUND)
	{
		// getting decrypted data size + padded bytes
		append_math_add(desc, REG0, VARSEQINLEN, REG0, MATH_LEN_8BYTE);

		// getting the padded bytes
		append_math_add_imm_u32(desc, REG2, VARSEQOUTLEN, IMM, 0);

		// reducing the padded bytes
		append_math_sub(desc, REG0, REG0, REG2, MATH_LEN_8BYTE);
		
	}
	else
	{
		append_math_add(desc, REG0, SEQINLEN, REG0, MATH_LEN_8BYTE);
	}

	/* Store in the descriptor but not in external memory */
	append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP |
			((stats_offset + 8) << MOVE_OFFSET_SHIFT) | sizeof(u64));
}

void get_stats_from_sa(PSAEntry sa, u32* pkts, u64* bytes, u8* pSeqOverflow)
{
	uint32_t *desc;
	uint32_t *stats_desc;
	uint64_t* bytes_desc;
	uint64_t  ullCurSeqNum;

	PDpaSecSAContext pSec_sa_context = sa->pSec_sa_context;

	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;
	stats_desc = (u32 *)(desc + sa->stats_offset / 4);

	stats_desc++;
	*pkts =  be32_to_cpu(*stats_desc);
	if ((pSeqOverflow) && (!sa->seq_overflow))
	{
		if (sa->direction  == CDX_DPA_IPSEC_OUTBOUND)
		{
			ullCurSeqNum = be32_to_cpu(sa->pSec_sa_context->sec_desc->pdb_en.seq_num_ext_hi);
			ullCurSeqNum <<= 32;
			ullCurSeqNum |= be32_to_cpu(sa->pSec_sa_context->sec_desc->pdb_en.seq_num);
		}
		else
		{
			ullCurSeqNum = be32_to_cpu(sa->pSec_sa_context->sec_desc->pdb_dec.seq_num_ext_hi);
			ullCurSeqNum <<= 32;
			ullCurSeqNum |= be32_to_cpu(sa->pSec_sa_context->sec_desc->pdb_dec.seq_num); 
		}

		if (sa->flags & SA_ALLOW_EXT_SEQ_NUM)
		{
			if (ullCurSeqNum > SEQ_NUM_ESN_SOFT_LIMIT)
			{
				*pSeqOverflow = 1;
				sa->seq_overflow = 1;
			}
		}
		else
		{
			if (ullCurSeqNum > SEQ_NUM_SOFT_LIMIT)
			{
				*pSeqOverflow = 1;
				sa->seq_overflow = 1;
			}
		}
	}
	/* increment 8 bytes to go to byte cnt */
	stats_desc++;
	bytes_desc = (uint64_t*)stats_desc;
	*bytes = be64_to_cpu(*bytes_desc);

	return;
}

static inline void save_stats_in_external_mem(PSAEntry sa)
{
	uint32_t *desc;
	uint32_t stats_offset;
	PDpaSecSAContext pSec_sa_context = sa->pSec_sa_context;

	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;


	/* statistics offset = predetermined offset */
	stats_offset = sa->stats_offset;

	/* Store command: in the case of the Descriptor Buffer the length
	 * is specified in 4-byte words, but in all other cases the length
	 * is specified in bytes. Offset in 4 byte words */
	append_store(desc, 0, CDX_DPA_IPSEC_STATS_LEN , LDST_CLASS_DECO |
			((stats_offset / 4) << LDST_OFFSET_SHIFT) |
			LDST_SRCDST_WORD_DESCBUF_SHARED);

	/* Jump with CALM to be sure previous operation was finished */
	append_jump(desc, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));
}


int cdx_ipsec_build_shared_descriptor(PSAEntry sa,
		dma_addr_t auth_key_dma,
		dma_addr_t crypto_key_dma, u32 bytes_to_copy)
{
	uint32_t *desc, *key_jump_cmd;
	//uint32_t  copy_ptr_index = 0;
	int opthdrsz;
	size_t pdb_len = 0;
	uint32_t sa_op; 
	PDpaSecSAContext pSec_sa_context; 

	pSec_sa_context =sa->pSec_sa_context; 

	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;
	/* Reserve 2 words for statistics */
	pdb_len = CDX_DPA_IPSEC_STATS_LEN * sizeof(u32);

	if (sa->direction  == CDX_DPA_IPSEC_OUTBOUND) {
		/* Compute optional header size, rounded up to descriptor
		 * word size */
		opthdrsz = 
			(caam32_to_cpu(pSec_sa_context->sec_desc->pdb_en.ip_hdr_len) +
			 3) & ~3;
		pdb_len += sizeof(struct ipsec_encap_pdb) + opthdrsz;
		init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL, pdb_len);
		//init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_WAIT, pdb_len);
		sa_op = OP_TYPE_ENCAP_PROTOCOL;  
	} else {
		pdb_len += sizeof(struct ipsec_decap_pdb);
		init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL, pdb_len);
		//init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_WAIT, pdb_len);
		sa_op = OP_TYPE_DECAP_PROTOCOL;
	}

	/* Key jump */
	if (((pSec_sa_context->auth_data.split_key_len) || 
		 (pSec_sa_context->auth_data.auth_key_len)) &&
		 (pSec_sa_context->cipher_data.cipher_key_len))
		key_jump_cmd = append_jump(desc, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_SHRD | JUMP_COND_SELF);
	else if (pSec_sa_context->cipher_data.cipher_key_len)
		key_jump_cmd = append_jump(desc, CLASS_1| JUMP_TEST_ALL |
				   JUMP_COND_SHRD | JUMP_COND_SELF);
	else
		key_jump_cmd = append_jump(desc, CLASS_2| JUMP_TEST_ALL |
			   JUMP_COND_SHRD | JUMP_COND_SELF);

	/* check whether a split of a normal key is used */
	if (pSec_sa_context->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(desc, auth_key_dma, pSec_sa_context->auth_data.split_key_len,
				CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else if (pSec_sa_context->auth_data.auth_key_len)
		/* Append normal authentication key */
		append_key(desc, auth_key_dma, pSec_sa_context->auth_data.auth_key_len,
				CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	if (pSec_sa_context->cipher_data.cipher_key_len)
		append_key(desc, crypto_key_dma, pSec_sa_context->cipher_data.cipher_key_len,
		   CLASS_1 | KEY_DEST_CLASS_REG);

	set_jump_tgt_here(desc, key_jump_cmd);
#if 0
	/*
	 * Should enable for dscp copy or ECN. Currently could not find where
	 * this is configured in  cdx. - Rajendran oct21. 
	 */
	/* copy frame meta data (IC) to enable DSCP / ECN propagation */
	if (sa->dscp_copy || sa->ecn_copy) {
		/* save location of ptr copy commands to update offset later */
		copy_ptr_index = desc_len(desc);
		build_meta_data_desc_cmds(sa, sa->dpa_ipsec->sec_era, 64);
	}
#endif
	if (bytes_to_copy == 0)
		goto skip_byte_copy;

	/* Copy L2 header from the original packet to the outer packet */

	/* ld: deco-deco-ctrl len=0 offs=8 imm -auto-nfifo-entries */
	append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

	/* seqfifold: both msgdata-last2-last1-flush1 len=4 */
	append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
			FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
			FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

	/* ld: deco-deco-ctrl len=0 offs=4 imm +auto-nfifo-entries */
	append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* move: ififo->deco-alnblk -> ofifo, len=4 */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* Done coping L2 header from the original packet to the outer packet */

skip_byte_copy:

	/* Enable Stats only for IPv4  TODO-IPV6 */

	if (sa->direction  != CDX_DPA_IPSEC_INBOUND)
	{
#ifdef PRINT_DESC
		cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
		build_stats_descriptor_part(sa, pdb_len);
#ifdef PRINT_DESC
		cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
	}

	if(sa->mode == SA_MODE_TUNNEL)
	{
		/* Protocol specific operation */
		append_operation(desc, OP_PCLID_IPSEC_TUNNEL |sa_op |
				pSec_sa_context->cipher_data.cipher_type |
				pSec_sa_context->auth_data.auth_type);
	}
	else {
		/* Protocol specific operation */
		append_operation(desc, OP_PCLID_IPSEC |sa_op |
				pSec_sa_context->cipher_data.cipher_type |
				pSec_sa_context->auth_data.auth_type);
	}

	if (sa->direction  == CDX_DPA_IPSEC_INBOUND)
	{
#ifdef PRINT_DESC
		cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
		build_stats_descriptor_part(sa, pdb_len);
#ifdef PRINT_DESC
		cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
	}

	/* Enable Stats only for IPv4  TODO-IPV6 */
	save_stats_in_external_mem(sa);
#if 0

	if (sa->dscp_copy || sa->ecn_copy)
		/* insert cmds to copy SEQ_IN/OUT_PTR - with updated offset */
		insert_ptr_copy_cmds(desc, copy_ptr_index,
				desc_len(desc), false);
#endif
	/*For inbound Ipsec traffic, copy SAGD  to the outer packet at the end */

#ifdef UNIQUE_IPSEC_CP_FQID
	if (0) /* not adding sgid  2 bytes to shared descriptor stuff */
#else
	if (sa->direction  == CDX_DPA_IPSEC_INBOUND)
#endif /* UNIQUE_IPSEC_CP_FQID */
	{
		/* ld: deco-deco-ctrl len=0 offs=8 imm -auto-nfifo-entries */
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

		/* fifo load immediate: sa-> handle value to input fifo */
		append_fifo_load_as_imm(desc, (void *)&sa->handle,
				2, FIFOLD_TYPE_MSG|
				FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
				FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

		/* ld: deco-deco-ctrl len=0 offs=4 imm +auto-nfifo-entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

		/* move: ififo->deco-alnblk -> ofifo, len=4 */
		append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | 2);

		/* seqfifostr: msgdata len=4 */
		append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, 2);

	}
	/* Done coping SAGD value to the outer packet at the end*/

#ifdef PRINT_DESC
	//if (sa->direction == CDX_DPA_IPSEC_OUTBOUND)
	cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
	if (desc_len(desc) >= MAX_CAAM_SHARED_DESCSIZE) {
		printk("%s:: Descriptor length increased more than 50 words :%x \n", __func__, desc_len(desc));
		memset((uint8_t *)desc + sa->stats_offset, 0,
				MAX_CAAM_DESCSIZE * sizeof(u32) -
				sa->stats_offset);
		return -EPERM;
	}

	return 0;
}

int built_encap_extra_material(PSAEntry sa,
		dma_addr_t auth_key_dma,
		dma_addr_t crypto_key_dma,
		unsigned int move_size)
{
	uint32_t *extra_cmds, *padding_jump, *key_jump_cmd;
	uint32_t len, off_b, off_w, off, opt;
	unsigned char job_desc_len, block_size;

	PDpaSecSAContext pSec_sa_context; 

	pSec_sa_context =sa->pSec_sa_context; 
	/*
	 * sec_desc_extra_cmds is the address were the first SEC extra command
	 * is located, from here SEC will overwrite Job descriptor part. Need
	 * to insert a dummy command because the LINUX CAAM API uses first word
	 * for storing the length of the descriptor.
	 */
	extra_cmds = pSec_sa_context->sec_desc_extra_cmds - 1;

	/*
	 * Dummy command - will not be executed at all. Only for setting to 1
	 * the length of the extra_cmds descriptor so that first extra material
	 * command will be located exactly at sec_desc_extra_cmds address.
	 */
	append_cmd(extra_cmds, 0xdead0000);

	/* Start Extra Material Group 1 */
	/* Load from the input address 64 bytes into internal register */
	/* load the data to be moved - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_load(extra_cmds, DUMMY_PTR_VAL, len, opt | off);

	/* Wait to finish previous operation */
	opt = JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT);
	append_jump(extra_cmds, opt);

	/* Store the data to the output FIFO - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_store(extra_cmds, DUMMY_PTR_VAL, len, opt | off);

	/* Fix LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off = 0x80 << LDST_OFFSET_SHIFT; /* NON_SEQ LIODN */
	append_cmd(extra_cmds, CMD_LOAD | opt | off);

	/* MATH0 += 1 (packet counter) */
	append_math_add(extra_cmds, REG0, REG0, ONE, MATH_LEN_8BYTE);

	/* Overwrite the job-desc location (word 51 or 53) with the second
	 * group (10 words) */
	job_desc_len = pSec_sa_context->job_desc_len;
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (10 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(extra_cmds, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Jump to the beginning of the JOB Descriptor to start executing
	 * the extra material group 2
	 */
	append_cmd(extra_cmds, 0xa00000f6);

	/* End of Extra Material Group 1 */

	/* Start Extra Material Group 2 */
	/* MATH REG 2 = Sequence in length + 2; 2 for pad-len and NH field */
	append_math_add_imm_u32(extra_cmds, REG2, SEQINLEN, IMM, 2);

	switch (pSec_sa_context->cipher_data.cipher_type) {
		case OP_PCL_IPSEC_3DES:
			block_size = 8; /* block size in bytes */
			break;
		case OP_PCL_IPSEC_AES_CBC:
		case OP_PCL_IPSEC_AES_CTR:
		case OP_PCL_IPSEC_AES_XTS:
		case OP_PCL_IPSEC_AES_CCM8:
		case OP_PCL_IPSEC_AES_CCM12:
		case OP_PCL_IPSEC_AES_CCM16:
		case OP_PCL_IPSEC_AES_GCM8:
		case OP_PCL_IPSEC_AES_GCM12:
		case OP_PCL_IPSEC_AES_GCM16:
		case OP_PCL_IPSEC_AES_GMAC:
			block_size = 16; /* block size in bytes */
			break;
		default:
			pr_crit("Invalid cipher algorithm for SA with spi %d\n", 
					sa->id.spi);
			return -EINVAL;
	}

	/* Adding padding to byte counter */
	append_math_and_imm_u32(extra_cmds, REG3, REG2, IMM, block_size - 1);

	/* Previous operation result is 0 i.e padding added to bytes count */
	padding_jump = append_jump(extra_cmds, CLASS_BOTH | JUMP_TEST_ALL |
			JUMP_COND_MATH_Z);

	/* MATH REG 2 = MATH REG 2 + 1 */
	append_math_add(extra_cmds, REG2, REG2, ONE, MATH_LEN_4BYTE);

	/* jump back to adding padding i.e jump back 4 words */
	off = (-4) & 0x000000FF;
	append_jump(extra_cmds, (off << JUMP_OFFSET_SHIFT));

	set_jump_tgt_here(extra_cmds, padding_jump);
	/* Done adding padding to byte counter */

	/*
	 * Perform 32-bit left shift of DEST and concatenate with left 32 bits
	 * of SRC1 i.e MATH REG 2 = 0x00bytecount_00000000
	 */
	append_math_ldshift(extra_cmds, REG2, REG0, REG2, MATH_LEN_8BYTE);

	/* MATH REG 0  = MATH REG 0 + MATH REG 2 */
	append_math_add(extra_cmds, REG0, REG0, REG2, MATH_LEN_8BYTE);

	/*
	 * Overwrite the job-desc location (word 51 or 53) with the third
	 * group (11 words)
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (11 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(extra_cmds, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Jump to the beginning of the JOB Descriptor to start executing
	 * the extra material group 3. The command for jumping back is already
	 * here from extra material group 1
	 */

	/* End of Extra Material Group 2 */

	/* Start Extra Material Group 3 */

	if (sa->enable_stats) {
		/* Store statistics in the CAAM internal descriptor */
		off_b = sa->stats_indx * CAAM_CMD_SZ;
		append_move(extra_cmds, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF |
				(off_b << MOVE_OFFSET_SHIFT) |
				sizeof(uint64_t));
	} else {
		/* Statistics are disabled. Do not update descriptor counter */
		append_cmd(extra_cmds, 0xA0000001); /* NOP for SEC */
	}

	/* Key jump */
	key_jump_cmd = append_jump(extra_cmds, CLASS_BOTH | JUMP_TEST_ALL |
			JUMP_COND_SHRD);

	/* check whether a split of a normal key is used */
	if (pSec_sa_context->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(extra_cmds, auth_key_dma,
				pSec_sa_context->auth_data.split_key_len,
				CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else if (pSec_sa_context->auth_data.auth_key_len)
		/* Append normal authentication key */
		append_key(extra_cmds, auth_key_dma, pSec_sa_context->auth_data.auth_key_len,
				CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	append_key(extra_cmds, crypto_key_dma, 
			pSec_sa_context->cipher_data.cipher_key_len,
			CLASS_1 | KEY_DEST_CLASS_REG);

	set_jump_tgt_here(extra_cmds, key_jump_cmd);

	/* Protocol specific operation */
	append_operation(extra_cmds, OP_PCLID_IPSEC | OP_TYPE_ENCAP_PROTOCOL |
			pSec_sa_context->cipher_data.cipher_type | 
			pSec_sa_context->auth_data.auth_type);

	if (sa->enable_stats) {
		/*
		 * Store command: in the case of the Descriptor Buffer the
		 * length is specified in 4-byte words, but in all other cases
		 * the length is specified in bytes. Offset in 4 byte words
		 */
		off_w = sa->stats_indx;
		append_store(extra_cmds, 0, CDX_DPA_IPSEC_STATS_LEN,
				LDST_CLASS_DECO | (off_w << LDST_OFFSET_SHIFT) |
				LDST_SRCDST_WORD_DESCBUF_SHARED);
	} else {
		/* Do not store lifetime counter in external memory */
		append_cmd(extra_cmds, 0xA0000001); /* NOP for SEC */
	}

	/* Jump with CALM to be sure previous operation was finished */
	append_jump(extra_cmds, JUMP_TYPE_HALT_USER | JUMP_COND_CALM);

	/* End of Extra Material Group 3 */
#ifdef PRINT_DESC
	cdx_ipsec_print_desc ( extra_cmds,__func__,__LINE__);
#endif

	return 0;
}

/* Move size should be set to 64 bytes */
void built_decap_extra_material(PSAEntry sa,
		dma_addr_t auth_key_dma,
		dma_addr_t crypto_key_dma)
{
	uint32_t *extra_cmds;
	uint32_t off_b, off_w, data;
	PDpaSecSAContext pSec_sa_context; 

	pSec_sa_context =sa->pSec_sa_context; 

	/*
	 * sec_desc_extra_cmds is the address were the first SEC extra command
	 * is located, from here SEC will overwrite Job descriptor part. Need
	 * to insert a dummy command because the LINUX CAAM API uses first word
	 * for storing the length of the descriptor.
	 */
	extra_cmds = pSec_sa_context->sec_desc_extra_cmds - 1;

	/*
	 * Dummy command - will not be executed at all. Only for setting to 1
	 * the length of the extra_cmds descriptor so that first extra material
	 * command will be located exactly at sec_desc_extra_cmds address.
	 */
	append_cmd(extra_cmds, 0xdead0000);

	data = 16;
	append_math_rshift_imm_u64(extra_cmds, REG2, REG2, IMM, data);

	/* math: (math1 - math2)->math1 len=8 */
	append_math_sub(extra_cmds, REG1, REG1, REG2, MATH_LEN_8BYTE);

	/* math: (math0 + 1)->math0 len=8 */
	append_math_add(extra_cmds, REG0, REG0, ONE, MATH_LEN_8BYTE);

	append_math_ldshift(extra_cmds, REG1, REG0, REG1, MATH_LEN_8BYTE);

	append_math_add(extra_cmds, REG0, REG0, REG1, MATH_LEN_8BYTE);

	append_cmd(extra_cmds, 0x7883c824);

	/* Store in the descriptor but not in external memory */
	off_b = sa->stats_offset;
	append_move(extra_cmds, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF |
			MOVE_WAITCOMP | (off_b << MOVE_OFFSET_SHIFT) | sizeof(u64));

	append_cmd(extra_cmds, 0xa70040fe);

	append_cmd(extra_cmds, 0xa00000f7);

	/* check whether a split of a normal key is used */
	if (pSec_sa_context->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(extra_cmds, auth_key_dma,
				pSec_sa_context->auth_data.split_key_len,
				CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else if (pSec_sa_context->auth_data.auth_key_len)
		/* Append normal authentication key */
		append_key(extra_cmds, auth_key_dma, 
				pSec_sa_context->auth_data.auth_key_len,
				CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	append_key(extra_cmds, crypto_key_dma, 
			pSec_sa_context->cipher_data.cipher_key_len,
			CLASS_1 | KEY_DEST_CLASS_REG);

	/* Protocol specific operation */
	append_operation(extra_cmds, OP_PCLID_IPSEC | OP_TYPE_DECAP_PROTOCOL |
			pSec_sa_context->cipher_data.cipher_type | 
			pSec_sa_context->auth_data.auth_type);

	/*
	 * Store command: in the case of the Descriptor Buffer the length
	 * is specified in 4-byte words, but in all other cases the length
	 * is specified in bytes. Offset in 4 byte words
	 */
	off_w = sa->stats_indx;
	append_store(extra_cmds, 0, CDX_DPA_IPSEC_STATS_LEN,
			LDST_CLASS_DECO | (off_w << LDST_OFFSET_SHIFT) |
			LDST_SRCDST_WORD_DESCBUF_SHARED);

	append_jump(extra_cmds, JUMP_TYPE_HALT_USER | JUMP_COND_CALM);
#ifdef PRINT_DESC
	cdx_ipsec_print_desc ( extra_cmds,__func__,__LINE__);
#endif
}

int cdx_ipsec_build_extended_encap_shared_descriptor(PSAEntry sa,
		dma_addr_t auth_key_dma,
		dma_addr_t crypto_key_dma,
		U32 bytes_to_copy,
		int sec_era)
{
	U32 *desc, *no_sg_jump, *extra_cmds;
	U32  len, off_b, off_w, opt, stats_off_b, sg_mask;
	unsigned int extra_cmds_len;
	unsigned char job_desc_len;
	dma_addr_t dma_extra_cmds;
	int ret;
	PDpaSecSAContext pSec_sa_context; 

	pSec_sa_context =sa->pSec_sa_context; 

	desc = (U32 *)pSec_sa_context->sec_desc->shared_desc;

	if (sec_era == 2) {
		if (sa->enable_stats)
			sa->stats_indx = 27;
		sa->next_cmd_indx = 29;
	} else {
		if (sa->enable_stats)
			sa->stats_indx = 28;
		sa->next_cmd_indx = 30;
	}

	/* This code only works when SEC is configured to use PTR on 64 bit
	 * so the Job Descriptor length is 13 words long when DPOWRD is set */
	job_desc_len = 13;

	/* Set CAAM Job Descriptor length */
	pSec_sa_context->job_desc_len = job_desc_len;

	/* Set lifetime counter stats offset */
	sa->stats_offset = sa->stats_indx * sizeof(uint32_t);

	ret = built_encap_extra_material(sa, auth_key_dma, crypto_key_dma, 64);
	if (ret < 0) {
		log_err("Failed to create extra CAAM commands\n");
		return -EAGAIN;
	}

	extra_cmds = pSec_sa_context->sec_desc_extra_cmds - 1;
	extra_cmds_len = desc_len(extra_cmds) - 1;

	/* get the jr device  */

	dma_extra_cmds = dma_map_single(jrdev_g,
			pSec_sa_context->sec_desc_extra_cmds,
			extra_cmds_len * sizeof(uint32_t),
			DMA_TO_DEVICE);
	if (!dma_extra_cmds) {
		log_err("Could not DMA map extra CAAM commands\n");
		return -ENXIO;
	}

	init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL,
			(sa->next_cmd_indx - 1) * sizeof(uint32_t));

	if (sec_era == 2) {
		/* disable iNFO FIFO entries for p4080rev2 & ??? */
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 * Offset refers to SRC
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_CLASS1INFIFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
				FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
				FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				extra_cmds_len * sizeof(uint32_t),
				FIFOLD_TYPE_MSG | FIFOLD_CLASS_BOTH |
				FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_LAST2 |
				FIFOLD_TYPE_FLUSH1);

		/* enable iNFO FIFO entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);
	} else {
		/* ????? */
		opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | opt | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_INFIFO_NOINFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes. No information FIFO entry even if automatic
		 * iNformation FIFO entries are enabled.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_CLASS_BOTH |
				FIFOLD_TYPE_NOINFOFIFO);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				extra_cmds_len * sizeof(uint32_t),
				FIFOLD_CLASS_BOTH | FIFOLD_TYPE_NOINFOFIFO);
	}

	/*
	 * throw away the first part of the S/G table and keep only the buffer
	 * address;
	 * offset = undefined memory after MATH3; Refers to the destination.
	 * len = 41 bytes to discard
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 8 << MOVE_OFFSET_SHIFT;
	len   = 41 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* put the buffer address (still in the IN FIFO) in MATH2 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 0 << MOVE_OFFSET_SHIFT;
	len   = 8 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* copy 15 bytes starting at 4 bytes before the OUT-PTR-CMD in
	 * the job-desc into math1
	 * i.e. in the low-part of math1 we have the out-ptr-cmd and
	 * in the math2 we will have the address of the out-ptr
	 */
	opt = MOVE_SRC_DESCBUF | MOVE_DEST_MATH1;
	off_b = (MAX_CAAM_DESCSIZE - job_desc_len + PTR_LEN) * sizeof(uint32_t);
	len = (8 + 4 * PTR_LEN - 1) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Copy 7 bytes of the in-ptr into math0 */
	opt   = MOVE_SRC_DESCBUF | MOVE_DEST_MATH0;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 1 + 3 + 2 * PTR_LEN;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * the SEQ OUT PTR command is now in math reg 1, so the SGF bit can be
	 * checked using a math command;
	 */
	sg_mask = SEQ_OUT_PTR_SGF_MASK;
	append_math_and_imm_u32(desc, NONE, REG1, IMM, sg_mask);

	opt = CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_COND_MATH_Z | JUMP_TEST_ALL;
	no_sg_jump = append_jump(desc, opt);

	append_math_add(desc, REG2, ZERO, REG3, MATH_LEN_8BYTE);

	/* update no S/G jump location */
	set_jump_tgt_here(desc, no_sg_jump);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* move: ififo->deco-alnblk -> ofifo, len=4 */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* Overwrite the job-desc location (word 51 or 53) with the first
	 * group (11 words)*/
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (11 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math0 (input address) to words 52+53 or 54+56
	 * depending where the Job Descriptor starts.
	 * They will be used later by the load command.
	 */
	opt = MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 1; /* 52 + 53 or 54 + 55 */
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math2 (output address) to words 56+57 or 58+59
	 * depending where the Job Descriptor starts.
	 * They will be used later by the store command.
	 */
	opt = MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 5; /* 56 + 57 or 58 + 59 */
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Fix LIODN - OFFSET[0:1] - 01 = SEQ LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x40; /* SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | (off_b << LDST_OFFSET_SHIFT));

	/* Copy the context of the counters from word 29 into math0 */
	/* Copy from descriptor to MATH REG 0 the current statistics */
	stats_off_b = sa->stats_indx * CAAM_CMD_SZ;
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 |
			(stats_off_b << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	dma_unmap_single(jrdev_g, dma_extra_cmds,
			extra_cmds_len * sizeof(uint32_t), DMA_TO_DEVICE);

#ifdef PRINT_DESC
	cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
	return 0;
}

int cdx_ipsec_build_extended_decap_shared_descriptor(PSAEntry sa,
		dma_addr_t auth_key_dma,
		dma_addr_t crypto_key_dma,
		uint32_t bytes_to_copy,
		uint8_t move_size,
		int sec_era)
{
	uint32_t *desc, *no_sg_jump, *extra_cmds;
	uint32_t len, off_b, off_w, opt, stats_off_b, sg_mask, extra_cmds_len,
		 esp_length, iv_length, icv_length, max_pad, data;
	dma_addr_t dma_extra_cmds;
	PDpaSecSAContext psec_as_context;

	psec_as_context = sa->pSec_sa_context;

	desc = (uint32_t *)psec_as_context->sec_desc->shared_desc;

	/* CAAM hdr cmd + PDB size in words */
	sa->next_cmd_indx =
		sizeof(struct ipsec_decap_pdb) / sizeof(uint32_t) + 1;
	if (sa->enable_stats) {
		sa->stats_indx = sa->next_cmd_indx;
		sa->next_cmd_indx += 2;
		if (sec_era != 2) {
			sa->stats_indx += 1;
			sa->next_cmd_indx += 1;
		}
	}

	/* Set lifetime counter stats offset */
	sa->stats_offset = sa->stats_indx * sizeof(uint32_t);

	built_decap_extra_material(sa, auth_key_dma, crypto_key_dma);

	extra_cmds = psec_as_context->sec_desc_extra_cmds - 1;
	extra_cmds_len = desc_len(extra_cmds) - 1;


	dma_extra_cmds = dma_map_single(jrdev_g, psec_as_context->sec_desc_extra_cmds,
			extra_cmds_len * sizeof(uint32_t),
			DMA_TO_DEVICE);
	if (!dma_extra_cmds) {
		log_err("Could not DMA map extra CAAM commands\n");
		return -ENXIO;
	}

	init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL,
			(sa->next_cmd_indx - 1) * sizeof(uint32_t));

	if (sec_era == 2) {
		/* disable iNFO FIFO entries for p4080rev2 & ??? */
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 * Offset refers to SRC
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_CLASS1INFIFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
				FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
				FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				extra_cmds_len * sizeof(uint32_t),
				FIFOLD_TYPE_MSG | FIFOLD_CLASS_BOTH |
				FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_LAST2 |
				FIFOLD_TYPE_FLUSH1);

		/* enable iNFO FIFO entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);
	} else {
		/* ????? */
		opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | opt | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_INFIFO_NOINFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes. No information FIFO entry even if automatic
		 * iNformation FIFO entries are enabled.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_CLASS_BOTH |
				FIFOLD_TYPE_NOINFOFIFO);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				extra_cmds_len * sizeof(uint32_t),
				FIFOLD_CLASS_BOTH | FIFOLD_TYPE_NOINFOFIFO);
	}

	/*
	 * throw away the first part of the S/G table and keep only the buffer
	 * address;
	 * offset = undefined memory after MATH3; Refers to the destination.
	 * len = 41 bytes to discard
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 8 << MOVE_OFFSET_SHIFT;
	len   = 41 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* put the buffer address (still in the IN FIFO) in MATH2 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 0 << MOVE_OFFSET_SHIFT;
	len   = 8 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/*
	 * Copy 15 bytes starting at 4 bytes before the OUT-PTR-CMD in
	 * the job-desc into math1
	 * i.e. in the low-part of math1 we have the out-ptr-cmd and
	 * in the math2 we will have the address of the out-ptr
	 */
	opt = MOVE_SRC_DESCBUF | MOVE_DEST_MATH1;
	off_b = (50 + 1 * PTR_LEN) * sizeof(uint32_t);
	len = (8 + 4 * PTR_LEN - 1) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Copy 7 bytes of the in-ptr into math0 */
	opt   = MOVE_SRC_DESCBUF | MOVE_DEST_MATH0;
	off_w = 50 + 1 + 3 + 2 * PTR_LEN;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * the SEQ OUT PTR command is now in math reg 1, so the SGF bit can be
	 * checked using a math command;
	 */
	sg_mask = SEQ_OUT_PTR_SGF_MASK;
	append_math_and_imm_u32(desc, NONE, REG1, IMM, sg_mask);

	opt = CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_COND_MATH_Z | JUMP_TEST_ALL;
	no_sg_jump = append_jump(desc, opt);

	append_math_add(desc, REG2, ZERO, REG3, MATH_LEN_8BYTE);

	/* update no S/G jump location */
	set_jump_tgt_here(desc, no_sg_jump);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* move: ififo->deco-alnblk -> ofifo, len */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* Overwrite the job-desc location (word 50) with the first
	 * group (10 words)*/
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF;
	off_w = 50;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (10 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math0 (input address) to words 32+33
	 * They will be used later by the load command.
	 */
	opt = MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF;
	off_w = 32;
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math2 (output address) to words 56+57 or 58+59
	 * depending where the Job Descriptor starts.
	 * They will be used later by the store command.
	 */
	opt = MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = 36;
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Fix LIODN - OFFSET[0:1] - 01 = SEQ LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x40; /* SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | (off_b << LDST_OFFSET_SHIFT));

	/* Load from the input address 64 bytes into internal register */
	/* load the data to be moved - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off_b = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_load(desc, DUMMY_PTR_VAL, len, opt | off_b);

	/* Wait to finish previous operation */
	opt = JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT);
	append_jump(desc, opt);

	/* Store the data to the output FIFO - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off_b = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_store(desc, DUMMY_PTR_VAL, len, opt | off_b);

	/* Fix LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x80 << LDST_OFFSET_SHIFT; /* NON_SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | off_b);

	/* Copy from descriptor to MATH REG 0 the current statistics */
	stats_off_b = sa->stats_indx * CAAM_CMD_SZ;
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
			(stats_off_b << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	/* Remove unnecessary headers
	 * MATH1 = 0 - (esp_length + iv_length + icv_length) */
	esp_length = 8; /* SPI + SEQ NUM */
	get_cipher_params(psec_as_context->alg_suite, &iv_length, &icv_length, &max_pad);
	data = (uint32_t) (esp_length + iv_length + icv_length);
	append_math_sub_imm_u64(desc, REG1, ZERO, IMM, data);

	/* MATH1 += SIL (bytes counter) */
	append_math_add(desc, REG1, SEQINLEN, REG1, MATH_LEN_8BYTE);

	/* data = outer IP header - should be read from DPOVRD register
	 * MATH 2 = outer IP header length */
	data = cpu_to_caam32(20);
	opt = LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2;
	len = sizeof(data) << LDST_LEN_SHIFT;
	append_load_as_imm(desc, &data, len, opt);

	off_w = 7;
	append_jump(desc, (off_w << JUMP_OFFSET_SHIFT));

	/* jump: all-match[] always-jump offset=0 local->[00] */
	append_jump(desc, (0 << JUMP_OFFSET_SHIFT));

	/* jump: all-match[] always-jump offset=0 local->[00] */
	append_jump(desc, (0 << JUMP_OFFSET_SHIFT));

	data = 0x00ff0000;
	append_math_and_imm_u64(desc, REG2, DPOVRD, IMM, data);

	dma_unmap_single(jrdev_g, dma_extra_cmds,
			extra_cmds_len * sizeof(uint32_t), DMA_TO_DEVICE);

#ifdef PRINT_DESC
	cdx_ipsec_print_desc ( desc,__func__, __LINE__);
#endif
	return 0;
}

int  cdx_ipsec_build_in_sa_pdb(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	PDpaSecSAContext psec_as_context;
	struct decap_ccm_opt *ccm_opt;
	uint8_t *salt;
	/*struct iphdr *outer_ip_hdr;*/

	psec_as_context = sa->pSec_sa_context;
	sec_desc= psec_as_context->sec_desc; 
	memset(&sec_desc->pdb_dec, 0, sizeof(sec_desc->pdb_dec));

	sec_desc->pdb_dec.seq_num =
		cpu_to_caam32(sa->seq & SEQ_NUM_LOW_MASK);


	if ( sa->flags & SA_ALLOW_EXT_SEQ_NUM ) {
		sec_desc->pdb_dec.seq_num_ext_hi =
			cpu_to_caam32((sa->seq & SEQ_NUM_HI_MASK) >> 32);
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_ESN;
	}


	if (sa->flags & SA_ALLOW_SEQ_ROLL  ) {
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARSNONE;
	}else{
		/* assuming anti reply window of 64 defult. This is not
		   known through cmm-cdx command */
		/*sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARS32; */
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARS64;
	}

	if(sa->mode == SA_MODE_TUNNEL)
	{
		/*
		 * Updated the offset to the point in frame were the encrypted
		 * stuff starts.
		 */
		sec_desc->pdb_dec.options |= (sa->header_len << PDBHDRLEN_ESP_DECAP_SHIFT);
		if (sa->natt.sport && sa->natt.dport) {
			/* UDP nat traversal so remove the UDP header also. */         
			sec_desc->pdb_dec.options &= 0xf000ffff;
			sec_desc->pdb_dec.options |= ((sa->header_len+UDP_HEADER_LEN) << PDBHDRLEN_ESP_DECAP_SHIFT);
		}
		/* by default copy dscp from outer to inner header */
		sec_desc->pdb_dec.options |= PDBHMO_ESP_DIFFSERV;

		if (sa->hdr_flags) {
			/*if (sa->hdr_flags & SA_HDR_COPY_TOS)
				sec_desc->pdb_dec.options |= PDBHMO_ESP_DIFFSERV; */
			if (sa->hdr_flags & SA_HDR_DEC_TTL)
				sec_desc->pdb_dec.options |= PDBHMO_ESP_DECAP_DEC_TTL;
			if (sa->hdr_flags & SA_HDR_COPY_DF)
			{
				pr_info("Copy DF bit not supported for inbound SAs");
			}
		}
	}
	else
	{
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_OUTFMT;
		if (sec_era > 4)
			sec_desc->pdb_dec.options |= PDBOPTS_ESP_AOFL;

		if(sa->family == PROTO_IPV4)
		{
			sec_desc->pdb_dec.options |= (sizeof(ipv4_hdr_t) << PDBHDRLEN_ESP_DECAP_SHIFT);
			sec_desc->pdb_dec.options |= PDBOPTS_ESP_VERIFY_CSUM;
		}
		else{
			sec_desc->pdb_dec.options |= (sizeof(ipv6_hdr_t) << PDBHDRLEN_ESP_DECAP_SHIFT);
			sec_desc->pdb_dec.options |= PDBOPTS_ESP_IPVSN;
		}
		sec_desc->pdb_dec.options |= (0x01 << PDB_NH_OFFSET_SHIFT);

	}

	/*        sec_desc->pdb_dec.hmo_ip_hdr_len =
		  cpu_to_caam16(sec_desc->pdb_dec.hmo_ip_hdr_len); */
	sec_desc->pdb_dec.options = cpu_to_caam32(sec_desc->pdb_dec.options);

	salt = sa->pSec_sa_context->cipher_data.cipher_key +
						sa->pSec_sa_context->cipher_data.cipher_key_len;
	if ((sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM8) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM12) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM16) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GMAC))
	{
		memcpy(sec_desc->pdb_dec.gcm.salt, salt, AES_GCM_SALT_LEN);
	}

	/* CCM */ // RFC 4309
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM8)
	{
		memcpy((u8 *)(&sec_desc->pdb_dec.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)&sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV8_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM12)
	{
		memcpy((u8 *)(&sec_desc->pdb_dec.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)&sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV12_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM16)
	{
		memcpy((u8 *)(&sec_desc->pdb_dec.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)&sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV16_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	return 0;
}

int  cdx_ipsec_build_out_sa_pdb(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	PDpaSecSAContext psec_as_context;
	struct iphdr *outer_ip_hdr;
	struct ipv6hdr *outer_ip6_hdr;
	struct encap_ccm_opt *ccm_opt;
	uint8_t	*salt;

	psec_as_context = sa->pSec_sa_context;
	sec_desc= psec_as_context->sec_desc; 
	memset(&sec_desc->pdb_en, 0, sizeof(sec_desc->pdb_en));

	//sec_desc->pdb_en.spi = cpu_to_caam32(sa->id.spi);
	sec_desc->pdb_en.spi = sa->id.spi;

	if (sa->flags & SA_ALLOW_EXT_SEQ_NUM ) {
		sec_desc->pdb_en.seq_num_ext_hi =
			cpu_to_caam32((sa->seq & SEQ_NUM_HI_MASK) >> 32);
		sec_desc->pdb_en.options |= PDBOPTS_ESP_ESN;
	}
	sec_desc->pdb_en.seq_num =
		cpu_to_caam32(sa->seq & SEQ_NUM_LOW_MASK);


	//if (!sa->init_vector)
	sec_desc->pdb_en.options |= PDBOPTS_ESP_IVSRC;
	/*else
	  memcpy(&sec_desc->pdb_en.cbc,
	  sa->init_vector->init_vector,
	  sa->.init_vector->length);*/

	if(sa->mode == SA_MODE_TUNNEL)
	{
		sec_desc->pdb_en.options |= PDBOPTS_OIHI_FROM_PDB;

		if (sa->hdr_flags) {
			if (sa->hdr_flags & SA_HDR_DEC_TTL)
				sec_desc->pdb_en.options |= PDBHMO_ESP_ENCAP_DEC_TTL;
			if (sa->hdr_flags & SA_HDR_COPY_DF){
				if (sa->family == PROTO_IPV4)
					sec_desc->pdb_en.options |= PDBHMO_ESP_DFBIT ;
				else
					pr_warn("Copy DF not supported for IPv6 SA");
			}

		}

		/* Copy the outer header and generate the original header checksum */
		memcpy(&sec_desc->pdb_en.ip_hdr[0],
				&sa->tunnel.ip4,
				sa->header_len);
		sec_desc->pdb_en.ip_hdr_len = sa->header_len ;
		if (sa->natt.sport && sa->natt.dport) {
			struct udphdr *udp_hdr;
			uint8_t *tmp;
			tmp = (uint8_t *) &sec_desc->pdb_en.ip_hdr[0];
			udp_hdr = (struct udphdr *) (tmp + sa->header_len);
			udp_hdr->source = htons(sa->natt.sport);
			udp_hdr->dest = htons(sa->natt.dport);
			udp_hdr->check = 0x0000;
			udp_hdr->len = 0x0000;
			/* ip header should include the 4 byte of UDP port fileds */
			sec_desc->pdb_en.ip_hdr_len += UDP_HEADER_LEN ;
			sec_desc->pdb_en.options |= PDBOPTS_NAT;
			sec_desc->pdb_en.options |= PDBOPTS_NAT_UDP_CHECKSM;

			if (sa->header_len == IPV4_HDR_SIZE ) {
				outer_ip_hdr = (struct iphdr *)
					&sec_desc->pdb_en.ip_hdr[0];
				outer_ip_hdr->protocol = IPPROTO_UDP;
			}else{
				outer_ip6_hdr = (struct ipv6hdr *) &sec_desc->pdb_en.ip_hdr[0];
				outer_ip6_hdr->nexthdr = IPPROTO_UDP;
			}
		}

		/* Update endianness of this value to match SEC endianness: */
		sec_desc->pdb_en.ip_hdr_len =
			cpu_to_caam32(sec_desc->pdb_en.ip_hdr_len);

		if (sa->family == PROTO_IPV4) {
			outer_ip_hdr = (struct iphdr *) &sec_desc->pdb_en.ip_hdr[0];
			if (!sa->natt.sport && !sa->natt.dport) 
				outer_ip_hdr->protocol = IPPROTO_ESP; 
			outer_ip_hdr->tot_len = ((sec_desc->pdb_en.ip_hdr_len >> 16) & 0xffff) ;
			outer_ip_hdr->check =
				ip_fast_csum((unsigned char *)outer_ip_hdr,
						outer_ip_hdr->ihl);
		}
		else{
			outer_ip6_hdr = (struct ipv6hdr *) &sec_desc->pdb_en.ip_hdr[0];
			if (!sa->natt.sport && !sa->natt.dport)
				outer_ip6_hdr->nexthdr = IPPROTO_ESP;
		}
	}
	else /* transport mode */
	{
		sec_desc->pdb_en.options |= PDBOPTS_ESP_INCIPHDR;

		if(sa->family == PROTO_IPV4)
		{
			sec_desc->pdb_en.ip_hdr_len = sizeof(ipv4_hdr_t);
			sec_desc->pdb_en.options |= PDBOPTS_ESP_UPDATE_CSUM;
		}
		else{
			sec_desc->pdb_en.ip_hdr_len = sizeof(ipv6_hdr_t);
			sec_desc->pdb_en.options |= PDBOPTS_ESP_IPV6;
		}
		sec_desc->pdb_en.options |= (0x01 << PDB_NH_OFFSET_SHIFT);
		sec_desc->pdb_en.options |= (IPPROTO_ESP << PDBNH_ESP_ENCAP_SHIFT);
		/* Update endianness of this value to match SEC endianness: */
		sec_desc->pdb_en.ip_hdr_len = cpu_to_caam32(sec_desc->pdb_en.ip_hdr_len);
	}


	sec_desc->pdb_en.options = cpu_to_caam32(sec_desc->pdb_en.options);
	salt = sa->pSec_sa_context->cipher_data.cipher_key+sa->pSec_sa_context->cipher_data.cipher_key_len;
	/*printk("%s(%d) salt [0] %02x,[1] %02x [2] %02x, [3] %02x\n",
		__FUNCTION__,__LINE__,salt[0],salt[1],salt[2],salt[3]); */
	if ((sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM8) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM12) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM16) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GMAC))
	{
		memcpy(sec_desc->pdb_en.gcm.salt, salt,  AES_GCM_SALT_LEN);
	}

	/* AES CCM */
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM8)
	{
		memcpy((u8 *)(&sec_desc->pdb_en.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)&sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV8_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM12)
	{
		memcpy((u8 *)(&sec_desc->pdb_en.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)&sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV12_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM16)
	{
		memcpy((u8 *)(&sec_desc->pdb_en.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)&sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV16_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}

	return 0;
}

int  cdx_ipsec_create_shareddescriptor(PSAEntry sa, uint32_t bytes_to_copy)
{
	struct sec_descriptor *sec_desc;
	dma_addr_t auth_key_dma = 0;
	dma_addr_t crypto_key_dma;
	dma_addr_t shared_desc_dma;
	int ret = 0;
	uint32_t bpid;
	uint32_t buf_size;
	PDpaSecSAContext psec_sa_context;

	if (cdx_dpa_get_ipsec_pool_info(&bpid, &buf_size))
		return -EIO;
	psec_sa_context = sa->pSec_sa_context;
	if(sa->direction == CDX_DPA_IPSEC_OUTBOUND ){
		cdx_ipsec_build_out_sa_pdb( sa);
	}else{
		cdx_ipsec_build_in_sa_pdb(sa);
	}

	/* check whether a split or a normal key is used */
	if (psec_sa_context->auth_data.split_key_len) {
#if 0
		printk("%s::split key::\n", __FUNCTION__);
		display_buff_data(psec_sa_context->auth_data.split_key, 
				psec_sa_context->auth_data.split_key_len);
#endif
		auth_key_dma = dma_map_single(jrdev_g, 
				psec_sa_context->auth_data.split_key,
				psec_sa_context->auth_data.split_key_pad_len,
				DMA_TO_DEVICE);
		if (!auth_key_dma) {
			log_err("Could not DMA map authentication key\n");
			return -EINVAL;
		}
	}
	else if (psec_sa_context->auth_data.auth_key_len) {
#if 0
		printk("%s::auth key::\n", __FUNCTION__);
		display_buff_data(psec_sa_context->auth_data.auth_key, 
				psec_sa_context->auth_data.auth_key_len);
#endif
		auth_key_dma = dma_map_single(jrdev_g, 
				psec_sa_context->auth_data.auth_key,
				psec_sa_context->auth_data.auth_key_len,
				DMA_TO_DEVICE);
		if (!auth_key_dma) {
			log_err("Could not DMA map authentication key\n");
			return -EINVAL;
		}
	}

#if 0
	printk("%s::cipher key::\n", __FUNCTION__);
	display_buff_data(psec_sa_context->cipher_data.cipher_key, 
			psec_sa_context->cipher_data.cipher_key_len);
#endif
	crypto_key_dma = dma_map_single(jrdev_g, 
			psec_sa_context->cipher_data.cipher_key,
			psec_sa_context->cipher_data.cipher_key_len,
			DMA_TO_DEVICE);
	if (!crypto_key_dma) {
		log_err("Could not DMA map cipher key\n");
		return -EINVAL;
	}

	/*
	 * Build the shared descriptor and see if its length is less than
	 * 64 words. If build_shared_descriptor returns -EPERM than it is
	 * required to build the extended shared descriptor in order to have
	 * all the SA features that were required.
	 * Forth argument is passed was l2_hdr_size. Since we already removed 
	 * L2 header before passing to sec , I am passing zero. 
	 * This need to be revisited and corrected if required.  
	 */

	ret = cdx_ipsec_build_shared_descriptor(sa, auth_key_dma, crypto_key_dma,
			bytes_to_copy);
	switch (ret) {
		case 0:
			psec_sa_context->sec_desc_extended = false;
			goto done_shared_desc;
		case -EPERM:
			psec_sa_context->sec_desc_extended = true;
			goto build_extended_shared_desc;
		default:
			log_err("Failed to create SEC descriptor for SA with   spi %d\n", sa->id.spi);
			return -EFAULT;
	}

build_extended_shared_desc:
	/* Build the extended shared descriptor */
	if (sa->direction == CDX_DPA_IPSEC_INBOUND)
		ret = cdx_ipsec_build_extended_decap_shared_descriptor(sa, 
				auth_key_dma,
				crypto_key_dma, 0, 64,
				sec_era);
	else
		ret = cdx_ipsec_build_extended_encap_shared_descriptor(sa, 
				auth_key_dma,
				crypto_key_dma, 0 ,
				sec_era);
	if (ret < 0) {
		log_err("Failed to create SEC descriptor for SA with spi %d\n", 
				sa->id.spi);
		return -EFAULT;
	}

done_shared_desc:
	sec_desc = psec_sa_context->sec_desc;
	/* setup preheader */

	PREHEADER_PREP_IDLEN(sec_desc->preheader, 
			desc_len(sec_desc->shared_desc));
	PREHEADER_PREP_BPID(sec_desc->preheader, bpid);
	PREHEADER_PREP_BSIZE(sec_desc->preheader, buf_size); // 0 indicates max size
	if (sa->direction  == CDX_DPA_IPSEC_INBOUND) {
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
				post_sec_in_data_off);
	}
	else
	{
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
				post_sec_out_data_off);
	}
	//printk("%s::preheader %p\n", __FUNCTION__, 
	//	(void *)sec_desc->preheader);
	sec_desc->preheader = cpu_to_caam64(sec_desc->preheader);

	if (psec_sa_context->auth_data.split_key_pad_len)
		dma_unmap_single(jrdev_g, auth_key_dma,
				psec_sa_context->auth_data.split_key_pad_len, 
				DMA_TO_DEVICE);
	else if (psec_sa_context->auth_data.auth_key_len)
		dma_unmap_single(jrdev_g, auth_key_dma,
				psec_sa_context->auth_data.auth_key_len, 
				DMA_TO_DEVICE);
	dma_unmap_single(jrdev_g, crypto_key_dma,
			psec_sa_context->cipher_data.cipher_key_len, 
			DMA_TO_DEVICE);
	shared_desc_dma = dma_map_single(jrdev_g, sec_desc,
			sizeof(struct sec_descriptor),
			DMA_TO_DEVICE);
	dma_unmap_single(jrdev_g, shared_desc_dma, 
			sizeof(struct sec_descriptor),
			DMA_TO_DEVICE);
	return 0;
}

static void split_key_done(struct device *dev, u32 *desc, u32 err,
		void *context)
{
	register atomic_t *done = context;
	//printk(KERN_ERR "%s: Job ring  err  value =%d\n", __func__, err);

	if (err)
		caam_jr_strstatus(dev, err);

	atomic_set(done, 1);
}

/* determine the HASH algorithm and the coresponding split key length */
int cdx_ipsec_get_split_key_info(struct auth_params *auth_param, u32 *hmac_alg)
{
	/*
	 * Sizes for MDHA pads (*not* keys): MD5, SHA1, 224, 256, 384, 512
	 * Running digest size
	 */
	const u8 mdpadlen[] = {16, 20, 32, 32, 64, 64};

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
			log_err("Unsupported authentication algorithm\n");
			return -EINVAL;
	}

	if (*hmac_alg)
		auth_param->split_key_len =
			mdpadlen[(*hmac_alg & OP_ALG_ALGSEL_SUBMASK) >>
			OP_ALG_ALGSEL_SHIFT] * 2;

	return 0;
}
int cdx_ipsec_generate_split_key(struct auth_params *auth_param)
{
	dma_addr_t dma_addr_in, dma_addr_out;
	u32 *desc, timeout = 1000000, alg_sel = 0;
	atomic_t done;
	int ret = 0;

	ret = cdx_ipsec_get_split_key_info(auth_param, &alg_sel);
	/* exit if error or there is no need to compute a split key */
	if (ret < 0 || alg_sel == 0)
		return ret;


	desc = kmalloc(CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2, GFP_KERNEL | GFP_DMA);
	if (!desc) {
		log_err("Allocate memory failed for split key desc\n");
		return -ENOMEM;
	}

	auth_param->split_key_pad_len = ALIGN(auth_param->split_key_len, 16);

	dma_addr_in = dma_map_single(jrdev_g, auth_param->auth_key,
			auth_param->auth_key_len, DMA_TO_DEVICE);
	if (dma_mapping_error(jrdev_g, dma_addr_in)) {
		dev_err(jrdev_g, "Unable to DMA map the input key address\n");
		kfree(desc);
		return -ENOMEM;
	}

	dma_addr_out = dma_map_single(jrdev_g, auth_param->split_key,
			auth_param->split_key_pad_len,
			DMA_FROM_DEVICE);
	if (dma_mapping_error(jrdev_g, dma_addr_out)) {
		dev_err(jrdev_g, "Unable to DMA map the output key address\n");
		dma_unmap_single(jrdev_g, dma_addr_in, auth_param->auth_key_len,
				DMA_TO_DEVICE);
		kfree(desc);
		return -ENOMEM;
	}
	init_job_desc(desc, 0);

	append_key(desc, dma_addr_in, auth_param->auth_key_len,
			CLASS_2 | KEY_DEST_CLASS_REG);

	/* Sets MDHA up into an HMAC-INIT */
	/*	append_operation(desc, (OP_ALG_TYPE_CLASS2 << OP_ALG_TYPE_SHIFT) | */
	append_operation(desc, OP_ALG_TYPE_CLASS2 |
			alg_sel | OP_ALG_AAI_HMAC |
			OP_ALG_DECRYPT | OP_ALG_AS_INIT);

	/* Do a FIFO_LOAD of zero, this will trigger the internal key expansion
	   into both pads inside MDHA */
	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_2_CCB |
			FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/* FIFO_STORE with the explicit split-key content store
	 * (0x26 output type) */
	append_fifo_store(desc, dma_addr_out, auth_param->split_key_len,
			LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);

#if 0//def PRINT_DESC
	cdx_ipsec_print_desc ( desc,__func__);
#endif
	atomic_set(&done, 0);
	ret = caam_jr_enqueue(jrdev_g, desc, split_key_done, &done);

	while (!atomic_read(&done) && --timeout) {
		udelay(1);
		cpu_relax();
	}

	if (timeout == 0)
		log_err("Timeout waiting for job ring to complete\n");

	dma_unmap_single(jrdev_g, dma_addr_out, auth_param->split_key_pad_len,
			DMA_FROM_DEVICE);
	dma_unmap_single(jrdev_g, dma_addr_in, auth_param->auth_key_len,
			DMA_TO_DEVICE);
	kfree(desc);
	return ret;
}

/* Fill the key information required for NATT (UDP) connection */
static int fill_natt_key_info(PSAEntry sa, struct en_exthash_tbl_entry *tbl_entry, uint32_t port_id)
{
	union dpa_key *key;
	unsigned char *saddr, *daddr;
	uint32_t key_size;
	int i;

	key = (union dpa_key *)&tbl_entry->hashentry.key[0];
	/*portid added to key */
	key->portid = port_id;

	if(sa->family == PROTO_IPV4)
	{
		key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
		key->ipv4_tcpudp_key.ipv4_saddr = sa->id.saddr[0];
		key->ipv4_tcpudp_key.ipv4_daddr = sa->id.daddr.a6[0];
		key->ipv4_tcpudp_key.ipv4_protocol = IPPROTO_UDP;
		key->ipv4_tcpudp_key.ipv4_sport = cpu_to_be16(sa->natt.sport);
		key->ipv4_tcpudp_key.ipv4_dport = cpu_to_be16(sa->natt.dport);
	}
	else
	{
		saddr = (unsigned char*)&sa->id.saddr[0];
		daddr = (unsigned char*)&sa->id.daddr.a6[0];
		key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
		for (i = 0; i < 16; i++)
			key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
		for (i = 0; i < 16; i++)
			key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

		key->ipv6_tcpudp_key.ipv6_protocol = IPPROTO_UDP;
		key->ipv6_tcpudp_key.ipv6_sport = cpu_to_be16(sa->natt.sport);
		key->ipv6_tcpudp_key.ipv6_dport = cpu_to_be16(sa->natt.dport);
	}
	return(key_size);
}

static int fill_ipsec_key_info(PSAEntry sa, struct en_exthash_tbl_entry *tbl_entry, 
		uint32_t port_id)
{
	union dpa_key *key;
	uint32_t key_size;
	uint32_t ii;
	uint8_t *sptr;

	key = (union dpa_key *)&tbl_entry->hashentry.key[0];
	//portid added to key
	key->portid = port_id;
	key_size = 1;

	if(sa->family == PROTO_IPV4)
	{
		key_size += sizeof(struct ipv4_esp_key);
		key->ipv4_esp_key.ipv4_daddr = sa->id.daddr.a6[0];
		key->ipv4_esp_key.ipv4_protocol = IPPROTOCOL_ESP;
		key->ipv4_esp_key.spi = sa->id.spi;
	}
	else
	{
		key_size += sizeof(struct ipv6_esp_key);
		sptr = (uint8_t *)&sa->id.daddr;
		for (ii = 0; ii < 16; ii++)
			key->ipv6_tcpudp_key.ipv6_saddr[ii] = *(sptr + ii);
		key->ipv6_esp_key.ipv6_protocol = IPPROTOCOL_ESP;
		key->ipv6_esp_key.spi = sa->id.spi;
	}
	return (key_size);
}


static int get_tbl_type(PSAEntry sa) 
{
	if (IS_NATT_SA(sa))
	{
		if(sa->family == PROTO_IPV4)
			return IPV4_UDP_TABLE;
		else
			return IPV6_UDP_TABLE;
	}
	else
	{
		
		if(sa->family == PROTO_IPV4)
			return ESP_IPV4_TABLE;
		else
			return ESP_IPV6_TABLE;
	}

}

/* This function processes NAT-T packets by
 - Checks if there are any NATT SAs with the matched 5-tuple entries
 - If found and already programmed to Fast path, update the array mask and fill the new spi's in the fast path entry
-- If not found then add the new entry as UDP tuple entry
*/

int cdx_ipsec_process_udp_classification_table_entry(PSAEntry sa)
{
	/* Check if the entry already exists */
	PSAEntry natt_sa;
	int arr_index;
	struct en_exthash_tbl_entry *natt_tbl_entry;
	struct en_ehash_ipsec_preempt_op *ipsec_preempt_params;
	uint32_t* sa_addr;
	uint32_t bytes_to_copy = ETH_HDR_LEN;

	natt_sa = M_ipsec_get_matched_natt_tunnel(sa);

	if (natt_sa && natt_sa->ct)
	{
		if (sa->direction == CDX_DPA_IPSEC_INBOUND)
			sa_addr = &sa->id.daddr.a6[0];
		else
			sa_addr = &sa->id.saddr[0];

		if( dpa_get_iface_info_by_ipaddress(sa->family, sa_addr, NULL, 
					NULL , NULL, &sa->netdev, (uint32_t)sa->handle) != SUCCESS)
		{
			DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
					__FUNCTION__);
			 goto err_ret;
		}
		if (!(sa->flags & SA_SH_DESC_BUILT))
		{
			if (cdx_ipsec_create_shareddescriptor(sa, bytes_to_copy)) {
				DPA_ERROR("%s::unable to create shared desc\n", __FUNCTION__);
				goto err_ret;
			}
			sa->flags |= SA_SH_DESC_BUILT;
		}

		sa->ct = natt_sa->ct;
		
		/* We need to lock this section of code */
		if (sa->direction ==  CDX_DPA_IPSEC_INBOUND)
		{
			/* update in table entry */
			natt_tbl_entry = (struct en_exthash_tbl_entry *)sa->ct->handle;
			ipsec_preempt_params = (struct en_ehash_ipsec_preempt_op*) natt_tbl_entry->ipsec_preempt_params;
			arr_index = get_free_natt_arr_index(be16_to_cpu(ipsec_preempt_params->natt_arr_mask));
			if (arr_index > MAX_SPI_PER_FLOW)
				goto err_ret;
			sa->ct->natt_in_refcnt++;
			ipsec_preempt_params->spi_param[arr_index].spi = sa->id.spi;
			ipsec_preempt_params->spi_param[arr_index].fqid = cpu_to_be32(sa->pSec_sa_context->to_sec_fqid);
			set_natt_arr_mask(&ipsec_preempt_params->natt_arr_mask, arr_index);
			sa->natt_arr_index = arr_index;
#ifdef CDX_DPA_DEBUG
			printk(" SPI : %x - natt_arr_mask :%x\n", sa->id.spi, ipsec_preempt_params->natt_arr_mask);
			display_ehash_tbl_entry(&natt_tbl_entry->hashentry, 14);
#endif
		}
		else
			sa->ct->natt_out_refcnt++;
	}
	else{
		cdx_ipsec_add_classification_table_entry(sa);
		if (sa->direction ==  CDX_DPA_IPSEC_INBOUND)
			sa->ct->natt_in_refcnt = 1;
		else
			sa->ct->natt_out_refcnt = 1;
	}
	
	return SUCCESS;
err_ret:
	return FAILURE;
}

int  cdx_ipsec_add_classification_table_entry(PSAEntry sa)
{
	int retval;
	uint32_t flags;
	uint8_t *ptr;
	uint32_t key_size;
	int tbl_type;
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	uint32_t sa_dir_in = 0;
	uint32_t  itf_id = 0;
	uint32_t bytes_to_copy = ETH_HDR_LEN;

#ifdef CDX_DPA_DEBUG
	printk("%s:: direction %d\n", __FUNCTION__, sa->direction);
#endif

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info) {
		DPA_ERROR("%s::unable to alloc mem for ins_info\n", __FUNCTION__);
		//remove shared desc here??? TBD
		return FAILURE;
	}
	memset(info, 0, sizeof(struct ins_entry_info));

	tbl_entry = NULL;
	//allocate hw ct entry
	sa->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!sa->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n", __FUNCTION__);
		goto err_ret;
	}
	memset(sa->ct, 0, sizeof(struct hw_ct));

	//fman used for ipsec on this SOC, hardcode it for LS1043/46 as there is only one FMAN
	info->fm_idx = IPSEC_FMAN_IDX;
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
				__FUNCTION__, info->fm_idx);
		goto err_ret;
	}


	flags = 0;
	tbl_type = get_tbl_type(sa);
	if (tbl_type ==  -1) {
		DPA_ERROR("%s::unable to get tbl type\n",
				__FUNCTION__);
		goto err_ret;
	}

	//get portand table info
	if(sa->direction == CDX_DPA_IPSEC_INBOUND)
	{
		//inbound
		/* Add the Flow to the ESP table of wan port*/ 
		sa_dir_in = 1;
#ifdef CDX_DPA_DEBUG
		printk("%s::inbound sa\n", __FUNCTION__);
#endif
		if( dpa_get_iface_info_by_ipaddress(sa->family, &sa->id.daddr.a6[0], NULL, 
					&itf_id , &info->port_id, &sa->netdev, (uint32_t)sa->handle) != SUCCESS)
		{
			DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
					__FUNCTION__);
			goto err_ret;
		}
		//get table descriptor based on type and port
		sa->ct->td = dpa_get_tdinfo(info->fm_idx, info->port_id, 
				tbl_type);
		if (sa->ct->td == NULL) {
			DPA_ERROR("%s::unable to get td for portid %d, type %d\n",
					__FUNCTION__, info->port_id, tbl_type);
			goto err_ret;
		}
		/*
		 * storing the interface id for the inbound sa.
		 * This is used for finding interface stats pointer for pppoe interface
		 * May also can be used for orginal interface stats also.  
		 */
		info->sa_itf_id = itf_id; 
		dpa_get_l2l3_info_by_itf_id( itf_id, &info->l2_info, &info->l3_info,sa_dir_in );
#ifdef CDX_DPA_DEBUG
		/*       printk("%s:: Got the table id for portid %d and key type %d as %p \n", 
					__FUNCTION__, info->port_id, key_info->type, sa->ct->td); */
#endif
	} else {
		/* Add the Flow to the ESP table of sec offline port*/ 
#ifdef CDX_DPA_DEBUG
		printk("%s::outbound sa\n", __FUNCTION__);
#endif
		sa_dir_in = 0;
		dpa_ipsec_ofport_td(ipsec_instance, tbl_type, &sa->ct->td,
				&info->port_id);

		if( dpa_get_iface_info_by_ipaddress(sa->family, &sa->id.saddr[0], NULL, 
					NULL , NULL,  &sa->netdev, (uint32_t)sa->handle) != SUCCESS)
		{
			DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
					__FUNCTION__);
			goto err_ret;
		}

/*
		if(!sa->pRtEntry)
		{
			DPA_ERROR("%s:: NULL ROUTE for out SA  finding outbound interface by ipaddress\n",
					__FUNCTION__);
			if (dpa_get_iface_info_by_ipaddress(sa->family,
						((sa->family == PROTO_IPV4) ?  &sa->tunnel.ip4.SourceAddress : 
						 &sa->tunnel.ip6.SourceAddress[0]),
						&info->l2_info.fqid, &itf_id, 
						NULL, NULL, (uint32_t) sa->handle) != SUCCESS)
			{
				DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
						__FUNCTION__);
				goto err_ret;
			}
			dpa_get_l2l3_info_by_itf_id( itf_id,
					&info->l2_info, &info->l3_info,sa_dir_in );
		} else {
*/
		if (dpa_get_out_tx_info_by_itf_id(sa->pRtEntry, 
					&info->l2_info, &info->l3_info)) {
			DPA_ERROR("%s:: dpa_get_out_tx_info_by_itf_id returned error\n",
					__FUNCTION__);
			goto err_ret;
		}
	}
	//create shared descriptoy
	/* In case of outbound SA , whenever there is no route,  
	 * we are removing the fastpath entry from the outbound ESP table
	 * when there is again a valid route, we are adding to the outbound ESP 
	 * table, to add to outbound ESP table 
	 * cdx_ipsec_add_classification_table_entry() is used,
	 * cdx_ipsec_add_classification_table_entry() is not only adding to ESP 
	 * fastpath table, also building shared descriptor
	 * when cdx_ipsec_add_classification_table_entry() it is called 2nd time
	 * onwards, we need not build shared descriptor,
	 * to know whether shared descriptor already built or not.
	 *  SA_SH_DESC_BUILT flag is introduced 
	 */ 
	if (!(sa->flags & SA_SH_DESC_BUILT))
	{
		if (cdx_ipsec_create_shareddescriptor(sa, bytes_to_copy)) {
			DPA_ERROR("%s::unable to create shared desc\n", __FUNCTION__);
			goto err_ret;
		}
		sa->flags |= SA_SH_DESC_BUILT;
	}
	//get table descriptor based on type and port
	info->td = sa->ct->td;
	//allocate hash table entry
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
				__FUNCTION__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	/*	printk("%s: Sa direction = %d Table id = %d port id = %d\n ", __func__,sa_dir_in, info->td, 
			info->port_id); */
#endif
	if (info->td == NULL) {
		DPA_ERROR("%s:: wrong table id passed \n",
				__FUNCTION__);
		goto err_ret;
	}
	/* Fill key information from entry */
	/* For NATT use the 5 tuple key info */
	if (IS_NATT_SA(sa))
		key_size = fill_natt_key_info(sa, tbl_entry, info->port_id); 
	else
		key_size = fill_ipsec_key_info(sa, tbl_entry, info->port_id);
	if (!key_size) {
		DPA_ERROR("%s::unable to compose key\n",
				__FUNCTION__);
		goto err_ret;
	}

	/*round off keysize to next 4 bytes boundary */
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	/*set start of opcode list */
	info->opcptr = ptr;
	/*ptr now after opcode section */
	ptr += MAX_OPCODES;
	flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter =
		cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = cpu_to_be32(JIFFIES32);
	sa->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
	/*set offset to first opcode */
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	/*set param offset*/
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	/*param_ptr now points after timestamp location */
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	/*param pointer and opcode pointer now valid */
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE -
			GET_PARAM_OFFSET(flags));
#ifdef CDX_DPA_DEBUG
	/*	printk("%s:: displaying SA table entry key\n",__func__);
		display_buf(&key_info->key.key_array[0],  key_info->dpa_key.size); */
#endif
	if(sa_dir_in) {
		//fix mtu and fqid for packets to sec
		info->l2_info.fqid = sa->pSec_sa_context->to_sec_fqid;
		info->l2_info.mtu = 0xffff;
		info->to_sec_fqid = sa->pSec_sa_context->to_sec_fqid;
	}
	if (fill_ipsec_actions(sa, info, sa_dir_in)) {
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
	if( IS_NATT_SA(sa) && sa_dir_in)
		tbl_entry->ipsec_preempt_params = info->preempt_params;
	else	
		tbl_entry->enqueue_params = info->enqueue_params;

	sa->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif 
	/*insert entry into hash table */
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry);
	if (retval == -1) {
		DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
		goto err_ret;
	}
	sa->ct->index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	if (sa->ct)
	{
		kfree(sa->ct);
		/*shared descriptor to be released? TBD??? */
		sa->ct = NULL;
	}
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	/*free hw flow entry if allocated */
	kfree(info);
	return FAILURE;
}

int IPsec_get_SEC_failure_stats(uint16_t *pcmd, uint16_t cmd_len)
{
	fpp_sec_failure_stats_query_cmd_t *pStats;
	int retval;

	if (cmd_len < sizeof(fpp_sec_failure_stats_query_cmd_t))
	{
		return ERR_WRONG_COMMAND_SIZE;
	}

	pStats = (fpp_sec_failure_stats_query_cmd_t *)pcmd;
	retval = ExternalHashGetSECfailureStats(&pStats->SEC_failure_stats);

	if (retval)
		return ERR_WRONG_COMMAND_PARAM;

	return cmd_len;
}

int IPsec_reset_SEC_failure_stats(uint16_t *pcmd, uint16_t cmd_len)
{
	ExternalHashResetSECfailureStats();
	return 0;
}
#endif /* DPA_IPSEC_OFFLOAD */
