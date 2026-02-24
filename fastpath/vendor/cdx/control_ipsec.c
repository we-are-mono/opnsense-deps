/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifdef DPA_IPSEC_OFFLOAD 
#include "dpaa_eth_common.h"
#include "cdx.h"
#include "cdx_common.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_pppoe.h"
#include "control_socket.h"
#include "layer2.h"
//#include "module_hidrv.h"
#include "control_ipsec.h"
#include "cdx_dpa_ipsec.h"
#include "misc.h"
//#include "module_socket.h"

//#define CONTROL_IPSEC_DEBUG 1

#define SOCKET_NATT	0

TIMER_ENTRY sa_timer;
int IPsec_Get_Next_SAEntry(PSAQueryCommand  pSAQueryCmd, int reset_action);
//static int IPsec_Free_Natt_socket_v6(PSAEntry sa);
//static int IPsec_Free_Natt_socket_v4(PSAEntry sa);

U16 M_ipsec_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd);
static int IPsec_handle_CREATE_SA(U16 *p, U16 Length);
static int IPsec_handle_DELETE_SA(U16 *p, U16 Length);
static int IPsec_handle_FLUSH_SA(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_KEYS(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_TUNNEL(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_NATT(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_STATE(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_LIFETIME(U16 *p, U16 Length);
static int IPsec_handle_FRAG_CFG(U16 *p, U16 Length);
struct slist_head sa_cache_by_spi[NUM_SA_ENTRIES];
struct slist_head sa_cache_by_h[NUM_SA_ENTRIES];
#ifdef UNIQUE_IPSEC_CP_FQID
struct slist_head sa_cache_by_fqid[NUM_SA_ENTRIES];
#endif /* UNIQUE_IPSEC_CP_FQID */

struct slist_head dpa_sa_context_list;
#ifdef PRINT_OFFLOAD_PKT_COUNT 
extern void print_ipsec_offload_pkt_count(void);
#endif
extern void * cdx_get_xfrm_state_of_sa(void *dev, uint16_t handle);

void sa_free(PSAEntry pSA)
{
	Heap_Free(pSA);
}

static PSAEntry sa_alloc(void)
{
	PSAEntry pSA = NULL;
	pSA = Heap_Alloc_ARAM(sizeof(SAEntry));	
	if(pSA)
		memset(pSA, 0, sizeof(SAEntry));
	return (pSA);
}

static int sa_add(PSAEntry pSA)
{
	/* TODO
	 * We should alloc A DPA Sec SA context here. - Rajendran 6 Oct  2016
	 */
	slist_add(&sa_cache_by_h[pSA->hash_by_h], &pSA->list_h);
	slist_add(&sa_cache_by_spi[pSA->hash_by_spi], &pSA->list_spi);

	return NO_ERR;
}

void sa_remove_from_list_fqid(PSAEntry pSA)
{
#ifdef UNIQUE_IPSEC_CP_FQID
	U16 hash;
	hash = (pSA->pSec_sa_context->to_cp_fqid & (NUM_SA_ENTRIES - 1));
	slist_remove(&sa_cache_by_fqid[hash], &pSA->list_fqid);
#endif /* UNIQUE_IPSEC_CP_FQID */
}
static void sa_remove(PSAEntry pSA, U32 hash_by_h, U32 hash_by_spi)
{
	L2_route_put(pSA->pRtEntry);
	pSA->pRtEntry = NULL;

	slist_remove(&sa_cache_by_h[hash_by_h], &pSA->list_h);
	slist_remove(&sa_cache_by_spi[hash_by_spi], &pSA->list_spi);

	/*
	 * remove the table entry and free the Sec_SA context
	 */
	cdx_ipsec_release_sa_resources(pSA);
}

void*  M_ipsec_get_sa_netdev( U16 handle)
{
	U16 hash = handle & (NUM_SA_ENTRIES -1);
	PSAEntry pEntry;
	struct net_device *net_dev = NULL;
	struct slist_entry *entry;

	slist_for_each(pEntry, entry, &sa_cache_by_h[hash], list_h)
	{
		if (pEntry->handle == handle)
			net_dev = pEntry->netdev;
	}
	return net_dev;
}

void*  M_ipsec_sa_cache_lookup_by_h( U16 handle)
{
	U16 hash = handle & (NUM_SA_ENTRIES -1);
	PSAEntry pEntry;
	PSAEntry pSA = NULL;
	struct slist_entry *entry;

	slist_for_each(pEntry, entry, &sa_cache_by_h[hash], list_h)
	{
		if (pEntry->handle == handle)
			pSA = pEntry;
	}
	return pSA;
}

/* This function matches if there is a NATT SA with the same 5-tuple info but different spi */
void* M_ipsec_get_matched_natt_tunnel(PSAEntry sa)
{
	int i;
	struct slist_entry *entry;
	PSAEntry pEntry;

	for (i = 0; i < NUM_SA_ENTRIES; i++)
	{
		slist_for_each(pEntry, entry, &sa_cache_by_h[i], list_h)
		{
			if (!IS_NATT_SA(sa))
				continue;
			/* This SA is under release process */
			if (pEntry->flags & SA_FREE_HASH_ENTRY)
				continue; 
#ifdef CONTROL_IPSEC_DEBUG
			printk("%x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x\n", \
				pEntry->natt.sport,  sa->natt.sport, pEntry->natt.dport,  \
				sa->natt.dport, pEntry->family, sa->family, pEntry->id.spi, sa->id.spi, \
				pEntry->id.saddr[0], sa->id.saddr[0], pEntry->id.saddr[1], sa->id.saddr[1], \
				pEntry->id.saddr[2],  sa->id.saddr[2], pEntry->id.saddr[3], sa->id.saddr[3], \
				pEntry->id.daddr.a6[0], sa->id.daddr.a6[0], pEntry->id.daddr.a6[1],  sa->id.daddr.a6[1], \
				pEntry->id.daddr.a6[2], sa->id.daddr.a6[2], pEntry->id.daddr.a6[3], sa->id.daddr.a6[3]);

#endif
			if ( (pEntry->natt.sport == sa->natt.sport) &&
					(pEntry->natt.dport == sa->natt.dport) &&
					(pEntry->family == sa->family) &&
					(pEntry->id.spi != sa->id.spi) &&
					(pEntry->id.saddr[0] == sa->id.saddr[0]) &&
					(pEntry->id.saddr[1] == sa->id.saddr[1]) &&
					(pEntry->id.saddr[2] == sa->id.saddr[2]) &&
					(pEntry->id.saddr[3] == sa->id.saddr[3]) &&
					(pEntry->id.daddr.a6[0] == sa->id.daddr.a6[0]) &&
					(pEntry->id.daddr.a6[1] == sa->id.daddr.a6[1]) &&
					(pEntry->id.daddr.a6[2] == sa->id.daddr.a6[2]) &&
					(pEntry->id.daddr.a6[3] == sa->id.daddr.a6[3]) ) 
				return pEntry;
		}
	}
	return NULL;
}

void* M_ipsec_sa_cache_lookup_by_spi(U32 *daddr, U32 spi, U8 proto, U8 family)
{
	U32     hash_key_sa;
	PSAEntry pSA = NULL;
	PSAEntry pEntry;
	struct slist_entry *entry;

	hash_key_sa = HASH_SA(daddr, spi, proto, family);
	slist_for_each(pEntry, entry, &sa_cache_by_spi[hash_key_sa], list_spi)
	{
		if ( (pEntry->id.proto == proto) &&
				(pEntry->id.spi == spi) &&
				(pEntry->id.daddr.a6[0] == daddr[0]) &&
				(pEntry->id.daddr.a6[1] == daddr[1]) &&
				(pEntry->id.daddr.a6[2] == daddr[2]) &&
				(pEntry->id.daddr.a6[3] == daddr[3])&&
				(pEntry->family != family))
		{
			pSA = pEntry;
		}


	}

	return pSA;
}


static int M_ipsec_sa_set_digest_key(PSAEntry sa, U16 key_alg, U16 key_bits, U8* key)
{
	U16      algo;

	if ((key_bits/8) > IPSEC_MAX_KEY_SIZE)
	{
		DPA_ERROR("%s (%d) key_bits %u higher than max key size\n",__FUNCTION__,__LINE__, key_bits);
		return -1;
	}

	switch (key_alg) {
		case SADB_AALG_MD5HMAC:
			algo =OP_PCL_IPSEC_HMAC_MD5_96;
			break;
		case SADB_AALG_SHA1HMAC:
			algo = OP_PCL_IPSEC_HMAC_SHA1_96;
			break;
		case SADB_X_AALG_SHA2_256HMAC:
			algo = OP_PCL_IPSEC_HMAC_SHA2_256_128;
			break;
		case SADB_X_AALG_SHA2_384HMAC:
			algo = OP_PCL_IPSEC_HMAC_SHA2_384_192;
			break;
		case SADB_X_AALG_SHA2_512HMAC:
			algo = OP_PCL_IPSEC_HMAC_SHA2_512_256;
			break;
		case SADB_X_AALG_AES_XCBC_MAC:
			algo = OP_PCL_IPSEC_AES_XCBC_MAC_96;
			break;
		case SADB_X_AALG_NULL:
			algo  =OP_PCL_IPSEC_HMAC_NULL;
			break;
		default:
			return -1;
	}
	sa->pSec_sa_context->auth_data.auth_type = algo;
	sa->pSec_sa_context->auth_data.auth_key_len = (key_bits/8);
	memcpy(sa->pSec_sa_context->auth_data.auth_key,	key, (key_bits/8));
	/* Generate the split key from the normal auth key */
	if (algo != SADB_X_AALG_AES_XCBC_MAC)
		cdx_ipsec_generate_split_key(&sa->pSec_sa_context->auth_data );
	return 0;
}


static int M_ipsec_sa_set_cipher_key(PSAEntry sa, U16 key_alg, U16 key_bits, U8* key)
{
	U16      algo;
	uint8_t	 comb_mode=0, extra_size=0;

	if ((key_bits/8) > IPSEC_MAX_KEY_SIZE)
	{
		DPA_ERROR("%s (%d) key_bits %u higher than max key size\n",__FUNCTION__,__LINE__, key_bits);
		return -1;
	}

	switch (key_alg) {
		case SADB_X_EALG_AESCTR:
			algo = OP_PCL_IPSEC_AES_CTR;
			break;
		case SADB_X_EALG_AESCBC:
			algo = OP_PCL_IPSEC_AES_CBC;
			sa->blocksz = 16;
			break;
		case SADB_X_EALG_AES_CCM_ICV8:
			algo = OP_PCL_IPSEC_AES_CCM8;
			comb_mode = 1;
			extra_size = 3;
			sa->blocksz = 16;
			sa->icvsz = 8;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_CCM_ICV12:
			algo = OP_PCL_IPSEC_AES_CCM12;
			comb_mode = 1;
			extra_size = 3;
			sa->blocksz = 16;
			sa->icvsz = 12;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_CCM_ICV16:
			algo = OP_PCL_IPSEC_AES_CCM16;
			sa->blocksz = 16;
			comb_mode = 1;
			extra_size = 3;
			sa->icvsz = 16;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_GCM_ICV8:
			algo = OP_PCL_IPSEC_AES_GCM8;
			sa->blocksz = 16;
			comb_mode = 1;
			extra_size = 4;
			sa->icvsz = 8;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_GCM_ICV12:
			algo = OP_PCL_IPSEC_AES_GCM12;
			comb_mode = 1;
			extra_size = 4;
			sa->blocksz = 16;
			sa->icvsz = 12;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_GCM_ICV16:
			algo = OP_PCL_IPSEC_AES_GCM16;
			sa->blocksz = 16;
			comb_mode = 1;
			extra_size = 4;
			sa->icvsz = 16;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_NULL_AES_GMAC:
			algo = OP_PCL_IPSEC_AES_GMAC;
			sa->blocksz = 16;
			comb_mode = 1;
			extra_size = 4;
			sa->icvsz = 16;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_EALG_3DESCBC:
			algo = OP_PCL_IPSEC_3DES;
			sa->blocksz = 8;
			break;
		case SADB_EALG_DESCBC:
			algo = OP_PCL_IPSEC_DES;
			sa->blocksz = 8;
			break;
		case SADB_EALG_NULL:
			algo  = OP_PCL_IPSEC_NULL_ENC;
			sa->blocksz = 0;
			break;
		default:
			return -1;
	}
	sa->pSec_sa_context->cipher_data.cipher_type =algo ;
	sa->pSec_sa_context->cipher_data.cipher_key_len = (key_bits/8);
	memcpy(sa->pSec_sa_context->cipher_data.cipher_key, key, (key_bits/8));
	if (comb_mode)
	{
		sa->pSec_sa_context->cipher_data.cipher_key_len -= extra_size;
	}

	return 0;
}

void* M_ipsec_sa_cache_create(U32 *saddr,U32 *daddr, U32 spi, U8 proto, U8 family, U16 handle, U8 replay, U8 esn, U16 mtu, U16 dev_mtu, U8 dir)
{
	U32     hash_key_sa;
	PSAEntry sa;


	//sa = Heap_Alloc_ARAM(sizeof(SAEntry));
	sa = sa_alloc();
	if (sa) {
		memset(sa, 0, sizeof(SAEntry));
		hash_key_sa = HASH_SA(daddr, spi, proto, family);
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_INFO "%s hash_key_sa:%d\n", __func__,hash_key_sa);
#endif
		sa->id.saddr[0] = saddr[0];
		sa->id.saddr[1] = saddr[1];
		sa->id.saddr[2] = saddr[2];
		sa->id.saddr[3] = saddr[3];

		sa->id.daddr.a6[0] = daddr[0];
		sa->id.daddr.a6[1] = daddr[1];
		sa->id.daddr.a6[2] = daddr[2];
		sa->id.daddr.a6[3] = daddr[3];
		sa->id.spi = spi;
		sa->id.proto = proto;
		sa->family = family;
		sa->handle = handle;
		sa->mtu = mtu;
		sa->dev_mtu = dev_mtu;
		sa->state = SA_STATE_INIT;
		if (dir)
			sa->direction = CDX_DPA_IPSEC_INBOUND;
		else
		{
			sa->direction = CDX_DPA_IPSEC_OUTBOUND;
			/* setting an option to set flag to copy DF bit from inner IP hdr to outer IP hdr */
			if (sa->family == PROTO_IPV4)
				sa->hdr_flags |= SA_HDR_COPY_DF;
		}
#ifdef CONTROL_IPSEC_DEBUG
		printk("%s(%d) dir %s, handle %x\n",
				__FUNCTION__,__LINE__,(dir)?"INBOUND" : "OUTBOUND", sa->handle);
#endif
		/* Look like staring seq number is not passed
			 In the shared descriptor we need to set this value.
			 hence for the time being setting to zero*/
		sa->seq = 0;
		sa->pSec_sa_context=cdx_ipsec_sec_sa_context_alloc(handle);
		if(!sa->pSec_sa_context)
		{
			sa_free(sa);
			return NULL;
		}
		if (!replay)
			sa->flags |= SA_ALLOW_SEQ_ROLL;

		//Per RFC 4304 - Should be used by default for IKEv2, unless specified by SA configuration.

		sa->pSec_sa_context->auth_data.auth_type = OP_PCL_IPSEC_HMAC_NULL;
		sa->pSec_sa_context->cipher_data.cipher_type =OP_PCL_IPSEC_NULL_ENC;
		if(esn)
			sa->flags |= SA_ALLOW_EXT_SEQ_NUM;
		sa->hash_by_spi = hash_key_sa;
		sa->hash_by_h   =  handle & (NUM_SA_ENTRIES - 1);
#ifdef UNIQUE_IPSEC_CP_FQID
		/* maintaining SA table with cp_to_fqids */
		slist_add(&sa_cache_by_fqid[(sa->pSec_sa_context->to_cp_fqid & (NUM_SA_ENTRIES - 1))],
				&sa->list_fqid);
#endif /* UNIQUE_IPSEC_CP_FQID */
#ifdef CONTROL_IPSEC_DEBUG
		printk("%s(%d) SA pointer %p, FQID hash %d, fqid %d(%x)\n",__FUNCTION__,__LINE__,sa,
				(sa->pSec_sa_context->to_cp_fqid & (NUM_SA_ENTRIES - 1)), sa->pSec_sa_context->to_cp_fqid,
				sa->pSec_sa_context->to_cp_fqid);
		printk("%s::sa %p, context %p handle %d dir %d\n",
				__FUNCTION__, sa, sa->pSec_sa_context, sa->hash_by_h, sa->direction);
#endif

		if (sa_add(sa) != NO_ERR)
		{
#ifdef CONTROL_IPSEC_DEBUG
			printk(KERN_INFO "%s sa_add failed\n", __func__);
#endif
			return NULL;

		}

	}
	return sa;
}

static int M_ipsec_sa_cache_delete(U16 handle)
{
	U32     hash_key_sa_by_spi;
	U32	hash_key_sa_by_h = handle & (NUM_SA_ENTRIES-1);
	PSAEntry pSA;


	pSA = M_ipsec_sa_cache_lookup_by_h(handle);
	if (!pSA)
		return ERR_SA_UNKNOWN;
	hash_key_sa_by_spi = HASH_SA(pSA->id.daddr.top, pSA->id.spi, pSA->id.proto, pSA->family);

	sa_remove(pSA , hash_key_sa_by_h , hash_key_sa_by_spi);
	return NO_ERR;
}


int IPsec_handle_CREATE_SA(U16 *p, U16 Length)
{
	CommandIPSecCreateSA cmd;
	U8 family;

	/* Check length */
	if (Length != sizeof(CommandIPSecCreateSA))
		return ERR_WRONG_COMMAND_SIZE;

	memset(&cmd, 0, sizeof(CommandIPSecCreateSA));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif
	family = (cmd.said.proto_family == PROTO_FAMILY_IPV4) ? PROTO_IPV4 : PROTO_IPV6;
	if (M_ipsec_sa_cache_lookup_by_spi((U32*) cmd.said.dst_ip , cmd.said.spi, cmd.said.sa_type , family)) {
		return ERR_SA_DUPLICATED;
	}
	if (M_ipsec_sa_cache_lookup_by_h(cmd.sagd)) {
		return ERR_SA_DUPLICATED;
	}

	if (M_ipsec_sa_cache_create((U32*)cmd.said.src_ip, (U32*)cmd.said.dst_ip , cmd.said.spi, cmd.said.sa_type , family, cmd.sagd, cmd.said.replay_window, (cmd.said.flags & NLKEY_SAFLAGS_ESN), cmd.said.mtu, cmd.said.dev_mtu, (cmd.said.flags & NLKEY_SAFLAGS_INBOUND))) {
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_CRIT "%s::spi %x, type %d, dstip %08x, sagd %d family %d flags %d\n",
				__FUNCTION__, cmd.said.spi, cmd.said.sa_type, cmd.said.dst_ip[0], 
				cmd.sagd, cmd.said.proto_family, cmd.said.flags);
#endif
		return NO_ERR;
	}
	else
		return ERR_CREATION_FAILED;

}



static int IPsec_handle_DELETE_SA(U16 *p, U16 Length)
{
	CommandIPSecDeleteSA cmd;
	int rc;

	/* Check length */
	if (Length != sizeof(CommandIPSecDeleteSA))
		return ERR_WRONG_COMMAND_SIZE;
	memset(&cmd, 0, sizeof(CommandIPSecDeleteSA));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::sagd %d\n", __func__,
			cmd.sagd);
#endif

	rc = M_ipsec_sa_cache_delete(cmd.sagd);

	return (rc);

}

int cdx_ipsec_handle_get_inbound_sagd(U32 spi, U16 * sagd )
{
	PSAEntry pEntry;
	int i;

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::\n", __func__);
#endif
	// scan sa_cache and retrun matching handle
	for(i = 0; i < NUM_SA_ENTRIES; i++)
	{
		struct slist_entry *entry;
		slist_for_each_safe(pEntry, entry, &sa_cache_by_h[i], list_h)
		{
			//if((pEntry->direction == CDX_DPA_IPSEC_INBOUND) &&
			//	(pEntry->id.spi == spi)) { 
			if(pEntry->direction == CDX_DPA_IPSEC_INBOUND)
			{
				*sagd = pEntry->handle ;
				return NO_ERR;
			}
		}
	}

	return ERR_CT_ENTRY_INVALID_SA;
}

#ifdef UNIQUE_IPSEC_CP_FQID
struct net_device *get_netdev_of_SA_by_fqid(uint32_t fqid,uint16_t *sagd_pkt)
{
	PSAEntry sa_ptr;
	struct slist_entry *tmp;
	uint16_t fqid_hash = (fqid & (NUM_SA_ENTRIES - 1));

	slist_for_each(sa_ptr,tmp,&sa_cache_by_fqid[fqid_hash],list_fqid)
	{
		if (sa_ptr->flags & SA_DELETE)
		{
			printk("%s(%d) SA marked for deletion , fqid %x, handle %x\n",
					__FUNCTION__,__LINE__,fqid, sa_ptr->handle);
			return NULL;
		}
		/*printk("%s(%d) hash %d  fqid sa %d, arg fqid %d \n",
			__FUNCTION__,__LINE__,fqid_hash, sa_ptr->pSec_sa_context->to_cp_fqid , fqid); */
		if (sa_ptr->pSec_sa_context->to_cp_fqid ==  fqid)
		{
			*sagd_pkt = sa_ptr->handle;
			return sa_ptr->netdev;
		}
	}
	return NULL;
}
#endif /* UNIQUE_IPSEC_CP_FQID */


static int IPsec_handle_FLUSH_SA(U16 *p, U16 Length)
{
	PSAEntry pEntry;
	int i;

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::\n", __func__);
#endif
	// scan sa_cache and delete sa
	for(i = 0; i < NUM_SA_ENTRIES; i++)
	{
		struct slist_entry *entry;
		slist_for_each_safe(pEntry, entry, &sa_cache_by_h[i], list_h)
		{
			U32  hash_key_sa_by_h = pEntry->handle & (NUM_SA_ENTRIES-1);
			U32  hash_key_sa_by_spi = HASH_SA(pEntry->id.daddr.top, pEntry->id.spi, pEntry->id.proto, pEntry->family);

			sa_remove(pEntry, hash_key_sa_by_h, hash_key_sa_by_spi);
		}
	}
	memset(sa_cache_by_h, 0, sizeof(struct slist_head)*NUM_SA_ENTRIES);
	memset(sa_cache_by_spi, 0, sizeof(struct slist_head)*NUM_SA_ENTRIES);
	return NO_ERR;
}

int IPsec_handle_SA_SET_KEYS(U16 *p, U16 Length)
{
	CommandIPSecSetKey cmd;
	PIPSec_key_desc key;
	PSAEntry sa;
	int i;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetKey))
		return ERR_WRONG_COMMAND_SIZE;
	memset(&cmd, 0, sizeof(CommandIPSecSetKey));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d, numkeys %d\n", __func__, cmd.sagd,cmd.num_keys);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);
	sa->pSec_sa_context->auth_data.auth_type = 0;

	if (sa == NULL)
		return ERR_SA_UNKNOWN;
	for (i = 0;i<cmd.num_keys;i++) {
		key = (PIPSec_key_desc)&cmd.keys[i];
#ifdef CONTROL_IPSEC_DEBUG
		printk("%s(%d) key type %d, key alg %d, key bits %d \n",
				__FUNCTION__,__LINE__, key->key_type, key->key_alg,key->key_bits);
#endif
		if (key->key_type) {
			if (M_ipsec_sa_set_cipher_key(sa, key->key_alg, key->key_bits, key->key))
			{
				DPA_ERROR("%s (%d) M_ipsec_sa_set_cipher_key failed\n",__FUNCTION__,__LINE__);
				return ERR_SA_INVALID_CIPHER_KEY;
			}
		}
		else if (M_ipsec_sa_set_digest_key(sa, key->key_alg, key->key_bits, key->key))
		{
			DPA_ERROR("%s (%d) M_ipsec_sa_set_digest_keyfailed\n",__FUNCTION__,__LINE__);
			return ERR_SA_INVALID_DIGEST_KEY;
		}
	}

	return NO_ERR;
}

int IPsec_handle_SA_SET_TUNNEL(U16 *p, U16 Length)
{
	CommandIPSecSetTunnel cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetTunnel))
		return ERR_WRONG_COMMAND_SIZE;
	memset(&cmd, 0, sizeof(CommandIPSecSetTunnel));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;
	if (cmd.proto_family == PROTO_FAMILY_IPV4) {
		sa->header_len = IPV4_HDR_SIZE;
		memcpy(&sa->tunnel.ip4, &cmd.h.ipv4h, sa->header_len);
		sa->tunnel.ip4.Protocol = IPPROTOCOL_ESP;
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_ERR "%s IPV4 Tunnel header, length= %d \n", __func__,sa->header_len);
		printk(KERN_ERR " version %02x tos  %02x length  %04x \n ",cmd.h.ipv4h.Version_IHL,cmd.h.ipv4h.TypeOfService, cmd.h.ipv4h.TotalLength);
		printk(KERN_ERR " Identification  %04x Flag_Frag %04x \n",cmd.h.ipv4h.Identification,cmd.h.ipv4h.Flags_FragmentOffset);
		printk(KERN_ERR " TTL %02x protocol  %02x header check sum  %04x\n ",cmd.h.ipv4h.TTL,cmd.h.ipv4h.Protocol, cmd.h.ipv4h.HeaderChksum );
		printk(KERN_ERR " Source %08x \n dest %08x \n ",cmd.h.ipv4h.SourceAddress,cmd.h.ipv4h.DestinationAddress );
#endif
	}
	else {
		sa->header_len = IPV6_HDR_SIZE;
		memcpy(&sa->tunnel.ip6, &cmd.h.ipv6h, sa->header_len);
		sa->tunnel.ip6.NextHeader = IPPROTOCOL_ESP;
	}

	sa->mode = SA_MODE_TUNNEL;
#if 0
	/* TODO
	 * 
	 * We need to add dpa specific logic here
	 */  
	sa_update(sa);
#endif
	return NO_ERR;

}

static int IPsec_handle_SA_SET_NATT(U16 *p, U16 Length)
{
	CommandIPSecSetNatt  cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetNatt))
		return ERR_WRONG_COMMAND_SIZE;

	// NAT-T modifications
	memset(&cmd, 0, sizeof(CommandIPSecSetNatt));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::sagd %d\n", __func__,
			cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;

	// Add the socket information
	sa->natt.sport = htons(cmd.sport);
	sa->natt.dport = htons(cmd.dport);
	sa->natt.socket = NULL;

	return NO_ERR;
}


static int ipsec_push_sa_to_fast_path(PSAEntry sa)
{
	if (IS_NATT_SA(sa))
	{
		cdx_ipsec_process_udp_classification_table_entry(sa);
	}
	else {
		if (cdx_ipsec_add_classification_table_entry(sa))
			return ERR_CREATION_FAILED;
	}

	if (!(sa->xfrm_state = cdx_get_xfrm_state_of_sa(sa->netdev, sa->handle)))
	{
		printk(KERN_ERR "%s(%d) : cdx_get_xfrm_state_of_sa failed\n",
				__FUNCTION__,__LINE__);
		return ERR_CREATION_FAILED;
	}
	sa->flags |= SA_ENABLED;
	sa->lft_cur.bytes = 0;
	sa->lft_cur.packets = 0;
	return NO_ERR;
}


static int IPsec_handle_SA_SET_TNL_ROUTE(U16 *p, U16 Length)
{
	CommandIPSecSetTunnelRoute  cmd;
	PSAEntry sa;
	PRouteEntry NewRtEntry;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetTunnelRoute))
		return ERR_WRONG_COMMAND_SIZE;

	memset(&cmd, 0, sizeof(CommandIPSecSetTunnelRoute));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;

	if (sa->mode != SA_MODE_TUNNEL)
		return ERR_SA_INVALID_MODE;

	if (sa->pRtEntry)
	{
		/* sa has route already, remove it */
#ifdef CONTROL_IPSEC_DEBUG
		printk("%s::removing rtentry %p in sa %p  dir %d\n", 
				__FUNCTION__, sa->pRtEntry, sa, sa->direction);
#endif
		L2_route_put(sa->pRtEntry);
	}

	NewRtEntry = L2_route_get(cmd.route_id);
	sa->route_id = cmd.route_id;
#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s : new route id = %d new route Entry = %p \n ",__func__ ,sa->route_id,NewRtEntry);
#endif

	if (NewRtEntry != sa->pRtEntry) {
		sa->pRtEntry = NewRtEntry; /* changing to new route entry */
		if (sa->direction == CDX_DPA_IPSEC_INBOUND)
			return NO_ERR;
		/* remove the old fastpath entry */
		if ((sa->ct) && (sa->ct->handle)) 
			cdx_ipsec_delete_fp_entry(sa);
		if ((sa->state == SA_STATE_VALID) && (NewRtEntry)) {
#ifdef CONTROL_IPSEC_DEBUG
			printk("%s::route updated on outbound sa %p, pushing entry to fp\n",
					__FUNCTION__, sa);
#endif
			return(ipsec_push_sa_to_fast_path(sa));
		}
	}
	return NO_ERR;
}

int IPsec_handle_SA_SET_STATE(U16 *p, U16 Length)
{
	CommandIPSecSetState cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetState))
		return ERR_WRONG_COMMAND_SIZE;
	memset(&cmd, 0, sizeof(CommandIPSecSetState));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif

	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;
#ifdef CONTROL_IPSEC_DEBUG
	printk("%s::cmd state :%x sa state %x sa %p, dir %d\n", 
			__FUNCTION__, cmd.state, sa->state, sa, sa->direction);
#endif
	if ((cmd.state == XFRM_STATE_VALID) &&  (sa->state == SA_STATE_INIT)) {
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_INFO "valid:\n");
#endif
		sa->state = SA_STATE_VALID;
		/* SA information is populated in various commands.
		 * This will be the final command in the sequnce.  
		 * So here we can push all the relevent information to DPAA.
		 * a) populate  algorithm, key, tunnel header to shared descriptor.
		 * b) create flow entry for encrypted traffic. 
		 * For ipsec enabled traffic there will be total of 4 flows (considering  both 
		 * directions). Two flows will get added during  SA creation time. 
		 * Other two will get added when the connection tracker add the flow. 
		 * The entry added during sa will be used by all the connections which will 
		 * use this SA.  
		 *       - for inbound SA flow entry  will be added to WAN interface's ESP
		 *	  classification table.
		 *	- for outbound SA,flow entry will be added to offline port's ESP
		 *         classification table. 
		 */
		if ((sa->direction == CDX_DPA_IPSEC_OUTBOUND) && (!sa->pRtEntry)) {
#ifdef CONTROL_IPSEC_DEBUG
			printk("%s::no route on outbound sa skip adding sagd %d entry to fast path\n",
					__FUNCTION__, cmd.sagd);
#endif
			return NO_ERR;

		}
		return (ipsec_push_sa_to_fast_path(sa));
	} 
	else if (cmd.state != XFRM_STATE_VALID) {
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_INFO "not valid:\n");
#endif
		sa->state = SA_STATE_DEAD;
		sa->flags &= ~SA_ENABLED;
		M_ipsec_sa_cache_delete(sa->handle);
		return NO_ERR;
	}
#if 0 
	/* TODO
	 * how use state information in case of dpa offload 
	 */
	sa_update(sa);
#endif
	return NO_ERR;
}


int IPsec_handle_SA_SET_LIFETIME(U16 *p, U16 Length)
{
	CommandIPSecSetLifetime cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetLifetime))
		return ERR_WRONG_COMMAND_SIZE;

	memset(&cmd, 0, sizeof(CommandIPSecSetLifetime));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::sagd %d\n", __func__,
			cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;

	sa->lft_conf.soft_byte_limit =  (U64)cmd.soft_time.bytes[0] + ((U64)cmd.soft_time.bytes[1] << 32);
	sa->lft_conf.soft_packet_limit = cmd.soft_time.allocations;
	sa->lft_conf.hard_byte_limit =  (U64)cmd.hard_time.bytes[0] + ((U64)cmd.hard_time.bytes[1] << 32);
	sa->lft_conf.hard_packet_limit = cmd.hard_time.allocations;

#ifdef CONTROL_IPSEC_DEBUG
	printk (KERN_INFO "set_lifetime:bytes:%llu - %llu\n",sa->lft_conf.soft_byte_limit, sa->lft_conf.hard_byte_limit);
#endif
#if 0
	sa_update(sa);
	hw_sa_set_lifetime(&cmd,sa);
#endif
	return NO_ERR;
}

static int IPsec_handle_FRAG_CFG(U16 *p, U16 Length)
{
	CommandIPSecSetPreFrag cmd;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetPreFrag))
		return ERR_WRONG_COMMAND_SIZE;
#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s .. Started..\n", __func__);
#endif

	memset(&cmd, 0, sizeof(CommandIPSecSetPreFrag));
	memcpy((U8*)&cmd, (U8*)p,  Length);
#if 0
	/* TODO
	 * How do we hanlde frag in dpaa offload
	 */
	ipsec_set_pre_frag(cmd.pre_frag_en);
#endif
	return NO_ERR;

}
//#define PRINT_SA_INFO 1

#ifdef PRINT_SA_INFO 
static int IPsec_Get_Hash_SAEntries(int sa_handle_index)
{

	int tot_sa_entries = 0;
	PSAEntry  pSAEntry;
	struct slist_entry *entry;

	slist_for_each(pSAEntry, entry, &sa_cache_by_h[sa_handle_index], list_h)
	{
		tot_sa_entries++;
	}

	return tot_sa_entries;

}

void display_sa_info(PSAEntry pSA)
{
	struct en_tbl_entry_stats stats;


	memset(&stats, 0, sizeof(stats));
	printk("===========================================\n");
	printk("SA information::(spi = 0x%x SAGD = %d  )\n",htonl(pSA->id.spi),pSA->handle);	
	printk("===========================================\n");
	printk("SA direction : %d\n",pSA->direction);
	printk("SA route id = %d and route pointer = %p\n", pSA->route_id,pSA->pRtEntry);
	if(pSA->ct){

		printk("Classification table %p and handle = %p\n",pSA->ct->td,
				pSA->ct->handle);
		printk("index = %d\n ",pSA->ct->index);
		ExternalHashTableEntryGetStatsAndTS(pSA->ct->handle, &stats);
		{
			printk(" entry pkt count = %lu and byte count = %lu\n ",
					(unsigned long)stats.pkts,(unsigned long)stats.bytes );
		}
	}else{
		printk("Hardware ct is NULL\n");
	}
}
extern void print_ipsec_exception_pkt_cnt(void);

int IPsec_print_SAEntrys(PSAQueryCommand  pSAQueryCmd, int reset_action)
{
	int ipsec_sa_hash_entries;
	int sa_hash_index;

	sa_hash_index = 0;
	while( sa_hash_index < NUM_SA_ENTRIES)
	{
		ipsec_sa_hash_entries = IPsec_Get_Hash_SAEntries(sa_hash_index);
		if(!ipsec_sa_hash_entries) {
			sa_hash_index++;
			continue;
		}
		{
			PSAEntry pSAEntry;
			struct slist_entry *entry;

			slist_for_each(pSAEntry, entry, &sa_cache_by_h[sa_hash_index], list_h)
			{
				display_sa_info(pSAEntry);
				display_fq_info(pSAEntry->pSec_sa_context->dpa_ipsecsa_handle);
			}
		}
		sa_hash_index++;
	}
#ifdef PRINT_OFFLOAD_PKT_COUNT 
	print_ipsec_offload_pkt_count();
#endif
	print_ipsec_exception_pkt_cnt();
	return NO_ERR;
}

#endif

/**
 * M_ipsec_cmdproc
 *
 *
 *
 */
U16 M_ipsec_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc = ERR_UNKNOWN_COMMAND;
	U16 retlen = 2;
	//	printk(KERN_DEBUG "%s: cmd_code=0x%04x, cmd_len=%d\n", __func__, cmd_code, cmd_len);

	switch (cmd_code)
	{
		case CMD_IPSEC_SA_CREATE:
			rc = IPsec_handle_CREATE_SA(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_DELETE:
			rc = IPsec_handle_DELETE_SA(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_FLUSH:
			rc = IPsec_handle_FLUSH_SA(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_SET_KEYS:
			rc = IPsec_handle_SA_SET_KEYS(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_SET_TUNNEL:
			rc = IPsec_handle_SA_SET_TUNNEL(pcmd, cmd_len);
			break;
			/* Could not find defintion for CMD_IPSEC_SA_SET_TNL_ROUTE 
			 * deifed some tmp value in cdx_cmdhandler.h file
			 * time being - Rajendran 6 Oct 2016  
			 */
		case CMD_IPSEC_SA_SET_TNL_ROUTE:
			rc = IPsec_handle_SA_SET_TNL_ROUTE(pcmd, cmd_len);
			break;
		case CMD_IPSEC_SA_SET_NATT:
			rc = IPsec_handle_SA_SET_NATT(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_SET_STATE:
			rc = IPsec_handle_SA_SET_STATE(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_SET_LIFETIME:
			rc = IPsec_handle_SA_SET_LIFETIME(pcmd, cmd_len);
			break;
		case CMD_IPSEC_SA_ACTION_QUERY:
		case CMD_IPSEC_SA_ACTION_QUERY_CONT:
#ifdef PRINT_SA_INFO 
			if(cmd_code == CMD_IPSEC_SA_ACTION_QUERY)
				IPsec_print_SAEntrys((PSAQueryCommand)pcmd, 0);
#endif
			rc = IPsec_Get_Next_SAEntry((PSAQueryCommand)pcmd, cmd_code == CMD_IPSEC_SA_ACTION_QUERY);
			if (rc == NO_ERR)
				retlen += sizeof (SAQueryCommand);
			break;

		case CMD_IPSEC_FRAG_CFG:
			rc = IPsec_handle_FRAG_CFG(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SEC_FAILURE_STATS:
			rc = IPsec_get_SEC_failure_stats(pcmd, cmd_len);

			if (rc > 0) /* in case of success , retval is stats struct length */
				retlen += rc;
			break;

		case CMD_IPSEC_RESET_SEC_FAILURE_STATS:
			rc = IPsec_reset_SEC_failure_stats(pcmd, cmd_len);
			break;

		default:
			printk("%s::ERR_UNKNOWN_COMMAND\n", __FUNCTION__);
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;

	return retlen;
}

static __inline int M_ipsec_sa_expire_notify(PSAEntry sa, int hard)
{
	struct _tCommandIPSecExpireNotify *message;
	HostMessage *pmsg;

	pmsg = msg_alloc();
	if (!pmsg)
		goto err;

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "sending an event:%x:%x\n",hard,sa->handle);
#endif
	message = (struct _tCommandIPSecExpireNotify *)	pmsg->data;

	/*Prepare indication message*/
	message->sagd = sa->handle;
	message->action = (hard) ? IPSEC_HARD_EXPIRE : IPSEC_SOFT_EXPIRE;
	pmsg->code = CMD_IPSEC_SA_NOTIFY;
	pmsg->length = sizeof(*message);

	if (msg_send(pmsg) < 0)
		goto err;

	return 0;

err:
	return 1;
}


static int M_ipsec_sa_timer(struct timer_entry_t *timer_node)
{
	PSAEntry pEntry;
	int i;
	struct en_tbl_entry_stats stats;

	/* Check if classification table entire's  byte/packet count exceed the limit
	 * set in SA 
	 */
	for(i = 0; i < NUM_SA_ENTRIES; i++)
	{
		struct slist_entry *entry;

		slist_for_each(pEntry, entry, &sa_cache_by_h[i], list_h)
		{
			if ((pEntry->ct) && 
					(pEntry->lft_conf.hard_byte_limit ||
					 pEntry->lft_conf.hard_packet_limit ||
					 pEntry->lft_conf.soft_packet_limit || 
					 pEntry->lft_conf.soft_byte_limit))
			{
				ExternalHashTableEntryGetStatsAndTS(pEntry->ct->handle, &stats);

				if ((pEntry->state == SA_STATE_VALID ||
							pEntry->state == SA_STATE_DYING) && 
						((pEntry->lft_conf.hard_byte_limit && 
							(stats.bytes >= pEntry->lft_conf.hard_byte_limit))||
						 (pEntry->lft_conf.hard_packet_limit && 
							(stats.pkts >= pEntry->lft_conf.hard_packet_limit)))) 
				{
#ifdef CONTROL_IPSEC_DEBUG
					printk("%s:: entry pkt count = %lu and byte count = %lu\n SA pkt count = %lu and byte count = %lu \n",__func__,
							(unsigned long)stats.pkts,(unsigned long)stats.bytes , (unsigned long)pEntry->lft_conf.hard_packet_limit,(unsigned long) pEntry->lft_conf.hard_byte_limit);
					printk(KERN_INFO "E");
#endif
					pEntry->state = SA_STATE_EXPIRED;
					pEntry->notify = 1;
				}
				if ((pEntry->state == SA_STATE_VALID) && 
						((pEntry->lft_conf.soft_byte_limit && 
							(stats.bytes >= pEntry->lft_conf.soft_byte_limit))
						 ||(pEntry->lft_conf.soft_packet_limit &&
							 (stats.pkts >= pEntry->lft_conf.soft_packet_limit))))
				{
#ifdef CONTROL_IPSEC_DEBUG
					printk("%s:: entry pkt count = %lu and byte count = %lu\n SA pkt count = %lu and byte count = %lu \n",__func__,
							(unsigned long)stats.pkts,(unsigned long)stats.bytes , (unsigned long)pEntry->lft_conf.soft_packet_limit,(unsigned long) pEntry->lft_conf.soft_byte_limit);
					printk(KERN_INFO "D");
#endif
					pEntry->state = SA_STATE_DYING;
					pEntry->notify = 1;
				}
			}

			if (pEntry->notify)
			{
				int rc;

				if (pEntry->state == SA_STATE_EXPIRED)
					rc = M_ipsec_sa_expire_notify(pEntry, 1);
				else if (pEntry->state == SA_STATE_DYING)
					rc = M_ipsec_sa_expire_notify(pEntry, 0);
				else
					rc = 0;

				if (rc == 0)
					pEntry->notify = 0;
			}
		}

	}
	//printk("%s initializing timer \n", __func__);
	/*
	 * Please check whether adding the same timer node in the timer 
	 * hanler is an issue or not.
	 */
	cdx_timer_add(&sa_timer, SA_TIMER_INTERVAL);
	return 0;
}

#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
static struct qman_fq *cdx_get_to_sec_fq_handler(uint32_t handle)
{
	PSAEntry sa;
	PDpaSecSAContext pSec_sa_context; 

#ifdef CDX_DPA_DEBUG	
	net_crit_ratelimited("%s:: handle %d \n", __FUNCTION__, handle);
#endif 

	if ((sa = M_ipsec_sa_cache_lookup_by_h(handle ))== NULL) {
		/* net_crit_ratelimited("%s:: could not find a SA with handle %d\n",__FUNCTION__,handle); */
		return NULL;
	}

	pSec_sa_context =sa->pSec_sa_context; 
#ifdef CDX_DPA_DEBUG	
	net_crit_ratelimited("%s::SA %p context %p handle %d encryption Sec fqid is %d \n",__FUNCTION__, 
			sa, pSec_sa_context, handle, pSec_sa_context->to_sec_fqid) ; 
#endif 

	return get_to_sec_fq(pSec_sa_context->dpa_ipsecsa_handle); 

}
#endif
BOOL ipsec_init(void)
{
	int i;

	for (i = 0; i < NUM_SA_ENTRIES; i++)
	{
		slist_head_init(&sa_cache_by_h[i]);
		slist_head_init(&sa_cache_by_spi[i]);
	}
	/* TODO
	 *  Here We need to add logic for following 
	 *       - Add function cdx_dpa.c  which will pre allocate fqid pair and shared desriptor for Max number of SA 
	 *       - Allocate DPA Sec SA context stuture and store these fqid pair and shared desciptor and put it in a single linked list
	 *       - Initialise sa_cache_by h and sa_achceby spi linted list table.  
	 */

	/* initialize a singled list for puting the sec sa context with the pair of fqid
	 * and the shared descriptor and other memory if any required by Sec. 
	 */
	cdx_ipsec_init();
#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s timer is initialized \n", __func__);
#endif
	cdx_timer_init(&sa_timer, M_ipsec_sa_timer);
	cdx_timer_add(&sa_timer, SA_TIMER_INTERVAL);

	set_cmd_handler(EVENT_IPS_IN, M_ipsec_cmdproc);
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
	//register hook function for intercepting ipsec packets from ethernet driver
	if (dpa_register_ipsec_fq_handler(cdx_get_to_sec_fq_handler)) {
		printk(KERN_INFO "%s unable to registeri ipsec hook func\n", 
				__func__);
		return -1;
	}
#endif
	return 0;
}

void ipsec_exit(void)
{
	cdx_timer_del(&sa_timer);
}
#endif  // DPA_IPSEC_OFFLOAD
