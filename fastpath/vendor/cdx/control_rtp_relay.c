/*
 *  Copyright 2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "portdefs.h"
#include "cdx.h"
#include "misc.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_socket.h"
#include "module_rtp_relay.h"


U8 gDTMF_PT[2];


typedef void *      t_Handle;   /* actually defined in ncsw_ext.h */
typedef uint32_t    t_Error;  /* actually defined in ncsw_ext.h */

extern t_Error FM_MURAM_FreeMem(t_Handle h_FmMuram, void *ptr);
extern void  * FM_MURAM_AllocMem(t_Handle h_FmMuram, uint32_t size, uint32_t align);
struct _thw_RTPinfo * cdx_rtp_alloc_muram_rtpinfo(void);


struct slist_head rtpflow_cache[NUM_RTPFLOW_ENTRIES] __attribute__((aligned(32)));
extern TIMER_ENTRY rtpflow_timer;

struct slist_head rtpcall_list[NUM_RTPFLOW_ENTRIES];


/* extern TIMER_ENTRY rtpqos_timer; */
/* extern struct slist_head rtpqos_list; */
/* struct dlist_head hw_rtpqos_removal_list; */


static void RTP_release_flow(PRTPflow pFlow);


static __inline U32 HASH_RTPCALLID(U16 id)
{
	return (id & (NUM_RTPFLOW_ENTRIES - 1));
}

static PVOID rtp_call_alloc(void)
{
	return kzalloc(sizeof(struct _tRTPcall), GFP_KERNEL);
}

static void rtp_call_free(PRTPCall pCall)
{
	kfree((PVOID)pCall);
}

static PVOID rtp_flow_alloc(void)
{
	return kzalloc(sizeof(struct _tRTPflow), GFP_KERNEL);
}

static void rtp_flow_free(PRTPflow pFlow)
{
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;

	if (pFlow->hw_flow)
	{
		if (pFlow->hw_flow->rtp_info)
		{
			// allocate MURAM memory for the RTP info, which is required to be accessed and modified by ucode
			h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
			if (h_FmMuram)
			{
				FM_MURAM_FreeMem(h_FmMuram, (void *)pFlow->hw_flow->rtp_info);
				pFlow->hw_flow->rtp_info  = NULL;
			}
			else
			{
				DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
			}
		}
		kfree(pFlow->hw_flow);
		pFlow->hw_flow = NULL;
	}
	kfree((PVOID)pFlow);
}

struct _thw_RTPinfo * cdx_rtp_alloc_muram_rtpinfo(void)
{
	struct _thw_RTPinfo *rtp_info;
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;

	DPA_INFO("%s(%d) sizeof(struct _thw_RTPinfo) %lu\n",
			__FUNCTION__,__LINE__, sizeof(struct _thw_RTPinfo));
	// allocate MURAM memory for the RTP info, which is required to be accessed and modified by ucode
	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		return NULL;
	}

	rtp_info = FM_MURAM_AllocMem(h_FmMuram, sizeof(struct _thw_RTPinfo), 32);

	return rtp_info;
}

void cdx_muram_rtpinfo_free(void *hw_flow)
{
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;

	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		return;
	}

	FM_MURAM_FreeMem(h_FmMuram, hw_flow);
	return;
}

int cdx_rtp_set_hwinfo_fields(PRTPflow pFlow, PSockEntry pFromSocket)
{
	struct _thw_rtpflow *hw_flow;
	struct _thw_RTPinfo *pRtp_info = NULL;
	uint16_t flags = 0;

	hw_flow =  pFlow->hw_flow;

	flags = 0;

	if (create_ddr_and_copy_from_muram((void *)hw_flow->rtp_info, (void **)&pRtp_info, sizeof(struct _thw_RTPinfo)) == NULL)
	{
		DPA_ERROR("%s(%d) Failed to copy from muram to ddr:\n", __FUNCTION__, __LINE__);
		return -1;
	}
	/* reflect changes to hardware flow */
	if (pFlow->takeover_flags & SSRC_TAKEOVER)
	{
		if (pFlow->takeover_mode & RTP_TAKEOVER_MODE_SSRC_AUTO)
		{
			flags |= RTP_OFFLOAD_SSRC_AUTO_TAKEOVER;
		}
		flags |=  RTP_OFFLOAD_SSRC_TAKEOVER;
		pRtp_info->SSRC = cpu_to_be32(pFlow->SSRC);
	}

	if (pFlow->takeover_flags & SSRC_1_TAKEOVER)
		flags |=  RTP_OFFLOAD_SSRC_1_TAKEOVER;

	if (pFlow->takeover_flags & TIMESTAMP_TAKEOVER)
	{
		flags |=  RTP_OFFLOAD_TS_TAKEOVER;
	}

	if (pFlow->takeover_flags & SEQ_NUM_TAKEOVER)
		flags |= RTP_OFFLOAD_SEQ_TAKEOVER;

	DPA_INFO("%s(%d) MarkerBitConfMode %d , takeover_flags %x, MARKER_BIT_TAKEOVER %x\n",
			__FUNCTION__, __LINE__,
			pFlow->takeover_flags, pFlow->MarkerBitConfMode, MARKER_BIT_TAKEOVER);

	// Marker Bit Configuration Mode 1 -- Processing is done to Reset the bit (1->0,0->0)
	if ((pFlow->takeover_flags & MARKER_BIT_TAKEOVER) &&
			(pFlow->MarkerBitConfMode))
	{
		DPA_INFO("%s(%d) \n", __FUNCTION__, __LINE__);
		flags |= RTP_OFFLOAD_RESET_MARKER_BIT;
	}

	if (pFlow->takeover_resync)
		flags |= RTP_OFFLOAD_TAKEOVER_RESYNC;

	if (pFromSocket->SocketFamily == PROTO_IPV4)
		flags |= RTP_OFFLOAD_IPV4_PACKET;

	if (pFlow->RTPcall->Special_tx_active)
		flags |= RTP_OFFLOAD_SPECIAL_TX_ACTIVE;

	if (pFromSocket->proto == 17)
		flags |= RTP_OFFLOAD_UDP_PROTOCOL;

	if (pFlow->rtp_info.first_packet)
		flags |= RTP_OFFLOAD_RTP_FIRST_PACKET;

	if (pFromSocket->unconnected == SOCKET_UNCONNECTED)
		flags |=  RTP_OFFLOAD_VERIFY_SOURCE_ADDR;


	if (pFlow->state)
	{
		flags |= RTP_OFFLOAD_PROCESS_PKT;
	}

	if (pFlow->call_update_seen)
		flags |= RTP_OFFLOAD_CALL_UPDATE_SEEN;

	if (pFlow->takeover_mode  & RTP_TAKEOVER_MODE_TSINCR_FREQ)
		flags |= RTP_OFFLOAD_TS_TAKEOVER_SAMPL_FREQ;

	DPA_INFO("%s(%d) flags %x \n", __FUNCTION__,__LINE__, flags);
	pRtp_info->TimestampBase = cpu_to_be32(pFlow->TimestampBase);
	pRtp_info->flags = cpu_to_be16(flags);
	pRtp_info->Seq = cpu_to_be16(pFlow->Seq);
	memcpy(hw_flow->Special_payload1, pFlow->RTPcall->Special_payload1, RTP_SPECIAL_PAYLOAD_LEN);
	memcpy(hw_flow->Special_payload2, pFlow->RTPcall->Special_payload2, RTP_SPECIAL_PAYLOAD_LEN);

	pRtp_info->probation = pFlow->rtp_info.probation;

	copy_ddr_to_muram_and_free_ddr((void *)hw_flow->rtp_info, (void **)&pRtp_info, sizeof(struct _thw_RTPinfo));

	return 0;
}
static int rtp_flow_add(PRTPflow pFlow, U32 hash, PSockEntry pFromSocket, PSockEntry pToSocket)
{
	//allocate memory for offload stuff
	pFlow->hw_flow = (struct _thw_rtpflow *)kzalloc(sizeof(struct _thw_rtpflow), GFP_KERNEL);
	if (!pFlow->hw_flow)
	{
		DPA_ERROR("%s::unable to alloc mem for pFlow->hw_flow\n",
				__FUNCTION__);
		return ERR_NOT_ENOUGH_MEMORY;
	}

	pFlow->hw_flow->rtp_info = cdx_rtp_alloc_muram_rtpinfo();
	if (!pFlow->hw_flow->rtp_info)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		kfree(pFlow->hw_flow);
		return ERR_NOT_ENOUGH_MEMORY;
	}

	// create an entry in ehash table
	if (cdx_create_rtp_conn_in_classif_table(pFlow, pFromSocket, pToSocket))
	{
		cdx_muram_rtpinfo_free((void *)pFlow->hw_flow->rtp_info);
		kfree(pFlow->hw_flow);
		pFlow->hw_flow = NULL;
		return -1;
	}

	if (cdx_rtp_set_hwinfo_fields(pFlow, pFromSocket) != 0)
	{
		DPA_ERROR("%s(%d) Error in setting rtp hwinfo fields.\n", __FUNCTION__,__LINE__);
		cdx_muram_rtpinfo_free((void *)pFlow->hw_flow->rtp_info);
		kfree(pFlow->hw_flow);
		pFlow->hw_flow = NULL;
		return -1;
	}
	cdx_ehash_set_rtp_info_params(pFlow->hw_flow->ehash_rtp_relay_params, 
			pFlow, pFromSocket);

	/* Add software entry to local hash */
	slist_add(&rtpflow_cache[hash], &pFlow->list);

	return NO_ERR;
}

#if 0
/* add a hardware flow entry to packet engine hash */
static void rtp_flow_link(struct _thw_rtpflow *hw_flow, U32 hash)
{
	struct _thw_rtpflow *hw_flow_first;

	/* add hw entry to active list and update next pointer */
	if(!dlist_empty(&hw_flow_active_list[hash]))
	{
		/* list is not empty, and we'll be added at head, so current first will become our next pointer */
		hw_flow_first = container_of(dlist_first(&hw_flow_active_list[hash]), typeof(struct _thw_rtpflow), list);
		hw_entry_set_field(&hw_flow->next, hw_entry_get_field(&hw_flow_first->dma_addr));
	}
	else
	{
		/* entry is empty, so we'll be the first and only one entry */
		hw_entry_set_field(&hw_flow->next, 0);
	}

	/* this rtp flow is now the head of the hw entry list, so put it also to pfe's internal hash */
	rtp_flow_add_to_pe(hw_flow->dma_addr, hash);

	dlist_add(&hw_flow_active_list[hash], &hw_flow->list);
}

#endif // 0
/* remove a hardware flow entry from the packet engine hash */
static void rtp_flow_unlink(struct _thw_rtpflow *hw_flow, U32 hash)
{
	if ((hw_flow->eeh_entry_handle) &&
			(ExternalHashTableDeleteKey(hw_flow->td, 
																	hw_flow->eeh_entry_index, hw_flow->eeh_entry_handle))) 
	{
		DPA_ERROR("%s(%d)::unable to remove entry from hash table\n", __FUNCTION__, __LINE__);
	}
	//free table entry
	if (hw_flow->eeh_entry_handle)
		ExternalHashTableEntryFree(hw_flow->eeh_entry_handle);
	hw_flow->eeh_entry_handle =  NULL;
}

static void rtp_flow_remove(PRTPflow pFlow)
{
	struct _thw_rtpflow *hw_flow;
	U32 hash = HASH_RTP(pFlow->ingress_socketID);

	/* Check if there is a hardware flow */
	if ((hw_flow = pFlow->hw_flow))
	{
		/* remove it in ucode  */
		rtp_flow_unlink(hw_flow, 0);

	}

	slist_remove(&rtpflow_cache[hash], &pFlow->list);

	RTP_release_flow(pFlow);
}

static PRTPflow RTP_create_flow(U16 in_socket, U16 out_socket)
{
	struct _tRTPflow* pFlow;

	pFlow = rtp_flow_alloc();
	if (pFlow) {
		memset(pFlow, 0, sizeof(struct _tRTPflow));
		pFlow->ingress_socketID = in_socket;
		pFlow->egress_socketID = out_socket;
		pFlow->rtp_info.first_packet = TRUE;
		pFlow->rtp_info.probation = RTP_MIN_SEQUENTIAL;

		SOCKET_bind(in_socket, pFlow, SOCK_OWNER_RTP_RELAY);
	}

	return pFlow;
}

static void RTP_release_flow(PRTPflow pFlow)
{
	SOCKET_unbind(pFlow->ingress_socketID);

	rtp_flow_free(pFlow);
}

static int RTP_change_flow(PRTPflow pFlow, U16 ingress_socketID, U16 egress_socketID,
		PSockEntry pingress_socket, PSockEntry pegress_socket)
{
	struct _thw_rtpflow *hw_flow = pFlow->hw_flow;
	U32	hash;

	pFlow->takeover_resync = TRUE;
	pFlow->rtp_info.first_packet = TRUE;

	hash = HASH_RTP(pFlow->ingress_socketID);

	// delete the previous entry in ucode
	rtp_flow_unlink(hw_flow, hash);

	/* now managing changes in software flow */
	slist_remove(&rtpflow_cache[hash], &pFlow->list);

	SOCKET_unbind(pFlow->ingress_socketID);

	pingress_socket->out_rtp_flow =  NULL;

	pFlow->ingress_socketID = ingress_socketID;
	pFlow->egress_socketID = egress_socketID;
	pFlow->call_update_seen = TRUE;

	SOCKET_bind(ingress_socketID, pFlow, SOCK_OWNER_RTP_RELAY);

	hash = HASH_RTP(ingress_socketID);

	slist_add(&rtpflow_cache[hash], &pFlow->list);

	/* reflect changes to hardware flow */
	// create an entry in ehash table
	if(cdx_create_rtp_conn_in_classif_table(pFlow, pingress_socket, pegress_socket))
	{
		DPA_ERROR("%s(%d) error in creating eehash table entry\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (cdx_rtp_set_hwinfo_fields(pFlow, pingress_socket) != 0)
	{
		DPA_ERROR("%s(%d) Error in setting rtp hwinfo fields.\n", __FUNCTION__,__LINE__);
		return -1;
	}
	cdx_ehash_set_rtp_info_params(hw_flow->ehash_rtp_relay_params, pFlow, pingress_socket);

	return 0;
}


int rtp_flow_reset(void)
{
	PRTPflow pEntry;
	struct slist_entry *entry;
	int hash;

	for(hash = 0; hash < NUM_RTPFLOW_ENTRIES; hash++)
	{
		slist_for_each_safe(pEntry, entry, &rtpflow_cache[hash], list)
		{
			rtp_flow_remove(pEntry);
		}
	}

	return NO_ERR;
}

static PRTPCall RTP_find_call(U16 CallID)
{
	PRTPCall pCall;
	struct slist_entry *entry;
	int hash;

	hash = HASH_RTPCALLID(CallID);

	slist_for_each(pCall, entry, &rtpcall_list[hash], list)
	{
		if (pCall->valid && (pCall->call_id == CallID))
			return 	pCall;
	}

	return NULL;
}


static PRTPCall RTP_create_call(U16 CallID)
{
	PRTPCall pCall = NULL;
	int hash;

	hash = HASH_RTPCALLID(CallID);

	if((pCall = rtp_call_alloc()))
	{
		pCall->valid = TRUE;
		pCall->call_id = CallID;

		slist_add(&rtpcall_list[hash], &pCall->list);
	}

	return pCall;
}


static void RTP_release_call(PRTPCall pCall)
{
	int hash;
	if(pCall)
	{
		hash = HASH_RTPCALLID(pCall->call_id);
		slist_remove(&rtpcall_list[hash], &pCall->list);

		rtp_call_free(pCall);
	}
}

int rtp_call_reset(void)
{
	PRTPCall pEntry;
	struct slist_entry *entry;
	int ii;

	for (ii=0; ii< NUM_RTPFLOW_ENTRIES; ii++)
	{
		slist_for_each_safe(pEntry, entry, &rtpcall_list[ii], list)
		{
			RTP_release_call(pEntry);
		}
	}

	return NO_ERR;
}

static U16 RTP_Call_Open (U16 *p, U16 Length)
{
	RTPOpenCommand RTPCmd;
	PRTPCall pCall;
	PSockEntry pSocketA = NULL, pSocketB = NULL;
	int rc = NO_ERR;

	// Check length
	if (Length != sizeof(RTPOpenCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&RTPCmd, (U8*)p, sizeof(RTPOpenCommand));

	// Make sure sockets exist but are unused
	if (RTPCmd.SocketA) {
		pSocketA = SOCKET_find_entry_by_id(RTPCmd.SocketA);
		if (!pSocketA)
			return ERR_SOCKID_UNKNOWN;

		if (pSocketA->owner)
			return ERR_SOCK_ALREADY_IN_USE;

		if (RTPCmd.SocketA == RTPCmd.SocketB)
			return ERR_SOCK_ALREADY_IN_USE;
	}

	if (RTPCmd.SocketB) {
		pSocketB = SOCKET_find_entry_by_id(RTPCmd.SocketB);
		if (!pSocketB)
			return ERR_SOCKID_UNKNOWN;

		if (pSocketB->owner)
			return ERR_SOCK_ALREADY_IN_USE;
	}

	if (pSocketA && pSocketB)
	{
		if (pSocketA->SocketFamily != pSocketB->SocketFamily)
			return ERR_WRONG_SOCK_FAMILY;

		if (pSocketA->proto != pSocketB->proto)
			return ERR_WRONG_SOCK_PROTO;
	}
	else
	{
		return ERR_SOCKID_UNKNOWN;
	}

	if(!pSocketA->pRtEntry)
	{
		DPA_INFO("%s(%d) missing route, checking for route\n",
				__FUNCTION__,__LINE__);
		SOCKET4_check_route(pSocketA);
	}
	if(!pSocketB->pRtEntry)
	{
		DPA_INFO("%s(%d) missing route, checking for route\n",
				__FUNCTION__,__LINE__);
		SOCKET4_check_route(pSocketB);
	}

	if (!pSocketA->pRtEntry || !pSocketB->pRtEntry)
		return ERR_NO_ROUTE_TO_SOCK;

	if (RTP_find_call(RTPCmd.CallID))
		return ERR_RTP_CALLID_IN_USE;

	pCall = RTP_create_call(RTPCmd.CallID);
	if (pCall == NULL)
		return ERR_CREATION_FAILED;

	pCall->AtoB_flow = RTP_create_flow(RTPCmd.SocketA, RTPCmd.SocketB);
	if (pCall->AtoB_flow == NULL) {
		rc = ERR_NOT_ENOUGH_MEMORY;
		goto err_flow_a;
	}

	pCall->AtoB_flow->RTPcall = pCall;

	pCall->BtoA_flow = RTP_create_flow(RTPCmd.SocketB, RTPCmd.SocketA);
	if (pCall->BtoA_flow == NULL) {
		rc = ERR_NOT_ENOUGH_MEMORY;
		goto err_flow_b;
	}

	pCall->BtoA_flow->RTPcall = pCall;

	/* Now adding hardware flows to packet engine's flow cache */	
	if(rtp_flow_add(pCall->AtoB_flow, HASH_RTP(RTPCmd.SocketA), pSocketA, pSocketB) != NO_ERR)
	{
		printk(KERN_ERR "%s: AtoB ERR_NOT_ENOUGH_MEMORY\n", __func__);
		rc = ERR_NOT_ENOUGH_MEMORY;
		goto err_hw_flow_a;
	}

	if(rtp_flow_add(pCall->BtoA_flow, HASH_RTP(RTPCmd.SocketB), pSocketB, pSocketA) != NO_ERR)
	{
		printk(KERN_ERR "%s: BtoA ERR_NOT_ENOUGH_MEMORY\n", __func__);
		rtp_flow_remove(pCall->AtoB_flow);
		RTP_release_flow(pCall->BtoA_flow);
		rc = ERR_NOT_ENOUGH_MEMORY;
		goto err_hw_flow_b;
	}

	pSocketB->out_rtp_flow =  pCall->AtoB_flow;
	pSocketA->out_rtp_flow = pCall->BtoA_flow;

	return NO_ERR;

err_hw_flow_a:
	RTP_release_flow(pCall->BtoA_flow);

err_flow_b:
	RTP_release_flow(pCall->AtoB_flow);

err_flow_a:
err_hw_flow_b:
	RTP_release_call(pCall);

	return rc;
}


static U16 RTP_Call_Update (U16 *p, U16 Length)
{
	RTPOpenCommand RTPCmd;
	PRTPCall pCall;
	PSockEntry pSocketA = NULL, pSocketB = NULL;

	// Check length
	if (Length != sizeof(RTPOpenCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&RTPCmd, (U8*)p, sizeof(RTPOpenCommand));

	if ((pCall = RTP_find_call(RTPCmd.CallID)) == NULL)
		return ERR_RTP_UNKNOWN_CALL;

	if (RTPCmd.SocketA && (RTPCmd.SocketA == RTPCmd.SocketB))
		return ERR_SOCK_ALREADY_IN_USE;

	if (RTPCmd.SocketA)
	{
		pSocketA = SOCKET_find_entry_by_id(RTPCmd.SocketA);
		if (!pSocketA)
			return ERR_SOCKID_UNKNOWN;

		if (pSocketA->owner && (pCall->AtoB_flow->ingress_socketID != RTPCmd.SocketA))
			return ERR_SOCK_ALREADY_IN_USE;
	}
	else
		pSocketA = SOCKET_find_entry_by_id(pCall->AtoB_flow->ingress_socketID);

	if (RTPCmd.SocketB)
	{
		pSocketB = SOCKET_find_entry_by_id(RTPCmd.SocketB);
		if (!pSocketB)
			return ERR_SOCKID_UNKNOWN;

		if (pSocketB->owner && (pCall->BtoA_flow->ingress_socketID != RTPCmd.SocketB))
			return ERR_SOCK_ALREADY_IN_USE;
	}
	else
		pSocketB = SOCKET_find_entry_by_id(pCall->BtoA_flow->ingress_socketID);

	if (pSocketA && pSocketB)
	{
		if (pSocketA->SocketFamily != pSocketB->SocketFamily)
			return ERR_WRONG_SOCK_FAMILY;

		if (pSocketA->proto != pSocketB->proto)
			return ERR_WRONG_SOCK_PROTO;
	}
	else
	{
		return ERR_SOCKID_UNKNOWN;
	}

	if(!pSocketA->pRtEntry)
	{
		DPA_INFO("%s(%d) missing route, checking for route\n",
				__FUNCTION__,__LINE__);
		SOCKET4_check_route(pSocketA);
	}
	if(!pSocketB->pRtEntry)
	{
		DPA_INFO("%s(%d) missing route, checking for route\n",
				__FUNCTION__,__LINE__);
		SOCKET4_check_route(pSocketB);
	}

	if (!pSocketA->pRtEntry || !pSocketB->pRtEntry)
		return ERR_NO_ROUTE_TO_SOCK;


	if (RTP_change_flow(pCall->BtoA_flow, RTPCmd.SocketB, RTPCmd.SocketA, pSocketB, pSocketA))
		return -1;
	if (RTP_change_flow(pCall->AtoB_flow, RTPCmd.SocketA, RTPCmd.SocketB, pSocketA, pSocketB))
		return -1;

	pSocketB->out_rtp_flow = pCall->AtoB_flow;
	pSocketA->out_rtp_flow = pCall->BtoA_flow;

	return NO_ERR;
}


static U16 RTP_Call_Close (U16 *p, U16 Length)
{
	RTPCloseCommand RTPCmd;
	PRTPCall pCall;
	int rc = NO_ERR;
	PSockEntry pSocketA = NULL, pSocketB = NULL;

	// Check length
	if (Length != sizeof(RTPCloseCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&RTPCmd, (U8*)p, sizeof(RTPCloseCommand));

	if ((pCall = RTP_find_call(RTPCmd.CallID)) == NULL)
		return ERR_RTP_UNKNOWN_CALL;


	pSocketA = SOCKET_find_entry_by_id(pCall->AtoB_flow->ingress_socketID);
	if (pSocketA)
	{
		pSocketA->owner_type = SOCK_OWNER_NONE;
		pSocketA->owner =  NULL;
		pSocketA->out_rtp_flow = NULL;
	}

	pSocketB = SOCKET_find_entry_by_id(pCall->BtoA_flow->ingress_socketID);
	if (pSocketB)
	{
		pSocketB->owner_type = SOCK_OWNER_NONE;
		pSocketB->owner =  NULL;
		pSocketB->out_rtp_flow = NULL;
	}

	/* remove hardware flow from packet engine */
	rtp_flow_remove(pCall->BtoA_flow);
	rtp_flow_remove(pCall->AtoB_flow);

	RTP_release_call(pCall);

	return rc;
}

// currently only discard or process state is changed in this func
static U16 RTP_Call_Control (U16 *p, U16 Length)
{
	RTPControlCommand RTPCmd;
	PRTPCall pCall;
	PSockEntry pSocket = NULL;
	struct _thw_RTPinfo *pRtp_info = NULL;
	uint32_t vlan_hdr_val;
	U16		 flags,ii;

	// Check length
	if (Length != sizeof(RTPControlCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&RTPCmd, (U8*)p, sizeof(RTPControlCommand));

	if ((pCall = RTP_find_call(RTPCmd.CallID)) == NULL)
		return ERR_RTP_UNKNOWN_CALL;

	DPA_INFO("%s(%d) RTPCmd.ControlDir %0x\n",
			__FUNCTION__,__LINE__,RTPCmd.ControlDir);
	pCall->AtoB_flow->state = (RTPCmd.ControlDir & 0x1);
	pCall->BtoA_flow->state = (RTPCmd.ControlDir & 0x2);
	if (RTPCmd.ControlDir & 0x4)
	{
		pCall->AtoB_flow->hw_flow->flags &= ~(RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING);
		pCall->BtoA_flow->hw_flow->flags &= ~(RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING);
		if (RTPCmd.ControlDir & 0x8)
		{
			pCall->AtoB_flow->hw_flow->flags |= RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING;
			DPA_INFO("%s(%d) AtoB flow VLAN learningn feature is enabled\n",__FUNCTION__,__LINE__);
		}

		if (RTPCmd.ControlDir & 0x16)
		{
			pCall->BtoA_flow->hw_flow->flags |= RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING;
			DPA_INFO("%s(%d) BtoA flow VLAN learningn feature is enabled\n",__FUNCTION__,__LINE__);
		}
	}
	else
	{
		pCall->AtoB_flow->hw_flow->flags &= ~(RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING);
		pCall->BtoA_flow->hw_flow->flags &= ~(RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING);
	}	
	if (RTPCmd.vlanPbitConf)
	{
		if (RTPCmd.vlanPbitConf & 0x01) // packets received on socket A
		{
			pCall->AtoB_flow->vlan_p_bit_val = (RTPCmd.vlanPbitConf & 0x1C ) >> 2 ;
			for (ii=0; ii<pCall->AtoB_flow->hw_flow->num_vlan_hdrs; ii++)
			{
				vlan_hdr_val = *(pCall->AtoB_flow->hw_flow->vlan_hdr_ptr+ii);
				DPA_INFO("%s(%d) vlan-hdr val %0x, pbit bit %d\n",
						__FUNCTION__,__LINE__,vlan_hdr_val,pCall->AtoB_flow->vlan_p_bit_val);
				vlan_hdr_val = vlan_hdr_val & 0xff1fffff;
				vlan_hdr_val = vlan_hdr_val | 
					(pCall->AtoB_flow->vlan_p_bit_val << 21);
				*(pCall->AtoB_flow->hw_flow->vlan_hdr_ptr+ii) = vlan_hdr_val;
				DPA_INFO("%s(%d) new vlan-hdr val %x\n",
						__FUNCTION__,__LINE__,vlan_hdr_val);
			}
		}
		if (RTPCmd.vlanPbitConf & 0x02) // packets received on socket B
		{
			pCall->BtoA_flow->vlan_p_bit_val = (RTPCmd.vlanPbitConf & 0xE0 ) >> 5;
			for (ii=0; ii<pCall->BtoA_flow->hw_flow->num_vlan_hdrs; ii++)
			{
				vlan_hdr_val = *(pCall->BtoA_flow->hw_flow->vlan_hdr_ptr+ii);
				DPA_INFO("%s(%d) vlan-hdr val %0x, pbit val %d\n",
						__FUNCTION__,__LINE__,vlan_hdr_val,
						pCall->BtoA_flow->vlan_p_bit_val);
				vlan_hdr_val = vlan_hdr_val & 0xff1fffff;
				vlan_hdr_val = vlan_hdr_val | 
					(pCall->BtoA_flow->vlan_p_bit_val << 21);
				*(pCall->BtoA_flow->hw_flow->vlan_hdr_ptr+ii) = vlan_hdr_val;
				DPA_INFO("%s(%d) new vlan-hdr val %0x\n",
						__FUNCTION__,__LINE__,vlan_hdr_val);
			}
		}
	}	


	//TODO for more options of NFD for rtp relay
	if (pCall->AtoB_flow->state)
	{
		if (create_ddr_and_copy_from_muram((void *)pCall->AtoB_flow->hw_flow->rtp_info,
					(void **)&pRtp_info, sizeof(struct _thw_RTPinfo)) == NULL)
		{
			DPA_ERROR("%s(%d) Failed to copy from muram to ddr:\n", __FUNCTION__, __LINE__);
			return -1;
		}

		flags = be16_to_cpu(pRtp_info->flags);
		flags |= RTP_OFFLOAD_PROCESS_PKT;
		pRtp_info->flags = cpu_to_be16(flags);

		copy_ddr_to_muram_and_free_ddr((void *)pCall->AtoB_flow->hw_flow->rtp_info,
				(void **)&pRtp_info, sizeof(struct _thw_RTPinfo));
	}

	if (pCall->BtoA_flow->state)
	{
		if (create_ddr_and_copy_from_muram((void *)pCall->BtoA_flow->hw_flow->rtp_info,
					(void **)&pRtp_info, sizeof(struct _thw_RTPinfo)) == NULL)
		{
			DPA_ERROR("%s(%d) Failed to copy from muram to ddr:\n", __FUNCTION__, __LINE__);
			return -1;
		}

		flags = be16_to_cpu(pRtp_info->flags);
		flags |= RTP_OFFLOAD_PROCESS_PKT;
		pRtp_info->flags = cpu_to_be16(flags);

		copy_ddr_to_muram_and_free_ddr((void *)pCall->BtoA_flow->hw_flow->rtp_info,
				(void **)&pRtp_info, sizeof(struct _thw_RTPinfo));
	}

	if (RTPCmd.ControlDir & 0x04)
	{
		if (RTPCmd.ControlDir & 0x10)
			pCall->AtoB_flow->pkt_dup_enable = 1;

		if (RTPCmd.ControlDir & 0x20)
			pCall->BtoA_flow->pkt_dup_enable = 1;
	}
	else if (RTPCmd.ControlDir & 0x08)
	{
		if (RTPCmd.ControlDir & 0x10)
			pCall->AtoB_flow->pkt_dup_enable = 0;

		if (RTPCmd.ControlDir & 0x20)
			pCall->BtoA_flow->pkt_dup_enable = 0;
	}


	pSocket = SOCKET_find_entry_by_id(pCall->AtoB_flow->ingress_socketID);
	if (pSocket)
	{
		cdx_ehash_set_rtp_info_params(pCall->AtoB_flow->hw_flow->ehash_rtp_relay_params, 
				pCall->AtoB_flow, pSocket);
	}

	pSocket = SOCKET_find_entry_by_id(pCall->BtoA_flow->ingress_socketID);
	if (pSocket)
	{
		cdx_ehash_set_rtp_info_params(pCall->BtoA_flow->hw_flow->ehash_rtp_relay_params, 
				pCall->BtoA_flow, pSocket);
	}
	return NO_ERR;
}

#ifdef CDX_DPA_DEBUG
static int display_rtp_info(struct _thw_RTPinfo	*rtp_info_muram)
{
	struct _thw_RTPinfo *rtp_info = NULL;

	DPA_INFO("%s (%d) RTP_INFO: \n", __FUNCTION__,__LINE__);
	if (create_ddr_and_copy_from_muram((void *)rtp_info_muram, (void **)&rtp_info,
				sizeof(struct _thw_RTPinfo)) == NULL)
	{
		DPA_ERROR("%s(%d) Failed to copy from muram to ddr:\n", __FUNCTION__, __LINE__);
		return -1;
	}

	DPA_INFO("flags : %x, last-rx-time %x (msec), %x (cycles) \n", 
			be16_to_cpu(rtp_info->flags), 
			rtp_info->last_rx_time.msec, rtp_info->last_rx_time.cycles);
	DPA_INFO("last recvd seq.num %u , last rcvd SSRC %x \n", 
			be16_to_cpu(rtp_info->last_Seq), be32_to_cpu(rtp_info->last_SSRC));
	DPA_INFO("last rcvd time stamp %x, probation %d \n", rtp_info->last_TS, rtp_info->probation);
	DPA_INFO("seq.num %u, SSRC %x, timestamp base %x \n", 
			be16_to_cpu(rtp_info->Seq), be32_to_cpu(rtp_info->SSRC),
			be32_to_cpu(rtp_info->TimestampBase));
	DPA_INFO("***************\n");

	kfree(rtp_info);
	rtp_info = NULL;
	return 0;
}
#endif //CDX_DPA_DEBUG

static U16 RTP_Call_TakeOver (U16 *p, U16 Length)
{
	RTPTakeoverCommand RTPCmd;
	PRTPflow pflow;
	PRTPCall pCall;
	PSockEntry pSocket = NULL;
	struct _thw_rtpflow *hw_flow;
	struct _thw_RTPinfo	*rtp_info, *old_rtp_info;
	PRTCPStats egress_stats = NULL;
	uint16_t flags = 0;

	// Check length
	if (Length != sizeof(RTPTakeoverCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&RTPCmd, (U8*)p, sizeof(RTPTakeoverCommand));

	if ((pCall = RTP_find_call(RTPCmd.CallID)) == NULL)
		return ERR_RTP_UNKNOWN_CALL;

	if ((pSocket = SOCKET_find_entry_by_id(RTPCmd.Socket)) == NULL)
		return ERR_SOCKID_UNKNOWN;

	if (pCall->AtoB_flow->egress_socketID == RTPCmd.Socket)
		pflow = pCall->AtoB_flow;
	else if (pCall->BtoA_flow->egress_socketID == RTPCmd.Socket)
		pflow = pCall->BtoA_flow;
	else
		return ERR_WRONG_SOCKID;

	pflow->SSRC_1 = RTPCmd.SSRC_1;
	pflow->SSRC = RTPCmd.SSRC;
	pflow->TimestampBase = RTPCmd.TimeStampBase;
	pflow->TimeStampIncr = RTPCmd.TimeStampIncr;
	pflow->takeover_mode = RTPCmd.mode ; //(RTPCmd.mode & RTP_TAKEOVER_MODE_TSINCR_FREQ);
	pflow->takeover_flags = RTPCmd.ParamFlags; // takeover mode
	pflow->Seq = RTPCmd.SeqNumberBase;
	//	pflow->SSRC_takeover =  (((pflow->SSRC) == 0) ? RTP_TAKEOVER_SSRC_TRANSPARENT : RTP_TAKEOVER_SSRC_MANGLE);
	//	pflow->TS_takeover =  (((pflow->TimestampBase) == 0) ? 0 : 1);
	//	pflow->Seq_takeover =  (((pflow->Seq) == 0) ? 0 : 1);
	//	pflow->SSRC_1_takeover = (((pflow->SSRC_1) == 0) ? 0 : 1);
	pflow->MarkerBitConfMode =  RTPCmd.MarkerBitConfMode;

	pflow->takeover_resync = TRUE;
	pflow->rtp_info.first_packet = TRUE;

	hw_flow = pflow->hw_flow;

	old_rtp_info =  pflow->hw_flow->rtp_info;

	rtp_info = cdx_rtp_alloc_muram_rtpinfo();
	if (!rtp_info)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		return ERR_NOT_ENOUGH_MEMORY;
	}

	pflow->hw_flow->rtp_info = rtp_info;

	/* reflect changes to hardware flow */
	DPA_INFO("%s(%d) takeover flags %x, takeover mode %x \n",
			__FUNCTION__, __LINE__, pflow->takeover_flags, pflow->takeover_mode);
	// in case of SSRC AUTO takeover , set SSRC value.
	if (pflow->takeover_mode & RTP_TAKEOVER_MODE_SSRC_AUTO)
	{
		/* If automatic SSRC takeover is configured then let's the control plane generates the initial SSRC value. If any
			 change in incoming SSRC occurs during the call, then the PFE will recomputes a new ssrc internally */
		pflow->SSRC = cpu_to_be32((pflow->egress_socketID << 16) | (jiffies & 0xFFFF));

		/* Here accessing only one variable from two different Muram memories at a time. For just single variable
			 update it's not worthy to creat corresponding two ddr memories and copy, update restore back and free, instead
			 using writel. In future, needs to update  more variables then can do those things. */
		egress_stats = (PRTCPStats)pSocket->hw_stats;

		/* Initial SSRC computed by the Host control code should be also reflected in the egress socket's statistics */
		/* FIXME: Here rtp_info structure in hw_flow is just allocated memory from Muram, but structure fields are not updated with
			 any value. It may be the value should take from pflow->SSRC(is updating above). */
		writel(hw_flow->rtp_info->SSRC, &egress_stats->ssrc_overwrite_value);
	}

	if (cdx_rtp_set_hwinfo_fields(pflow, pSocket) != 0)
	{
		DPA_ERROR("%s(%d) Error in setting rtp hwinfo fields.\n", __FUNCTION__,__LINE__);
		return -1;
	}
	cdx_ehash_set_rtp_info_params(hw_flow->ehash_rtp_relay_params, 
			pflow, pSocket);

#ifdef CDX_DPA_DEBUG
	{
		struct en_exthash_tbl_entry *tbl_entry;
		tbl_entry = hw_flow->eeh_entry_handle;
		display_ehash_tbl_entry(&tbl_entry->hashentry, 8);
		display_rtp_info(hw_flow->rtp_info);
	}
#endif // CDX_DPA_DEBUG
	cdx_ehash_update_rtp_info_params(hw_flow->ehash_rtp_relay_params, 
			(uint32_t *)hw_flow->rtp_info);

	/* Here also accessing only one variable so not worthy to create ddr memory, copy, read and free, instead using readw. */
	flags = be16_to_cpu(readw(&old_rtp_info->flags));
	if (flags & RTP_OFFLOAD_PROCESS_PKT)
	{
		if (ExternalHashTableFmPcdHcSync(hw_flow->td))
		{
			DPA_ERROR("%s(%d) ExternalHashTableFmPcdHcSync failed\n", __FUNCTION__,__LINE__);
		}
	}

	cdx_muram_rtpinfo_free((void *)old_rtp_info);

	return NO_ERR;
}

//TODO_SPECIAL_PKT
static U16 RTP_Call_SpecialTx_Payload (U16 *p, U16 Length)
{
	RTPSpecTxPayloadCommand RTPCmd;
	PRTPCall pCall;
	U8*	payload;

	// Check length
	if (Length < sizeof(RTPSpecTxPayloadCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&RTPCmd, (U8*)p, sizeof(RTPSpecTxPayloadCommand));

	if ((pCall = RTP_find_call(RTPCmd.CallID)) == NULL)
		return ERR_RTP_UNKNOWN_CALL;

	if (RTPCmd.payloadID)
		payload = pCall->Next_Special_payload2;
	else
		payload = pCall->Next_Special_payload1;

	memset(payload, 0, RTP_SPECIAL_PAYLOAD_LEN);
	memcpy(payload, RTPCmd.payload, RTPCmd.payloadLength);

	return NO_ERR;
}


//TODO_SPECIAL_PKT
static U16 RTP_Call_SpecialTx_Control (U16 *p, U16 Length)
{
	RTPSpecTxCtrlCommand RTPCmd;
	PRTPCall pCall;
	struct _thw_RTPinfo *pRtp_info_AtoB = NULL;
	struct _thw_RTPinfo *pRtp_info_BtoA = NULL;
	uint16_t flags;

	// Check length
	if (Length < sizeof(RTPSpecTxCtrlCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&RTPCmd, (U8*)p, sizeof(RTPSpecTxCtrlCommand));

	if ((pCall = RTP_find_call(RTPCmd.CallID)) == NULL)
		return ERR_RTP_UNKNOWN_CALL;

	/* reflect changes in hardware flow */

	if (create_ddr_and_copy_from_muram((void *)pCall->AtoB_flow->hw_flow->rtp_info,
				(void **)&pRtp_info_AtoB, sizeof(struct _thw_RTPinfo)) == NULL)
	{
		DPA_ERROR("%s(%d) Failed to copy from muram to ddr:\n", __FUNCTION__, __LINE__);
		return -1;
	}
	if (create_ddr_and_copy_from_muram((void *)pCall->BtoA_flow->hw_flow->rtp_info,
				(void **)&pRtp_info_BtoA, sizeof(struct _thw_RTPinfo)) == NULL)
	{
		kfree(pRtp_info_AtoB);
		DPA_ERROR("%s(%d) Failed to copy from muram to ddr:\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (RTPCmd.Type == RTP_SPEC_TX_STOP)
	{
		flags = be16_to_cpu(pRtp_info_AtoB->flags);
		flags = flags & ~(RTP_OFFLOAD_SPECIAL_TX_ACTIVE);
		pRtp_info_AtoB->flags =  cpu_to_be16(flags);

		flags = be16_to_cpu(pRtp_info_BtoA->flags);
		flags = flags & ~(RTP_OFFLOAD_SPECIAL_TX_ACTIVE);
		pRtp_info_BtoA->flags =  cpu_to_be16(flags);
	}
	else
	{
		flags = be16_to_cpu(pRtp_info_AtoB->flags);
		flags = flags | (RTP_OFFLOAD_SPECIAL_TX_ACTIVE);
		pRtp_info_AtoB->flags =  cpu_to_be16(flags);

		flags = be16_to_cpu(pRtp_info_BtoA->flags);
		flags = flags | (RTP_OFFLOAD_SPECIAL_TX_ACTIVE);
		pRtp_info_BtoA->flags =  cpu_to_be16(flags);


		memcpy(pCall->AtoB_flow->hw_flow->Special_payload1, pCall->Next_Special_payload1, RTP_SPECIAL_PAYLOAD_LEN);
		memcpy(pCall->AtoB_flow->hw_flow->Special_payload2, pCall->Next_Special_payload2, RTP_SPECIAL_PAYLOAD_LEN);

		memcpy(pCall->BtoA_flow->hw_flow->Special_payload1, pCall->Next_Special_payload1, RTP_SPECIAL_PAYLOAD_LEN);
		memcpy(pCall->BtoA_flow->hw_flow->Special_payload2, pCall->Next_Special_payload2, RTP_SPECIAL_PAYLOAD_LEN);
	}

	//TODO special
	//	pCall->AtoB_flow->hw_flow->rtp_info->Special_tx_type = RTPCmd.Type;
	//	pCall->BtoA_flow->hw_flow->rtp_info->Special_tx_type = RTPCmd.Type;

	copy_ddr_to_muram_and_free_ddr((void *)pCall->AtoB_flow->hw_flow->rtp_info, (void **)&pRtp_info_AtoB, sizeof(struct _thw_RTPinfo));
	copy_ddr_to_muram_and_free_ddr((void *)pCall->BtoA_flow->hw_flow->rtp_info, (void **)&pRtp_info_BtoA, sizeof(struct _thw_RTPinfo));

	return NO_ERR;
}


/* This function is used by both RTP Relay Stats and RTP FF Stats feature */
static int RTP_query_stats_common(PRTCPQueryResponse pRTPRep, PRTCPStats pStats)
{
	U8 first_packet = 0;
	U32 num_rx_valid = 0;

	if((pStats == NULL) || (pRTPRep == NULL))
		return 1;

	if(pStats->prev_reception_period >= 1000)
		pRTPRep->prev_reception_period = pStats->prev_reception_period / 1000; // expressed in msec
	if(pStats->last_reception_period >= 1000)
		pRTPRep->last_reception_period = pStats->last_reception_period / 1000; //expressed in msec
	pRTPRep->num_tx_pkts = pStats->num_tx_pkts;
	pRTPRep->num_rx_pkts = pStats->num_rx_pkts;
	pRTPRep->last_rx_Seq = pStats->last_rx_Seq;
	pRTPRep->last_TimeStamp = pStats->last_TimeStamp;
	memcpy(pRTPRep->RTP_header, pStats->first_received_RTP_header, RTP_HDR_SIZE);	
	pRTPRep->num_rx_dup = pStats->packets_duplicated;
	pRTPRep->num_rx_since_RTCP = pStats->num_rx_since_RTCP;
	pRTPRep->num_tx_bytes = pStats->num_tx_bytes;
	pRTPRep->num_malformed_pkts = pStats->num_malformed_pkts;
	pRTPRep->num_expected_pkts = pStats->num_expected_pkts;
	pRTPRep->num_late_pkts = pStats->num_late_pkts;
	pRTPRep->ssrc_overwrite_value = pStats->ssrc_overwrite_value;

	if (pStats->num_expected_pkts > pStats->num_rx_pkts_in_seq)
		pRTPRep->num_rx_lost_pkts = pStats->num_expected_pkts - pStats->num_rx_pkts_in_seq;

	pRTPRep->num_cumulative_rx_lost_pkts = pStats->num_previous_rx_lost_pkts + pRTPRep->num_rx_lost_pkts;

	if(pStats->num_rx_pkts > 1) 
	{
		//jitter statistics
		pRTPRep->min_jitter = (pStats->min_jitter != 0xffffffff)? (pStats->min_jitter >> 4): 0; //if min value has never been computed just return 0
		pRTPRep->max_jitter = pStats->max_jitter >> 4; //expressed in us
		pRTPRep->mean_jitter = pStats->mean_jitter >> 4; //expressed in us

		//interarrival statistics
		pRTPRep->min_reception_period = (pStats->min_reception_period != 0xffffffff)? pStats->min_reception_period : 0;//expressed in us	
		pRTPRep->max_reception_period = pStats->max_reception_period; //expressed in us

		//first rtp packet of the session is not include in the average_reception_period variable, as we need at least 2 packets to compute an interval
		//that's why we substract one packet when computing average
		if(pStats->state == RTP_STATS_FIRST_PACKET) 
			first_packet = 1;

		//FIXME: do_div should be implemented in hal for non-linux code
		num_rx_valid = pStats->num_rx_pkts - first_packet - pStats->num_late_pkts - pStats->packets_duplicated - pStats->num_big_jumps;
		if((pStats->average_reception_period >= num_rx_valid) && (num_rx_valid))
		{
			DPA_INFO("%s(%d) \n", __FUNCTION__,__LINE__); //TODO_RTP_TIME

			pRTPRep->average_reception_period = pStats->average_reception_period / num_rx_valid; //expressed in us
		}
	}
	else
	{
		//make sure clean values are reported even if no packets received
		pRTPRep->min_jitter = 0;
		pRTPRep->max_jitter = 0;
		pRTPRep->mean_jitter = 0;
		pRTPRep->min_reception_period = 0;
		pRTPRep->max_reception_period = 0;
		pRTPRep->average_reception_period = 0;
	}

	pStats->num_rx_since_RTCP = 0;

	pRTPRep->sport = ntohs(pStats->sport);
	pRTPRep->dport = ntohs(pStats->dport);

	return NO_ERR;
}

static PRTCPStats RTCP_get_stats(PRTCPStats sw_stats, PRTCPStats hw_stats, U32 stats_size)
{
	PRTCPStats pStats = NULL;
	U32 msb32, lsb32 = 0;

	if(hw_stats)
	{
		/* set back statistics from util to host endianess */
		memcpy(sw_stats, hw_stats, stats_size);
		pStats = sw_stats;

		pStats->prev_reception_period = be32_to_cpu(pStats->prev_reception_period);
		pStats->last_reception_period = be32_to_cpu(pStats->last_reception_period);
		pStats->num_tx_pkts = be32_to_cpu(pStats->num_tx_pkts);
		pStats->num_rx_pkts = be32_to_cpu(pStats->num_rx_pkts);
		pStats->num_rx_pkts_in_seq = be32_to_cpu(pStats->num_rx_pkts_in_seq);
		pStats->last_rx_Seq = be16_to_cpu(pStats->last_rx_Seq);
		pStats->last_TimeStamp = be32_to_cpu(pStats->last_TimeStamp);
		pStats->packets_duplicated = be32_to_cpu(pStats->packets_duplicated);
		pStats->num_rx_since_RTCP = be32_to_cpu(pStats->num_rx_since_RTCP);
		pStats->num_tx_bytes = be32_to_cpu(pStats->num_tx_bytes);
		pStats->min_jitter = be32_to_cpu(pStats->min_jitter);
		pStats->max_jitter = be32_to_cpu(pStats->max_jitter);
		pStats->mean_jitter = be32_to_cpu(pStats->mean_jitter);
		pStats->num_rx_lost_pkts = be32_to_cpu(pStats->num_rx_lost_pkts);
		pStats->min_reception_period = be32_to_cpu(pStats->min_reception_period);
		pStats->max_reception_period = be32_to_cpu(pStats->max_reception_period);
		msb32 = be32_to_cpu(pStats->average_reception_period << 32); lsb32 = be32_to_cpu(pStats->average_reception_period >> 32);
		pStats->average_reception_period = msb32 | lsb32;
		pStats->num_malformed_pkts = be32_to_cpu(pStats->num_malformed_pkts);
		pStats->num_expected_pkts = be32_to_cpu(pStats->num_expected_pkts);
		pStats->num_late_pkts = be32_to_cpu(pStats->num_late_pkts);
		pStats->sport = be16_to_cpu(pStats->sport);
		pStats->dport = be16_to_cpu(pStats->dport);
		pStats->num_big_jumps = be32_to_cpu(pStats->num_big_jumps);
		pStats->num_previous_rx_lost_pkts = be32_to_cpu(pStats->num_previous_rx_lost_pkts);
		pStats->ssrc_overwrite_value = be32_to_cpu(pStats->ssrc_overwrite_value);
	}

	return pStats;
}

static int RTP_reset_stats(PRTCPStats pStats_muram, U8 type)
{
	PRTCPStats pStats = NULL;

	if (create_ddr_and_copy_from_muram((void *)pStats_muram, (void **)&pStats, sizeof(RTCPStats)) == NULL)
	{
		DPA_ERROR("%s(%d) Failed to copy from muram to ddr:\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if(type == RTP_STATS_FULL_RESET) //full reset, all stats are cleared
	{
		pStats->prev_reception_period = 0;
		pStats->last_reception_period = 0;
		pStats->seq_base = 0;
		pStats->last_rx_Seq = 0;
		pStats->last_TimeStamp= 0;
		pStats->num_rx_pkts_in_seq = 0;
		pStats->num_expected_pkts = 0;
		pStats->num_previous_rx_lost_pkts = 0;
	}
	if(type == RTP_STATS_FULL_RESET || type == RTP_STATS_PARTIAL_RESET) //partial reset used for session restart
	{
		pStats->num_tx_pkts = 0;
		pStats->num_tx_bytes = 0;
	}
	if(type == RTP_STATS_FULL_RESET || type == RTP_STATS_PARTIAL_RESET || type == RTP_STATS_RX_RESET)
	{
		pStats->max_jitter = pStats->mean_jitter = 0;
		pStats->min_jitter = 0xffffffff;
		pStats->max_reception_period = pStats->average_reception_period = 0;
		pStats->min_reception_period = 0xffffffff;
		pStats->num_rx_pkts = 0;
		pStats->packets_duplicated = 0;
		pStats->num_malformed_pkts = 0;
		pStats->num_late_pkts = 0;
		pStats->num_big_jumps = 0;
	}
	pStats->state = type;   /* cpu_to_be16(type); state variable modified 1 byte */

	copy_ddr_to_muram_and_free_ddr((void *)pStats_muram, (void **)&pStats, sizeof(RTCPStats));
	return 0;
}

static U16 RTCP_Query (U16 *p, U16 Length)
{
	RTCPQueryCommand *pRTPCmd = (RTCPQueryCommand *)p;
	RTCPQueryResponse RTPRep;
	PSockEntry pSock = NULL;
	PRTCPStats pStats = NULL;

	if (Length < sizeof(RTCPQueryCommand))
		return ERR_WRONG_COMMAND_SIZE;

	pSock = SOCKET_find_entry_by_id(pRTPCmd->SocketID);

	if (!pSock)
		return ERR_SOCKID_UNKNOWN;

	if (pSock->SocketType == SOCKET_TYPE_ACP)
		return ERR_WRONG_SOCK_TYPE;

	pStats = RTCP_get_stats((PRTCPStats)pSock->SocketStats, (PRTCPStats)pSock->hw_stats, SOCKET_STATS_SIZE);
	if(pStats == NULL)
		return ERR_RTP_STATS_NOT_AVAILABLE;

	memset((U8*)&RTPRep, 0, sizeof(RTCPQueryResponse));
	if (RTP_query_stats_common(&RTPRep, pStats))
		return ERR_RTP_STATS_STREAMID_UNKNOWN;

	pStats = (PRTCPStats)pSock->SocketStats;
	pStats->num_rx_since_RTCP = 0;

	if(pRTPCmd->flags)
		if (RTP_reset_stats((PRTCPStats)pSock->hw_stats, pRTPCmd->flags) != 0)
			return ERR_RTP_STATS_RESET;

	memcpy((U8*)(p + 1), (U8*)&RTPRep, sizeof(RTCPQueryResponse));


#ifdef CDX_DPA_DEBUG
	{
		//		display_rtp_info(hw_flow->rtp_info);
	}
#endif // CDX_DPA_DEBUG
	return NO_ERR;
}

#ifdef TODO_RTP_QOS
/*************************** RTP Stats for QoS Measurement ****************************
Notes:
-----
The goal of this feature is to add RTP QoS MEasurement support for both fast forwarded and Relayed connections in C1000
FPP code. This feature is different from the RTCP Query for RTP Relay feature, but provides similar service.

MSPD has implements similar API and common code in FPP to collect both RTP statistics for
Relay and Fast Forwarded connections (only CMM CLI usage differs). So in terms of RTP
Statistics only (processing, statistics format, etc) 

Same control plane is used for both RTP FF Stats and RTP Relay Stats in order to minimize FPP modules
usage
 ************************************************************************************/


static void rtpqos_free_entry(PRTPQOS_ENTRY pEntry)
{
	if(pEntry->slot < MAX_RTP_STATS_ENTRY)
	{
		memset((U8*)&pEntry->rtp_info, 0, sizeof(RTPinfo));
		memset((U8*)&pEntry->stats, 0, sizeof(RTCPStats));
		pEntry->stream_id = RTP_STATS_FREE;
		pEntry->stream_type = 0;
	}
}

static PRTPQOS_ENTRY rtpqos_alloc_entry(U16 stream_id)
{
	int i;
	PRTPQOS_ENTRY pStat = NULL;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++) {
		if (rtpqos_cache[i].stream_id == RTP_STATS_FREE) {
			pStat = &rtpqos_cache[i];
			pStat->stream_id = stream_id;
			break;
		}
	}
	return pStat;
}



static void rtpqos_remove_entry(PRTPQOS_ENTRY pEntry)
{
	rtpqos_free_entry(pEntry);
}

static void rtpqos_update(PSockEntry pSocket)
{
}


static int rtpqos_check_entry(U16 stream_id, U32 *saddr, U32 *daddr, U16 sport, U16 dport, U8 family)
{
	PRTPQOS_ENTRY pEntry = NULL;
	int i;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++)
	{
		pEntry = &rtpqos_cache[i];

		if(pEntry)
		{
			if(stream_id == pEntry->stream_id)
				return ERR_RTP_STATS_STREAMID_ALREADY_USED;

			if(family == IP4) {
				if((pEntry->stream_id != RTP_STATS_FREE) && (saddr[0] == pEntry->saddr[0]) && (daddr[0] == pEntry->daddr[0]) && (sport == pEntry->sport) && (dport == pEntry->dport))
					return ERR_RTP_STATS_DUPLICATED;

			} else {
				if((pEntry->stream_id != RTP_STATS_FREE) && !IPV6_CMP(saddr, pEntry->saddr) && !IPV6_CMP(daddr, pEntry->daddr) && (sport == pEntry->sport) && (dport == pEntry->dport))
					return ERR_RTP_STATS_DUPLICATED;
			}
		}
	}

	return ERR_RTP_STATS_STREAMID_UNKNOWN;
}


static PRTPQOS_ENTRY rtpqos_get_entry_by_id(U16 stream_id)
{
	int i;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++)
	{
		if(stream_id == rtpqos_cache[i].stream_id)
			return &rtpqos_cache[i];
	}
	return NULL;
}
#endif // TODO_RTP_QOS


PRTPflow RTP_find_flow(U16 id)
{
	PRTPflow flow_entry;
	struct slist_entry *entry;
	U32 hash_key;

	hash_key = HASH_RTP(id);
	slist_for_each(flow_entry, entry, &rtpflow_cache[hash_key], list)
	{
		if (id && (flow_entry->ingress_socketID == id))
			return flow_entry;
	}

	return NULL;
}


#ifdef TODO_RTP_QOS
static int RTPQOS_enable_stats(U16 *p, U16 Length)
{
	RTP_ENABLE_STATS_COMMAND cmd;
	PCtEntry pCT_entry = NULL;
	PMC4Entry pMC_entry = NULL;
	PMC6Entry pMC6_entry = NULL;
	PSockEntry pSocket = NULL;
	PSock6Entry pSocket6 = NULL;
	PRTPQOS_ENTRY pStatEntry = NULL;
	int check_status = NO_ERR;
	U8 ip_family;

	//check length
	if (Length != sizeof(RTP_ENABLE_STATS_COMMAND))
		return ERR_WRONG_COMMAND_SIZE;

	memset((U8*)&cmd, 0, sizeof(RTP_ENABLE_STATS_COMMAND));

	// Ensure alignment
	memcpy((U8*)&cmd, (U8*)p, sizeof(RTP_ENABLE_STATS_COMMAND));

	//0xFFFF is a reserved value and connot be used as a stream ID
	if(cmd.stream_id == RTP_STATS_FREE)
		return ERR_WRONG_COMMAND_PARAM;

	//check all possible error cases before marking the connection

	if((cmd.stream_type == IP4) || (cmd.stream_type == MC4) ||(cmd.stream_type == RLY))
		ip_family = IP4;
	else if((cmd.stream_type == IP6) || (cmd.stream_type == MC6) ||(cmd.stream_type == RLY6))
		ip_family = IP6;
	else
		return ERR_RTP_STATS_WRONG_TYPE;

	if((check_status = rtpqos_check_entry(cmd.stream_id, cmd.saddr, cmd.daddr, cmd.sport, cmd.dport, ip_family)) != ERR_RTP_STATS_STREAMID_UNKNOWN)
		return check_status;

	pStatEntry = rtpqos_alloc_entry(cmd.stream_id);
	if(pStatEntry == NULL)
		return ERR_RTP_STATS_MAX_ENTRIES;

	//find corresponding CT or MC entry, if exists
	switch(cmd.stream_type)
	{
		case IP4:
			//auto mode not supported for ipv4
			cmd.mode = 0;
			if((pCT_entry = IPv4_get_ctentry(cmd.saddr[0], cmd.daddr[0], cmd.sport, cmd.dport, cmd.proto)) != NULL)
			{
				pCT_entry->status |= CONNTRACK_RTP_STATS;
				pCT_entry->rtpqos_slot = pStatEntry->slot;
			}
			break;

		case IP6:
			//auto mode not supported for ipv6
			cmd.mode = 0;
			if((pCT_entry = IPv6_get_ctentry(cmd.saddr, cmd.daddr, cmd.sport, cmd.dport, cmd.proto)) != NULL)
			{
				pCT_entry->status |= CONNTRACK_RTP_STATS;
				pCT_entry->rtpqos_slot = pStatEntry->slot;
			}
			break;

		case MC4:
			if((pMC_entry = MC4_rule_search(cmd.saddr[0], cmd.daddr[0])) != NULL)
			{
				pMC_entry->status |= CONNTRACK_RTP_STATS;
				pMC_entry->rtpqos_slot = pStatEntry->slot;
				pMC_entry->rtpqos_ref_count++;
			}
			break;

		case MC6:
			if((pMC6_entry = MC6_rule_search(cmd.saddr, cmd.daddr)) != NULL)
			{
				pMC6_entry->status |= CONNTRACK_RTP_STATS;
				pMC6_entry->rtpqos_slot = pStatEntry->slot;
				pMC6_entry->rtpqos_ref_count++;
			}
			break;

		case RLY:
			pSocket = SOCKET4_find_entry(cmd.saddr[0], cmd.sport, cmd.daddr[0], cmd.dport, cmd.proto);
			if(pSocket != NULL)
			{
				pSocket->qos_enable = TRUE;
				pSocket->rtpqos_slot = pStatEntry->slot;
			}
			break;

		case RLY6:
			pSocket6 = SOCKET6_find_entry(cmd.saddr, cmd.sport, cmd.daddr, cmd.dport, cmd.proto);
			if(pSocket6 != NULL)
			{
				pSocket6->qos_enable = TRUE;
				pSocket6->rtpqos_slot = pStatEntry->slot;
			}
			break;

		default:
			return ERR_RTP_STATS_WRONG_TYPE;
	}

	memcpy(pStatEntry->saddr, cmd.saddr, 4*sizeof(U32)); memcpy(pStatEntry->daddr, cmd.daddr, 4*sizeof(U32));
	pStatEntry->sport = cmd.sport;  pStatEntry->dport = cmd.dport;
	pStatEntry->proto = cmd.proto;

	pStatEntry->stream_type = cmd.stream_type;
	pStatEntry->rtp_info.first_packet = TRUE;
	pStatEntry->rtp_info.probation = RTP_MIN_SEQUENTIAL;
	pStatEntry->rtp_info.mode = cmd.mode;

	//in multicast unset ports if auto mode is enabled
	if((cmd.mode == 1) && ((cmd.stream_type == MC4) || (cmd.stream_type == MC6)))
	{
		pStatEntry->stats.sport = 0xFFFF;
		pStatEntry->stats.dport = 0xFFFF;
	}
	else
	{
		pStatEntry->stats.sport = cmd.sport;
		pStatEntry->stats.dport = cmd.dport;
	}

	/* Now adding hardware rtp qos stats entry to packet engine's cache */
	if(rtpqos_add_entry(pStatEntry) != NO_ERR)
		return ERR_NOT_ENOUGH_MEMORY;

	return NO_ERR;
}


static int RTPQOS_disable_stats(U16 *p, U16 Length)
{
	PRTPQOS_ENTRY pRTPQos_entry = NULL;
	PCtEntry pCT_entry = NULL;
	PMC4Entry pMC_entry = NULL;
	PMC6Entry pMC6_entry = NULL;
	PSockEntry pSocket = NULL;
	PSock6Entry pSocket6 = NULL;
	U32 saddr[4];
	U32 daddr[4];
	U16 sport, dport, proto, stream_id;

	//check length
	if (Length != sizeof(RTP_DISABLE_STATS_COMMAND))
		return ERR_WRONG_COMMAND_SIZE;

	stream_id = p[0];

	if((pRTPQos_entry = rtpqos_get_entry_by_id(stream_id)) == NULL)
		return ERR_RTP_STATS_STREAMID_UNKNOWN;

	memcpy(saddr, pRTPQos_entry->saddr, 4*sizeof(U32)); memcpy(daddr, pRTPQos_entry->daddr, 4*sizeof(U32));
	sport = pRTPQos_entry->sport; dport = pRTPQos_entry->dport;
	proto = pRTPQos_entry->proto;

	switch(pRTPQos_entry->stream_type)
	{
		case IP4:
			//find corresponding CT or MC entry, if exists
			if((pCT_entry = IPv4_get_ctentry(saddr[0], daddr[0], sport, dport, proto)) == NULL)
				goto reset_slot;
			//set  CT or MC marker for per packet first level processing
			pCT_entry->status &= ~ CONNTRACK_RTP_STATS;
			break;

		case IP6:
			if((pCT_entry = IPv6_get_ctentry(saddr, daddr, sport, dport, proto)) == NULL)
				goto reset_slot;
			pCT_entry->status &= ~ CONNTRACK_RTP_STATS;
			break;

		case MC4:
			if((pMC_entry = MC4_rule_search(saddr[0], daddr[0])) == NULL)
				goto reset_slot;
			if(pMC_entry->rtpqos_ref_count)
			{
				if(--pMC_entry->rtpqos_ref_count == 0)
					pMC_entry->status &= ~ CONNTRACK_RTP_STATS;
			}
			break;

		case MC6:
			if((pMC6_entry = MC6_rule_search(saddr, daddr))== NULL)
				goto reset_slot;
			if(pMC6_entry->rtpqos_ref_count)
			{
				if(--pMC6_entry->rtpqos_ref_count == 0)
					pMC6_entry->status &= ~ CONNTRACK_RTP_STATS;
			}
			break;

		case RLY:
			pSocket = SOCKET4_find_entry(saddr[0], sport, daddr[0], dport, proto);
			if(pSocket == NULL)
				goto reset_slot;
			pSocket->qos_enable = FALSE;
			break;

		case RLY6:
			pSocket6 = SOCKET6_find_entry(saddr, sport, daddr, dport, proto);
			if(pSocket6 == NULL)
				goto reset_slot;
			pSocket6->qos_enable = FALSE;
			break;
	}

reset_slot:
	rtpqos_remove_entry(pRTPQos_entry);

	return NO_ERR;
}


static U16 RTPQOS_query_stats (U16 *p, U16 Length)
{
	RTCPQueryCommand *pRTPCmd = (RTCPQueryCommand *)p;
	PRTPQOS_ENTRY pEntry = NULL;
	RTCPQueryResponse RTPRep;
	PRTCPStats pStats;
	U16 stream_id;

	// Check length
	if (Length != sizeof(RTP_QUERY_STATS_COMMAND))
		return ERR_WRONG_COMMAND_SIZE;

	stream_id = p[0];

	memset((U8*)&RTPRep, 0, sizeof(RTCPQueryResponse));

	if((pEntry = rtpqos_get_entry_by_id(stream_id)) == NULL)
		return ERR_RTP_STATS_STREAMID_UNKNOWN;

	pStats = RTCP_get_stats(&pEntry->stats, &pEntry->hw_rtpqos->stats, sizeof(RTCPStats));
	if(pStats == NULL)
		return ERR_RTP_STATS_NOT_AVAILABLE;

	/* check against null pStats pointer is done in the RTP_query_stats_common function */
	if(RTP_query_stats_common(&RTPRep, pStats))
		return ERR_RTP_STATS_STREAMID_UNKNOWN;


	if(pRTPCmd->flags)
		RTP_reset_stats((PRTCPStats)&pEntry->hw_rtpqos->stats, pRTPCmd->flags);

	memcpy((U8*)(p + 1), (U8*)&RTPRep, sizeof(RTCPQueryResponse));
	return NO_ERR;

}
#endif // TODO_RTP_QOS


static int rtp_set_dtmf_pt(U16 *p, U16 Length)
{
	U8 pt1, pt2;
	PRTPflow flow_entry;
	struct slist_entry *entry;
	U32 hash_key;

	if (Length != sizeof(RTP_DTMF_PT_COMMAND))
		return ERR_WRONG_COMMAND_SIZE;

	pt1 = p[0] & 0x00FF;
	pt2 = (p[0] & 0xFF00) >> 8;

	if(pt2 == 0)
		pt2 = pt1;

	gDTMF_PT[0] = pt1; gDTMF_PT[1] = pt2;
	for (hash_key =0; hash_key<NUM_RTPFLOW_ENTRIES; hash_key++)
	{
		slist_for_each(flow_entry, entry, &rtpflow_cache[hash_key], list)
		{
			if (flow_entry->hw_flow && flow_entry->hw_flow->ehash_rtp_relay_params)
			{
				cdx_ehash_update_dtmf_rtp_info_params(flow_entry->hw_flow->ehash_rtp_relay_params, 
						gDTMF_PT);
			}
		}
	}

	return NO_ERR;
}

static U16 M_rtp_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc;
	U16 retlen = 2;

	switch (cmd_code)
	{
		case CMD_RTP_OPEN:
			rc = RTP_Call_Open(pcmd, cmd_len);
			break;

		case CMD_RTP_UPDATE:
			rc = RTP_Call_Update(pcmd, cmd_len);
			break;

		case CMD_RTP_TAKEOVER:
			rc = RTP_Call_TakeOver(pcmd, cmd_len);
			break;

		case CMD_RTP_CONTROL:
			rc = RTP_Call_Control(pcmd, cmd_len);
			break;

		case CMD_RTP_CLOSE:
			rc = RTP_Call_Close(pcmd, cmd_len);
			break;

		case CMD_RTP_SPECTX_PLD:
			rc = RTP_Call_SpecialTx_Payload(pcmd, cmd_len);
			break;

		case CMD_RTP_SPECTX_CTRL:
			rc = RTP_Call_SpecialTx_Control(pcmd, cmd_len);
			break;

		case CMD_RTCP_QUERY:
			rc = RTCP_Query(pcmd, cmd_len);
			if (rc == NO_ERR)
				retlen += sizeof(RTCPQueryResponse);
			break;

		case CMD_RTP_STATS_DTMF_PT:
			rc = rtp_set_dtmf_pt(pcmd, cmd_len);
			break;	

#if 0
		case CMD_RTP_STATS_ENABLE:
			rc = RTPQOS_enable_stats(pcmd, cmd_len);
			break;	

		case CMD_RTP_STATS_DISABLE:
			rc = RTPQOS_disable_stats(pcmd, cmd_len);
			break;	

		case CMD_RTP_STATS_QUERY:
			rc = RTPQOS_query_stats(pcmd, cmd_len);
			if (rc == NO_ERR)
				retlen += sizeof(RTCPQueryResponse);
			break;	

		case CMD_VOICE_BUFFER_LOAD:
			rc = voice_buffer_command_load(pcmd, cmd_len);
			break;

		case CMD_VOICE_BUFFER_UNLOAD:
			rc = voice_buffer_command_unload(pcmd, cmd_len);
			break;

		case CMD_VOICE_BUFFER_START:
			rc = voice_buffer_command_start(pcmd, cmd_len);
			break;

		case CMD_VOICE_BUFFER_STOP:
			rc = voice_buffer_command_stop(pcmd, cmd_len);
			break;

		case CMD_VOICE_BUFFER_RESET:
			rc = voice_buffer_command_reset(pcmd, cmd_len);
			break;
#endif // 0
		default:
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;
	return retlen;
}

#ifdef TODO_RTP_QOS
/* link a CT4 entry to a RTP statistics slot */
int rtpqos_ipv4_link_stats_entry_by_tuple(PCtEntry pCT, U32 saddr, U32 daddr, U16 sport, U16 dport)
{
	int i;
	PRTPQOS_ENTRY pEntry;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++)
	{
		pEntry = &rtpqos_cache[i];

		if(pEntry->stream_id != RTP_STATS_FREE)
		{
			if((saddr == pEntry->saddr[0]) && (daddr == pEntry->daddr[0]) && (sport == pEntry->sport) && (dport == pEntry->dport))
			{
				pCT->status |= CONNTRACK_RTP_STATS;
				pCT->rtpqos_slot = pEntry->slot;

				return ERR_RTP_STATS_DUPLICATED;
			}
		}
	}

	return ERR_RTP_STATS_STREAMID_UNKNOWN;
}


/* link a CT6 entry to a RTP statistics slot */
int rtpqos_ipv6_link_stats_entry_by_tuple(PCtEntryIPv6 pCT, U32 *saddr, U32 *daddr, U16 sport, U16 dport)
{
	int i;
	PRTPQOS_ENTRY pEntry;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++)
	{
		pEntry = &rtpqos_cache[i];

		if(pEntry->stream_id != RTP_STATS_FREE)
		{
			if(!IPV6_CMP(saddr, pEntry->saddr) && !IPV6_CMP(daddr, pEntry->daddr) && (sport == pEntry->sport) && (dport == pEntry->dport))
			{
				pCT->status |= CONNTRACK_RTP_STATS;
				pCT->rtpqos_slot = pEntry->slot;

				return ERR_RTP_STATS_DUPLICATED;
			}
		}
	}
	return ERR_RTP_STATS_STREAMID_UNKNOWN;
}


/* link a MC4 entry to a RTP statistics slot */
int rtpqos_mc4_link_stats_entry_by_tuple(PMC4Entry pMC, U32 saddr, U32 daddr)
{
	int i;
	PRTPQOS_ENTRY pEntry;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++)
	{
		pEntry = &rtpqos_cache[i];

		if(pEntry->stream_id != RTP_STATS_FREE)
		{
			if((saddr == pEntry->saddr[0]) && (daddr == pEntry->daddr[0]))
			{
				pMC->status |= CONNTRACK_RTP_STATS;
				pMC->rtpqos_slot = pEntry->slot;
				pMC->rtpqos_ref_count++;

				return ERR_RTP_STATS_DUPLICATED;
			}
		}
	}

	return ERR_RTP_STATS_STREAMID_UNKNOWN;
}


/* link a MC6 entry to a RTP statistics slot */
int rtpqos_mc6_link_stats_entry_by_tuple(PMC6Entry pMC, U32 *saddr, U32 *daddr)
{
	int i;
	PRTPQOS_ENTRY pEntry;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++)
	{
		pEntry = &rtpqos_cache[i];

		if(pEntry->stream_id != RTP_STATS_FREE)
		{
			if (!IPV6_CMP(saddr, pEntry->saddr) && !IPV6_CMP(daddr, pEntry->daddr)) 
			{
				pMC->status |= CONNTRACK_RTP_STATS;
				pMC->rtpqos_slot = pEntry->slot;
				pMC->rtpqos_ref_count++;

				return ERR_RTP_STATS_DUPLICATED;
			}
		}
	}

	return ERR_RTP_STATS_STREAMID_UNKNOWN;
}

/* link a socket entry to a RTP statistics slot */
int rtpqos_relay_link_stats_entry_by_tuple(PSockEntry pSocket, U32 saddr, U32 daddr, U16 sport, U16 dport)
{
	int i;
	PRTPQOS_ENTRY pEntry = NULL;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++)
	{
		pEntry = &rtpqos_cache[i];

		if(pEntry->stream_id != RTP_STATS_FREE)
		{
			if((saddr == pEntry->saddr[0]) && (daddr == pEntry->daddr[0]) && (sport == pEntry->sport) && (dport == pEntry->dport))
			{
				pSocket->qos_enable = TRUE;
				pSocket->rtpqos_slot = pEntry->slot;

				return ERR_RTP_STATS_DUPLICATED;
			}
		}
	}

	return ERR_RTP_STATS_STREAMID_UNKNOWN;
}


/* link a socket6 entry to a RTP statistics slot */
int rtpqos_relay6_link_stats_entry_by_tuple(PSock6Entry pSocket, U32 *saddr, U32 *daddr, U16 sport, U16 dport)
{
	int i;
	PRTPQOS_ENTRY pEntry = NULL;

	for (i = 0; i < MAX_RTP_STATS_ENTRY; i++)
	{
		pEntry = &rtpqos_cache[i];

		if(pEntry->stream_id != RTP_STATS_FREE)
		{
			if(!IPV6_CMP(saddr, pEntry->saddr) && !IPV6_CMP(daddr, pEntry->daddr) && (sport == pEntry->sport) && (dport == pEntry->dport))
			{
				pSocket->qos_enable = TRUE;
				pSocket->rtpqos_slot = pEntry->slot;

				return ERR_RTP_STATS_DUPLICATED;
			}
		}
	}
	return ERR_RTP_STATS_STREAMID_UNKNOWN;
}

#endif // TODO_RTP_QOS

BOOL rtp_relay_init(void)
{
	int i;

	set_cmd_handler(EVENT_RTP_RELAY, M_rtp_cmdproc);

	gDTMF_PT[0] = 96;
	gDTMF_PT[1] = 97;

	for (i = 0; i < NUM_RTPFLOW_ENTRIES; i++)
	{
		slist_head_init(&rtpflow_cache[i]);

		slist_head_init(&rtpcall_list[i]);
	}

#ifdef TODO_RTP_QOS
	voice_buffer_init();

	/* RTP QOS Measurement */

	dlist_head_init(&hw_rtpqos_removal_list);

	timer_init(&rtpqos_timer, hw_rtpqos_delayed_remove);
	timer_add(&rtpqos_timer, CT_TIMER_INTERVAL);

	/* mark all rtp stats entry as unused */
	for(i = 0; i < MAX_RTP_STATS_ENTRY; i++) {
		rtpqos_cache[i].stream_id = RTP_STATS_FREE;
		rtpqos_cache[i].slot = i;
	}

#endif //TODO_RTP_QOS
	return 0;
}


void rtp_relay_exit(void)
{
#ifdef TODO_RTP_QOS
	struct dlist_head *entry;
	struct _thw_rtpflow *hw_flow;
	struct _thw_rtpqos_entry *hw_rtpqos;

	voice_buffer_exit();

	timer_del(&rtpflow_timer);
#endif //TODO_RTP_QOS

	rtp_flow_reset();
	rtp_call_reset();

}

