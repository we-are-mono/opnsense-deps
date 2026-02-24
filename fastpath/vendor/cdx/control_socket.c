/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
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

typedef void *      t_Handle;   /* actually defined in ncsw_ext.h */
typedef uint32_t    t_Error;  /* actually defined in ncsw_ext.h */

extern t_Error FM_MURAM_FreeMem(t_Handle h_FmMuram, void *ptr);
extern void  * FM_MURAM_AllocMem(t_Handle h_FmMuram, uint32_t size, uint32_t align);


struct slist_head sock4_cache[NUM_SOCK_ENTRIES];
struct slist_head sock6_cache[NUM_SOCK_ENTRIES];
struct slist_head sockid_cache[NUM_SOCK_ENTRIES];

static void SOCKET4_delete_route(PSockEntry pSocket)
{
	L2_route_put(pSocket->pRtEntry);
	pSocket->pRtEntry = NULL;
}

static void SOCKET6_delete_route(PSock6Entry pSocket)
{
	L2_route_put(pSocket->pRtEntry);
	pSocket->pRtEntry = NULL;
}

BOOL SOCKET4_check_route(PSockEntry pSocket)
{
	PRouteEntry pRtEntry;

	pRtEntry = L2_route_get(pSocket->route_id);
	if (pRtEntry == NULL)
		return FALSE;

	pSocket->pRtEntry = pRtEntry;
	return TRUE;
}

BOOL SOCKET6_check_route(PSock6Entry pSocket)
{
	PRouteEntry pRtEntry;

	pRtEntry = L2_route_get(pSocket->route_id);
	if (pRtEntry == NULL)
		return FALSE;

	pSocket->pRtEntry = pRtEntry;
	return TRUE;
}


void socket4_update(PSockEntry pSocket, u8 event)
{
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	if (pSocket->SocketType != SOCKET_TYPE_MSP)
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	{
		if(!pSocket->pRtEntry)
			SOCKET4_check_route(pSocket);
	}

#ifdef CDX_TODO
	// update hw entry, if it exists
#endif
}


void socket6_update(PSock6Entry pSocket, u8 event)
{
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	if (pSocket->SocketType != SOCKET_TYPE_MSP)
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	{
		if(!pSocket->pRtEntry)
			SOCKET6_check_route(pSocket);
	}

#ifdef CDX_TODO
	// update hw entry, if it exists
#endif
}


PSockEntry socket4_alloc(void)
{
	return kzalloc(sizeof(SockEntry), GFP_KERNEL);
}

void socket4_free(PSockEntry pSocket)
{
	kfree(pSocket);
}

/** Adds a software socket entry to the local hash
*
* @param pEntry		pointer to the software socket
* @param hash		hash index where to add the socket
*
* @return		NO_ERR in case of success, ERR_xxx in case of error
*/
int socket4_add(PSockEntry pSocket)
{
	int rc = NO_ERR;

	/* fill in the hw entry */
	socket4_update(pSocket, SOCKET_CREATE);

	/* Add software entry to local hash */
	slist_add(&sock4_cache[pSocket->hash], &pSocket->list);
	slist_add(&sockid_cache[pSocket->hash_by_id], &pSocket->list_id);

	return rc;

#ifdef CDX_TODO
err:
	socket4_free(pSocket);
	return rc;
#endif

}


/** Removes a software socket entry from the local hash
* The software socket is removed immediately from the local hash.
*
* @param pEntry		pointer to the software socket
* @param hash		hash index where to remove the socket
*
*/
void socket4_remove(PSockEntry pSocket, U32 hash, U32 hash_by_id)
{

	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;
#ifdef CDX_TODO
	/* Check if there is a hardware socket */
#endif

	/* destroy sw socket entry */
	SOCKET4_delete_route(pSocket);

	/* Unlink from software list */
	slist_remove(&sock4_cache[hash], &pSocket->list);
	slist_remove(&sockid_cache[hash_by_id], &pSocket->list_id);

	if (pSocket->hw_stats)
	{
		h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
		if (!h_FmMuram)
		{
			DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		}
		else
			FM_MURAM_FreeMem(h_FmMuram, (void *)pSocket->hw_stats);
		pSocket->hw_stats = NULL;
	}	
	socket4_free(pSocket);
}

PSock6Entry socket6_alloc(void)
{
	return kzalloc(sizeof(Sock6Entry), GFP_KERNEL);
}

void socket6_free(PSock6Entry pSocket)
{
	kfree(pSocket);
}

int socket6_add(PSock6Entry pSocket)
{
	int rc = NO_ERR;

	/* fill in the hw entry */
	socket6_update(pSocket, SOCKET_CREATE);

	/* Add software entry to local hash */
	slist_add(&sock6_cache[pSocket->hash], &pSocket->list);
	slist_add(&sockid_cache[pSocket->hash_by_id], &pSocket->list_id);

	return rc;

#ifdef CDX_TODO
err:
	socket6_free(pSocket);
	return rc;
#endif

}


/** Removes a software socket entry from the local hash
* The software socket is removed immediately from the local hash.
*
* @param pEntry		pointer to the software socket
* @param hash		hash index where to remove the socket
*
*/
void socket6_remove(PSock6Entry pSocket, U32 hash, U32 hash_by_id)
{
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;

#ifdef CDX_TODO
	/* Check if there is a hardware socket */
#endif

	/* destroy sw socket entry */
	SOCKET6_delete_route(pSocket);

	/* Unlink from software list */
	slist_remove(&sock6_cache[hash], &pSocket->list);
	slist_remove(&sockid_cache[hash_by_id], &pSocket->list_id);

	if (pSocket->hw_stats)
	{
		h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
		if (!h_FmMuram)
		{
			DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		}
		else
			FM_MURAM_FreeMem(h_FmMuram, (void *)pSocket->hw_stats);
		pSocket->hw_stats =  NULL;
	}	
	socket6_free(pSocket);
}


PSockEntry SOCKET_bind(U16 socketID, PVOID owner, U16 owner_type)
{
 	PSockEntry pSocket = SOCKET_find_entry_by_id(socketID);

	if (pSocket) {
		pSocket->owner = owner;
		pSocket->owner_type = owner_type;

		/* update hardware socket */
		if(pSocket->SocketFamily == PROTO_IPV6)
			socket6_update((PSock6Entry)pSocket, SOCKET_BIND);
		else
			socket4_update(pSocket, SOCKET_BIND);
	}

	return pSocket;
}

PSockEntry SOCKET_unbind(U16 socketID)
{
	PSockEntry pSocket = SOCKET_find_entry_by_id(socketID);

	if (pSocket) {
		pSocket->owner = NULL;
		pSocket->owner_type = SOCK_OWNER_NONE;

		/* update hardware socket */
		if(pSocket->SocketFamily == PROTO_IPV6)
			socket6_update((PSock6Entry)pSocket, SOCKET_UNBIND);
		else
			socket4_update(pSocket, SOCKET_UNBIND);
	}
	
	return pSocket;
}

PSockEntry SOCKET_find_entry_by_id(U16 socketID)
{
	PSockEntry pEntry;
	PSockEntry pSocket = NULL;
	struct slist_entry *entry;
	int hash;

	hash = HASH_SOCKID(socketID);

	slist_for_each(pEntry, entry, &sockid_cache[hash], list_id)
	{
		if (pEntry->SocketID == socketID)
			pSocket = pEntry;
	}

	return pSocket;
}

PSockEntry SOCKET4_find_entry(U32 saddr, U16 sport, U32 daddr, U16 dport, U16 proto)
{
	PSockEntry pEntry;
	PSockEntry pSock3 = NULL;
	struct slist_entry *entry;
	U32 hash = HASH_SOCK(daddr, dport, proto);

	slist_for_each(pEntry, entry, &sock4_cache[hash], list)
	{
		if (pEntry->Daddr_v4 == daddr && pEntry->Dport == dport && pEntry->proto == proto) {
			if (!pEntry->unconnected) {
				// check 5-tuples for connected sockets
				if (pEntry->Saddr_v4 == saddr && pEntry->Sport == sport) {
					return pEntry;
				}	
			}
			else // remind last 3 tuples match (should be unique)
				pSock3 = pEntry;
		}
	}

	return pSock3;
}


PSock6Entry SOCKET6_find_entry(U32 *saddr, U16 sport, U32 *daddr, U16 dport, U16 proto)
{
	PSock6Entry pEntry;
	PSock6Entry pSock3 = NULL;
	struct slist_entry *entry;
	U32 hash;
	U32 daddr_lo;

	daddr_lo = READ_UNALIGNED_INT(daddr[IP6_LO_ADDR]);
	hash = HASH_SOCK6(daddr_lo, dport, proto);
	
	slist_for_each(pEntry, entry, &sock6_cache[hash], list)
	{
		if (!IPV6_CMP(pEntry->Daddr_v6, daddr) && (pEntry->Dport == dport) && (pEntry->proto == proto))
		{
			// 3-tuples match
			if (!pEntry->unconnected) {
				// check 5-tuples for connected sockets
				if (!IPV6_CMP(pEntry->Saddr_v6, saddr) && (pEntry->Sport == sport)) 
						return pEntry;	
			}
			else // remind last 3 tuples match (should be unique)
			 	pSock3 = pEntry;
		}
	}
	
	return pSock3;
}

/* free IPv4 sockets entries */
void SOCKET4_free_entries(void)
{
	int i;
	U32 hash_by_id;
	PSockEntry pSock;

	for(i = 0; i < NUM_SOCK_ENTRIES; i++)
	{
		struct slist_entry *entry;

		slist_for_each_safe(pSock, entry, &sock4_cache[i], list)
		{
			hash_by_id = HASH_SOCKID(pSock->SocketID);
			socket4_remove(pSock, i, hash_by_id);
		}
	}
}


int SOCKET4_HandleIP_Socket_Open (U16 *p, U16 Length)
{
	SockOpenCommand SocketCmd;
	PSockEntry pEntry;
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;
	PRouteEntry pRtEntry;
	int i;

	DPA_INFO("%s(%d) length %d, size %lu \n",
		__FUNCTION__,__LINE__, Length, sizeof(SockOpenCommand));

	// Check length
	if (Length != sizeof(SockOpenCommand))
		return ERR_WRONG_COMMAND_SIZE;
	// Ensure alignment
	memcpy((U8*)&SocketCmd, (U8*)p, sizeof(SockOpenCommand));


	DPA_INFO("id %d, queue %d, saddr %x sport %d\n",
		SocketCmd.SockID, SocketCmd.queue, SocketCmd.Saddr, SocketCmd.Sport);
	DPA_INFO("daddr %x,, dport %d, mode %d, proto %d, type %d\n",
		SocketCmd.Daddr, SocketCmd.Dport, SocketCmd.mode, SocketCmd.proto, SocketCmd.SockType);

	DPA_INFO("%s(%d) \n",__FUNCTION__,__LINE__);
	if (!SocketCmd.SockID)
		return ERR_WRONG_SOCKID;

	DPA_INFO("%s(%d) \n",__FUNCTION__,__LINE__);
	// sockets with same set of addresses even with different mode not allowed.
	pEntry = SOCKET4_find_entry(SocketCmd.Saddr, SocketCmd.Sport, SocketCmd.Daddr, SocketCmd.Dport, SocketCmd.proto);
	if ((pEntry)/* && (pEntry->connected == SocketCmd.mode) */) {
		if (pEntry->SocketID != SocketCmd.SockID)
			return ERR_SOCK_ALREADY_OPENED_WITH_OTHER_ID;
		else
			return ERR_SOCK_ALREADY_OPEN;
	}

	DPA_INFO("%s(%d) \n",__FUNCTION__,__LINE__);
	if (SOCKET_find_entry_by_id(SocketCmd.SockID) != NULL)
		return ERR_SOCKID_ALREADY_USED;

	DPA_INFO("%s(%d) \n",__FUNCTION__,__LINE__);
	switch (SocketCmd.SockType) {
	case SOCKET_TYPE_FPP:
		break;

	case SOCKET_TYPE_ACP:
		break;

	case SOCKET_TYPE_MSP:
		if (SocketCmd.proto != IPPROTOCOL_UDP)
			return ERR_WRONG_SOCK_PROTO;

		/* FIXME, if MSP support was not compiled in we should return error */
		break;

	case SOCKET_TYPE_L2TP:
		if (!SocketCmd.mode)
			return ERR_WRONG_SOCK_MODE;

		break;

	case SOCKET_TYPE_LRO:
		return ERR_WRONG_SOCK_TYPE;

	default:
		return ERR_WRONG_SOCK_TYPE;
	}

#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	if (SocketCmd.SockType != SOCKET_TYPE_MSP)
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	{
		if (!SocketCmd.route_id)
			return ERR_NO_ROUTE_TO_SOCK;

		pRtEntry = L2_route_get(SocketCmd.route_id);
		if (pRtEntry == NULL)
			return ERR_NO_ROUTE_TO_SOCK;
		L2_route_put(pRtEntry);
	}

	if ((pEntry = (struct _tSockEntry*)socket4_alloc()) == NULL)
	  	return ERR_NOT_ENOUGH_MEMORY;

	DPA_INFO("%s(%d) \n",__FUNCTION__,__LINE__);
	memset(pEntry, 0, sizeof (SockEntry));
	pEntry->SocketFamily = PROTO_IPV4;
	pEntry->Daddr_v4 = SocketCmd.Daddr;
	pEntry->Saddr_v4 = SocketCmd.Saddr;
	pEntry->Dport = SocketCmd.Dport;
	pEntry->Sport = SocketCmd.Sport;
	pEntry->proto = SocketCmd.proto;
	pEntry->SocketID = SocketCmd.SockID;
	pEntry->queue = SocketCmd.queue;
	pEntry->dscp = SocketCmd.dscp;
	pEntry->SocketType = SocketCmd.SockType;	
	pEntry->unconnected = SocketCmd.mode;
	pEntry->route_id = SocketCmd.route_id;
	pEntry->initial_takeover_done = FALSE;
	pEntry->hash = HASH_SOCK(pEntry->Daddr_v4, pEntry->Dport, pEntry->proto);
	pEntry->hash_by_id = HASH_SOCKID(pEntry->SocketID);
	pEntry->expt_flag =  (uint8_t)SocketCmd.expt_flag;
	pEntry->hw_stats = NULL;

	pEntry->secure = SocketCmd.secure;
	if (SocketCmd.SA_nr_rx > SA_MAX_OP || SocketCmd.SA_nr_tx > SA_MAX_OP) {
		socket4_free(pEntry);
		return ERR_CT_ENTRY_TOO_MANY_SA_OP;
	}
	pEntry->SA_nr_rx = SocketCmd.SA_nr_rx;
	for (i = 0; i < SocketCmd.SA_nr_rx; i++)
		pEntry->SA_handle_rx[i] = SocketCmd.SA_handle_rx[i];
	pEntry->SA_nr_tx = SocketCmd.SA_nr_tx;
	for (i = 0; i < SocketCmd.SA_nr_tx; i++)
		pEntry->SA_handle_tx[i] = SocketCmd.SA_handle_tx[i];

	if (pEntry->SocketType == SOCKET_TYPE_L2TP)
		pEntry->owner_type = SOCK_OWNER_L2TP;
	else
		pEntry->owner_type = SOCK_OWNER_NONE;

	/* allocate MURAM memory for statistics */
	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		socket4_free(pEntry);
		return ERR_NOT_ENOUGH_MEMORY;
	}
	
	DPA_INFO("%s(%d) \n",__FUNCTION__,__LINE__);
	if (sizeof(RTCPStats) > SOCKET_STATS_SIZE)
	{
		DPA_ERROR("%s(%d) RTCPStats size more than SOCKET_STATS_SIZE. Please update SOCKET_STATS_SIZE properly.\n"
				, __FUNCTION__,__LINE__);
		socket4_free(pEntry);
		return ERR_NOT_ENOUGH_MEMORY;
	}
	pEntry->hw_stats = FM_MURAM_AllocMem(h_FmMuram, SOCKET_STATS_SIZE, 16);
	if (!pEntry->hw_stats)
	{
		DPA_ERROR("%s(%d) FM_MURAM_AllocMem failed\n", __FUNCTION__,__LINE__);
		socket4_free(pEntry);
		return ERR_NOT_ENOUGH_MEMORY;
	}
	memset(pEntry->hw_stats, 0, SOCKET_STATS_SIZE);

	/* check if rtp stats entry is created for this socket, if found link the two object and mark the socket 's for RTP stats */
#ifdef CDX_TODO_RTPRELAYQOS
	rtpqos_relay_link_stats_entry_by_tuple(pEntry, pEntry->Saddr_v4, pEntry->Daddr_v4, pEntry->Dport, pEntry->Sport);
#endif

	DPA_INFO("%s(%d) \n",__FUNCTION__,__LINE__);
	/* Add software and hardware entry to local and packet engine hash */
	socket4_add(pEntry);  // this func not returning error in any case

#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	if (SocketCmd.SockType == SOCKET_TYPE_MSP) {
		pEntry->iifindex = SocketCmd.iifindex;
		cdx_create_rtp_qos_slowpath_flow(pEntry);
		return NO_ERR;
	}
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	if(!pEntry->pRtEntry)
	{
		socket4_remove(pEntry, pEntry->hash, pEntry->hash_by_id);
		return ERR_NO_ROUTE_TO_SOCK;
	}
	return NO_ERR;
}

int SOCKET4_HandleIP_Socket_Update (U16 *p, U16 Length)
{
	SockUpdateCommand SocketCmd;
	PSockEntry pEntry, pingress_socket;
	PRouteEntry pRtEntry;
	uint8_t update_flow = 0;
	int rc = NO_ERR;

	// Check length
	if (Length != sizeof(SockUpdateCommand))
		return ERR_WRONG_COMMAND_SIZE;
	// Ensure alignment
	memcpy((U8*)&SocketCmd, (U8*)p, sizeof(SockUpdateCommand));

	pEntry = SOCKET_find_entry_by_id(SocketCmd.SockID);

	if (pEntry == NULL)
		return ERR_SOCKID_UNKNOWN;

	if (pEntry->SocketFamily != PROTO_IPV4)
		return ERR_WRONG_SOCK_FAMILY;

	if (!pEntry->unconnected &&
	    (((SocketCmd.Saddr != 0xFFFFFFFF) && (SocketCmd.Saddr != pEntry->Saddr_v4)) ||
	    ((SocketCmd.Sport != 0xffff) && (SocketCmd.Sport != pEntry->Sport))))
		return ERR_SOCK_ALREADY_OPEN;

	if (pEntry->route_id != SocketCmd.route_id) {
		/* If no route return error */
		if (!(pRtEntry = L2_route_get(pEntry->route_id)))
			return ERR_NO_ROUTE_TO_SOCK;
		L2_route_put(pRtEntry);
		SOCKET4_delete_route(pEntry);
		pEntry->route_id = SocketCmd.route_id;
		update_flow = 1;
	}

	if ((SocketCmd.Saddr != 0xFFFFFFFF) && (SocketCmd.Saddr != pEntry->Saddr_v4)) {
		/* If no route return error */
		if (!(pRtEntry = L2_route_get(pEntry->route_id)))
			return ERR_NO_ROUTE_TO_SOCK;
		L2_route_put(pRtEntry);
		SOCKET4_delete_route(pEntry);
		pEntry->Saddr_v4 = SocketCmd.Saddr;
		update_flow = 1;
	}

	if (SocketCmd.expt_flag != 0xffff)
	{
		pEntry->expt_flag = SocketCmd.expt_flag;
		update_flow =  1;
	}

	if (SocketCmd.Sport != 0xffff)	
	{
		if (pEntry->Sport !=  SocketCmd.Sport)
			update_flow = 1;
		pEntry->Sport = SocketCmd.Sport;
	}

	if (SocketCmd.queue != 0xff)
		pEntry->queue = SocketCmd.queue;

	if (SocketCmd.dscp != 0xffff)
		pEntry->dscp = SocketCmd.dscp;

	if (SocketCmd.secure != 0xffff)
	{
		int i;
		if (SocketCmd.SA_nr_rx > SA_MAX_OP || SocketCmd.SA_nr_tx > SA_MAX_OP)
			return ERR_CT_ENTRY_TOO_MANY_SA_OP;
		pEntry->secure = SocketCmd.secure;
		pEntry->SA_nr_rx = SocketCmd.SA_nr_rx;
		for (i = 0; i < SocketCmd.SA_nr_rx; i++)
			pEntry->SA_handle_rx[i] = SocketCmd.SA_handle_rx[i];
		pEntry->SA_nr_tx = SocketCmd.SA_nr_tx;
		for (i = 0; i < SocketCmd.SA_nr_tx; i++)
			pEntry->SA_handle_tx[i] = SocketCmd.SA_handle_tx[i];
	}

	socket4_update(pEntry, SOCKET_UPDATE);

	if ((pEntry->out_rtp_flow) &&
		 (update_flow))
	{
		PRTPflow 			 pFlow;
		void 				*td;
		void				*eeh_entry_handle;
		uint16_t			 eeh_entry_index;

		// egress rtp flow should be modified with route info, etc.
		// deleting old entry and creating new one

		pFlow = (PRTPflow) pEntry->out_rtp_flow;

		pingress_socket = SOCKET_find_entry_by_id(pFlow->ingress_socketID);
		if (!pingress_socket)
		{
			DPA_ERROR("%s(%d) error in finding ingress socket\n", __FUNCTION__, __LINE__);
			return ERR_SOCK_UPDATE_ERR;
		}	
		if(!pingress_socket->pRtEntry)
		{
			DPA_INFO("%s(%d) missing route, checking for route\n",
			__FUNCTION__,__LINE__);
			SOCKET4_check_route(pingress_socket);
		}

		if ((!pingress_socket->pRtEntry) || (!pEntry->pRtEntry))
		{
			DPA_ERROR("%s(%d) missing route for to_socket or from_socket \n",
				__FUNCTION__,__LINE__);
			return ERR_NO_ROUTE_TO_SOCK;
		}

		td = pFlow->hw_flow->td;
		eeh_entry_handle = pFlow->hw_flow->eeh_entry_handle;
		eeh_entry_index = pFlow->hw_flow->eeh_entry_index;
		pFlow->hw_flow->eeh_entry_handle =  NULL;
		pFlow->hw_flow->eeh_entry_index = 0;

		if (ExternalHashTableDeleteKey(td, 
				eeh_entry_index, 
				eeh_entry_handle)) {
			DPA_ERROR("%s(%d)::unable to remove entry from hash table\n",
				__FUNCTION__, __LINE__);
		}
		//free table entry
		ExternalHashTableEntryFree(eeh_entry_handle);
		
		/* reflect changes to hardware flow */
		// create an entry in ehash table
		if(cdx_create_rtp_conn_in_classif_table(pFlow, pingress_socket, pEntry))
		{
			DPA_ERROR("%s(%d) error in creating eehash table entry\n", __FUNCTION__, __LINE__);
			return ERR_SOCK_UPDATE_ERR;
		}
	
		if (cdx_rtp_set_hwinfo_fields(pFlow, pingress_socket) != 0)
		{
			DPA_ERROR("%s(%d) Error in setting rtp hwinfo fields.\n", __FUNCTION__,__LINE__);
			return -1;
		}
		cdx_ehash_set_rtp_info_params(pFlow->hw_flow->ehash_rtp_relay_params, 
										pFlow, pingress_socket);

		pFlow = (PRTPflow) pEntry->owner;
		cdx_ehash_set_rtp_info_params(pFlow->hw_flow->ehash_rtp_relay_params, 
									pFlow, pEntry);
	}

	return rc;
}


int SOCKET4_HandleIP_Socket_Close (U16 *p, U16 Length)
{
	SockCloseCommand SocketCmd;
	PSockEntry pEntry;
	U32 hash, hash_by_id;

	// Check length
	if (Length != sizeof(SockCloseCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&SocketCmd, (U8*)p, sizeof(SockCloseCommand));

	pEntry = SOCKET_find_entry_by_id(SocketCmd.SockID);

	if (pEntry == NULL)
		return ERR_SOCKID_UNKNOWN;

	// return error if RTP connection already exists on socket
	if (pEntry->owner)
	{
		DPA_ERROR("RTP relay connection exists with this SOCKET");
		return ERR_SOCK_ALREADY_IN_USE;
	}

	hash = HASH_SOCK(pEntry->Daddr_v4, pEntry->Dport, pEntry->proto);
	hash_by_id = HASH_SOCKID(pEntry->SocketID);

#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	if (pEntry->SocketType == SOCKET_TYPE_MSP) {
		/* deleting entry */

		if (ExternalHashTableDeleteKey(pEntry->SktEhTblHdl.td, 
			pEntry->SktEhTblHdl.eeh_entry_index, 
			pEntry->SktEhTblHdl.eeh_entry_handle)) {
			DPA_ERROR("%s(%d)::unable to remove entry from hash table\n",
					__FUNCTION__, __LINE__);
		}
		/* free table entry */
		ExternalHashTableEntryFree(pEntry->SktEhTblHdl.eeh_entry_handle);
		DPA_INFO("%s()::%d Successfully deleted old extended hash table key and entry:\n", 
							__func__, __LINE__);
	}
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	/* destroy hw socket entry */
	socket4_remove(pEntry, hash, hash_by_id);

	return NO_ERR;
}


/* free IPv6 sockets entries */
void SOCKET6_free_entries(void)
{
	int i;
	U32 hash_by_id;
	PSock6Entry pSock;

	for (i = 0; i < NUM_SOCK_ENTRIES; i++)
	{
		struct slist_entry *entry;

		slist_for_each_safe(pSock, entry, &sock6_cache[i], list)
		{
			hash_by_id = HASH_SOCKID(pSock->SocketID);
			socket6_remove(pSock, i, hash_by_id);
		}
	}
}


int SOCKET6_HandleIP_Socket_Open(U16 *p, U16 Length)
{
	Sock6OpenCommand SocketCmd;
	PSock6Entry pEntry;
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;
	int i;

	DPA_INFO("%s(%d) length %d, size %lu \n",
		__FUNCTION__,__LINE__, Length, sizeof(Sock6OpenCommand));

	// Check length
	if (Length != sizeof(Sock6OpenCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&SocketCmd, (U8*)p, sizeof(Sock6OpenCommand));

	if (!SocketCmd.SockID)
		return ERR_WRONG_SOCKID;

	// sockets with same set of addresses even with different mode not allowed.
	pEntry = SOCKET6_find_entry(SocketCmd.Saddr, SocketCmd.Sport, SocketCmd.Daddr, SocketCmd.Dport, SocketCmd.proto);
	if ((pEntry) /* && (pEntry->connected == SocketCmd.mode) */ ) {
		if (pEntry->SocketID != SocketCmd.SockID)
			return ERR_SOCK_ALREADY_OPENED_WITH_OTHER_ID;
		else
			return ERR_SOCK_ALREADY_OPEN;
	}

	if (SOCKET_find_entry_by_id(SocketCmd.SockID) != NULL)
		return ERR_SOCKID_ALREADY_USED;

	switch (SocketCmd.SockType) {
	case SOCKET_TYPE_FPP:
	case SOCKET_TYPE_ACP:
	case SOCKET_TYPE_MSP:
		break;

	case SOCKET_TYPE_L2TP:
	case SOCKET_TYPE_LRO:
	default:
		return ERR_WRONG_SOCK_TYPE;
	}
	
	if ((pEntry = socket6_alloc()) == NULL)
		return ERR_NOT_ENOUGH_MEMORY;

	pEntry->SocketFamily = PROTO_IPV6;
	memcpy(pEntry->Daddr_v6, SocketCmd.Daddr, IPV6_ADDRESS_LENGTH);
	memcpy(pEntry->Saddr_v6, SocketCmd.Saddr, IPV6_ADDRESS_LENGTH);
	pEntry->Dport = SocketCmd.Dport;
	pEntry->Sport = SocketCmd.Sport;
	pEntry->proto = SocketCmd.proto;
	pEntry->SocketID = SocketCmd.SockID;
	pEntry->queue = SocketCmd.queue;
	pEntry->dscp = SocketCmd.dscp;
	pEntry->unconnected = SocketCmd.mode;
	pEntry->SocketType = SocketCmd.SockType;	
	pEntry->route_id = SocketCmd.route_id;
	pEntry->hash = HASH_SOCK6(pEntry->Daddr_v6[IP6_LO_ADDR], pEntry->Dport, pEntry->proto);
	pEntry->hash_by_id = HASH_SOCKID(pEntry->SocketID);
	pEntry->hw_stats = NULL;
	pEntry->expt_flag =  (uint8_t)SocketCmd.expt_flag;

	if (pEntry->SocketType == SOCKET_TYPE_L2TP)
		pEntry->owner_type = SOCK_OWNER_L2TP;
	else
		pEntry->owner_type = SOCK_OWNER_NONE;

	pEntry->secure = SocketCmd.secure;
	if (SocketCmd.SA_nr_rx > SA_MAX_OP || SocketCmd.SA_nr_tx > SA_MAX_OP) {
		socket6_free(pEntry);
		return ERR_CT_ENTRY_TOO_MANY_SA_OP;
	}
	pEntry->SA_nr_rx = SocketCmd.SA_nr_rx;
	for (i = 0; i < SocketCmd.SA_nr_rx; i++)
		pEntry->SA_handle_rx[i] = SocketCmd.SA_handle_rx[i];
	pEntry->SA_nr_tx = SocketCmd.SA_nr_tx;
	for (i = 0; i < SocketCmd.SA_nr_tx; i++)
		pEntry->SA_handle_tx[i] = SocketCmd.SA_handle_tx[i];

	/* allocate MURAM memory for statistics */
	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		socket6_free(pEntry);
		return ERR_NOT_ENOUGH_MEMORY;
	}
	
	if (sizeof(RTCPStats) > SOCKET_STATS_SIZE)
	{
		DPA_ERROR("%s(%d) RTCPStats size more than SOCKET_STATS_SIZE. Please update SOCKET_STATS_SIZE properly.\n"
				, __FUNCTION__,__LINE__);
		socket6_free(pEntry);
		return ERR_NOT_ENOUGH_MEMORY;
	}
	pEntry->hw_stats = FM_MURAM_AllocMem(h_FmMuram, SOCKET_STATS_SIZE, 32);
	if (!pEntry->hw_stats)
	{
		DPA_ERROR("%s(%d) FM_MURAM_AllocMem failed\n", __FUNCTION__,__LINE__);
		socket6_free(pEntry);
		return ERR_NOT_ENOUGH_MEMORY;
	}
	memset(pEntry->hw_stats, 0, SOCKET_STATS_SIZE);

	/* check if rtp stats entry is created for this socket, if found link the two object and mark the socket 's for RTP stats */
#ifdef CDX_TODO_RTPRELAY
	rtpqos_relay6_link_stats_entry_by_tuple(pEntry, pEntry->Saddr_v6, pEntry->Daddr_v6, pEntry->Dport, pEntry->Sport);
#endif

	socket6_add(pEntry);  // this func not returning error in any case

#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	if (SocketCmd.SockType == SOCKET_TYPE_MSP) {
		pEntry->iifindex = SocketCmd.iifindex;
		cdx_create_rtp_qos_slowpath_flow(pEntry);
		return NO_ERR;
	}
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	if(!pEntry->pRtEntry)
	{
		socket6_remove(pEntry, pEntry->hash, pEntry->hash_by_id);
		return ERR_NO_ROUTE_TO_SOCK;
	}

	return NO_ERR;

}


int SOCKET6_HandleIP_Socket_Update(U16 *p, U16 Length)
{
	Sock6UpdateCommand SocketCmd;
	PSock6Entry pEntry, pingress_socket;
	PRouteEntry	pRtEntry;
	uint8_t update_flow = 0;
	int i;
	int rc = NO_ERR;
	U32 nulladdr[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};

	// Check length
	if (Length != sizeof(Sock6UpdateCommand))
		return ERR_WRONG_COMMAND_SIZE;
	// Ensure alignment
	memcpy((U8*)&SocketCmd, (U8*)p, sizeof(Sock6UpdateCommand));

	pEntry = (PSock6Entry)SOCKET_find_entry_by_id(SocketCmd.SockID);

	if (pEntry == NULL)
		return ERR_SOCKID_UNKNOWN;

	if (pEntry->SocketFamily != PROTO_IPV6)
		return ERR_WRONG_SOCK_FAMILY;

	/* For connected sockets don't allow 5-tuple to change */
	if (!pEntry->unconnected &&
	    ((IPV6_CMP(SocketCmd.Saddr, nulladdr) && IPV6_CMP(SocketCmd.Saddr, pEntry->Saddr_v6)) ||
	    ((SocketCmd.Sport != 0xffff) && (SocketCmd.Sport != pEntry->Sport))))
		return ERR_SOCK_ALREADY_OPEN;

	if (pEntry->route_id != SocketCmd.route_id)
	{
		// If no route return error
		if (!(pRtEntry = L2_route_get(SocketCmd.route_id)))
			return ERR_NO_ROUTE_TO_SOCK;
		L2_route_put(pRtEntry);

		// Route has changed -> delete it
		update_flow = 1;
		SOCKET6_delete_route(pEntry);
		pEntry->route_id = SocketCmd.route_id;
	}

	if (IPV6_CMP(SocketCmd.Saddr, nulladdr) && IPV6_CMP(SocketCmd.Saddr, pEntry->Saddr_v6))
	{
		// If no route return error
		if (!(pRtEntry = L2_route_get(pEntry->route_id)))
			return ERR_NO_ROUTE_TO_SOCK;
		L2_route_put(pRtEntry);
		// Route has changed -> delete it
		update_flow = 1;
		SOCKET6_delete_route(pEntry);
		memcpy(pEntry->Saddr_v6, SocketCmd.Saddr, IPV6_ADDRESS_LENGTH);
	}


	if (SocketCmd.Sport != 0xffff)
	{
		if (pEntry->Sport != SocketCmd.Sport)
			update_flow = 1;
		pEntry->Sport = SocketCmd.Sport;
	}

	if (SocketCmd.queue != 0xff)
		pEntry->queue = SocketCmd.queue;

	if (SocketCmd.dscp != 0xffff)
		pEntry->dscp = SocketCmd.dscp;

	if (SocketCmd.expt_flag != 0xffff)
	{
		pEntry->expt_flag = SocketCmd.expt_flag;
		update_flow =  1;
	}

	if (SocketCmd.SA_nr_rx > SA_MAX_OP || SocketCmd.SA_nr_tx > SA_MAX_OP)
		return ERR_CT_ENTRY_TOO_MANY_SA_OP;
	pEntry->secure = SocketCmd.secure;
	pEntry->SA_nr_rx = SocketCmd.SA_nr_rx;
	for (i = 0; i < SocketCmd.SA_nr_rx; i++)
		pEntry->SA_handle_rx[i] = SocketCmd.SA_handle_rx[i];
	pEntry->SA_nr_tx = SocketCmd.SA_nr_tx;
	for (i = 0; i < SocketCmd.SA_nr_tx; i++)
		pEntry->SA_handle_tx[i] = SocketCmd.SA_handle_tx[i];

	socket6_update(pEntry, SOCKET_UPDATE);

	if ((pEntry->out_rtp_flow) &&
		 (update_flow))
	{
		PRTPflow		pFlow;
		void				*td;
		void				*eeh_entry_handle;
		uint16_t		eeh_entry_index;

		// egress rtp flow should be modified with route info, etc.
		// deleting old entry and creating new one

		pFlow = (PRTPflow) pEntry->out_rtp_flow;

		pingress_socket = SOCKET_find_entry_by_id(pFlow->ingress_socketID);
		if (!pingress_socket)
		{
			DPA_ERROR("%s(%d) error in finding ingress socket\n", __FUNCTION__, __LINE__);
			return ERR_SOCK_UPDATE_ERR;
		}	

		if(!pingress_socket->pRtEntry)
		{
			DPA_INFO("%s(%d) missing route, checking for route\n",
			__FUNCTION__,__LINE__);
			SOCKET6_check_route(pingress_socket);
		}

		if ((!pingress_socket->pRtEntry) || (!pEntry->pRtEntry))
		{
			DPA_ERROR("%s(%d) missing route for to_socket or from_socket \n",
				__FUNCTION__,__LINE__);
			return ERR_NO_ROUTE_TO_SOCK;
		}

		td = pFlow->hw_flow->td;
		eeh_entry_handle = pFlow->hw_flow->eeh_entry_handle;
		eeh_entry_index = pFlow->hw_flow->eeh_entry_index;
		pFlow->hw_flow->eeh_entry_handle =  NULL;
		pFlow->hw_flow->eeh_entry_index = 0;
		
		/* reflect changes to hardware flow */
		// create an entry in ehash table
		if(cdx_create_rtp_conn_in_classif_table(pFlow, pingress_socket, pEntry))
		{
			DPA_ERROR("%s(%d) error in creating eehash table entry\n", __FUNCTION__, __LINE__);
			return ERR_SOCK_UPDATE_ERR;
		}


		if (ExternalHashTableDeleteKey(td, 
				eeh_entry_index, 
				eeh_entry_handle))
		{
			DPA_ERROR("%s(%d)::unable to remove entry from hash table\n",
				__FUNCTION__, __LINE__);
		}
		//free table entry
		ExternalHashTableEntryFree(eeh_entry_handle);

		
		if (cdx_rtp_set_hwinfo_fields(pFlow, pingress_socket) != 0)
		{
			DPA_ERROR("%s(%d) Error in setting rtp hwinfo fields.\n", __FUNCTION__,__LINE__);
			return -1;
		}
		cdx_ehash_set_rtp_info_params(pFlow->hw_flow->ehash_rtp_relay_params, 
										pFlow, pingress_socket);

		pFlow = (PRTPflow) pEntry->owner;
		cdx_ehash_set_rtp_info_params(pFlow->hw_flow->ehash_rtp_relay_params, 
									pFlow, pEntry);
	}

	return rc;
}


int SOCKET6_HandleIP_Socket_Close(U16 *p, U16 Length)
{
	Sock6CloseCommand SocketCmd;
	PSock6Entry pEntry;
	U32 hash, hash_by_id;

	// Check length
	if (Length != sizeof(Sock6CloseCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&SocketCmd, (U8*)p, sizeof(Sock6CloseCommand));

	pEntry = (PSock6Entry)SOCKET_find_entry_by_id(SocketCmd.SockID);

	if (pEntry == NULL)
		return ERR_SOCKID_UNKNOWN;

	// return error if RTP connection already exists on socket
	if (pEntry->owner)
	{
		DPA_ERROR("RTP relay connection exists with this SOCKET");
		return ERR_SOCK_ALREADY_IN_USE;
	}

	hash = HASH_SOCK6(pEntry->Daddr_v6[IP6_LO_ADDR], pEntry->Dport, pEntry->proto);
	hash_by_id = HASH_SOCKID(pEntry->SocketID);

#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	if (pEntry->SocketType == SOCKET_TYPE_MSP) {
		/* deleting entry */

		if (ExternalHashTableDeleteKey(pEntry->SktEhTblHdl.td, 
			pEntry->SktEhTblHdl.eeh_entry_index, 
			pEntry->SktEhTblHdl.eeh_entry_handle)) {
			DPA_ERROR("%s(%d)::unable to remove entry from hash table\n",
					__FUNCTION__, __LINE__);
		}
		/* free table entry */
		ExternalHashTableEntryFree(pEntry->SktEhTblHdl.eeh_entry_handle);
		DPA_INFO("%s()::%d Successfully deleted extended hash table key and entry:\n", 
							__func__, __LINE__);
	}
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */

	socket6_remove(pEntry, hash, hash_by_id);

	return NO_ERR;
}


BOOL socket_init(void)
{
	int i;
	for (i = 0; i < NUM_SOCK_ENTRIES; i++)
	{
		slist_head_init(&sock4_cache[i]);
		slist_head_init(&sock6_cache[i]);
		slist_head_init(&sockid_cache[i]);
	}

	return 0;
}

void socket_exit(void)
{
	SOCKET4_free_entries();
	SOCKET6_free_entries();
}

