/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "cdx.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_socket.h"
#include "control_ipsec.h"

static int ipv6_cmp_aligned(void *src, void *dst)
{
	u32 off = 0;

	if ((unsigned long)src & 0x2) {
		if (*(u16 *)src - *(u16 *)dst)
			return 1;

		off = 2;
		src += 2;
		dst += 2;
	}

	if ((*(u32 *)(src + 0) - *(u32 *)(dst + 0)) ||
			(*(u32 *)(src + 4) - *(u32 *)(dst + 4)) ||
			(*(u32 *)(src + 8) - *(u32 *)(dst + 8)))
		return 1;

	if (off)
		return (*(u16 *)(src + 12) - *(u16 *)(dst + 12)) ? 1 : 0;
	else
		return (*(u32 *)(src + 12) - *(u32 *)(dst + 12)) ? 1 : 0;
}

static int ipv6_cmp_unaligned(void *src, void *dst)
{
	return ((*(u32 *)(src + 0) - READ_UNALIGNED_INT(*(u32 *)(dst + 0))) ||
			(*(u32 *)(src + 4) - READ_UNALIGNED_INT(*(u32 *)(dst + 4))) ||
			(*(u32 *)(src + 8) - READ_UNALIGNED_INT(*(u32 *)(dst + 8))) ||
			(*(u32 *)(src + 12) - READ_UNALIGNED_INT(*(u32 *)(dst + 12))));
}

int ipv6_cmp(void *src, void *dst)
{
	if (((unsigned long)src & 0x3) == ((unsigned long)dst & 0x3))
		return ipv6_cmp_aligned(src, dst);
	else {
		if ((unsigned long)src & 0x3)
			return ipv6_cmp_unaligned(dst, src);
		else
			return ipv6_cmp_unaligned(src, dst);
	}
}

/**
 * IPv6_delete_CTpair()
 *
 *
 */
int IPv6_delete_CTpair(PCtEntry ctEntry)
{
	PCtEntry twin_entry;
	struct _tCtCommandIPv6 *message;
	HostMessage *pmsg;

	twin_entry = CT_TWIN(ctEntry);
	if ((twin_entry->status & CONNTRACK_ORIG) == CONNTRACK_ORIG)
	{
		ctEntry = twin_entry;
		twin_entry = CT_TWIN(ctEntry);
	}

	// Send indication message
	pmsg = msg_alloc();
	if (!pmsg)
		goto err;

	message = (struct _tCtCommandIPv6 *)pmsg->data;

	// Prepare indication message
	message->action = (ctEntry->status & CONNTRACK_TCP_FIN) ? ACTION_TCP_FIN : ACTION_REMOVED;
	memcpy(message->Saddr, ctEntry->Saddr_v6, IPV6_ADDRESS_LENGTH);
	memcpy(message->Daddr, ctEntry->Daddr_v6, IPV6_ADDRESS_LENGTH);
	message->Sport= ctEntry->Sport;
	message->Dport= ctEntry->Dport;
	memcpy(message->SaddrReply, twin_entry->Saddr_v6, IPV6_ADDRESS_LENGTH);
	memcpy(message->DaddrReply, twin_entry->Daddr_v6, IPV6_ADDRESS_LENGTH);
	message->SportReply= twin_entry->Sport;
	message->DportReply= twin_entry->Dport;
	message->protocol= GET_PROTOCOL(ctEntry);
	message->qosconnmark = 0;

	pmsg->code = CMD_IPV6_CONNTRACK_CHANGE;
	pmsg->length = sizeof(*message);

	if (msg_send(pmsg) < 0)
		goto err;

	//Remove conntrack from list
	ct_remove(ctEntry);

	return 0;

err:
	/* Can't send indication, try later from timeout routine */
	return 1;
}




/**
 * IPv6_handle_RESET
 *
 *	-- called from IPv4 reset handler
 *
 *
 */
int IPv6_handle_RESET(void)
{
	int rc = NO_ERR;

	/* free IPv4 sockets entries */
	SOCKET6_free_entries();

	return rc;
}


PCtEntry IPv6_find_ctentry(U32 *saddr, U32 *daddr, U16 sport, U16 dport, U8 proto)
{
	U32 hash;
	PCtEntry pEntry;
	struct slist_entry *entry;

	hash = HASH_CT6(saddr, daddr, sport, dport, proto);
	slist_for_each(pEntry, entry, &ct_cache[hash], list)
	{
		if (IS_IPV6_FLOW(pEntry) && !IPV6_CMP(pEntry->Saddr_v6, saddr) && !IPV6_CMP(pEntry->Daddr_v6, daddr) && pEntry->Sport == sport && pEntry->Dport == dport && pEntry->proto == proto)
			return pEntry;
	}

	return NULL;
}


static int IPv6_HandleIP_Get_Timeout(U16 * p, U16 Length)
{
	int rc = NO_ERR;
	PTimeoutCommand TimeoutCmd;
	CtCommandIPv6 	Ctcmd;
	PCtEntry	pEntry;
	// Check length
	if (Length != sizeof(CtCommandIPv6))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&Ctcmd, (U8*)p,  Length);
	if ((pEntry = IPv6_find_ctentry(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol)) != NULL)
	{
		PCT_PAIR ppair;
		cdx_timer_t timeout_value;

		memset(p, 0, 256);
		TimeoutCmd = (PTimeoutCommand)(p+1); // first word is for rc
		TimeoutCmd->protocol = GET_PROTOCOL(pEntry);
		if (!(pEntry->status & CONNTRACK_ORIG))
			pEntry = CT_TWIN(pEntry);
		ppair = container_of(pEntry, CT_PAIR, orig);
		timeout_value = ct_get_time_remaining(ppair);
		TimeoutCmd->timeout_value1 = (U32)timeout_value / CT_TICKS_PER_SECOND;
	}
	else
	{
		return CMD_ERR;
	}
	return rc;
}





/**
 * IPv6_handle_CONNTRACK
 *
 *
 */
int IPv6_handle_CONNTRACK(U16 *p, U16 Length)
{
	PCtEntry pEntry_orig = NULL, pEntry_rep = NULL;
	PCT_PAIR ppair;
	CtExCommandIPv6 Ctcmd;
	int i, reset_action = 0;

	/* Check length */
	if ((Length != sizeof(CtCommandIPv6)) && (Length != sizeof(CtExCommandIPv6)))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy((U8*)&Ctcmd, (U8*)p,  Length);

	switch(Ctcmd.action)
	{
		case ACTION_DEREGISTER: 

			pEntry_orig = IPv6_find_ctentry(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol);
			pEntry_rep = IPv6_find_ctentry(Ctcmd.SaddrReply, Ctcmd.DaddrReply, Ctcmd.SportReply, Ctcmd.DportReply, Ctcmd.protocol);
			if (pEntry_orig == NULL || !IS_IPV6(pEntry_orig) || pEntry_rep == NULL || !IS_IPV6(pEntry_rep) ||
					CT_TWIN(pEntry_orig) != pEntry_rep || CT_TWIN(pEntry_rep) != pEntry_orig)
				return ERR_CT_ENTRY_NOT_FOUND;

			ct_remove(pEntry_orig);
			break;

		case ACTION_REGISTER: //Add entry

			pEntry_orig = IPv6_find_ctentry(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol);
			pEntry_rep = IPv6_find_ctentry(Ctcmd.SaddrReply, Ctcmd.DaddrReply, Ctcmd.SportReply, Ctcmd.DportReply, Ctcmd.protocol);
			if (pEntry_orig != NULL || pEntry_rep != NULL)
				return ERR_CT_ENTRY_ALREADY_REGISTERED; //trying to add exactly the same conntrack

#ifdef DPA_IPSEC_OFFLOAD 
			if (Ctcmd.format & CT_SECURE) {
				if (Ctcmd.SA_nr > SA_MAX_OP)
					return ERR_CT_ENTRY_TOO_MANY_SA_OP;
				for (i=0;i<Ctcmd.SA_nr;i++) {
					if (M_ipsec_sa_cache_lookup_by_h(Ctcmd.SA_handle[i]) == NULL)
						return ERR_CT_ENTRY_INVALID_SA; 
				}	

				if (Ctcmd.SAReply_nr > SA_MAX_OP)
					return ERR_CT_ENTRY_TOO_MANY_SA_OP;
				for (i=0;i<Ctcmd.SAReply_nr;i++) {
					if (M_ipsec_sa_cache_lookup_by_h(Ctcmd.SAReply_handle[i]) == NULL)
						return ERR_CT_ENTRY_INVALID_SA; 
				}	
			}
#endif

			/* allocate storage for ct entries and timer */
			if ((ppair = ct_alloc()) == NULL)
			{
				return ERR_NOT_ENOUGH_MEMORY;
			}
			pEntry_orig = &ppair->orig;
			pEntry_rep = &ppair->repl;

			/* originator -----------------------------*/					
			pEntry_orig->fftype = FFTYPE_IPV6;
			pEntry_orig->hash = HASH_CT6(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol);
			memcpy(pEntry_orig->Daddr_v6, Ctcmd.Daddr, IPV6_ADDRESS_LENGTH);
			memcpy(pEntry_orig->Saddr_v6, Ctcmd.Saddr, IPV6_ADDRESS_LENGTH);
			pEntry_orig->Sport = Ctcmd.Sport;
			pEntry_orig->Dport = Ctcmd.Dport;
			pEntry_orig->qosmark.markval = get_ctentry_qosmark_from_qosconnmark(Ctcmd.qosconnmark, CONN_ORIG);
			pEntry_orig->status = CONNTRACK_ORIG;

			if (Ctcmd.flags & CTCMD_FLAGS_ORIG_DISABLED)
				pEntry_orig->status |= CONNTRACK_FF_DISABLED;

			pEntry_orig->route_id = Ctcmd.route_id;
			IP_Check_Route(pEntry_orig);

#ifdef DPA_IPSEC_OFFLOAD 
			if (Ctcmd.format & CT_SECURE) {
				pEntry_orig->status |= CONNTRACK_SEC;
				for (i=0;i < SA_MAX_OP;i++) 
					pEntry_orig->hSAEntry[i] = 
						(i<Ctcmd.SA_nr) ? Ctcmd.SA_handle[i] : 0;
				if (pEntry_orig->hSAEntry[0])
					pEntry_orig->status &= ~CONNTRACK_SEC_noSA;
				else
					pEntry_orig->status |= CONNTRACK_SEC_noSA;
			}
#endif


			/* Replier ----------------------------------------*/ 	
			pEntry_rep->fftype = FFTYPE_IPV6;
			pEntry_rep->hash = HASH_CT6(Ctcmd.SaddrReply, Ctcmd.DaddrReply, Ctcmd.SportReply, Ctcmd.DportReply, Ctcmd.protocol);
			memcpy(pEntry_rep->Daddr_v6, Ctcmd.DaddrReply, IPV6_ADDRESS_LENGTH);
			memcpy(pEntry_rep->Saddr_v6, Ctcmd.SaddrReply, IPV6_ADDRESS_LENGTH);
			pEntry_rep->Sport = Ctcmd.SportReply;
			pEntry_rep->Dport = Ctcmd.DportReply;
			pEntry_rep->qosmark.markval = get_ctentry_qosmark_from_qosconnmark(Ctcmd.qosconnmark, CONN_REPLIER);
			pEntry_rep->status = 0;
			SET_PROTOCOL(pEntry_orig, pEntry_rep, Ctcmd.protocol);

			if (Ctcmd.flags & CTCMD_FLAGS_REP_DISABLED)
				pEntry_rep->status |= CONNTRACK_FF_DISABLED;

			pEntry_rep->route_id = Ctcmd.route_id_reply;
			IP_Check_Route(pEntry_rep);

#ifdef DPA_IPSEC_OFFLOAD 
			if (Ctcmd.format & CT_SECURE) {
				pEntry_rep->status |= CONNTRACK_SEC;
				for (i=0; i < SA_MAX_OP;i++) 
					pEntry_rep->hSAEntry[i]= 
						(i<Ctcmd.SAReply_nr) ? Ctcmd.SAReply_handle[i] : 0;
				if (pEntry_rep->hSAEntry[0])
					pEntry_rep->status &= ~CONNTRACK_SEC_noSA;
				else
					pEntry_rep->status |= CONNTRACK_SEC_noSA;
			}
#endif

			if ((Ctcmd.format & CT_ORIG_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_ORIG_DISABLED))
			{
				pEntry_orig->tnl_route = L2_route_get(Ctcmd.tunnel_route_id);
				if (IS_NULL_ROUTE(pEntry_orig->tnl_route))
				{
					ct_free((PCtEntry)pEntry_orig);
					return ERR_RT_LINK_NOT_POSSIBLE;
				}
			}

			if ((Ctcmd.format & CT_REPL_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_REP_DISABLED))
			{
				pEntry_rep->tnl_route = L2_route_get(Ctcmd.tunnel_route_id_reply);
				if (IS_NULL_ROUTE(pEntry_rep->tnl_route))
				{
					L2_route_put(pEntry_orig->tnl_route);
					ct_free((PCtEntry)pEntry_orig);
					return ERR_RT_LINK_NOT_POSSIBLE;
				}
			}

			// Check for NAT processing
			if (IPV6_CMP(Ctcmd.Saddr, Ctcmd.DaddrReply) || (Ctcmd.Sport != Ctcmd.DportReply))
			{
				pEntry_orig->status |= CONNTRACK_SNAT;
				pEntry_rep->status |= CONNTRACK_DNAT;
				if (Ctcmd.Sport != Ctcmd.DportReply)
				{
					pEntry_orig->status |= CONNTRACK_IPv6_PORTNAT;
					pEntry_rep->status |= CONNTRACK_IPv6_PORTNAT;
				}
			}
			if (IPV6_CMP(Ctcmd.Daddr, Ctcmd.SaddrReply) || (Ctcmd.Dport != Ctcmd.SportReply))
			{
				pEntry_orig->status |= CONNTRACK_DNAT;
				pEntry_rep->status |= CONNTRACK_SNAT;
				if (Ctcmd.Dport != Ctcmd.SportReply)
				{
					pEntry_orig->status |= CONNTRACK_IPv6_PORTNAT;
					pEntry_rep->status |= CONNTRACK_IPv6_PORTNAT;
				}
			}
			if (pEntry_orig->status & (CONNTRACK_SNAT | CONNTRACK_DNAT))
			{
				/* Check sum correction pre-computation RFC1624 */
				U32 sum = 0;
				for (i = 0; i < 4; i++)
				{
					sum += (Ctcmd.Daddr[i] & 0xffff) +
						(Ctcmd.Daddr[i] >> 16) +
						((Ctcmd.SaddrReply[i] & 0xffff) ^ 0xffff) +
						((Ctcmd.SaddrReply[i] >> 16) ^ 0xffff);
					sum += (Ctcmd.Saddr[i] & 0xffff) +
						(Ctcmd.Saddr[i] >> 16) +
						((Ctcmd.DaddrReply[i] & 0xffff) ^ 0xffff) +
						((Ctcmd.DaddrReply[i] >> 16) ^ 0xffff);
				}
				sum += Ctcmd.Dport + (Ctcmd.SportReply ^ 0xffff);
				sum += Ctcmd.Sport + (Ctcmd.DportReply ^ 0xffff);
				while (sum >> 16)
					sum = (sum & 0xffff) + (sum >> 16);
				if (sum == 0xffff)
					sum = 0;
				pEntry_orig->tcp_udp_chksm_corr = sum;
				pEntry_rep->tcp_udp_chksm_corr = sum == 0 ? 0 : sum ^ 0xffff;
			}

			/* Everything went Ok. We can safely put querier and replier entries in hash tables */

			return ct_add(pEntry_orig, ct_aging_handler);

		case ACTION_UPDATE: 

			pEntry_orig = IPv6_find_ctentry(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol);
			pEntry_rep = IPv6_find_ctentry(Ctcmd.SaddrReply, Ctcmd.DaddrReply, Ctcmd.SportReply, Ctcmd.DportReply, Ctcmd.protocol);
			// Check for errors before changing anything
			if (pEntry_orig == NULL || !IS_IPV6(pEntry_orig) || pEntry_rep == NULL || !IS_IPV6(pEntry_rep) ||
					CT_TWIN(pEntry_orig) != pEntry_rep || CT_TWIN(pEntry_rep) != pEntry_orig)
				return ERR_CT_ENTRY_NOT_FOUND;

#ifdef DPA_IPSEC_OFFLOAD 
			if ((Ctcmd.format & CT_ORIG_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_ORIG_DISABLED))
			{
				PRouteEntry tnl_route;
				tnl_route = L2_route_get(Ctcmd.tunnel_route_id);  // do "dry run"
				if (IS_NULL_ROUTE(tnl_route))
					return ERR_RT_LINK_NOT_POSSIBLE;
				L2_route_put(tnl_route);			  // undo "dry run"
			}
#endif
			if ((Ctcmd.format & CT_REPL_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_REP_DISABLED))
			{
				PRouteEntry tnl_route;
				tnl_route = L2_route_get(Ctcmd.tunnel_route_id_reply);  // do "dry run"
				if (IS_NULL_ROUTE(tnl_route))
					return ERR_RT_LINK_NOT_POSSIBLE;
				L2_route_put(tnl_route);			  // undo "dry run"
			}
#ifdef DPA_IPSEC_OFFLOAD 
			if (Ctcmd.format & CT_SECURE) {
				if (Ctcmd.SA_nr > SA_MAX_OP)
					return ERR_CT_ENTRY_TOO_MANY_SA_OP;

				for (i = 0; i < Ctcmd.SA_nr; i++) {
					if ( Ctcmd.SA_handle[i] && (pEntry_orig->hSAEntry[i] != Ctcmd.SA_handle[i]))
						if (M_ipsec_sa_cache_lookup_by_h(Ctcmd.SA_handle[i]) == NULL)
							return ERR_CT_ENTRY_INVALID_SA; 
				}

				if (Ctcmd.SAReply_nr > SA_MAX_OP)
					return ERR_CT_ENTRY_TOO_MANY_SA_OP;

				for (i = 0; i < Ctcmd.SAReply_nr; i++) {
					if (Ctcmd.SAReply_handle[i] && (pEntry_rep->hSAEntry[i] != Ctcmd.SAReply_handle[i]))
						if (M_ipsec_sa_cache_lookup_by_h(Ctcmd.SAReply_handle[i]) == NULL)
							return ERR_CT_ENTRY_INVALID_SA;
				}
			}
#endif
			pEntry_orig->qosmark.markval = get_ctentry_qosmark_from_qosconnmark(Ctcmd.qosconnmark, CONN_ORIG);

			if (Ctcmd.flags & CTCMD_FLAGS_ORIG_DISABLED) {
				pEntry_orig->status |= CONNTRACK_FF_DISABLED;
				IP_delete_CT_route((PCtEntry)pEntry_orig);
			} else
				pEntry_orig->status &= ~CONNTRACK_FF_DISABLED;

#ifdef DPA_IPSEC_OFFLOAD 
			if (Ctcmd.format & CT_SECURE) {
				pEntry_orig->status |= CONNTRACK_SEC;

				for (i = 0;i < SA_MAX_OP; i++)
					pEntry_orig->hSAEntry[i] = 
						(i<Ctcmd.SA_nr) ? Ctcmd.SA_handle[i] : 0;

				if (pEntry_orig->hSAEntry[0])
					pEntry_orig->status &= ~ CONNTRACK_SEC_noSA;
				else 
					pEntry_orig->status |= CONNTRACK_SEC_noSA;
			} else
				pEntry_orig->status &= ~(CONNTRACK_SEC | CONNTRACK_SEC_noSA);
#endif
			pEntry_rep->qosmark.markval = get_ctentry_qosmark_from_qosconnmark(Ctcmd.qosconnmark, CONN_REPLIER);
			if (Ctcmd.flags & CTCMD_FLAGS_REP_DISABLED) {
				pEntry_rep->status |= CONNTRACK_FF_DISABLED;
				IP_delete_CT_route((PCtEntry)pEntry_rep);
			} else
				pEntry_rep->status &= ~CONNTRACK_FF_DISABLED;

#ifdef DPA_IPSEC_OFFLOAD 
			if (Ctcmd.format & CT_SECURE) {
				pEntry_rep->status |= CONNTRACK_SEC;

				for (i = 0; i < SA_MAX_OP; i++) 
					pEntry_rep->hSAEntry[i]= 
						(i<Ctcmd.SAReply_nr) ? (Ctcmd.SAReply_handle[i]) : 0;

				if ( pEntry_rep->hSAEntry[0])
					pEntry_rep->status &= ~CONNTRACK_SEC_noSA;
				else 
					pEntry_rep->status |= CONNTRACK_SEC_noSA;
			} else
				pEntry_rep->status &= ~(CONNTRACK_SEC | CONNTRACK_SEC_noSA);
#endif


			/* Update route entries if needed */
			if (IS_NULL_ROUTE(pEntry_orig->pRtEntry))
			{
				pEntry_orig->route_id = Ctcmd.route_id;
			}
			else if (pEntry_orig->route_id != Ctcmd.route_id)
			{
				IP_delete_CT_route((PCtEntry)pEntry_orig);
				pEntry_orig->route_id = Ctcmd.route_id;
			}
			IP_Check_Route(pEntry_orig);

			if (IS_NULL_ROUTE(pEntry_rep->pRtEntry))
			{
				pEntry_rep->route_id = Ctcmd.route_id_reply;
			}
			else if (pEntry_rep->route_id != Ctcmd.route_id_reply)
			{
				IP_delete_CT_route((PCtEntry)pEntry_rep);
				pEntry_rep->route_id = Ctcmd.route_id_reply;
			}
			IP_Check_Route(pEntry_rep);

			if (pEntry_orig->tnl_route)
			{
				L2_route_put(pEntry_orig->tnl_route);
				pEntry_orig->tnl_route = NULL;
			}
			if ((Ctcmd.format & CT_ORIG_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_ORIG_DISABLED))
			{
				pEntry_orig->tnl_route = L2_route_get(Ctcmd.tunnel_route_id);
			}

			if (pEntry_rep->tnl_route)
			{
				L2_route_put(pEntry_rep->tnl_route);
				pEntry_rep->tnl_route = NULL;
			}
			if ((Ctcmd.format & CT_REPL_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_REP_DISABLED))
			{
				pEntry_rep->tnl_route = L2_route_get(Ctcmd.tunnel_route_id_reply);
			}

			ct_update(pEntry_orig);
			return NO_ERR;

		case ACTION_QUERY:
			reset_action = 1;
			/* fall through */

		case ACTION_QUERY_CONT:
			{
				PCtExCommandIPv6 pCt = (CtExCommandIPv6*)p;
				int rc;

				rc = IPv6_Get_Next_Hash_CTEntry(pCt, reset_action);

				return rc;
			}

		default :
			return ERR_UNKNOWN_COMMAND;

	}

	return NO_ERR;

}


/**
 * M_ipv6_cmdproc
 *
 *
 *
 */
U16 M_ipv6_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc;
	U16 querySize = 0;
	U16 action;

	switch (cmd_code)
	{
		case CMD_IPV6_CONNTRACK:			
			action = *pcmd;
			rc = IPv6_handle_CONNTRACK(pcmd, cmd_len);
			if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
				querySize = sizeof(CtExCommandIPv6);
			break;

		case CMD_IPV6_RESET:			
			//now handled as part of IPv4 reset -- just return success
			rc = NO_ERR;
			break;

		case CMD_IPV6_GET_TIMEOUT:
			rc = IPv6_HandleIP_Get_Timeout(pcmd, cmd_len);
			if (rc == NO_ERR)
				querySize = sizeof(TimeoutCommand);
			break;

		case CMD_IPV6_SOCK_OPEN:
			rc = SOCKET6_HandleIP_Socket_Open(pcmd, cmd_len);
			break;

		case CMD_IPV6_SOCK_CLOSE:
			rc = SOCKET6_HandleIP_Socket_Close(pcmd, cmd_len);
			break;

		case CMD_IPV6_SOCK_UPDATE:
			rc = SOCKET6_HandleIP_Socket_Update(pcmd, cmd_len);
			break;

#ifdef CDX_TODO_IPV6FRAG
		case CMD_IPV6_FRAGTIMEOUT:
			rc = IPv6_HandleIP_Set_FragTimeout(pcmd, cmd_len);
			break;
#endif

		default:
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;
	return 2 + querySize;
}


int ipv6_init(void)
{
	set_cmd_handler(EVENT_IPV6, M_ipv6_cmdproc);
	return 0;
}

void ipv6_exit(void)
{
}

/* This function returns total ipv6 conntrack entries 
	 configured in a given hash index */
static int IPv6_Get_Hash_CtEntries(int ct6_hash_index)
{
	int tot_ipv6_ct_entries = 0;
	PCtEntry pCtEntry;
	struct slist_entry *entry;

	slist_for_each(pCtEntry, entry, &ct_cache[ct6_hash_index], list)
	{
		if (IS_IPV6(pCtEntry) && (pCtEntry->status & CONNTRACK_ORIG) == CONNTRACK_ORIG)
			tot_ipv6_ct_entries++;
	}

	return tot_ipv6_ct_entries;

}

/* This function fills the snapshot of ipv6 CT entries in a given hash index */
static int IPv6_CT_Get_Hash_Snapshot(int ct6_hash_index,int v6_ct_total_entries, PCtExCommandIPv6 pSnapshot)
{

	int tot_ipv6_ct_entries=0;
	PCtEntry pCtEntry;
	PCtEntry twin_entry;
	struct slist_entry *entry;

	slist_for_each(pCtEntry, entry, &ct_cache[ct6_hash_index], list)
	{
		if (IS_IPV6(pCtEntry) && (pCtEntry->status & CONNTRACK_ORIG) == CONNTRACK_ORIG)
		{
			twin_entry = CT_TWIN(pCtEntry);

			memcpy(pSnapshot->Daddr, pCtEntry->Daddr_v6, IPV6_ADDRESS_LENGTH);
			memcpy(pSnapshot->Saddr, pCtEntry->Saddr_v6, IPV6_ADDRESS_LENGTH);
			pSnapshot->Sport = 	pCtEntry->Sport;
			pSnapshot->Dport = 	pCtEntry->Dport;

			memcpy(pSnapshot->DaddrReply, twin_entry->Daddr_v6, IPV6_ADDRESS_LENGTH);
			memcpy(pSnapshot->SaddrReply, twin_entry->Saddr_v6, IPV6_ADDRESS_LENGTH);
			pSnapshot->SportReply = 	twin_entry->Sport;
			pSnapshot->DportReply = 	twin_entry->Dport;
			pSnapshot->protocol   =  GET_PROTOCOL(pCtEntry); 
			pSnapshot->qosconnmark     = IP_get_qosconnmark((PCtEntry)pCtEntry, (PCtEntry)twin_entry);
			pSnapshot->SA_nr      =	0;
			pSnapshot->SAReply_nr	= 	0;
			pSnapshot->format = 0;

#ifdef DPA_IPSEC_OFFLOAD 
			if ((pCtEntry->status & CONNTRACK_SEC) == CONNTRACK_SEC)
			{
				int i;
				pSnapshot->format |= CT_SECURE;
				for (i= 0; i < SA_MAX_OP; i++)
				{
					if (pCtEntry->hSAEntry[i])
					{
						pSnapshot->SA_nr++;
						pSnapshot->SA_handle[i] = pCtEntry->hSAEntry[i];
					}
				}

				for (i= 0; i < SA_MAX_OP; i++)
				{
					if (twin_entry->hSAEntry[i])
					{
						pSnapshot->SAReply_nr++;
						pSnapshot->SAReply_handle[i] = twin_entry->hSAEntry[i];
					}

				}

			}
#endif

			pSnapshot++;
			tot_ipv6_ct_entries++;

			if (--v6_ct_total_entries <= 0)
				break;
		}
	}

	return tot_ipv6_ct_entries;

}


/* This function creates the snapshot memory and returns the 
	 next ipv6 CT entry from the snapshop of the ipv6 conntrack entries of a
	 single hash to the caller  */

int IPv6_Get_Next_Hash_CTEntry(PCtExCommandIPv6 pV6CtCmd, int reset_action)
{
	int ipv6_ct_hash_entries;
	PCtExCommandIPv6 pV6Ct;
	static PCtExCommandIPv6 pV6CtSnapshot = NULL;
	static int v6_ct_hash_index = 0, v6_ct_snapshot_entries =0, v6_ct_snapshot_index=0, v6_ct_snapshot_buf_entries = 0;

	if(reset_action)
	{
		v6_ct_hash_index = 0;
		v6_ct_snapshot_entries =0;
		v6_ct_snapshot_index=0;
		if(pV6CtSnapshot)
		{
			Heap_Free(pV6CtSnapshot);
			pV6CtSnapshot = NULL;	
		}
		v6_ct_snapshot_buf_entries = 0;
	}

	if (v6_ct_snapshot_index == 0)
	{
		while( v6_ct_hash_index < NUM_CT_ENTRIES)
		{

			ipv6_ct_hash_entries = IPv6_Get_Hash_CtEntries(v6_ct_hash_index);
			if(ipv6_ct_hash_entries == 0)
			{
				v6_ct_hash_index++;
				continue;
			}

			if(ipv6_ct_hash_entries > v6_ct_snapshot_buf_entries)
			{

				if(pV6CtSnapshot)
					Heap_Free(pV6CtSnapshot);
				pV6CtSnapshot = Heap_Alloc(ipv6_ct_hash_entries * sizeof(CtExCommandIPv6));

				if (!pV6CtSnapshot)
				{
					v6_ct_hash_index = 0;
					v6_ct_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				v6_ct_snapshot_buf_entries = ipv6_ct_hash_entries;

			}
			v6_ct_snapshot_entries = IPv6_CT_Get_Hash_Snapshot(v6_ct_hash_index , ipv6_ct_hash_entries,pV6CtSnapshot);


			break;
		}

		if (v6_ct_hash_index >= NUM_CT_ENTRIES)
		{
			v6_ct_hash_index = 0;
			if(pV6CtSnapshot)
			{
				Heap_Free(pV6CtSnapshot);
				pV6CtSnapshot = NULL;	
			}
			v6_ct_snapshot_buf_entries = 0;
			return ERR_CT_ENTRY_NOT_FOUND;
		}

	}

	pV6Ct = &pV6CtSnapshot[v6_ct_snapshot_index++];
	memcpy(pV6CtCmd, pV6Ct, sizeof(CtExCommandIPv6));
	if (v6_ct_snapshot_index == v6_ct_snapshot_entries)
	{
		v6_ct_snapshot_index = 0;
		v6_ct_hash_index ++;
	}


	return NO_ERR;	

}
