/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "cdx.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_pppoe.h"
#include "control_socket.h"
#include "control_ipsec.h"
#include "fm_ehash.h"

#define hw_ct_set_active(ct, val)

int IPv4_Get_Next_Hash_CTEntry(PCtExCommand pCtCmd, int reset_action);
int IPV4_Get_Next_Hash_RtEntry(PRtCommand pRtCmd, int reset_action);

atomic_t num_active_connections;

static inline int is_CT_COMPLETE(PCtEntry pEntry)
{
	if((!pEntry) || IS_NULL_ROUTE(pEntry->pRtEntry) || (pEntry->status & (CONNTRACK_SEC_noSA | CONNTRACK_FF_DISABLED)))
		return 0;
	return 1;
}

/** Allocates a new software conntrack.
 * The originator and replier conntracks are allocated as a single object
 *
 * @return 		pointer to the new conntrack, NULL of error
 *
 */
PCT_PAIR ct_alloc(void)
{
	PCT_PAIR ppair;
	PCtEntry pEntry_orig;
	PCtEntry pEntry_rep;

	/* Allocate local entry */
	ppair = kzalloc(sizeof(CT_PAIR), GFP_KERNEL);
	if (!ppair)
		return NULL;
	memset(ppair, 0, sizeof(CT_PAIR));
	pEntry_orig = &ppair->orig;
	pEntry_rep = &ppair->repl;

	pEntry_orig->twin = pEntry_rep;
	pEntry_rep->twin = pEntry_orig;

	pEntry_orig->last_ct_timer = ct_timer;
	pEntry_rep->last_ct_timer = ct_timer;

	return ppair;
}


/** Frees a software conntrack.
 * The function fress both originator and replier conntracks
 *
 * @param pEntry_orig	pointer to the originator conntrack
 */
void ct_free(PCtEntry pEntry_orig)
{
	PCT_PAIR ppair = container_of(pEntry_orig, CT_PAIR, orig);
	kfree(ppair);
}

/**
 * ct_timer_update()
 *
 *
 */
void ct_timer_update(PCT_PAIR ppair)
{
	PCtEntry pEntry_orig = &ppair->orig;
	PCtEntry pEntry_repl = &ppair->repl;
	TIMER_ENTRY *timer = &ppair->timer;
	cdx_timer_t oldtimer = timer->timerdata;
	timer->timerdata = GET_TIMEOUT_VALUE(pEntry_orig, IS_BIDIR(pEntry_orig, pEntry_repl));
	// Only update timer if first time or new period is less than old
	if (oldtimer == 0 || timer->timerdata < oldtimer)
	{
		cdx_timer_t newtimeout;
		if (oldtimer == 0)
			newtimeout = ct_timer + timer->timerdata;
		else
			newtimeout = timer->timeout - oldtimer + timer->timerdata;
		//DPRINT_ERROR("oldtimer=%u, timer->timerdata=%u, ct_timer=%u, newtimeout=%u\n", oldtimer, timer->timerdata, ct_timer, newtimeout);
		cdx_timer_del(timer);
		cdx_timer_add(timer, TIME_BEFORE(newtimeout, ct_timer) ? 1 : newtimeout - ct_timer);
	}
}

/** Adds a software conntrack (both directions)
 *
 * @param pEntry_orig	pointer to the originator software conntrack
 * @param handler	pointer to the aging timer handler
 *
 * @return		NO_ERR in case of success, ERR_xxx in case of error
 */
int ct_add(PCtEntry pEntry_orig, TIMER_HANDLER handler)
{
	int rc;
	PCT_PAIR ppair = container_of(pEntry_orig, CT_PAIR, orig);
	PCtEntry pEntry_rep = &ppair->repl;

	//insert orig entry
	if (is_CT_COMPLETE(pEntry_orig))
	{
		rc = insert_entry_in_classif_table(pEntry_orig);
		if (rc)
		{
			DPRINT_ERROR("failed to insert orig entry\n");
			goto err0;
		}
		pEntry_orig->status |= CONNTRACK_HWSET;
	}

	//insert reply entry
	if (is_CT_COMPLETE(pEntry_rep))
	{
		rc = insert_entry_in_classif_table(pEntry_rep);
		if (rc)
		{
			DPRINT_ERROR("failed to insert rep entry\n");
			goto err1;
		}
		pEntry_rep->status |= CONNTRACK_HWSET;
	}
#ifdef CDX_TODO_RTPRELAY
	if(IS_IPV4(pEntry_orig))
	{
		/* check if rtp stats entry is created for this conntrack, if found link the two object and mark the conntrack 's status field for RTP stats */
		rtpqos_ipv4_link_stats_entry_by_tuple(pEntry_orig, pEntry_orig->Saddr_v4, pEntry_orig->Daddr_v4, pEntry_orig->Sport, pEntry_orig->Dport);
		rtpqos_ipv4_link_stats_entry_by_tuple(pEntry_rep, pEntry_rep->Saddr_v4, pEntry_rep->Daddr_v4, pEntry_rep->Sport, pEntry_rep->Dport);
	}
	else
	{
		/* check if rtp stats entry is created for this conntrack, if found link the two object and mark the conntrack 's status field for RTP stats */
		rtpqos_ipv6_link_stats_entry_by_tuple(pEntry_orig, pEntry_orig->Saddr_v6, pEntry_orig->Daddr_v6, pEntry_orig->Sport, pEntry_orig->Dport);
		rtpqos_ipv6_link_stats_entry_by_tuple(pEntry_rep, pEntry_rep->Saddr_v6, pEntry_rep->Daddr_v6, pEntry_rep->Sport, pEntry_rep->Dport);
	}
#endif

	/* Add to local hash */
	slist_add(&ct_cache[pEntry_orig->hash], &pEntry_orig->list);
	slist_add(&ct_cache[pEntry_rep->hash], &pEntry_rep->list);

	atomic_inc(&num_active_connections);

	cdx_timer_init(&ppair->timer, handler);
	ct_timer_update(ppair);
	return NO_ERR;

err1:
	if (pEntry_orig->status & CONNTRACK_HWSET)
		delete_entry_from_classif_table(pEntry_orig);

err0:
	IP_delete_CT_route(pEntry_orig);
	IP_delete_CT_route(pEntry_rep);
	L2_route_put(pEntry_orig->tnl_route);
	L2_route_put(pEntry_rep->tnl_route);
	ct_free(pEntry_orig);

	return rc;
}


/** Removes a software conntrack (both directions)
 *
 * @param pEntry_orig	pointer to the originator software conntrack
 *
 * @return		NO_ERR in case of success, ERR_xxx in case of error
 */
void ct_remove(PCtEntry pEntry_orig)
{
	PCT_PAIR ppair = container_of(pEntry_orig, CT_PAIR, orig);
	PCtEntry pEntry_rep = &ppair->repl;

	cdx_timer_del(&ppair->timer);

	if ((pEntry_orig->status & CONNTRACK_HWSET) && delete_entry_from_classif_table(pEntry_orig))
		DPRINT_ERROR("failed to delete orig entry\n");
	if ((pEntry_rep->status & CONNTRACK_HWSET) && delete_entry_from_classif_table(pEntry_rep))
		DPRINT_ERROR("failed to delete reply entry\n");

	if (pEntry_orig->status & CONNTRACK_DEL_FAILED)
	{
		/* free table entry */
		ExternalHashTableEntryFree(pEntry_orig->ct->handle);
		pEntry_orig->ct->handle =  NULL;
		kfree(pEntry_orig->ct);
		pEntry_orig->ct = NULL;
	}
	if (pEntry_rep->status & CONNTRACK_DEL_FAILED)
	{
		/* free table entry */
		ExternalHashTableEntryFree(pEntry_rep->ct->handle);
		pEntry_rep->ct->handle =  NULL;
		kfree(pEntry_rep->ct);
		pEntry_rep->ct = NULL;
	}

	IP_delete_CT_route(pEntry_orig);
	IP_delete_CT_route(pEntry_rep);
	L2_route_put(pEntry_orig->tnl_route);
	L2_route_put(pEntry_rep->tnl_route);

	slist_remove(&ct_cache[pEntry_orig->hash], &pEntry_orig->list);
	slist_remove(&ct_cache[pEntry_rep->hash], &pEntry_rep->list);

	/* Free local entry */
	ct_free(pEntry_orig);

	atomic_dec(&num_active_connections);
}


/** Updates a software conntrack
 * Updates an hardware conntrack based on an updated software conntrack.
 * We assume the hardware conntrack exists already, and update it in place.
 *
 * @param pEntry		pointer to the software conntrack
 */
void ct_update_one(PCtEntry pEntry)
{
	// TODO: for now, only supporting adding new entry -- need to support changes
	struct hw_ct *ct = pEntry->ct;
	struct en_ehash_enqueue_param *param;
	struct en_exthash_tbl_entry *tbl_entry;
	uint16_t orig_mtu = 0, new_mtu = 0;
	int rc, i;
	PSAEntry sa;

	//DPA_INFO("%s(%d) \n",__FUNCTION__,__LINE__);
	//insert entry
	if (!(pEntry->status & CONNTRACK_HWSET)){
		if(is_CT_COMPLETE(pEntry))
		{
			rc = insert_entry_in_classif_table(pEntry);
			if (rc)
				DPRINT_ERROR("failed to insert entry\n");
			else
				pEntry->status |= CONNTRACK_HWSET;
			return;
		}
	}
	else if (!is_CT_COMPLETE(pEntry))
	{
		/* If conntrack route is disabled(CONNTRACK_FF_DISABLED) or sec disabled(CONNTRACK_SEC_noSA),
			 delete the entry from classification table till an update is received.*/
		rc = delete_entry_from_classif_table(pEntry);
		if(rc)
		{
			pEntry->status |= CONNTRACK_DEL_FAILED;
			pEntry->status &= ~CONNTRACK_HWSET;
			DPRINT_ERROR("failed to delete entry\n");
		}
		else
			pEntry->status &= ~CONNTRACK_HWSET;

		return;
	}
	if (ct && ct->handle)
	{
		tbl_entry = (struct en_exthash_tbl_entry *) ct->handle;
		param = (struct en_ehash_enqueue_param *)tbl_entry->enqueue_params;
		if (param)
		{
			/* In case of SECURE connection and rekey,
				 if there is a change of frame queue ID, 
				 update it in enqueue params
			 */
			if (pEntry->status & CONNTRACK_SEC)
			{
				for (i=0;i < SA_MAX_OP;i++)
					if(((sa = M_ipsec_sa_cache_lookup_by_h(pEntry->hSAEntry[i])) != NULL) &&
							(sa->direction == CDX_DPA_IPSEC_OUTBOUND ))
					{
#ifdef IPV4_CONTROL_DEBUG
						printk("%s(%d) enque fqid %x, SA tosec fqid %x\n",
								__FUNCTION__,__LINE__,be32_to_cpu(param->fqid),
								sa->pSec_sa_context->to_sec_fqid);
#endif
						param->fqid = cpu_to_be32(sa->pSec_sa_context->to_sec_fqid);
						break;
					}
			}
			/* update MTU if required */
			orig_mtu = cpu_to_be16(param->mtu);
			if (!IS_NULL_ROUTE(pEntry->pRtEntry))
				new_mtu = pEntry->pRtEntry->mtu;
			if ((pEntry->status & CONNTRACK_SEC) && !IS_NULL_ROUTE(pEntry->tnl_route))
				new_mtu = pEntry->tnl_route->mtu;
			if (orig_mtu != new_mtu)
			{
				param->mtu = cpu_to_be16(new_mtu);
				//DPA_INFO("%s(%d) orig_mtu %d, new_mtu %d \n",__FUNCTION__,__LINE__, orig_mtu, param->mtu);
			}
		}
	}
}


/** Updates a software conntrack (both directions)
 *
 * @param pEntry_orig	pointer to the originator software conntrack
 */
void ct_update(PCtEntry pEntry_orig)
{
	PCT_PAIR ppair = container_of(pEntry_orig, CT_PAIR, orig);
	PCtEntry pEntry_rep = &ppair->repl;
	ct_update_one(pEntry_orig);
	ct_update_one(pEntry_rep);
	ct_timer_update(ppair);
}

/**
 * IP_delete_CT_route()
 *
 *
 */
void IP_delete_CT_route(PCtEntry pEntry)
{
	PRouteEntry pRtEntry = pEntry->pRtEntry;

	if (IS_NULL_ROUTE(pRtEntry))
		return;

	L2_route_put(pRtEntry);

	pEntry->pRtEntry = NULL;
}


PRouteEntry IP_Check_Route(PCtEntry pCtEntry)
{
	PRouteEntry pRtEntry = pCtEntry->pRtEntry;
	if (IS_NULL_ROUTE(pRtEntry))
	{
		pRtEntry = L2_route_get(pCtEntry->route_id);
		pCtEntry->pRtEntry = pRtEntry;
	}
	return pRtEntry;
}


U64 IP_get_qosconnmark(PCtEntry pOrigEntry, PCtEntry pReplEntry)
{
	U64 qosconnmark;

	qosconnmark = pOrigEntry->qosmark.markval;
	if (pReplEntry->qosmark.markval != 0)
	{
		qosconnmark |= (((U64)pReplEntry->qosmark.markval << 32) | ((uint64_t)1 << 63));
	}
	return qosconnmark;
}


int IPv4_delete_CTpair(PCtEntry ctEntry)
{
	PCtEntry twin_entry;
	struct _tCtCommand *message;
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

	message = (struct _tCtCommand *)pmsg->data;

	// Prepare indication message
	message->action = (ctEntry->status & CONNTRACK_TCP_FIN) ? ACTION_TCP_FIN : ACTION_REMOVED;
	message->Saddr= ctEntry->Saddr_v4;
	message->Daddr= ctEntry->Daddr_v4;
	message->Sport= ctEntry->Sport;
	message->Dport= ctEntry->Dport ;
	message->SaddrReply= ctEntry->twin_Saddr;
	message->DaddrReply= ctEntry->twin_Daddr;
	message->SportReply= ctEntry->twin_Sport;
	message->DportReply= ctEntry->twin_Dport;
	message->protocol= GET_PROTOCOL(ctEntry);
	message->qosconnmark = 0;

	pmsg->code = CMD_IPV4_CONNTRACK_CHANGE;
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


static void ct_timer_refresh(PCtEntry pEntry)
{
	struct hw_ct *ct;
	if ((ct = pEntry->ct) != NULL)
	{
		hw_ct_get_active(ct);
		pEntry->last_ct_timer = (cdx_timer_t)ct->timestamp;
	}
}


cdx_timer_t ct_get_time_remaining(PCT_PAIR ppair)
{
	cdx_timer_t latest_time;
	cdx_timer_t elapsed_time;
	PCtEntry pEntry_orig = &ppair->orig;
	PCtEntry pEntry_rep = &ppair->repl;
	TIMER_ENTRY *timer = &ppair->timer;
#ifndef ENABLE_FLOW_TIME_STAMPS
	//for debug only, if timestamping is not nabled do not age connections
	return 1; 
#endif
	if (IS_BIDIR(pEntry_orig, pEntry_rep))
	{
		ct_timer_refresh(pEntry_orig);
		ct_timer_refresh(pEntry_rep);
		latest_time = TIME_AFTER(pEntry_orig->last_ct_timer, pEntry_rep->last_ct_timer) ?
			pEntry_orig->last_ct_timer : pEntry_rep->last_ct_timer;
	}
	else if (!(pEntry_orig->status & CONNTRACK_FF_DISABLED))
	{
		ct_timer_refresh(pEntry_orig);
		latest_time = pEntry_orig->last_ct_timer;
	}
	else if (!(pEntry_rep->status & CONNTRACK_FF_DISABLED))
	{
		ct_timer_refresh(pEntry_rep);
		latest_time = pEntry_rep->last_ct_timer;
	}
	else
		return 0;
	elapsed_time = ct_timer - latest_time;
	//DPRINT_ERROR("ct_timer=%u, latest_time=%u, elapsed_time=%u\n", ct_timer, latest_time, elapsed_time);
	//	printk("ct_timer=%u, latest_time=%u, elapsed_time=%u\n", ct_timer, latest_time, elapsed_time);
	return elapsed_time >= timer->timerdata ? 0 : timer->timerdata - elapsed_time;
}

int ct_aging_handler(TIMER_ENTRY *timer)
{
	PCT_PAIR ppair = container_of(timer, CT_PAIR, timer);
	PCtEntry pEntry_orig = &ppair->orig;

	timer->period = ct_get_time_remaining(ppair);
	if (timer->period == 0)
	{
		int rc;
		if (IS_IPV4(pEntry_orig))
			rc = IPv4_delete_CTpair(pEntry_orig);
		else
			rc = IPv6_delete_CTpair(pEntry_orig);
		if (rc == 0) {
			return 0;	// ct delete succeeded
		}
		// notification failed -- try again next timer tick
		timer->period = 1;
	}
	//DPRINT_ERROR("new period=%u\n", timer->period);
	return 1;
}

void IP_deleteCt_from_onif_index(U32 if_index)
{
	int i;
	int rc;
	PCtEntry pCtEntry;
	struct slist_entry *entry;

	for (i = 0; i < NUM_CT_ENTRIES; i++)
	{
restart_loop:
		slist_for_each_safe(pCtEntry, entry, &ct_cache[i], list)
		{
			if (IS_NATPT(pCtEntry))	// for now, ignore NAT-PT connections
				continue;
			/* Check the conntrack entry matching with the corresponding Rtentry */
			if (!IS_NULL_ROUTE(pCtEntry->pRtEntry))
			{
				PRouteEntry pRtEntry = pCtEntry->pRtEntry;

				if (pRtEntry->itf->index == if_index)
				{
					if (IS_IPV6(pCtEntry))
						rc = IPv6_delete_CTpair(pCtEntry);
					else
						rc = IPv4_delete_CTpair(pCtEntry);

					if (!rc)
						goto restart_loop;
				}
			}
		}
	}
}

PCtEntry IPv4_find_ctentry(U32 saddr, U32 daddr, U16 sport, U16 dport, U8 proto)
{
	U32 hash;
	PCtEntry pEntry;
	struct slist_entry *entry;

	hash = HASH_CT(saddr, daddr, sport, dport, proto);
	slist_for_each(pEntry, entry, &ct_cache[hash], list)
	{
		if (IS_IPV4_FLOW(pEntry) && pEntry->Saddr_v4 == saddr && pEntry->Daddr_v4 == daddr && pEntry->Sport == sport && pEntry->Dport == dport && pEntry->proto == proto)
			return pEntry;
	}

	return NULL;
}

int IPv4_HandleIP_CONNTRACK(U16 *p, U16 Length)
{
	PCtEntry pEntry_orig = NULL, pEntry_rep = NULL;
	PCT_PAIR ppair;
	CtExCommand Ctcmd;
#ifdef DPA_IPSEC_OFFLOAD 
	int i;
#endif
	U32 sum;
	U32 tmpU32;
	PCtExCommand pCtCmd;

	// Check length
	if ((Length != sizeof(CtCommand)) && (Length != sizeof(CtExCommand)))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&Ctcmd, (U8*)p,  Length);

	switch(Ctcmd.action)
	{
		case ACTION_DEREGISTER:

			pEntry_orig = IPv4_find_ctentry(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol);
			pEntry_rep = IPv4_find_ctentry(Ctcmd.SaddrReply, Ctcmd.DaddrReply, Ctcmd.SportReply, Ctcmd.DportReply, Ctcmd.protocol);
			if (pEntry_orig == NULL || !IS_IPV4(pEntry_orig) || pEntry_rep == NULL || !IS_IPV4(pEntry_rep) ||
					CT_TWIN(pEntry_orig) != pEntry_rep || CT_TWIN(pEntry_rep) != pEntry_orig ||
					((pEntry_orig->status & CONNTRACK_ORIG) != CONNTRACK_ORIG))
				return ERR_CT_ENTRY_NOT_FOUND;

			ct_remove(pEntry_orig);
			break;

		case ACTION_REGISTER:

			/* We first check any possible errors case in the register request (already existing entries, route or arp not found...)
				 then conntract entries allocations is performed */ 

			pEntry_orig = IPv4_find_ctentry(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol);
			pEntry_rep = IPv4_find_ctentry(Ctcmd.SaddrReply, Ctcmd.DaddrReply, Ctcmd.SportReply, Ctcmd.DportReply, Ctcmd.protocol);

			if (pEntry_orig != NULL && pEntry_rep != NULL && ((pEntry_orig->status & CONNTRACK_ORIG) != CONNTRACK_ORIG))
				return ERR_CREATION_FAILED; // Reverse entry already exists

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

			/* originator ------------------------------------*/
			pEntry_orig->fftype = FFTYPE_IPV4;
			pEntry_orig->hash = HASH_CT(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol);
			pEntry_orig->Daddr_v4 = Ctcmd.Daddr;
			pEntry_orig->Saddr_v4 = Ctcmd.Saddr;
			pEntry_orig->Sport = Ctcmd.Sport;
			pEntry_orig->Dport = Ctcmd.Dport;
			pEntry_orig->twin_Daddr = Ctcmd.DaddrReply;
			pEntry_orig->twin_Saddr = Ctcmd.SaddrReply;
			pEntry_orig->twin_Sport = Ctcmd.SportReply;
			pEntry_orig->twin_Dport = Ctcmd.DportReply;
			pEntry_orig->qosmark.markval = get_ctentry_qosmark_from_qosconnmark(Ctcmd.qosconnmark, CONN_ORIG);
			DPRINT(KERN_ERR "%s:%d entry dip %08x qosmark : %x cmdqosconnmark  : %x  qno : %d\n", __func__, __LINE__, Ctcmd.Daddr, (unsigned int)pEntry_orig->qosmark.markval, (unsigned int)Ctcmd.qosconnmark, pEntry_orig->queue);
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
					pEntry_orig->status &= ~ CONNTRACK_SEC_noSA;
				else 
					pEntry_orig->status |= CONNTRACK_SEC_noSA;
			}
#endif

			/* Replier ----------------------------------------*/ 
			pEntry_rep->fftype = FFTYPE_IPV4;
			pEntry_rep->hash = HASH_CT(Ctcmd.SaddrReply, Ctcmd.DaddrReply, Ctcmd.SportReply, Ctcmd.DportReply, Ctcmd.protocol);
			pEntry_rep->Daddr_v4 = Ctcmd.DaddrReply;
			pEntry_rep->Saddr_v4 = Ctcmd.SaddrReply;
			pEntry_rep->Sport = Ctcmd.SportReply;
			pEntry_rep->Dport = Ctcmd.DportReply;
			pEntry_rep->twin_Daddr = Ctcmd.Daddr;
			pEntry_rep->twin_Saddr = Ctcmd.Saddr;
			pEntry_rep->twin_Sport = Ctcmd.Sport;
			pEntry_rep->twin_Dport = Ctcmd.Dport;
			pEntry_rep->qosmark.markval = get_ctentry_qosmark_from_qosconnmark(Ctcmd.qosconnmark, CONN_REPLIER);
			DPRINT(KERN_ERR "%s:%d entry dip %08x qosmark : %x  qno : %d\n", __func__, __LINE__, Ctcmd.Daddr, (unsigned int)pEntry_rep->qosmark.markval, pEntry_rep->queue);
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
				if ( pEntry_rep->hSAEntry[0])
					pEntry_rep->status &= ~CONNTRACK_SEC_noSA;
				else 
					pEntry_rep->status |= CONNTRACK_SEC_noSA;
			}
#endif

			pEntry_orig->ip_chksm_corr = 0x0001;
			pEntry_rep->ip_chksm_corr = 0x0001;

			/* precompute forward processing (NAT or IP forward?) */
			if((pEntry_orig->Daddr_v4 != pEntry_rep->Saddr_v4)
					|| (pEntry_orig->Sport != pEntry_rep->Dport) 
					|| (pEntry_orig->Dport != pEntry_rep->Sport ) 
					|| (pEntry_orig->Saddr_v4 != pEntry_rep->Daddr_v4))
			{
				U32 Daddr_diff = 0;
				U32 Saddr_diff = 0;
				U32 Sport_diff = 0;
				U32 Dport_diff = 0;

				/* Check sum correction pre-computation RFC1624 */

				/* DNAT ? */
				if(pEntry_orig->Daddr_v4 != pEntry_rep->Saddr_v4) 
				{
					Daddr_diff = (pEntry_orig->Daddr_v4 & 0xffff)+
						(pEntry_orig->Daddr_v4 >> 16) +
						((pEntry_rep->Saddr_v4 & 0xffff) ^ 0xffff) +
						((pEntry_rep->Saddr_v4 >>16)	^ 0xffff);
				}

				/* SNAT ? */
				if(pEntry_orig->Saddr_v4 != pEntry_rep->Daddr_v4)
				{
					Saddr_diff = (pEntry_orig->Saddr_v4 & 0xffff)+
						(pEntry_orig->Saddr_v4 >> 16) +
						((pEntry_rep->Daddr_v4 & 0xffff) ^ 0xffff) +
						((pEntry_rep->Daddr_v4 >>16)	^ 0xffff);
				}

				/* PDNAT ? */
				if(pEntry_orig->Dport != pEntry_rep->Sport)
				{
					Dport_diff = (pEntry_orig->Dport) +
						((pEntry_rep->Sport) ^ 0xffff);
				}

				/* PSNAT ? */
				if(pEntry_orig->Sport != pEntry_rep->Dport)
				{
					Sport_diff = (pEntry_orig->Sport) +
						((pEntry_rep->Dport) ^ 0xffff);
				}

				/* IP Checksum */
				sum = Daddr_diff + Saddr_diff;

				while (sum>>16)
					sum = (sum & 0xffff)+(sum >> 16);
				if (sum == 0xffff)
					sum = 0;

				tmpU32 = sum + 0x0001;
				if (tmpU32 + 1 >= 0x10000)	// add in carry, and convert 0xFFFF to 0x0000
					tmpU32++;
				pEntry_orig->ip_chksm_corr = tmpU32;

				/* Replier checksum */
				sum = sum == 0 ? 0 : sum ^ 0xffff;
				tmpU32 = sum + 0x0001;
				if (tmpU32 + 1 >= 0x10000)	// add in carry, and convert 0xFFFF to 0x0000
					tmpU32++;
				pEntry_rep->ip_chksm_corr = tmpU32;

				/* UDP/TCP checksum */
				sum = Daddr_diff + Saddr_diff + Dport_diff + Sport_diff;

				while (sum>>16)
					sum = (sum & 0xffff)+(sum >> 16);
				if (sum == 0xffff)
					sum = 0;

				pEntry_orig->tcp_udp_chksm_corr = sum;

				/* Replier checksum  */
				pEntry_rep->tcp_udp_chksm_corr = sum == 0 ? 0 : sum ^ 0xffff;

				/* Set status */
				pEntry_orig->status |= CONNTRACK_NAT;
				pEntry_rep->status  |= CONNTRACK_NAT;
			}

			if ((Ctcmd.format & CT_ORIG_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_ORIG_DISABLED))
			{
				pEntry_orig->tnl_route = L2_route_get(Ctcmd.tunnel_route_id);
				if (IS_NULL_ROUTE(pEntry_orig->tnl_route))
				{
					ct_free((PCtEntry)pEntry_orig);
					return ERR_RT_LINK_NOT_POSSIBLE;
				}
				pEntry_orig->status |= CONNTRACK_4O6;	
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
				pEntry_rep->status |= CONNTRACK_4O6;	
			}

			/* Everything went Ok. We can safely put querier and replier entries in hash tables */
			return ct_add(pEntry_orig, ct_aging_handler);

		case ACTION_UPDATE: 

			pEntry_orig = IPv4_find_ctentry(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol);
			pEntry_rep = IPv4_find_ctentry(Ctcmd.SaddrReply, Ctcmd.DaddrReply, Ctcmd.SportReply, Ctcmd.DportReply, Ctcmd.protocol);
			if (pEntry_orig == NULL || !IS_IPV4(pEntry_orig) || pEntry_rep == NULL || !IS_IPV4(pEntry_rep) ||
					CT_TWIN(pEntry_orig) != pEntry_rep || CT_TWIN(pEntry_rep) != pEntry_orig ||
					((pEntry_orig->status & CONNTRACK_ORIG) != CONNTRACK_ORIG))
				return ERR_CT_ENTRY_NOT_FOUND;

			if ((Ctcmd.format & CT_ORIG_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_ORIG_DISABLED))
			{
				PRouteEntry tnl_route;
				tnl_route = L2_route_get(Ctcmd.tunnel_route_id);  
				if (IS_NULL_ROUTE(tnl_route))
					return ERR_RT_LINK_NOT_POSSIBLE;
				L2_route_put(tnl_route);			 
			}
			if ((Ctcmd.format & CT_REPL_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_REP_DISABLED))
			{
				PRouteEntry tnl_route;
				tnl_route = L2_route_get(Ctcmd.tunnel_route_id_reply);  
				if (IS_NULL_ROUTE(tnl_route))
					return ERR_RT_LINK_NOT_POSSIBLE;
				L2_route_put(tnl_route);			  
			}

#ifdef DPA_IPSEC_OFFLOAD 
			if (Ctcmd.format & CT_SECURE) {
				if (Ctcmd.SA_nr > SA_MAX_OP)
					return ERR_CT_ENTRY_TOO_MANY_SA_OP;

				for (i = 0; i < Ctcmd.SA_nr; i++) {
					if (Ctcmd.SA_handle[i] && (pEntry_orig->hSAEntry[i] != Ctcmd.SA_handle[i]))
						if (M_ipsec_sa_cache_lookup_by_h( Ctcmd.SA_handle[i]) == NULL)
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
				IP_delete_CT_route(pEntry_orig);
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
				IP_delete_CT_route(pEntry_rep);
			} else
				pEntry_rep->status &= ~CONNTRACK_FF_DISABLED;

#ifdef DPA_IPSEC_OFFLOAD 
			if (Ctcmd.format & CT_SECURE) {
				pEntry_rep->status |= CONNTRACK_SEC;

				for (i = 0; i < SA_MAX_OP; i++) 
					pEntry_rep->hSAEntry[i]= 
						(i<Ctcmd.SAReply_nr) ? Ctcmd.SAReply_handle[i] : 0;

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
			else if (pEntry_orig->pRtEntry->id != Ctcmd.route_id)
			{
				IP_delete_CT_route(pEntry_orig);
				pEntry_orig->route_id = Ctcmd.route_id;
			}
			IP_Check_Route(pEntry_orig);

			if (IS_NULL_ROUTE(pEntry_rep->pRtEntry))
			{
				pEntry_rep->route_id = Ctcmd.route_id_reply;
			}
			else if (pEntry_rep->pRtEntry->id != Ctcmd.route_id_reply)
			{
				IP_delete_CT_route(pEntry_rep);
				pEntry_rep->route_id = Ctcmd.route_id_reply;
			}
			IP_Check_Route(pEntry_rep);

			if (pEntry_orig->tnl_route)
			{
				L2_route_put(pEntry_orig->tnl_route);
				pEntry_orig->tnl_route = NULL;
				pEntry_orig->status &= ~CONNTRACK_4O6;
			}
			if ((Ctcmd.format & CT_ORIG_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_ORIG_DISABLED))
			{
				pEntry_orig->tnl_route = L2_route_get(Ctcmd.tunnel_route_id);
				pEntry_orig->status |= CONNTRACK_4O6;	
			}

			if (pEntry_rep->tnl_route)
			{
				L2_route_put(pEntry_rep->tnl_route);
				pEntry_rep->tnl_route = NULL;
				pEntry_rep->status &= ~CONNTRACK_4O6;

			}
			if ((Ctcmd.format & CT_REPL_TUNNEL) && !(Ctcmd.flags & CTCMD_FLAGS_REP_DISABLED))
			{
				pEntry_rep->tnl_route = L2_route_get(Ctcmd.tunnel_route_id_reply);
				pEntry_rep->status |= CONNTRACK_4O6;	
			}

			ct_update(pEntry_orig);
			return NO_ERR;

		case ACTION_QUERY:
		case ACTION_QUERY_CONT:
			{
				int rc;

				pCtCmd = (PCtExCommand)p;
				rc = IPv4_Get_Next_Hash_CTEntry(pCtCmd, Ctcmd.action == ACTION_QUERY);

				return rc;
			}

		default :
			return ERR_UNKNOWN_ACTION;

	} 

	return NO_ERR;
}


int IP_HandleIP_ROUTE_RESOLVE (U16 *p, U16 Length)
{
	PRouteEntry pRtEntry;
	RtCommand RtCmd;
	PRtCommand pRtCmd;
	int rc = NO_ERR, reset_action = 0;
	POnifDesc onif_desc, iif_desc, underlying_iif_desc;

	// Check length
	if (Length != sizeof(RtCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&RtCmd, (U8*)p, sizeof(RtCommand));

	pRtEntry = L2_route_find(RtCmd.id);

	switch(RtCmd.action)
	{
		case ACTION_REGISTER:
			if (pRtEntry)
				return ERR_RT_ENTRY_ALREADY_REGISTERED; //trying to add exactly the same route

			onif_desc = get_onif_by_name(RtCmd.outputDevice);
			iif_desc  = get_onif_by_name(RtCmd.inputDevice);
			underlying_iif_desc = get_onif_by_name(RtCmd.UnderlyingInputDevice);
			if (!onif_desc) 
				return ERR_UNKNOWN_INTERFACE;

			pRtEntry = L2_route_add(RtCmd.id, 0);

			if (!pRtEntry)
				return ERR_NOT_ENOUGH_MEMORY;

			pRtEntry->itf = onif_desc->itf;

			if (pRtEntry->itf->type & IF_TYPE_PPPOE)
				COPY_MACADDR(pRtEntry->dstmac, ((pPPPoE_Info)pRtEntry->itf)->DstMAC);
			else
				COPY_MACADDR(pRtEntry->dstmac, RtCmd.macAddr);

			pRtEntry->onif_index 		= get_onif_index(onif_desc);
			if(iif_desc)
				pRtEntry->input_itf 		= iif_desc->itf; // For local routes like that of tunnels input_it and underlying_input_itf are NULL
			else
				pRtEntry->input_itf = NULL;
			if(underlying_iif_desc)
				pRtEntry->underlying_input_itf 	= underlying_iif_desc->itf; 
			else
				pRtEntry->underlying_input_itf = pRtEntry->input_itf;

			rte_set_mtu(pRtEntry, RtCmd.mtu);

			if (RtCmd.flags & RTCMD_FLAGS_6o4)
				*((U32 *)ROUTE_EXTRA_INFO(pRtEntry)) = RtCmd.daddr[0];
			else if (RtCmd.flags & RTCMD_FLAGS_4o6)
				memcpy(ROUTE_EXTRA_INFO(pRtEntry), RtCmd.daddr, IPV6_ADDRESS_LENGTH);

#ifdef VLAN_FILTER
			/* Egress filtering is enabled in routing path, i.e outgoing interface is bridge on which vlan filtering is enabled */
			if (RtCmd.flags & RTCMD_VLAN_FILTER_EN)
			{
				pRtEntry->vlan_filter_flags |= VLAN_FILTERED;
				pRtEntry->egress_vid = RtCmd.egress_vid;
				if (RtCmd.flags & RTCMD_EGRESS_UNTAG)
					pRtEntry->vlan_filter_flags |= VLAN_UNTAGGED;
			}

			/* Ingress filtering is enabled in routing path, i.e incoming interface is in bridge on which vlan filtering is enabled */
			if (RtCmd.flags & RTCMD_VLAN_FILTER_INGRESS_EN)
			{
				pRtEntry->vlan_filter_flags |= VLAN_INGRESS_FILTERED;
				pRtEntry->underlying_vid = RtCmd.underlying_vid;
				if (RtCmd.flags & RTCMD_INGRESS_PVID)
					pRtEntry->vlan_filter_flags |= VLAN_PVID;
			}
#endif
			break;

		case ACTION_UPDATE:
			if (!pRtEntry)
				return ERR_RT_ENTRY_NOT_FOUND;

			onif_desc = get_onif_by_name(RtCmd.outputDevice);
			iif_desc  = get_onif_by_name(RtCmd.inputDevice);
			underlying_iif_desc = get_onif_by_name(RtCmd.UnderlyingInputDevice);
			if (!onif_desc)
				return ERR_UNKNOWN_INTERFACE;

			pRtEntry->itf = onif_desc->itf;

			if (pRtEntry->itf->type & IF_TYPE_PPPOE)
				COPY_MACADDR(pRtEntry->dstmac, ((pPPPoE_Info)pRtEntry->itf)->DstMAC);
			else
				COPY_MACADDR(pRtEntry->dstmac, RtCmd.macAddr);
			pRtEntry->onif_index = get_onif_index(onif_desc);

			if(iif_desc)
				pRtEntry->input_itf 		= iif_desc->itf; // For local routes like that of tunnels input_it and underlying_input_itf are NULL
			else
				pRtEntry->input_itf = NULL;
			if(underlying_iif_desc)
				pRtEntry->underlying_input_itf 	= underlying_iif_desc->itf; 
			else
				pRtEntry->underlying_input_itf = pRtEntry->input_itf;

#ifdef VLAN_FILTER
			/* Egress filtering is enabled in routing path, i.e outgoing interface is bridge on which vlan filtering is enabled */
			if (RtCmd.flags & RTCMD_VLAN_FILTER_EN)
			{
				pRtEntry->vlan_filter_flags |= VLAN_FILTERED;
				pRtEntry->egress_vid = RtCmd.egress_vid;
				if (RtCmd.flags & RTCMD_EGRESS_UNTAG)
					pRtEntry->vlan_filter_flags |= VLAN_UNTAGGED;
			}

			/* Ingress filtering is enabled in routing path, i.e incoming interface is in bridge on which vlan filtering is enabled */
			if (RtCmd.flags & RTCMD_VLAN_FILTER_INGRESS_EN)
			{
				pRtEntry->vlan_filter_flags |= VLAN_INGRESS_FILTERED;
				pRtEntry->underlying_vid = RtCmd.underlying_vid;
				if (RtCmd.flags & RTCMD_INGRESS_PVID)
					pRtEntry->vlan_filter_flags |= VLAN_PVID;
			}
#endif
			break;

		case ACTION_DEREGISTER:
			if (pRtEntry)
			{
				DPRINT("ACTION_DEREGISTER: route ID=%x, dstmac=%pM, daddr=%pI4, mtu=%d, itf=%p, input_itf=%p\n",
						pRtEntry->id, pRtEntry->dstmac, &pRtEntry->Daddr_v4,
						pRtEntry->mtu, pRtEntry->itf, pRtEntry->input_itf);
			}
			rc = L2_route_remove(RtCmd.id);
			break;

		case ACTION_QUERY:
			reset_action = 1;

			/* fall through */

		case ACTION_QUERY_CONT:
			pRtCmd = (PRtCommand)p;
			rc = IPV4_Get_Next_Hash_RtEntry(pRtCmd, reset_action);
			break;

		default:
			rc =  ERR_UNKNOWN_ACTION;
			break;
	}  

	return rc;
}



static int IPv4_HandleIP_RESET (void)
{
	PRouteEntry pRtEntry = NULL;
	int i;
	int rc = NO_ERR;

	/* free Conntrack entries -- this handles both IPv4 and IPv6 */
	for(i = 0; i < NUM_CT_ENTRIES; i++)
	{
		PCtEntry pEntry_orig;
		struct slist_entry *entry;

		while ((entry = slist_first(&ct_cache[i])) != NULL)
		{
			pEntry_orig = CT_ORIG(container_of(entry, CtEntry, list));
			ct_remove(pEntry_orig);
		}
	}

	/* free IPv4 sockets entries */
	SOCKET4_free_entries();

	/* Do IPv6 reset */
	IPv6_handle_RESET();

	/* free all Route entries */
	for(i = 0; i < NUM_ROUTE_ENTRIES; i++)
	{
		struct slist_entry *entry;

		slist_for_each_safe(pRtEntry, entry, &rt_cache[i], list)
		{
			L2_route_remove(pRtEntry->id);
		}
	}

	return rc;
}


static int IPv4_HandleIP_SET_TIMEOUT (U16 *p, U16 Length)
{
	TimeoutCommand TimeoutCmd;
	int i;
	int rc = NO_ERR;

	// Check length
	if (Length != sizeof(TimeoutCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&TimeoutCmd, (U8*)p, sizeof(TimeoutCommand));

	// Check protocol and update timeout value
	switch(TimeoutCmd.protocol)
	{
		case IPPROTOCOL_TCP:
			if(TimeoutCmd.sam_4o6_timeout)
				tcp_4o6_timeout = TimeoutCmd.timeout_value1 * CT_TICKS_PER_SECOND;
			else
				tcp_timeout = TimeoutCmd.timeout_value1 * CT_TICKS_PER_SECOND;
			break;
		case IPPROTOCOL_UDP:
			if(TimeoutCmd.sam_4o6_timeout)
			{
				udp_4o6_bidir_timeout = TimeoutCmd.timeout_value1 * CT_TICKS_PER_SECOND;
				udp_4o6_unidir_timeout = (TimeoutCmd.timeout_value2 > 0 ? TimeoutCmd.timeout_value2 : TimeoutCmd.timeout_value1) * CT_TICKS_PER_SECOND;
			}
			else
			{
				udp_bidir_timeout = TimeoutCmd.timeout_value1 * CT_TICKS_PER_SECOND;
				udp_unidir_timeout = (TimeoutCmd.timeout_value2 > 0 ? TimeoutCmd.timeout_value2 : TimeoutCmd.timeout_value1) * CT_TICKS_PER_SECOND;
			}
			break;
#define UNKNOWN_PROTO 0
		case UNKNOWN_PROTO:
			if(TimeoutCmd.sam_4o6_timeout)
				other_4o6_proto_timeout = TimeoutCmd.timeout_value1 * CT_TICKS_PER_SECOND;
			else
				other_proto_timeout = TimeoutCmd.timeout_value1 * CT_TICKS_PER_SECOND;
			break;
		default:
			rc = ERR_UNKNOWN_ACTION;
			break;
	}

	/* Update all timeouts */
	for(i = 0; i < NUM_CT_ENTRIES; i++)
	{
		struct slist_entry *entry;
		PCtEntry ct;
		slist_for_each(ct, entry, &ct_cache[i], list)
		{
			if ((ct->status & CONNTRACK_ORIG) == CONNTRACK_ORIG)
			{
				PCT_PAIR ppair = container_of(ct, CT_PAIR, orig);
				ct_timer_update(ppair);
			}
		}
	}

	return rc;
}


static int IPv4_HandleIP_Get_Timeout(U16 *p, U16 Length)
{
	int rc = NO_ERR;
	PTimeoutCommand TimeoutCmd;
	CtCommand Ctcmd;
	PCtEntry pEntry;

	// Check length
	if (Length != sizeof(CtCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&Ctcmd, (U8*)p,  Length);

	if ((pEntry = IPv4_find_ctentry(Ctcmd.Saddr, Ctcmd.Daddr, Ctcmd.Sport, Ctcmd.Dport, Ctcmd.protocol)) != NULL)
	{
		PCT_PAIR ppair;
		cdx_timer_t timeout_value;
		memset(p, 0, 256);
		TimeoutCmd = (PTimeoutCommand)(p+1);
		TimeoutCmd->protocol = GET_PROTOCOL(pEntry);
		if (!(pEntry->status & CONNTRACK_ORIG))
			pEntry = CT_TWIN(pEntry);
		ppair = container_of(pEntry, CT_PAIR, orig);
		timeout_value = ct_get_time_remaining(ppair);
		// timeout value is rounded up
		TimeoutCmd->timeout_value1 = ((U32)timeout_value + CT_TICKS_PER_SECOND - 1) / CT_TICKS_PER_SECOND;
	}
	else
	{
		return CMD_ERR;
	}

	return rc;			
}


static int IPv4_HandleIP_FF_CONTROL (U16 *p, U16 Length)
{
	int rc = NO_ERR;
	FFControlCommand FFControlCmd;

	// Check length
	if (Length != sizeof(FFControlCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&FFControlCmd, (U8*)p, sizeof(FFControlCommand));

	if(FFControlCmd.enable == 1){
		PCtEntry ct;
		int i;

		ff_enable = 1;

		/* Reset all timeouts */
		for(i = 0; i < NUM_CT_ENTRIES; i++)
		{
			struct slist_entry *entry;

			slist_for_each(ct, entry, &ct_cache[i], list)
			{
				ct->last_ct_timer = ct_timer;
			}
		}
	}
	else if (FFControlCmd.enable == 0){
		ff_enable = 0;
	}
	else
		return ERR_WRONG_COMMAND_PARAM;

	return rc;
}



static U16 M_ipv4_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc;
	U16 querySize = 0;
	U16 action;
#ifdef  IPV4_CMD_DEBUG_
	printk(KERN_DEBUG "%s: cmd_code=0x%04x, cmd_len=%d\n", __func__, cmd_code, cmd_len);
#endif
	switch (cmd_code)
	{
		case CMD_IPV4_CONNTRACK:			
			action = *pcmd;
			rc = IPv4_HandleIP_CONNTRACK(pcmd, cmd_len);
			if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
				querySize = sizeof(CtExCommand);
			break;

		case CMD_IP_ROUTE:
			action = *pcmd;
			rc = IP_HandleIP_ROUTE_RESOLVE(pcmd, cmd_len);
			if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
				querySize = sizeof(RtCommand);
			break;

		case CMD_IPV4_RESET:			
			rc = IPv4_HandleIP_RESET();
			break;

		case CMD_IPV4_SET_TIMEOUT:
			rc = IPv4_HandleIP_SET_TIMEOUT(pcmd, cmd_len);
			break;

		case CMD_IPV4_GET_TIMEOUT:
			rc = IPv4_HandleIP_Get_Timeout(pcmd, cmd_len);
			if (rc == NO_ERR)
				querySize = sizeof(TimeoutCommand);
			break;

		case CMD_IPV4_FF_CONTROL:
			rc = IPv4_HandleIP_FF_CONTROL(pcmd, cmd_len);
			break;

#ifdef CDX_TODO_ALTCONF
			/* IPv4 module is used to handle alternate configuration API */
		case CMD_ALTCONF_SET:
			rc = ALTCONF_HandleCONF_SET(pcmd, cmd_len);
			break;
		case CMD_ALTCONF_RESET:
			rc = ALTCONF_HandleCONF_RESET_ALL(pcmd, cmd_len);
			break;
#endif

		case CMD_IPV4_SOCK_OPEN:
			DPRINT("%s(%d) \n",__FUNCTION__,__LINE__);
			rc = SOCKET4_HandleIP_Socket_Open(pcmd, cmd_len);
			break;

		case CMD_IPV4_SOCK_CLOSE:
			rc = SOCKET4_HandleIP_Socket_Close(pcmd, cmd_len);
			break;

		case CMD_IPV4_SOCK_UPDATE:
			rc = SOCKET4_HandleIP_Socket_Update(pcmd, cmd_len);
			break;

#ifdef CDX_TODO_IPV4FRAG
		case CMD_IPV4_FRAGTIMEOUT:
		case CMD_IPV4_SAM_FRAGTIMEOUT:
			rc = IPv4_HandleIP_Set_FragTimeout(pcmd, cmd_len, (cmd_code == CMD_IPV4_SAM_FRAGTIMEOUT));
			break;
#endif

		default:
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;
	return 2 + querySize;
}


int ipv4_init(void)
{
	set_cmd_handler(EVENT_IPV4, M_ipv4_cmdproc);

	/* Set default values to programmable L4 timeouts */
	udp_4o6_unidir_timeout =	udp_unidir_timeout = UDP_UNIDIR_TIMEOUT * CT_TICKS_PER_SECOND;
	udp_4o6_bidir_timeout  =	udp_bidir_timeout = UDP_BIDIR_TIMEOUT * CT_TICKS_PER_SECOND;
	tcp_4o6_timeout	       =	tcp_timeout = TCP_TIMEOUT * CT_TICKS_PER_SECOND;
	other_4o6_proto_timeout=	other_proto_timeout = OTHER_PROTO_TIMEOUT * CT_TICKS_PER_SECOND;

	return 0;
}


void ipv4_exit(void)
{
	/* Just call IPv4_HandleIP_RESET */
	IPv4_HandleIP_RESET();
}

U32 get_timeout_value(U32 Proto,int sam_flag, int bidir_flag)
{
	/* IPSec connections also treating as tunnel(4rd) and getting 4o6 timeout.
	 * As of now 4o6 tunnels are not supporting secure connections. So, if the 
	 * connection is secure it is not a 4rd tunnel.
	 */
	if (sam_flag & CONNTRACK_SEC)
		sam_flag = 0;
	switch (Proto)
	{
		case IPPROTOCOL_UDP:
			if(sam_flag)
				return bidir_flag ? udp_4o6_bidir_timeout : udp_4o6_unidir_timeout;
			return bidir_flag ? udp_bidir_timeout : udp_unidir_timeout;
			break;

		case IPPROTOCOL_TCP:
			return sam_flag ? tcp_4o6_timeout: tcp_timeout;
			break;

		case IPPROTOCOL_IPIP:
		default:
			return sam_flag ? other_4o6_proto_timeout : other_proto_timeout;
			break;
	}
}

/* This function returns total arp entries configured in a given hash index */
static int IPV4_Get_Hash_CTEntries(int ct_hash_index)
{

	int tot_ct_entries = 0;
	PCtEntry pCtEntry;
	struct slist_entry *entry;

	slist_for_each(pCtEntry, entry, &ct_cache[ct_hash_index], list)
	{
		if (IS_IPV4(pCtEntry) && (pCtEntry->status & CONNTRACK_ORIG) == CONNTRACK_ORIG)
			tot_ct_entries++;
	}

	return tot_ct_entries;
}

/* This function fills the snapshot of ipv4 CT entries in a given hash index */
static int IPv4_CT_Get_Hash_Snapshot(int ct_hash_index, int ct_total_entries, PCtExCommand pSnapshot)
{

	int tot_ct_entries=0;
	PCtEntry pCtEntry;
	PCtEntry pReplyEntry = NULL;
	struct slist_entry *entry;
#ifdef PRINT_CTENTRY_STATS
	struct dpa_cls_tbl_entry_stats stats;
#endif
	slist_for_each(pCtEntry, entry, &ct_cache[ct_hash_index], list)
	{
		if (IS_IPV4(pCtEntry) &&(pCtEntry->status & CONNTRACK_ORIG) == CONNTRACK_ORIG)
		{
			pReplyEntry = CT_TWIN(pCtEntry);
#ifdef PRINT_CTENTRY_STATS
			if(pCtEntry->ct){
				if (dpa_classif_table_get_entry_stats_by_ref(pCtEntry->ct->td, pCtEntry->ct->dpa_handle, &stats))
				{
					printk("%s:: Getting stats for CT entry failed\n",__func__);
				}
				else
				{
					printk(" entry pkt count = %lu and byte count = %lu\n ",
							(unsigned long)stats.pkts,(unsigned long)stats.bytes );
				}
			}else{
				printk("No classification table for orginal flow\n");
			}

			if(pReplyEntry->ct){
				if (dpa_classif_table_get_entry_stats_by_ref(pReplyEntry->ct->td, pReplyEntry->ct->dpa_handle, &stats))
				{
					printk("%s:: Getting stats for CT entry failed\n",__func__);
				}
				else
				{
					printk(" entry pkt count = %lu and byte count = %lu\n ",
							(unsigned long)stats.pkts,(unsigned long)stats.bytes );
				}
			}else{
				printk("No classification table for response flow\n");
			}
#endif
			pSnapshot->Daddr = pCtEntry->Daddr_v4;
			pSnapshot->Saddr = pCtEntry->Saddr_v4;
			pSnapshot->Sport = pCtEntry->Sport;
			pSnapshot->Dport = pCtEntry->Dport;

			pSnapshot->DaddrReply =  	pCtEntry->twin_Daddr;
			pSnapshot->SaddrReply =   pCtEntry->twin_Saddr;
			pSnapshot->SportReply = 	pCtEntry->twin_Sport;
			pSnapshot->DportReply = 	pCtEntry->twin_Dport;
			pSnapshot->protocol   =  GET_PROTOCOL(pCtEntry); 
			pSnapshot->qosconnmark     = IP_get_qosconnmark(pCtEntry, pReplyEntry);
			pSnapshot->SA_nr      =	0;
			pSnapshot->SAReply_nr	= 	0;
			pSnapshot->format = 0;

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
					if (pReplyEntry->hSAEntry[i])
					{
						pSnapshot->SAReply_nr++;
						pSnapshot->SAReply_handle[i] = pReplyEntry->hSAEntry[i];
					}

				}

			}


			pSnapshot++;
			tot_ct_entries++;

			if (--ct_total_entries <= 0)
				break;
		}
	}

	return tot_ct_entries;

}


/* This function creates the snapshot memory and returns the 
	 next ipv4 CT entry from the snapshop of the ipv4 conntrack entries of a
	 single hash to the caller  */

int IPv4_Get_Next_Hash_CTEntry(PCtExCommand pCtCmd, int reset_action)
{
	int ct_hash_entries;
	static PCtExCommand pCtSnapshot = NULL;
	static int ct_hash_index = 0,ct_snapshot_entries =0, ct_snapshot_index = 0, ct_snapshot_buf_entries = 0;
	PCtExCommand pCt;

	if(reset_action)
	{
		ct_hash_index = 0;
		ct_snapshot_entries =0;
		ct_snapshot_index = 0;
		if(pCtSnapshot)
		{
			Heap_Free(pCtSnapshot);
			pCtSnapshot = NULL;	
		}
		ct_snapshot_buf_entries = 0;
	}

	if (ct_snapshot_index == 0)
	{

		while( ct_hash_index < NUM_CT_ENTRIES)
		{

			ct_hash_entries = IPV4_Get_Hash_CTEntries(ct_hash_index);
			if(ct_hash_entries == 0)
			{
				ct_hash_index++;
				continue;
			}
			if (ct_hash_entries > ct_snapshot_buf_entries)
			{
				if(pCtSnapshot)
					Heap_Free(pCtSnapshot);

				pCtSnapshot = Heap_Alloc(ct_hash_entries * sizeof(CtExCommand));

				if (!pCtSnapshot)
				{
					ct_hash_index = 0;
					ct_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				ct_snapshot_buf_entries = ct_hash_entries;
			}

			ct_snapshot_entries = IPv4_CT_Get_Hash_Snapshot(ct_hash_index ,ct_hash_entries, pCtSnapshot);

			break;
		}

		if (ct_hash_index >= NUM_CT_ENTRIES)
		{
			ct_hash_index = 0;
			if(pCtSnapshot)
			{
				Heap_Free(pCtSnapshot);
				pCtSnapshot = NULL;
			}

			ct_snapshot_buf_entries = 0;
			return ERR_CT_ENTRY_NOT_FOUND;
		}

	}

	pCt = &pCtSnapshot[ct_snapshot_index++];
	memcpy(pCtCmd, pCt, sizeof(CtExCommand));
	if (ct_snapshot_index == ct_snapshot_entries)
	{
		ct_snapshot_index = 0;
		ct_hash_index ++;
	}

	return NO_ERR;	

}



/* This function returns total routes configured in a given hash index */
static int IPV4_Get_Hash_Routes(int rt_hash_index)
{
	int tot_routes = 0;
	struct slist_entry *entry;

	slist_for_each_entry(entry, &rt_cache[rt_hash_index])
	{
		tot_routes++;
	}

	return tot_routes;
}

/* This function fills the snapshot of route entries in a given hash index */
static int IPV4_RT_Get_Hash_Snapshot(int rt_hash_index,int rt_total_entries, PRtCommand pSnapshot)
{

	int tot_routes=0;
	PRouteEntry pRtEntry;
	struct slist_entry *entry;
	POnifDesc onif_desc;

	slist_for_each(pRtEntry, entry, &rt_cache[rt_hash_index], list)
	{
		COPY_MACADDR(pSnapshot->macAddr, pRtEntry->dstmac);

		onif_desc = get_onif_by_index(pRtEntry->itf->index);
		if (onif_desc)
			strcpy((char *)pSnapshot->outputDevice, (char *)onif_desc->name);
		else
			pSnapshot->outputDevice[0] = '\0';

		pSnapshot->inputDevice[0] = '\0';
		if(pRtEntry->input_itf)
		{
			onif_desc = get_onif_by_index(pRtEntry->input_itf->index);
			if (onif_desc)
				strcpy((char *)pSnapshot->inputDevice, (char *)onif_desc->name);
		}

		pSnapshot->mtu = pRtEntry->mtu;
		pSnapshot->id = pRtEntry->id;
		memcpy( pSnapshot->daddr, ROUTE_EXTRA_INFO(pRtEntry), IPV6_ADDRESS_LENGTH);

		pSnapshot++;
		tot_routes++;

		if (--rt_total_entries <= 0)
			break;
	}

	return tot_routes;
}



/* This function creates the snapshot memory and returns the 
	 next route entry from the snapshop of the route entries of a
	 single hash to the caller  */

int IPV4_Get_Next_Hash_RtEntry(PRtCommand pRtCmd, int reset_action)
{
	int rt_hash_entries;
	PRtCommand pRt;
	static PRtCommand pRtSnapshot = NULL;
	static int rt_hash_index = 0, rt_snapshot_entries =0, rt_snapshot_index=0, rt_snapshot_buf_entries = 0;

	if(reset_action)
	{
		rt_hash_index = 0;
		rt_snapshot_entries =0;
		rt_snapshot_index=0;
		if(pRtSnapshot)
		{
			Heap_Free(pRtSnapshot);
			pRtSnapshot = NULL;
		}
		rt_snapshot_buf_entries = 0;
	}

	if (rt_snapshot_index == 0)
	{
		while( rt_hash_index < NUM_ROUTE_ENTRIES)
		{

			rt_hash_entries = IPV4_Get_Hash_Routes(rt_hash_index);
			if(rt_hash_entries == 0)
			{
				rt_hash_index++;
				continue;
			}

			if(rt_hash_entries > rt_snapshot_buf_entries)
			{
				if(pRtSnapshot)
					Heap_Free(pRtSnapshot);
				pRtSnapshot = Heap_Alloc(rt_hash_entries * sizeof(RtCommand));

				if (!pRtSnapshot)
				{
					rt_hash_index = 0;
					rt_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				rt_snapshot_buf_entries = rt_hash_entries;
			}

			rt_snapshot_entries = IPV4_RT_Get_Hash_Snapshot(rt_hash_index ,rt_hash_entries, pRtSnapshot);

			break;
		}

		if (rt_hash_index >= NUM_ROUTE_ENTRIES)
		{
			rt_hash_index = 0;
			if(pRtSnapshot)
			{
				Heap_Free(pRtSnapshot);
				pRtSnapshot = NULL;
			}
			rt_snapshot_buf_entries = 0;
			return ERR_RT_ENTRY_NOT_FOUND;
		}

	}

	pRt = &pRtSnapshot[rt_snapshot_index++];
	memcpy(pRtCmd, pRt, sizeof(RtCommand));
	if (rt_snapshot_index == rt_snapshot_entries)
	{
		rt_snapshot_index = 0;
		rt_hash_index ++;
	}


	return NO_ERR;	

}
