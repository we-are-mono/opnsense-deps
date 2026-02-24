/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#include "portdefs.h"
#include "cdx.h"
#include "control_pppoe.h"
#include "misc.h"
#include "control_stat.h"

extern spinlock_t dpa_devlist_lock;

U8 gStatPPPoEQueryStatus; 

int PPPoE_Get_Next_SessionEntry(pPPPoECommand pSessionCmd, int reset_action);

static pPPPoE_Info pppoe_alloc(void)
{
	return kzalloc(sizeof(PPPoE_Info), GFP_KERNEL);
}


static void pppoe_free(pPPPoE_Info pEntry)
{
	kfree(pEntry);
}


static int M_pppoe_timer(TIMER_ENTRY *timer);

static void __pppoe_add(pPPPoE_Info pEntry, U16 hash_key)
{
	/* Add to our local hash */
	slist_add(&pppoe_cache[hash_key], &pEntry->list);

#ifdef CDX_TODO_PPPOE
	/* Construct the hardware entry, converting virtual addresses and endianess where needed */
#endif
	cdx_timer_init(&pEntry->timer, M_pppoe_timer);
	cdx_timer_add(&pEntry->timer, PPPOE_TIMER_PERIOD);
}

static void pppoe_add(pPPPoE_Info pEntry, U16 hash_key)
{
	__pppoe_add(pEntry, hash_key);
}

static void pppoe_add_relay(pPPPoE_Info pEntry, U16 hash_key, pPPPoE_Info pRelayEntry, U16 relay_hash_key)
{
	__pppoe_add(pEntry, hash_key);
	__pppoe_add(pRelayEntry, relay_hash_key);
}

static void __pppoe_remove(pPPPoE_Info pEntry, U16 hash_key)
{
	struct slist_entry *prev;

	cdx_timer_del(&pEntry->timer);

	prev = slist_prev(&pppoe_cache[hash_key], &pEntry->list);

#ifdef CDX_TODO_PPPOE
	/* remove the hardware entry */
#endif

	/* Remove from our local hash */
	slist_remove_after(prev);

	pppoe_free(pEntry);
}

static void pppoe_remove(pPPPoE_Info pEntry, U16 hash_key)
{
	__pppoe_remove(pEntry, hash_key);
}

static void pppoe_remove_relay(pPPPoE_Info pEntry, U16 hash_key, pPPPoE_Info pRelayEntry, U16 relay_hash_key)
{
	__pppoe_remove(pEntry, hash_key);
	__pppoe_remove(pRelayEntry, relay_hash_key);
}


static int M_pppoe_timer(TIMER_ENTRY *timer)
{
	pPPPoE_Info pEntry = container_of(timer, PPPoE_Info, timer);
#ifdef CDX_TODO_PPPOE
	if (hw_get_active_pppoe_rcv(zzz))		// TODO: implement check
#endif
		pEntry->last_pkt_rcvd = JIFFIES32;
#ifdef CDX_TODO_PPPOE
	if (hw_get_active_pppoe_xmt(zzz))		// TODO: implement check
#endif
		pEntry->last_pkt_xmit = JIFFIES32;
	return 1;
}

static int PPPoE_Handle_Get_Idle(U16* p, U16 Length)
{
	pPPPoEIdleTimeCmd cmd;
	POnifDesc ppp_if;
	pPPPoE_Info pppoeinfo;

	cmd = (pPPPoEIdleTimeCmd)p;
	if (Length != sizeof(PPPoEIdleTimeCmd)) 
		return ERR_WRONG_COMMAND_SIZE;

	ppp_if = get_onif_by_name(cmd->ppp_intf);
	if (!ppp_if || !ppp_if->itf || !(ppp_if->itf->type & IF_TYPE_PPPOE))
		return ERR_UNKNOWN_INTERFACE;

	pppoeinfo = (pPPPoE_Info)ppp_if->itf;

	cmd = (pPPPoEIdleTimeCmd)(p+1);
	memcpy(cmd->ppp_intf,ppp_if->name,sizeof(ppp_if->name));
	cmd->recv_idle = (JIFFIES32 - pppoeinfo->last_pkt_rcvd) / HZ;
	cmd->xmit_idle = (JIFFIES32 - pppoeinfo->last_pkt_xmit) / HZ;
	return NO_ERR;
}


static int PPPoE_Handle_Relay_Entry(U16 *p, U16 Length)
{
	pPPPoERelayCommand cmd;
	pPPPoE_Info pEntry;
	pPPPoE_Info pRelayEntry;
	POnifDesc onif,relayonif;
	U16 hash_key,relay_hash_key;
	struct slist_entry *entry;
	int retval;

	cmd = (pPPPoERelayCommand) p;
	if (Length != sizeof(PPPoERelayCommand))
		return ERR_WRONG_COMMAND_SIZE;

	cmd->sesID = htons(cmd->sesID);
	cmd->relaysesID = htons(cmd->relaysesID);

	hash_key = HASH_PPPOE(cmd->sesID, cmd->peermac1);
	relay_hash_key = HASH_PPPOE(cmd->relaysesID, cmd->peermac2);

	switch (cmd->action)
	{
		case ACTION_REGISTER:

			slist_for_each(pEntry, entry, &pppoe_cache[hash_key], list)
			{
				if((pEntry->sessionID == cmd->sesID) && TESTEQ_MACADDR(pEntry->DstMAC, cmd->peermac1))
					return ERR_PPPOE_ENTRY_ALREADY_REGISTERED; //trying to add the same pppoe session
			}

			slist_for_each(pRelayEntry, entry, &pppoe_cache[relay_hash_key], list)
			{
				if((pRelayEntry->sessionID == cmd->relaysesID) && TESTEQ_MACADDR(pRelayEntry->DstMAC, cmd->peermac2))
					return ERR_PPPOE_ENTRY_ALREADY_REGISTERED; //trying to add the same pppoe session
			}

			if ((pEntry = pppoe_alloc()) == NULL)
			{
				return ERR_NOT_ENOUGH_MEMORY;
			}
			pEntry->itf.type = IF_TYPE_PPPOE;

			if ((pRelayEntry = pppoe_alloc()) == NULL)
			{
				pppoe_free(pEntry);
				return ERR_CREATION_FAILED;
			}
			pRelayEntry->itf.type = IF_TYPE_PPPOE;

			/* populate relay pairs */
			pEntry->sessionID = cmd->sesID;
			COPY_MACADDR(pEntry->DstMAC,cmd->peermac1);

			pRelayEntry->sessionID = cmd->relaysesID;
			COPY_MACADDR(pRelayEntry->DstMAC,cmd->peermac2);

			DPA_INFO("\r\ncontrol_pppoe.c sesID = %d",cmd->sesID);
			DPA_INFO("\r\ncontrol_pppoe.c relaysesID = %d",cmd->relaysesID);

			/*Check if the Physical interface is known by the Interface manager*/
			onif = get_onif_by_name(cmd->ipifname);
			relayonif = get_onif_by_name(cmd->opifname);

			if ((!onif) || (!relayonif)) {
				pppoe_free(pEntry);
				pppoe_free(pRelayEntry);
				return ERR_UNKNOWN_INTERFACE;
			}

			pEntry->last_pkt_rcvd = JIFFIES32;
			pEntry->last_pkt_xmit = JIFFIES32;
			pRelayEntry->last_pkt_rcvd = JIFFIES32;
			pRelayEntry->last_pkt_xmit = JIFFIES32;

			pEntry->itf.phys = onif->itf;
			pRelayEntry->itf.phys = relayonif->itf;

			/*Now link these two entries by relay ptr */
			pEntry->relay = pRelayEntry;
			pRelayEntry->relay = pEntry;

			pppoe_add_relay(pEntry, hash_key, pRelayEntry, relay_hash_key);

			/* hw support for pppoe relay entry */
			COPY_MACADDR(pEntry->hw_entry.SrcMAC,cmd->ipif_mac); /* param source mac for the paired session */
			COPY_MACADDR(pRelayEntry->hw_entry.SrcMAC,cmd->opif_mac); /* param source mac for the paired session */

			strncpy(&pEntry->hw_entry.in_ifname[0],&cmd->ipifname[0], IF_NAME_SIZE);
			pEntry->hw_entry.in_ifname[IF_NAME_SIZE - 1] = '\0';
			DPA_INFO("\r\n incoming interface = %s",cmd->ipifname);
			DPA_INFO("\r\n %s",pEntry->hw_entry.in_ifname);

			strncpy(&pRelayEntry->hw_entry.in_ifname[0],&cmd->opifname[0], IF_NAME_SIZE);
			pRelayEntry->hw_entry.in_ifname[IF_NAME_SIZE - 1] = '\0';
			DPA_INFO("\r\n outgoing interface = %s",cmd->opifname);
			DPA_INFO("\r\n %s",pRelayEntry->hw_entry.in_ifname);

			/* Add PPPOE Relay entries to HW */
			retval =  insert_pppoe_relay_entry_in_classif_table(pEntry);
			if(!retval)
			{
				DPA_INFO("\r\nAdding second pppoe relay entry");
				retval =  insert_pppoe_relay_entry_in_classif_table(pRelayEntry);
				if(!retval)
				{
					DPA_INFO("\r\n Successfully added pppoe relay session entries to HW");
				} 
				else
				{
					DPA_ERROR("\r\n Unable to add second pppoe relay session entry to HW");
					delete_pppoe_relay_entry_from_classif_table(pEntry); 
				}
			}
			else
			{
				DPA_ERROR("\r\n Unable to add the first pppoe relay session entry itself to HW");
			}
			gStatPPPoEQueryStatus = STAT_PPPOE_QUERY_NOT_READY;
			break;

		case ACTION_DEREGISTER:
			slist_for_each(pEntry, entry, &pppoe_cache[hash_key], list)
			{
				if (pEntry->relay)
				{
					if((pEntry->sessionID == cmd->sesID) && TESTEQ_MACADDR(pEntry->DstMAC, cmd->peermac1)
							&& (pEntry->relay->sessionID == cmd->relaysesID) &&
							TESTEQ_MACADDR(pEntry->relay->DstMAC, cmd->peermac2))
						goto found;

				}
			}

			return ERR_PPPOE_ENTRY_NOT_FOUND;

found:
			/* Now relay part as we already searched for relay link, just check for peer2mac and relaysesID */

			slist_for_each(pRelayEntry, entry, &pppoe_cache[relay_hash_key], list)
			{
				if((pRelayEntry->sessionID == cmd->relaysesID) &&
						(TESTEQ_MACADDR(pRelayEntry->DstMAC, cmd->peermac2)) &&
						(pRelayEntry->relay == pEntry))
					goto found_relay;
			}

			return ERR_PPPOE_ENTRY_NOT_FOUND;

found_relay:
			/* remove hw entries first */

			delete_pppoe_relay_entry_from_classif_table(pEntry);
			delete_pppoe_relay_entry_from_classif_table(pRelayEntry);

			pppoe_remove_relay(pEntry, hash_key, pRelayEntry, relay_hash_key);

			gStatPPPoEQueryStatus = STAT_PPPOE_QUERY_NOT_READY;

			break;

		default :
			return ERR_UNKNOWN_COMMAND;
	}

	return NO_ERR;
}

static int PPPoE_Handle_Entry(U16 *p, U16 Length)
{
	pPPPoECommand cmd;
	pPPPoE_Info pEntry;
	POnifDesc phys_onif;
	U32 hash_key;
	struct slist_entry *entry;

	cmd = (pPPPoECommand) p;
	if (Length != sizeof(PPPoECommand))
		return ERR_WRONG_COMMAND_SIZE;

	cmd->sessionID = htons(cmd->sessionID);

	hash_key = HASH_PPPOE(cmd->sessionID, cmd->macAddr);

	switch (cmd->action)
	{
		case ACTION_DEREGISTER:
			slist_for_each(pEntry, entry, &pppoe_cache[hash_key], list)
			{
				if ((pEntry->sessionID == cmd->sessionID) && TESTEQ_MACADDR(pEntry->DstMAC, cmd->macAddr) &&
						(pEntry->relay == NULL)  && !strcmp(get_onif_name(pEntry->itf.index), (char *)cmd->log_intf) )
					goto found;
			}

			return ERR_PPPOE_ENTRY_NOT_FOUND;

found:
			/*Tell the Interface Manager to remove the pppoe IF*/
			remove_onif_by_index(pEntry->itf.index);

			pppoe_remove(pEntry, hash_key);

			gStatPPPoEQueryStatus = STAT_PPPOE_QUERY_NOT_READY;
			break;

		case ACTION_REGISTER:

			if (get_onif_by_name(cmd->log_intf))
				return ERR_PPPOE_ENTRY_ALREADY_REGISTERED;

			/*Check if the Physical interface is known by the Interface manager*/
			phys_onif = get_onif_by_name(cmd->phy_intf);
			if (!phys_onif)
				return ERR_UNKNOWN_INTERFACE;

			slist_for_each(pEntry, entry, &pppoe_cache[hash_key], list)
			{
				if ((pEntry->sessionID == cmd->sessionID) && TESTEQ_MACADDR(pEntry->DstMAC, cmd->macAddr))
					return ERR_PPPOE_ENTRY_ALREADY_REGISTERED; //trying to add exactly the same vlan entry
			}

			if ((pEntry = pppoe_alloc()) == NULL)
			{
				return ERR_NOT_ENOUGH_MEMORY;
			}

			/* populate pppoe_info entry */
			pEntry->sessionID = cmd->sessionID;
			COPY_MACADDR(pEntry->DstMAC,cmd->macAddr);

			pEntry->last_pkt_rcvd = JIFFIES32;
			pEntry->last_pkt_xmit = JIFFIES32;

			if (cmd->mode & PPPOE_AUTO_MODE)
				pEntry->ppp_flags |= PPPOE_AUTO_MODE;

			/*Now create a new interface in the Interface Manager and remember the index*/
			if (!add_onif(cmd->log_intf, &pEntry->itf, phys_onif->itf, IF_TYPE_PPPOE))
			{
				pppoe_free(pEntry);
				return ERR_CREATION_FAILED;
			}
			//printk("%s::adding dpa pppoe iface\n", __FUNCTION__);

			if (dpa_add_pppoe_if(cmd->log_intf,  &pEntry->itf, 
						phys_onif->itf, pEntry->DstMAC,
						pEntry->sessionID)) {
				remove_onif_by_index(pEntry->itf.index);
				pppoe_free(pEntry);
				return ERR_CREATION_FAILED;
			}

			pppoe_add(pEntry, hash_key);
			gStatPPPoEQueryStatus = STAT_PPPOE_QUERY_NOT_READY;
			break;

		case ACTION_QUERY:
		case ACTION_QUERY_CONT:
			{
				int rc;

				rc = PPPoE_Get_Next_SessionEntry(cmd, cmd->action == ACTION_QUERY);
				return rc;

			}

		default:
			return ERR_UNKNOWN_ACTION;
	}

	/* return success */
	return NO_ERR;
}


static U16 M_pppoe_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc = NO_ERR;
	U16 ret_len = 2;
	U16 action;

	switch (cmd_code)
	{
		case CMD_PPPOE_ENTRY:
			action = *pcmd;
			rc = PPPoE_Handle_Entry(pcmd, cmd_len);
			if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
				ret_len = sizeof(PPPoECommand);
			break;

		case CMD_PPPOE_RELAY_ENTRY:
			action = *pcmd;
			rc = PPPoE_Handle_Relay_Entry(pcmd, cmd_len);
			if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
				ret_len = sizeof(PPPoECommand);
			break;

		case CMD_PPPOE_GET_IDLE:
			rc = PPPoE_Handle_Get_Idle(pcmd, cmd_len);
			if (rc == NO_ERR)
				ret_len = sizeof(PPPoEIdleTimeCmd) + 2;
			break;	

		default:
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;
	return ret_len;
}


int pppoe_init(void)
{
	int i;

	set_cmd_handler(EVENT_PPPOE, M_pppoe_cmdproc);

	for (i = 0; i < NUM_PPPOE_ENTRIES; i++)
	{
		slist_head_init(&pppoe_cache[i]);
	}

	return 0;
}

void pppoe_exit(void)
{
	int i;
	pPPPoE_Info pPPPoEEntry;
	struct slist_entry *entry;
	for (i = 0; i < NUM_PPPOE_ENTRIES; i++)
	{
		slist_for_each_safe(pPPPoEEntry, entry, &pppoe_cache[i], list)
		{
			pppoe_remove(pPPPoEEntry, i);
		}
	}
}


/* This function returns total PPPoE configured in FPP */

static int PPPoE_Get_Hash_Sessions(int pppoe_hash_index)
{
	int tot_sessions=0;
	struct slist_entry *entry;

	slist_for_each_entry(entry, &pppoe_cache[pppoe_hash_index])
		tot_sessions++;

	return tot_sessions;

}

/* This function fills in the snapshot of all PPPoE Sessions 
	 in a Session Table */

static int PPPoE_Get_Session_Snapshot(int pppoe_hash_index , int pppoe_tot_entries, pPPPoECommand pPPPoESnapshot)
{
	int tot_sessions=0;
	pPPPoE_Info pPPPoEEntry;
	struct slist_entry *entry;

	slist_for_each(pPPPoEEntry, entry, &pppoe_cache[pppoe_hash_index], list)
	{
		pPPPoESnapshot->sessionID   = ntohs(pPPPoEEntry->sessionID);
		COPY_MACADDR(pPPPoESnapshot->macAddr, pPPPoEEntry->DstMAC);

		if (!pPPPoEEntry->relay)
		{
			strcpy((char *)pPPPoESnapshot->phy_intf, get_onif_name(pPPPoEEntry->itf.phys->index));
			strcpy((char *)pPPPoESnapshot->log_intf, get_onif_name(pPPPoEEntry->itf.index));
		}
		else
		{
			strcpy((char *)pPPPoESnapshot->phy_intf, get_onif_name(pPPPoEEntry->itf.phys->index));
			strcpy((char *)pPPPoESnapshot->log_intf, "relay");
		}

		pPPPoESnapshot++;
		tot_sessions++;

		if (--pppoe_tot_entries <= 0)
			break;
	}

	return tot_sessions;
}

/* This function creates the snapshot memory and returns the 
	 next PPPoE session entry from the PPPoE Session snapshot 
	 to the caller  */
int PPPoE_Get_Next_SessionEntry(pPPPoECommand pSessionCmd, int reset_action)
{
	int pppoe_hash_entries;
	pPPPoECommand pSession;
	static pPPPoECommand pPPPoESnapshot = NULL;
	static int pppoe_session_hash_index =0, pppoe_snapshot_entries = 0, pppoe_snapshot_index = 0, pppoe_snapshot_buf_entries = 0;

	if(reset_action)
	{
		pppoe_session_hash_index =0;
		pppoe_snapshot_entries = 0;
		pppoe_snapshot_index = 0;
		if(pPPPoESnapshot)
		{
			Heap_Free(pPPPoESnapshot);
			pPPPoESnapshot = NULL;
		}
		pppoe_snapshot_buf_entries = 0;
	}

	if (pppoe_snapshot_index == 0)
	{

		while( pppoe_session_hash_index <  NUM_PPPOE_ENTRIES)
		{
			pppoe_hash_entries = PPPoE_Get_Hash_Sessions(pppoe_session_hash_index);
			if (pppoe_hash_entries == 0)
			{
				pppoe_session_hash_index++;
				continue;
			}

			if(pppoe_hash_entries > pppoe_snapshot_buf_entries)
			{
				if(pPPPoESnapshot)
					Heap_Free(pPPPoESnapshot);

				pPPPoESnapshot = Heap_Alloc(pppoe_hash_entries * sizeof(PPPoECommand));
				if (!pPPPoESnapshot)
				{
					pppoe_session_hash_index =0;
					pppoe_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				pppoe_snapshot_buf_entries = pppoe_hash_entries;
			}

			pppoe_snapshot_entries = PPPoE_Get_Session_Snapshot(pppoe_session_hash_index,pppoe_hash_entries,pPPPoESnapshot);
			break;
		}
		if (pppoe_session_hash_index >= NUM_PPPOE_ENTRIES)
		{
			pppoe_session_hash_index = 0;
			if(pPPPoESnapshot)
			{
				Heap_Free(pPPPoESnapshot);
				pPPPoESnapshot = NULL;	
			}
			pppoe_snapshot_buf_entries = 0;
			return ERR_PPPOE_ENTRY_NOT_FOUND;
		}

	}

	pSession = &pPPPoESnapshot[pppoe_snapshot_index++];

	memcpy(pSessionCmd, pSession, sizeof(PPPoECommand));
	if (pppoe_snapshot_index == pppoe_snapshot_entries)
	{
		pppoe_snapshot_index = 0;
		pppoe_session_hash_index++;

	}

	return NO_ERR;
}

static U16 pppoe_stats_get(pPPPoE_Info pEntry, PStatPPPoEEntryResponse snapshot, U8 do_reset)
{
	struct dpa_iface_info *iface_info = NULL;
	struct iface_stats ifstats;
	struct iface_stats *last_stats;
	U16 ret = 0;

	spin_lock(&dpa_devlist_lock);
	if ((iface_info = dpa_get_ifinfo_by_itfid((uint32_t)pEntry->itf.index)) == NULL)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to find the interface index 0x%x\n", __FUNCTION__, pEntry->itf.index);
		return ERR_UNKNOWN_INTERFACE;
	}
	spin_unlock(&dpa_devlist_lock);
	if ((ret = dpa_iface_stats_get(iface_info, &ifstats)) != NO_ERR)
	{
		DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __FUNCTION__, ret);
		return ret;
	}

	last_stats = iface_info->last_stats;
	snapshot->total_packets_received = ifstats.rx_packets - last_stats->rx_packets;
	snapshot->total_packets_transmitted = ifstats.tx_packets - last_stats->tx_packets;

	if (do_reset)
		dpa_iface_stats_reset(iface_info, &ifstats);

	return NO_ERR;
}

/* This function fills in the snapshot of all PPPoE Sessions 
	 in a Session Table */

static U16 stat_PPPoE_Get_Session_Snapshot(int stat_pppoe_hash_index, int stat_tot_entries, 
		PStatPPPoEEntryResponse pStatPPPoESnapshot, int *stat_tot_sessions)
{
	pPPPoE_Info pStatPPPoEEntry;
	struct slist_entry *entry;
	U16 ret = 0;

	*stat_tot_sessions = 0;
	slist_for_each(pStatPPPoEEntry, entry, &pppoe_cache[stat_pppoe_hash_index], list)
	{
		pStatPPPoESnapshot->eof = 0;
		pStatPPPoESnapshot->sessionID = htons(pStatPPPoEEntry->sessionID);
		pStatPPPoESnapshot->interface_no = itf_get_phys_port(&pStatPPPoEEntry->itf);

		if ((ret = pppoe_stats_get(pStatPPPoEEntry, pStatPPPoESnapshot,
						gStatPPPoEQueryStatus & STAT_PPPOE_QUERY_RESET)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __FUNCTION__, ret);
			return ret;
		}

		pStatPPPoESnapshot++;
		(*stat_tot_sessions)++;

		if (--stat_tot_entries <= 0)
			break;
	}

	return NO_ERR;
}

/* This function creates the snapshot memory and returns the 
	 next PPPoE session entry from the PPPoE Session snapshot 
	 to the caller  */
U16 stat_PPPoE_Get_Next_SessionEntry(PStatPPPoEEntryResponse pStatSessionCmd, int reset_action)
{
	int stat_pppoe_hash_entries;
	PStatPPPoEEntryResponse pStatSession;
	static PStatPPPoEEntryResponse pStatPPPoESnapshot = NULL;
	static int stat_pppoe_session_hash_index=0, stat_pppoe_snapshot_entries = 0, stat_pppoe_snapshot_index = 0, stat_pppoe_snapshot_buf_entries = 0;
	U16 ret = 0;

	if(reset_action)
	{
		stat_pppoe_session_hash_index = 0;
		stat_pppoe_snapshot_entries = 0;
		stat_pppoe_snapshot_index = 0;
		if(pStatPPPoESnapshot)
		{
			Heap_Free(pStatPPPoESnapshot);
			pStatPPPoESnapshot = NULL;
		}
		stat_pppoe_snapshot_buf_entries = 0;
		return NO_ERR;
	}

	if (stat_pppoe_snapshot_index == 0)
	{
		while( stat_pppoe_session_hash_index <  NUM_PPPOE_ENTRIES)
		{
			stat_pppoe_hash_entries = PPPoE_Get_Hash_Sessions(stat_pppoe_session_hash_index);
			if (stat_pppoe_hash_entries == 0)
			{
				stat_pppoe_session_hash_index++;
				continue;
			}

			if(stat_pppoe_hash_entries > stat_pppoe_snapshot_buf_entries)
			{
				if(pStatPPPoESnapshot)
					Heap_Free(pStatPPPoESnapshot);	
				pStatPPPoESnapshot = Heap_Alloc(stat_pppoe_hash_entries * sizeof(StatPPPoEEntryResponse));
				if (!pStatPPPoESnapshot)
				{
					stat_pppoe_session_hash_index = 0;
					stat_pppoe_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				stat_pppoe_snapshot_buf_entries = stat_pppoe_hash_entries;
			}
			if ((ret = stat_PPPoE_Get_Session_Snapshot(stat_pppoe_session_hash_index,
							stat_pppoe_hash_entries, pStatPPPoESnapshot,
							&stat_pppoe_snapshot_entries)) != NO_ERR)
			{
				return ret;
			}
			break;
		}
		if (stat_pppoe_session_hash_index >= NUM_PPPOE_ENTRIES)
		{
			stat_pppoe_session_hash_index = 0;
			if(pStatPPPoESnapshot)
			{
				Heap_Free(pStatPPPoESnapshot);
				pStatPPPoESnapshot = NULL;
			}
			stat_pppoe_snapshot_buf_entries = 0;
			return ERR_PPPOE_ENTRY_NOT_FOUND;
		}
	}

	pStatSession = &pStatPPPoESnapshot[stat_pppoe_snapshot_index++];

	memcpy(pStatSessionCmd, pStatSession, sizeof(StatPPPoEEntryResponse));
	if (stat_pppoe_snapshot_index == stat_pppoe_snapshot_entries)
	{
		stat_pppoe_snapshot_index = 0;
		stat_pppoe_session_hash_index++;
	}

	return NO_ERR;
}

