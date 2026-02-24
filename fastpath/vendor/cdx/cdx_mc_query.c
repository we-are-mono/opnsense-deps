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
#include "list.h"
#include "cdx_common.h"
#include "misc.h"
#include "control_ipv4.h"
#include "layer2.h"
#include "fe.h"
#include "dpa_control_mc.h"

/* This function returns total multicast entries 
   configured in a given hash index */

static int MC4_Get_Hash_Entries(int mc4_hash_index)
{

	int tot_mc4_entries = 0;
	struct mcast_group_info *pMcastGrpInfo;
	struct list_head *ptr;

	list_for_each(ptr, &mc4_grp_list[mc4_hash_index])
	{
		pMcastGrpInfo = list_entry(ptr,struct mcast_group_info,list);
		tot_mc4_entries++;
		if((pMcastGrpInfo->uiListenerCnt > MC4_MAX_LISTENERS_IN_QUERY))
			tot_mc4_entries++;
	}
	return tot_mc4_entries;

}


/* This function fills the snapshot of MC4 entries in a given hash index */
static int MC4_Get_Hash_Snapshot(int mc4_hash_index, int mc4_tot_entries, PMC4Command pMC4Snapshot)
{
	int tot_mc4_entries = 0, i;
	struct mcast_group_info *pMcastGrpInfo;
	struct list_head *ptr;
	int j = 0;

	list_for_each(ptr, &mc4_grp_list[mc4_hash_index])
	{
		pMcastGrpInfo = list_entry(ptr,struct mcast_group_info,list);

		memset(pMC4Snapshot, 0, sizeof(MC4Command));
		pMC4Snapshot->src_addr  	= pMcastGrpInfo->ipv4_saddr;
		//pMC4Snapshot->src_addr_mask	= pMC4Entry->mcdest.src_mask_len;
		pMC4Snapshot->dst_addr 		= pMcastGrpInfo->ipv4_daddr;
		//pMC4Snapshot->queue = pMC4Entry->mcdest.queue_base;
		strncpy((char*)pMC4Snapshot->input_device_str,
				pMcastGrpInfo->ucIngressIface,IF_NAME_SIZE-1);
		for(i = 0,j = 0; j < MC_MAX_LISTENERS_PER_GROUP; j++) //pMcastGrpInfo->uiListenerCnt; j++)
		{
			if (!pMcastGrpInfo->members[j].bIsValidEntry)
				continue;
			strncpy((char *)pMC4Snapshot->output_list[i].output_device_str,
					pMcastGrpInfo->members[j].if_info, IF_NAME_SIZE-1);
#if 0
			pMC4Snapshot->output_list[i].timer = pMC4Entry->mcdest.listeners[j].timer;
			pMC4Snapshot->output_list[i].shaper_mask= pMC4Entry->mcdest.listeners[j].shaper_mask;
			pMC4Snapshot->output_list[i].uc_bit = (pMC4Entry->mcdest.listeners[j].uc_bit);
			if(pMC4Snapshot->output_list[i].uc_bit)
				COPY_MACADDR(pMC4Snapshot->output_list[i].uc_mac,pMC4Entry->mcdest.listeners[j].dstmac);
			pMC4Snapshot->output_list[i].queue = pMC4Entry->mcdest.listeners[j].queue_base;
#endif
			if((++i >= MC4_MAX_LISTENERS_IN_QUERY) &&
					( (pMcastGrpInfo->uiListenerCnt - (i)) ))
			{
				pMC4Snapshot->num_output = MC4_MAX_LISTENERS_IN_QUERY;
				pMC4Snapshot++;
				tot_mc4_entries++;
				mc4_tot_entries--;
				i = 0;
				memset(pMC4Snapshot, 0, sizeof(MC4Command));
			}
		}
		pMC4Snapshot->num_output = i;
#if 0
		if (i < MC4_MAX_LISTENERS_IN_QUERY)
		{
			pMC4Snapshot->num_output++;
			strcpy((char *)pMC4Snapshot->output_list[i].output_device_str, "ACP");
			//pMC4Snapshot->output_list[i].timer = pMC4Entry->mcdest.wifi_listener_timer;
		}
#endif
		pMC4Snapshot++;
		tot_mc4_entries++;
		mc4_tot_entries--;
		if (mc4_tot_entries == 0)
			break;
	}

	return tot_mc4_entries;
}


/* This function creates the snapshot memory and returns the 
	 next MC4 entry from the snapshot of the MC4 entries of a
	 single hash to the caller  */

int MC4_Get_Next_Hash_Entry(PMC4Command pMC4Cmd, int reset_action)
{
	int mc4_hash_entries;
	PMC4Command pMC4;
	static PMC4Command pMC4Snapshot = NULL;
	static int mc4_hash_index = 0, mc4_snapshot_entries =0, mc4_snapshot_index=0, mc4_snapshot_buf_entries = 0;

	if(reset_action)
	{
		mc4_hash_index = 0;
		mc4_snapshot_entries =0;
		mc4_snapshot_index=0;
		if(pMC4Snapshot)
		{
			Heap_Free(pMC4Snapshot);
			pMC4Snapshot = NULL;
		}
		mc4_snapshot_buf_entries = 0;
	}

	if (mc4_snapshot_index == 0)
	{

		while( mc4_hash_index <  MC4_NUM_HASH_ENTRIES)
		{

			mc4_hash_entries = MC4_Get_Hash_Entries(mc4_hash_index);
			if(mc4_hash_entries == 0)
			{
				mc4_hash_index++;
				continue;
			}

			if(mc4_hash_entries > mc4_snapshot_buf_entries)
			{
				if(pMC4Snapshot)
					Heap_Free(pMC4Snapshot);
				pMC4Snapshot = Heap_Alloc(mc4_hash_entries * sizeof(MC4Command));

				if (!pMC4Snapshot)
				{
					mc4_hash_index = 0;
					mc4_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				mc4_snapshot_buf_entries = mc4_hash_entries;
			}

			mc4_snapshot_entries = MC4_Get_Hash_Snapshot(mc4_hash_index ,mc4_hash_entries, pMC4Snapshot);

			break;
		}

		if (mc4_hash_index >= MC4_NUM_HASH_ENTRIES)
		{
			mc4_hash_index = 0;
			if(pMC4Snapshot)
			{
				Heap_Free(pMC4Snapshot);
				pMC4Snapshot = NULL;
			}
			mc4_snapshot_buf_entries = 0;
			return ERR_MC_ENTRY_NOT_FOUND;
		}

	}

	pMC4 = &pMC4Snapshot[mc4_snapshot_index++];
	memcpy(pMC4Cmd, pMC4, sizeof(MC4Command));
	if (mc4_snapshot_index == mc4_snapshot_entries)
	{
		mc4_snapshot_index = 0;
		mc4_hash_index ++;
	}
	return NO_ERR;	

}

/* This function returns total multicastv6 entries 
	 configured in a given hash index */
static int MC6_Get_Hash_Entries(int mc6_hash_index)
{

	int tot_mc6_entries = 0;
	struct mcast_group_info *pMcastGrpInfo;
	struct list_head *ptr;

	list_for_each(ptr, &mc6_grp_list[mc6_hash_index])
	{
		pMcastGrpInfo = list_entry(ptr,struct mcast_group_info,list);

		tot_mc6_entries++;
		if(pMcastGrpInfo->uiListenerCnt > MC4_MAX_LISTENERS_IN_QUERY)
			tot_mc6_entries++;
	}

	return tot_mc6_entries;

}


/* This function fills the snapshot of MC6 entries in a given hash index */
static int MC6_Get_Hash_Snapshot(int mc6_hash_index, int mc6_tot_entries, PMC6Command pMC6Snapshot)
{

	int tot_mc6_entries = 0,i,j;
	struct mcast_group_info *pMcastGrpInfo;
	struct list_head *ptr;

	list_for_each(ptr, &mc6_grp_list[mc6_hash_index])
	{
		pMcastGrpInfo = list_entry(ptr,struct mcast_group_info,list);
		memset(pMC6Snapshot, 0, sizeof(MC6Command));
		memcpy(pMC6Snapshot->src_addr, pMcastGrpInfo->ipv6_saddr, IPV6_ADDRESS_LENGTH);
		//pMC6Snapshot->src_mask_len	= pMC6Entry->mcdest.src_mask_len;
		memcpy(pMC6Snapshot->dst_addr, pMcastGrpInfo->ipv6_daddr, IPV6_ADDRESS_LENGTH);
		//pMC6Snapshot->queue = pMC6Entry->mcdest.queue_base;
		strncpy((char*)pMC6Snapshot->input_device_str,
				pMcastGrpInfo->ucIngressIface,IF_NAME_SIZE-1);
		for(i = 0,j = 0; j < MC_MAX_LISTENERS_PER_GROUP; j++) //pMcastGrpInfo->uiListenerCnt; j++)
		{
			if (!pMcastGrpInfo->members[j].bIsValidEntry)
				continue;
			strncpy((char *)pMC6Snapshot->output_list[i].output_device_str,
					pMcastGrpInfo->members[j].if_info, IF_NAME_SIZE-1);
#if 0
			pMC6Snapshot->output_list[i].timer = pMC6Entry->mcdest.listeners[j].timer;
			pMC6Snapshot->output_list[i].shaper_mask= pMC6Entry->mcdest.listeners[j].shaper_mask;
			pMC6Snapshot->output_list[i].uc_bit = pMC6Entry->mcdest.listeners[j].uc_bit;
			if(pMC6Snapshot->output_list[i].uc_bit)
				COPY_MACADDR(pMC6Snapshot->output_list[i].uc_mac,pMC6Entry->mcdest.listeners[j].dstmac);
			pMC6Snapshot->output_list[i].queue = pMC6Entry->mcdest.listeners[j].queue_base;
#endif
			if((++i >= MC4_MAX_LISTENERS_IN_QUERY) &&
					( (pMcastGrpInfo->uiListenerCnt - (i)) ))
			{
				pMC6Snapshot->num_output = MC6_MAX_LISTENERS_IN_QUERY;
				pMC6Snapshot++;
				tot_mc6_entries++;
				mc6_tot_entries--;
				i = 0;
				memset(pMC6Snapshot, 0, sizeof(MC6Command));
			}
		}
		pMC6Snapshot->num_output = i;
#if 0
		if ((pMC6Entry->mcdest.flags & MC_ACP_LISTENER) && i < MCx_MAX_LISTENERS_IN_QUERY)
		{
			pMC6Snapshot->num_output++;
			strcpy((char *)pMC6Snapshot->output_list[i].output_device_str, "ACP");
			pMC6Snapshot->output_list[i].timer = pMC6Entry->mcdest.wifi_listener_timer;
		}
#endif
		pMC6Snapshot++;
		tot_mc6_entries++;
		mc6_tot_entries--;
		if (mc6_tot_entries == 0)
			break;
	}

	return tot_mc6_entries;
}


/* This function creates the snapshot memory and returns the 
	 next MC6 entry from the snapshot of the MC4 entries of a
	 single hash to the caller  */

int MC6_Get_Next_Hash_Entry(PMC6Command pMC6Cmd, int reset_action)
{
	int mc6_hash_entries;
	PMC6Command pMC6;
	static PMC6Command pMC6Snapshot = NULL;
	static int mc6_hash_index = 0, mc6_snapshot_entries =0, mc6_snapshot_index=0, mc6_snapshot_buf_entries = 0;

	if(reset_action)
	{
		mc6_hash_index = 0;
		mc6_snapshot_entries =0;
		mc6_snapshot_index=0;
		if(pMC6Snapshot)
		{
			Heap_Free(pMC6Snapshot);
			pMC6Snapshot = NULL;	
		}
		mc6_snapshot_buf_entries = 0;
	}

	if (mc6_snapshot_index == 0)
	{
		while( mc6_hash_index <  MC6_NUM_HASH_ENTRIES)
		{

			mc6_hash_entries = MC6_Get_Hash_Entries(mc6_hash_index);
			if(mc6_hash_entries == 0)
			{
				mc6_hash_index++;
				continue;
			}

			if(mc6_hash_entries > mc6_snapshot_buf_entries)
			{
				if(pMC6Snapshot)
					Heap_Free(pMC6Snapshot);
				pMC6Snapshot = Heap_Alloc(mc6_hash_entries * sizeof(MC6Command));

				if (!pMC6Snapshot)
				{
					mc6_hash_index = 0;
					mc6_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				mc6_snapshot_buf_entries = mc6_hash_entries;
			}

			mc6_snapshot_entries = MC6_Get_Hash_Snapshot(mc6_hash_index , mc6_hash_entries, pMC6Snapshot);

			break;
		}

		if (mc6_hash_index >= MC6_NUM_HASH_ENTRIES)
		{
			mc6_hash_index = 0;
			if(pMC6Snapshot)
			{
				Heap_Free(pMC6Snapshot);
				pMC6Snapshot = NULL;	
			}
			mc6_snapshot_buf_entries =  0;
			return ERR_MC_ENTRY_NOT_FOUND;
		}

	}

	pMC6 = &pMC6Snapshot[mc6_snapshot_index++];
	memcpy(pMC6Cmd, pMC6, sizeof(MC6Command));
	if (mc6_snapshot_index == mc6_snapshot_entries)
	{
		mc6_snapshot_index = 0;
		mc6_hash_index ++;
	}

	return NO_ERR;	

}
