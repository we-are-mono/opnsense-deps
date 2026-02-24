/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include "cdx.h"
#include "control_bridge.h"
#include "misc.h"

//snap shot buffer pointer
static PL2BridgeL2FlowEntryCommand pL2FlowSnapshot = NULL;
//next hash index for get
static U32 L2Flow_hash_index = 0;
//number of entries in the snapshot buffer at the current hash_index
static int L2Flow_snapshot_entries = 0; 
//next hash index for get in snapshot buffer
static int L2Flow_snapshot_index = 0; 
//number of entries in snap shot buffer can hold
static int L2Flow_snapshot_buf_entries = 0;

extern U32 L2Bridge_timeout;

PVOID bridge_snapshot_alloc(U32 size)
{
	return kzalloc(size, GFP_KERNEL);
}

void bridge_snapshot_free(PVOID p)
{
	kfree(p);
}

/* This function fills the snapshot of bridge entries at a given hash index */
static void rx_Get_Hash_Snapshot_L2FlowEntries(U32 hash, PL2BridgeL2FlowEntryCommand pL2FlowSnapshot)
{
	struct L2Flow_entry *entry;
	hlist_for_each_entry(entry, &l2flow_hash_table[hash].flowlist, node)
	{
		memset(pL2FlowSnapshot, 0, sizeof(L2BridgeL2FlowEntryCommand));
		memcpy(pL2FlowSnapshot->destaddr, entry->l2flow.da, ETHER_ADDR_LEN);
		memcpy(pL2FlowSnapshot->srcaddr, entry->l2flow.sa, ETHER_ADDR_LEN);
		pL2FlowSnapshot->ethertype = entry->l2flow.ethertype;
		pL2FlowSnapshot->svlan_tag = entry->l2flow.svlan_tag;
		pL2FlowSnapshot->cvlan_tag = entry->l2flow.cvlan_tag;
#ifdef VLAN_FILTER
		pL2FlowSnapshot->vid = entry->l2flow.vid;
		pL2FlowSnapshot->vlan_flags = entry->l2flow.vlan_flags;
#endif
		pL2FlowSnapshot->session_id = entry->l2flow.session_id;
		strcpy(pL2FlowSnapshot->input_name, entry->in_ifname);
		strcpy(pL2FlowSnapshot->output_name, entry->out_ifname);
		pL2FlowSnapshot->timeout = br_get_time_remaining(entry)/HZ;
		pL2FlowSnapshot++;
	}
}

/* This function creates the snapshot memory of a hash bucket and returns the 
   next bridge entry from the snapshot to the caller */ 
int rx_Get_Next_Hash_L2FlowEntry(PL2BridgeL2FlowEntryCommand pL2FlowCmd, int reset_action)
{
	int retval;
	int L2Flow_hash_entries;

	if(reset_action){
		/* start all over */
		L2Flow_hash_index = 0;
		L2Flow_snapshot_entries = 0;
		L2Flow_snapshot_index = 0;
		L2Flow_snapshot_buf_entries = 0;
		if(pL2FlowSnapshot) {
			bridge_snapshot_free(pL2FlowSnapshot);
			pL2FlowSnapshot = NULL;
		}
	}

	//check if we have entries in snap shot buffer to return
	if (L2Flow_snapshot_index < L2Flow_snapshot_entries)
		goto return_next_entry;	
	else
	{
		L2Flow_snapshot_index = 0;
	}
	//go to next bucket that is not empty
	L2Flow_hash_entries = 0;
	while (L2Flow_hash_index < NUM_BT_ENTRIES){
		L2Flow_hash_entries = l2flow_hash_table[L2Flow_hash_index].num_entries;
		if(L2Flow_hash_entries)
			break;
		L2Flow_hash_index++;
	}
	//check if we are done
	if (!L2Flow_hash_entries && (L2Flow_hash_index == NUM_BT_ENTRIES)) {
		//reset the hash index back
		L2Flow_hash_index = 0;
		//release snap shot buffer if any
		if(pL2FlowSnapshot){
			bridge_snapshot_free(pL2FlowSnapshot);
			pL2FlowSnapshot = NULL;
		}
		L2Flow_snapshot_buf_entries = 0;
	 	retval = ERR_BRIDGE_ENTRY_NOT_FOUND;
		goto err_ret;
	}
	/* Alloc snapshot buffer if there is none or if the size of the already available one 
	   is insufficient */
	if (L2Flow_hash_entries > L2Flow_snapshot_buf_entries) {
		if(pL2FlowSnapshot)	
			bridge_snapshot_free(pL2FlowSnapshot);
		   
		pL2FlowSnapshot = bridge_snapshot_alloc(L2Flow_hash_entries * sizeof(L2BridgeL2FlowEntryCommand));
		if (!pL2FlowSnapshot) {
			L2Flow_snapshot_index = 0;
			L2Flow_snapshot_buf_entries = 0;
			L2Flow_snapshot_entries = 0;
			L2Flow_hash_index = 0;
			retval = ERR_NOT_ENOUGH_MEMORY;
			goto err_ret;
		}
	}
	L2Flow_snapshot_buf_entries = L2Flow_hash_entries;
	L2Flow_snapshot_entries = L2Flow_hash_entries;
	//get all entries into snapshot buffer at this index
	rx_Get_Hash_Snapshot_L2FlowEntries(L2Flow_hash_index, pL2FlowSnapshot);
	L2Flow_hash_index++;
	//release the bucket
return_next_entry:	
	memcpy(pL2FlowCmd, &pL2FlowSnapshot[L2Flow_snapshot_index], sizeof(L2BridgeL2FlowEntryCommand));
	//move to next index
	L2Flow_snapshot_index++;
	//if no more entries are at this bucket, increment hash index and zero the index
	return NO_ERR;
err_ret:
	return retval;		
}
