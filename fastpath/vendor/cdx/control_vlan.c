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
#include "control_vlan.h"
#include "misc.h"
#include "control_stat.h"


extern spinlock_t dpa_devlist_lock;
U8 gStatVlanQueryStatus; 

static PVlanEntry vlan_alloc(void)
{
	return kzalloc(sizeof(VlanEntry), GFP_KERNEL);
}

static void vlan_free(PVlanEntry pEntry)
{
	kfree(pEntry);
}

static void vlan_add(PVlanEntry pEntry)
{
	U32 hash;

	hash = HASH_VLAN(pEntry->vlanID);

	/* Add to our local hash */
	slist_add(&vlan_cache[hash], &pEntry->list);
}

static void vlan_remove(PVlanEntry pEntry)
{
	struct slist_entry *prev;
	U32 hash;

	/*Tell the Interface Manager to remove the Vlan IF*/
	remove_onif_by_index(pEntry->itf.index);

	hash = HASH_VLAN(pEntry->vlanID);

#ifdef CDX_TODO_VLAN
	/* remove the hardware entry */
#endif

	/* Remove from our local table */
	prev = slist_prev(&vlan_cache[hash], &pEntry->list);
	slist_remove_after(prev);
}


static U16 Vlan_handle_reset(void)
{
	PVlanEntry pEntry;
	struct slist_entry *entry;
	int i;

	/* free VLAN entries */
	for(i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_for_each_safe(pEntry, entry, &vlan_cache[i], list)
		{
			vlan_remove(pEntry);
			vlan_free(pEntry);
		}
	}

	return NO_ERR;
}


static U16 Vlan_handle_entry(U16 * p,U16 Length)
{
	PVlanEntry pEntry;
	struct slist_entry *entry;
	VlanCommand vlancmd;
	POnifDesc phys_onif;
	int reset_action = 0;
	U32 hash;
	struct net_device *device = NULL, *parent_device = NULL;
	int rc = NO_ERR;

	// Check length
	if (Length != sizeof(VlanCommand))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy((U8*)&vlancmd, (U8*)p,  sizeof(VlanCommand));
	hash = HASH_VLAN(htons(vlancmd.vlanID));

	switch(vlancmd.action)
	{
		case ACTION_DEREGISTER: 

			device = dev_get_by_name(&init_net, vlancmd.vlanifname);

			slist_for_each(pEntry, entry, &vlan_cache[hash], list)
			{
				if ((pEntry->vlanID == htons(vlancmd.vlanID & 0xfff)) && (strcmp(get_onif_name(pEntry->itf.index), (char *)vlancmd.vlanifname) == 0))
					goto found;
			}

			rc = ERR_VLAN_ENTRY_NOT_FOUND;
			break;

found:
			if (device)
				device->wifi_offload_dev = NULL;
			vlan_remove(pEntry);
			vlan_free(pEntry);
			break;

		case ACTION_REGISTER: 

			device = dev_get_by_name(&init_net, vlancmd.vlanifname);
			parent_device = dev_get_by_name(&init_net, vlancmd.phyifname);

			if ((!device) || (!parent_device)){
				DPA_INFO("%s::could not find device %s or %s\n", __FUNCTION__, vlancmd.vlanifname, vlancmd.phyifname);
				rc = FAILURE;
				break;
			}

			if (get_onif_by_name(vlancmd.vlanifname))
			{
				rc = ERR_VLAN_ENTRY_ALREADY_REGISTERED;
				break;
			}

			slist_for_each(pEntry, entry, &vlan_cache[hash], list)
			{
				if ((pEntry->vlanID == htons(vlancmd.vlanID & 0xfff)) && (strcmp(get_onif_name(pEntry->itf.index), (char *)vlancmd.vlanifname) == 0) )
				{
					rc = ERR_VLAN_ENTRY_ALREADY_REGISTERED; //trying to add exactly the same vlan entry
					goto end;
				}
			}

			if ((pEntry = vlan_alloc()) == NULL)
			{
				rc =  ERR_NOT_ENOUGH_MEMORY;
				break;
			}

			pEntry->vlanID = htons(vlancmd.vlanID & 0xfff);

			/*Check if the Physical interface is known by the Interface manager*/
			phys_onif = get_onif_by_name(vlancmd.phyifname);
			if (!phys_onif)
			{
				vlan_free(pEntry);
				rc = ERR_UNKNOWN_INTERFACE;
				break;
			}

			/*Now create a new interface in the Interface Manager and remember the index*/
			if (!add_onif(vlancmd.vlanifname, &pEntry->itf, phys_onif->itf, IF_TYPE_VLAN))
			{
				vlan_free(pEntry);
				rc = ERR_CREATION_FAILED;
				break;
			}
			if (dpa_add_vlan_if(vlancmd.vlanifname, &pEntry->itf, phys_onif->itf, pEntry->vlanID, vlancmd.macaddr)) {
				remove_onif_by_index(pEntry->itf.index);
				vlan_free(pEntry);
				rc =  ERR_CREATION_FAILED;
				break;
			}

			if(parent_device->wifi_offload_dev)
				device->wifi_offload_dev = parent_device->wifi_offload_dev;

			vlan_add(pEntry);

			break;

		case ACTION_QUERY:
			reset_action = 1;
			/* fall through */
		case ACTION_QUERY_CONT:
			{
				PVlanCommand pVlan = (VlanCommand*)p;
				int rc;

				rc = Vlan_Get_Next_Hash_Entry(pVlan, reset_action);
				return rc;
			}
		default:
			return ERR_UNKNOWN_ACTION;
	}
end:
	if (device)
		dev_put(device);
	if (parent_device)
		dev_put(parent_device);

	return rc;
}


static U16 M_vlan_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc;
	U16 retlen = 2;
	U16 action;

	switch (cmd_code)
	{
		case CMD_VLAN_ENTRY:
			action = *pcmd;
			rc = Vlan_handle_entry(pcmd, cmd_len);
			if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
				retlen += sizeof (VlanCommand);
			break;

		case CMD_VLAN_ENTRY_RESET:
			rc = Vlan_handle_reset();
			break;

		default:
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;
	return retlen;
}


int vlan_init(void)
{
	int i;

	set_cmd_handler(EVENT_VLAN, M_vlan_cmdproc);

	for(i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_head_init(&vlan_cache[i]);
	}

	return 0;
}


void vlan_exit(void)
{
	PVlanEntry pEntry;
	struct slist_entry *entry;
	int i;

	for (i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_for_each_safe(pEntry, entry, &vlan_cache[i], list)
		{
			vlan_remove(pEntry);
			vlan_free(pEntry);
		}
	}

}


/* This function returns total vlan interfaces configured in FPP */
static int Vlan_Get_Hash_Entries(int vlan_hash_index)
{
	int tot_vlans=0;
	struct slist_entry *entry;

	slist_for_each_entry(entry, &vlan_cache[vlan_hash_index])
		tot_vlans++;

	return tot_vlans;
}


/* This function fills in the snapshot of all Vlan entries of a VLAN cache */

static int Vlan_Get_Hash_Snapshot(int vlan_hash_index, int vlan_entries, PVlanCommand pVlanSnapshot)
{
	int tot_vlans=0;
	PVlanEntry pVlanEntry;
	struct slist_entry *entry;

	slist_for_each(pVlanEntry, entry, &vlan_cache[vlan_hash_index], list)
	{
		pVlanSnapshot->vlanID = ntohs(pVlanEntry->vlanID);
		strcpy((char *)pVlanSnapshot->vlanifname, get_onif_name(pVlanEntry->itf.index));
		strcpy((char *)pVlanSnapshot->phyifname, get_onif_name(pVlanEntry->itf.phys->index));

		pVlanSnapshot++;
		tot_vlans++;

		if (--vlan_entries <= 0)
			break;
	}

	return tot_vlans;

}



int Vlan_Get_Next_Hash_Entry(PVlanCommand pVlanCmd, int reset_action)
{
	int total_vlan_entries;
	PVlanCommand pVlan;
	static PVlanCommand pVlanSnapshot = NULL;
	static int vlan_hash_index = 0, vlan_snapshot_entries =0, vlan_snapshot_index=0, vlan_snapshot_buf_entries = 0;

	if(reset_action)
	{
		vlan_hash_index = 0;
		vlan_snapshot_entries =0;
		vlan_snapshot_index=0;
		if(pVlanSnapshot)
		{
			Heap_Free(pVlanSnapshot);
			pVlanSnapshot = NULL;
		}
		vlan_snapshot_buf_entries = 0;
	}

	if (vlan_snapshot_index == 0)
	{
		while( vlan_hash_index < NUM_VLAN_ENTRIES)
		{
			total_vlan_entries = Vlan_Get_Hash_Entries(vlan_hash_index);
			if (total_vlan_entries == 0)
			{
				vlan_hash_index++;
				continue;
			}

			if(total_vlan_entries > vlan_snapshot_buf_entries)
			{
				if(pVlanSnapshot)
					Heap_Free(pVlanSnapshot);

				pVlanSnapshot = Heap_Alloc(total_vlan_entries * sizeof(VlanCommand));

				if (!pVlanSnapshot)
				{
					vlan_hash_index = 0;
					vlan_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;	
				}
				vlan_snapshot_buf_entries = total_vlan_entries;
			}


			vlan_snapshot_entries = Vlan_Get_Hash_Snapshot(vlan_hash_index,total_vlan_entries,pVlanSnapshot);
			break;

		}
		if (vlan_hash_index >= NUM_VLAN_ENTRIES)
		{
			vlan_hash_index = 0;
			if(pVlanSnapshot)
			{
				Heap_Free(pVlanSnapshot);
				pVlanSnapshot = NULL;
			}
			vlan_snapshot_buf_entries = 0;
			return ERR_VLAN_ENTRY_NOT_FOUND;
		}
	}

	pVlan = &pVlanSnapshot[vlan_snapshot_index++];

	memcpy(pVlanCmd, pVlan, sizeof(VlanCommand));
	if (vlan_snapshot_index == vlan_snapshot_entries)
	{
		vlan_snapshot_index = 0;
		vlan_hash_index++;
	}

	return NO_ERR;
}

static U16 vlan_stats_get(PVlanEntry pEntry, PStatVlanEntryResponse snapshot, U32 do_reset)
{
	struct iface_stats ifstats;
	struct dpa_iface_info *iface_info = NULL;
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
	snapshot->total_bytes_received[0] = statistics_get_lsb(ifstats.rx_bytes - last_stats->rx_bytes);
	snapshot->total_bytes_received[1] = statistics_get_msb(ifstats.rx_bytes - last_stats->rx_bytes);

	snapshot->total_packets_transmitted = ifstats.tx_packets - last_stats->tx_packets;
	snapshot->total_bytes_transmitted[0] = statistics_get_lsb(ifstats.tx_bytes - last_stats->tx_bytes);
	snapshot->total_bytes_transmitted[1] = statistics_get_msb(ifstats.tx_bytes - last_stats->tx_bytes);

	if (do_reset)
		dpa_iface_stats_reset(iface_info, &ifstats);

	return NO_ERR;
}

static U16 stat_VLAN_Get_Session_Snapshot(int stat_vlan_hash_index, int stat_vlan_entries,
		PStatVlanEntryResponse pStatVLANSnapshot, int *stat_tot_vlans)
{
	PVlanEntry pStatVlanEntry;
	struct slist_entry *entry;
	U16 ret = 0;

	*stat_tot_vlans = 0;
	slist_for_each(pStatVlanEntry, entry, &vlan_cache[stat_vlan_hash_index], list)
	{
		pStatVLANSnapshot->eof = 0;
		pStatVLANSnapshot->vlanID = ntohs(pStatVlanEntry->vlanID);
		strcpy((char *)pStatVLANSnapshot->vlanifname, get_onif_name(pStatVlanEntry->itf.index));
		strcpy((char *)pStatVLANSnapshot->phyifname, get_onif_name(pStatVlanEntry->itf.phys->index));

		if ((ret = vlan_stats_get(pStatVlanEntry, pStatVLANSnapshot,
						gStatVlanQueryStatus & STAT_VLAN_QUERY_RESET)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __FUNCTION__, ret);
			return ret;
		}

		pStatVLANSnapshot++;
		(*stat_tot_vlans)++;

		if (--stat_vlan_entries <= 0)
			break;
	}	

	return NO_ERR;

}

U16 stat_VLAN_Get_Next_SessionEntry(PStatVlanEntryResponse pStatVlanCmd, int reset_action)
{
	int stat_total_vlan_entries;
	PStatVlanEntryResponse pStatVlan;
	static PStatVlanEntryResponse pStatVLANSnapshot = NULL;
	static int stat_vlan_hash_index = 0, stat_vlan_snapshot_entries =0, stat_vlan_snapshot_index=0, stat_vlan_snapshot_buf_entries = 0;
	U16 ret = 0;

	if(reset_action)
	{
		stat_vlan_hash_index = 0;
		stat_vlan_snapshot_entries =0;
		stat_vlan_snapshot_index=0;
		if(pStatVLANSnapshot)
		{
			Heap_Free(pStatVLANSnapshot);
			pStatVLANSnapshot = NULL;
		}
		stat_vlan_snapshot_buf_entries = 0;
		return NO_ERR;
	}

	if (stat_vlan_snapshot_index == 0)
	{
		while(stat_vlan_hash_index < NUM_VLAN_ENTRIES)
		{
			stat_total_vlan_entries = Vlan_Get_Hash_Entries(stat_vlan_hash_index);
			if (stat_total_vlan_entries == 0)
			{
				stat_vlan_hash_index++;
				continue;
			}

			if(stat_total_vlan_entries > stat_vlan_snapshot_buf_entries)
			{
				if(pStatVLANSnapshot)
					Heap_Free(pStatVLANSnapshot);

				pStatVLANSnapshot = Heap_Alloc(stat_total_vlan_entries * sizeof(StatVlanEntryResponse));

				if (!pStatVLANSnapshot)
				{
					stat_vlan_hash_index = 0;
					stat_vlan_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;	
				}
				stat_vlan_snapshot_buf_entries = stat_total_vlan_entries;
			}


			if ((ret = stat_VLAN_Get_Session_Snapshot(stat_vlan_hash_index, stat_total_vlan_entries,
							pStatVLANSnapshot, &stat_vlan_snapshot_entries)) != NO_ERR)
			{
				return ret;
			}
			break;		
		}

		if (stat_vlan_hash_index >= NUM_VLAN_ENTRIES)
		{
			stat_vlan_hash_index = 0;
			if(pStatVLANSnapshot)
			{
				Heap_Free(pStatVLANSnapshot);
				pStatVLANSnapshot = NULL;
			}
			stat_vlan_snapshot_buf_entries = 0;
			return ERR_VLAN_ENTRY_NOT_FOUND;
		}
	}

	pStatVlan = &pStatVLANSnapshot[stat_vlan_snapshot_index++];

	memcpy(pStatVlanCmd, pStatVlan, sizeof(StatVlanEntryResponse));
	if (stat_vlan_snapshot_index == stat_vlan_snapshot_entries)
	{
		stat_vlan_snapshot_index = 0;
		stat_vlan_hash_index++;
	}

	return NO_ERR;
}
