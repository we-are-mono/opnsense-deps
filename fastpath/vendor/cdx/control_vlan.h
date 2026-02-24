/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _CONTROL_VLAN_H_
#define _CONTROL_VLAN_H_

/*Internal VLAN entry used by the VLAN engine*/
typedef struct _tVlanEntry {
	itf_t itf;

	struct slist_entry list;

	U16 vlanID;						/*In big endian format*/
}VlanEntry, *PVlanEntry;

/*Structure defining the VLAN ENTRY command*/
typedef struct _tVLANCommand {
	U16 action;		 	/*Action to perform*/
	U16 vlanID;
	U8 vlanifname[IF_NAME_SIZE];
	U8 phyifname[IF_NAME_SIZE];
	U8 macaddr[6];
	U8 unused[2];
}VlanCommand, *PVlanCommand;

int Vlan_Get_Next_Hash_Entry(PVlanCommand pVlanCmd, int reset_action);

int vlan_init(void);
void vlan_exit(void);


/** Vlan entry hash calculation (based on vlan id).
*
* @param entry	vlan_id VLAN ID in network by order
*
* @return	vlan hash index
*
*/
static __inline U32 HASH_VLAN(U16 vlan_id)
{
	vlan_id = ntohs(vlan_id);
	return ((vlan_id >> 12) ^ (vlan_id >> 8) ^ (vlan_id)) & (NUM_VLAN_ENTRIES - 1);
}

#endif /* _CONTROL_VLAN_H_ */

