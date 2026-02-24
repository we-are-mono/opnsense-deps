/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
        
/**     
 * @file                cdx_dpa.c     
 * @description         cdx DPAA interface functions
 */             

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "misc.h"
#include "cdx.h"
#include "cdx_common.h"
#include "types.h"
#include "list.h"
#include "cdx_ioctl.h"
#include "layer2.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_tunnel.h"
#include "control_bridge.h"
#include "dpa_ipsec.h"


//#define CDX_DPA_DEBUG 1

#ifdef CDX_DPA_DEBUG
#define CDX_DPA_DPRINT(fmt, args...) printk(KERN_ERR "%s:: " fmt, __func__, ##args)
#else
#define CDX_DPA_DPRINT(fmt, args...) do { } while(0)
#endif

//disable flow statistics
#define ENABLE_STATISTICS 1

#define PPPoE_HASH_TBL_BUCKETS	(1 << 4) //16 
struct pppoe_table_entry {
	struct pppoe_table_entry *next;
	struct pppoe_key key;	
	int dpa_handle;
};

struct pppoe_sess_table {
	spinlock_t lock;	
	struct pppoe_table_entry *head;
};


/* static struct pppoe_sess_table *pppoe_tbl[MAX_FRAME_MANAGERS][MAX_PORTS_PER_FMAN]; */


/* add ethernet type device */
int cdx_add_eth_onif(char *name)
{
	uint32_t ii;

	CDX_DPA_DPRINT("adding iface %s\n", name);
	//find free slot in phys list
	for (ii = 0; ii < MAX_PHY_PORTS; ii++) {
		if (!phy_port[ii].flags) {
			phy_port[ii].id = ii;
			phy_port[ii].flags = 
				(IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
			break;
		}
	}
	if (ii == MAX_PHY_PORTS) {
		DPA_ERROR("%s::mac phys port limit reached\n", __FUNCTION__);
		return -EINVAL;
	}
	//call add onif to add device
	if (add_onif(name, &phy_port[ii].itf, NULL, 
				(IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL)) == NULL) 	{
		memset(&phy_port[ii], 0, sizeof(struct physical_port));
		DPA_ERROR("%s::add_onif failed\n", __FUNCTION__);
		return -EIO;
	}
	//fill mac address in phys port
	dpa_get_mac_addr(name, &phy_port[ii].mac_addr[0]);
	CDX_DPA_DPRINT("added iface %s\n", name);
	return 0;
}

int cdx_add_oh_iface(char *name)
{

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::adding oh iface %s\n", __FUNCTION__,
			name);
#endif
	if (dpa_add_oh_if(name)) {
		DPA_ERROR("%s::add oh port failed\n", __FUNCTION__);
		return -EIO;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::added oh iface %s\n", __FUNCTION__,
			name);
#endif
	return 0;
}

int add_incoming_iface_info(PCtEntry entry)
{
	if (!entry->pRtEntry) 
		return 1;
	if (!entry->pRtEntry->input_itf)
	{
		DPA_ERROR("%s No Input interface information \n",__func__);
		return ERR_UNKNOWN_INTERFACE;
	}

	entry->inPhyPortNum = entry->pRtEntry->input_itf->index;
	return NO_ERR;
}

//insert entry in pppoe class table
int insert_entry_in_pppoe_table(int fm_idx, int port_idx,
			uint8_t *ac_mac_addr, uint32_t sessid, 
			uint32_t ppp_pid)
{
	printk("%s::not implemented\n", __FUNCTION__);
	return FAILURE;
}

