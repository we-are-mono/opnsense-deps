/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**     
 * @file                ifstats.c     
 * @description         interface statistics management routines.
 */

#include "fm_muram_ext.h"
#include "dpaa_eth.h"
#include "fm_ehash.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "layer2.h"
#include "portdefs.h"
#include "fm_muram_ext.h"

#ifdef INCLUDE_IFSTATS_SUPPORT

//uncomment to enable debug prints fron this file
//#define IFSTATS_DEBUG	1


DEFINE_SPINLOCK(dpa_statslist_lock);
//base of stats area
static void *stats_mem;
//stats area phys addr
uint32_t stats_mem_phys;
//free lists will be manipulated under device locks
//free list all interface other than PPPoE
struct cdx_iface_ifinfo *ifstats_freelist;
//free list for pppoe
struct cdx_pppoe_iface_ifinfo *pppoe_ifstats_freelist;

extern void *FmMurambaseAddr;

/* allocate muram and create free lists */
int cdxdrv_init_stats(void *muram_handle)
{
	uint32_t ii;
	uint32_t num_log_ifaces;
	uint32_t size;
	struct cdx_pppoe_iface_ifinfo *pppoe_stats;
	struct cdx_iface_ifinfo *ifstats;

	size = (MAX_PPPoE_INTERFACES * sizeof(struct cdx_pppoe_iface_ifinfo)) + 
			((MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES) * sizeof(struct cdx_iface_ifinfo));
	stats_mem = FM_MURAM_AllocMem(muram_handle, size, sizeof(uint64_t));
	if (!stats_mem) {
		printk("%s::unable to allocate muram for iface stats, size %u\n", __FUNCTION__, size );
		return -1;
	}
	stats_mem_phys = (uint32_t)((uint8_t *)stats_mem - (uint8_t *)FmMurambaseAddr);
#ifdef IFSTATS_DEBUG
	printk("%s::ifstats mem base %p phys %x size %ld\n", __FUNCTION__, stats_mem, stats_mem_phys, size);
	/* fill pppoe stats free lists */
	printk("%s::pppoe ifstats at %p\n", __FUNCTION__, stats_mem);
#endif
	spin_lock(&dpa_statslist_lock);
	pppoe_ifstats_freelist = (struct cdx_pppoe_iface_ifinfo *)stats_mem;
	pppoe_stats = pppoe_ifstats_freelist;
	for (ii = 0; ii < MAX_PPPoE_INTERFACES; ii++) {
		if (ii != (MAX_PPPoE_INTERFACES - 1))
			pppoe_stats->next = (pppoe_stats + 1);
		else
			pppoe_stats->next = NULL;
		pppoe_stats++;
	}
	ifstats = (struct cdx_iface_ifinfo *)pppoe_stats;
	/* calculate space remaining for other logical interfaces */
	num_log_ifaces = (MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES); 
#ifdef IFSTATS_DEBUG
	printk("%s::ifstats at %p max log ifaces %d\n", __FUNCTION__, ifstats,
		num_log_ifaces);
#endif
	ifstats_freelist = ifstats;
	/* fill other iface stats free lists */
	for (ii = 0; ii < num_log_ifaces; ii++) {
		if (ii != (num_log_ifaces - 1))
			ifstats->next = (ifstats + 1);
		else
			ifstats->next = NULL;
		ifstats++;
	} 
	spin_unlock(&dpa_statslist_lock);
	return 0;
}

int alloc_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface)
{
	iface->last_stats = (struct iface_stats *)kzalloc(sizeof(struct iface_stats), 0);  
	if (!iface->last_stats) {
		DPA_ERROR("%s:: memory alloc failed for iface last stats\n", __FUNCTION__);
		return FAILURE;
	}

	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_ifinfo *pppoe_stats;

		spin_lock(&dpa_statslist_lock);
		pppoe_stats = pppoe_ifstats_freelist;
		if (pppoe_stats) {
			pppoe_ifstats_freelist = pppoe_stats->next;
			memset(pppoe_stats, 0, sizeof(struct cdx_pppoe_iface_ifinfo));
			iface->rxstats_index = (((uint32_t)((uint8_t *)&pppoe_stats->stats.rxstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats_with_ts)) | STATS_WITH_TS);
			iface->txstats_index = (((uint32_t)((uint8_t *)&pppoe_stats->stats.txstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats_with_ts)) | STATS_WITH_TS);
#ifdef IFSTATS_DEBUG
			printk("%s::allocated pppoe stats %p, rx_offset %x tx_offset %x\n", 
				__FUNCTION__, pppoe_stats, iface->rxstats_index, iface->txstats_index);
#endif
		}
		iface->stats = pppoe_stats;
		spin_unlock(&dpa_statslist_lock);
	} else {
		struct cdx_iface_ifinfo *ifstats;

		spin_lock(&dpa_statslist_lock);
		ifstats = ifstats_freelist;
		if (ifstats) {
			ifstats_freelist = ifstats->next;
			memset(ifstats, 0, sizeof(struct cdx_iface_ifinfo));
			iface->rxstats_index = ((uint32_t )((uint8_t *)&ifstats->stats.rxstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats));
			iface->txstats_index = ((uint32_t )((uint8_t *)&ifstats->stats.txstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats));
#ifdef IFSTATS_DEBUG
			printk("%s::rxstats %p, txstats %p, mem %p\n", __FUNCTION__,
					&ifstats->stats.rxstats,
					&ifstats->stats.txstats,
					stats_mem);
			printk("%s::allocated stats %p, rxoffset %x txoffet %x\n", __FUNCTION__, 
				ifstats, iface->rxstats_index, iface->txstats_index);
#endif
		}
		iface->stats = ifstats;
		spin_unlock(&dpa_statslist_lock);
	}
	return SUCCESS;
}

void free_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface)
{	
	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_ifinfo *pppoe_stats;

		pppoe_stats = (struct cdx_pppoe_iface_ifinfo *)iface->stats;
		spin_lock(&dpa_statslist_lock);
		pppoe_stats->next = pppoe_ifstats_freelist;
		pppoe_ifstats_freelist = pppoe_stats;
		spin_unlock(&dpa_statslist_lock);
	} else {
		struct cdx_iface_ifinfo *ifstats;

		ifstats = (struct cdx_iface_ifinfo *)iface->stats;
		spin_lock(&dpa_statslist_lock);
		ifstats->next = ifstats_freelist;
		ifstats_freelist = ifstats;
		spin_unlock(&dpa_statslist_lock);
	}
	if (iface->last_stats)
		kfree(iface->last_stats);
}

uint32_t get_logical_ifstats_base(void)
{
	return (stats_mem_phys);
}
#else
int cdxdrv_init_stats(void *muram_handle) 
{
	printk("%s::interface statistics module disabled\n", __FUNCTION__);
	return SUCCESS;	
}
int alloc_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface)
{
	printk("%s::interface statistics disabled for type %x\n", 
			__FUNCTION__, dev_type);
	return FAILURE;	
}
void free_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface)
{
	printk("%s::interface statistics disabled for type %x\n",
			__FUNCTION__, dev_type);

}
uint32_t get_logical_ifstats_base(void)
{
	printk("%s::interface statistics disabled for all types\n", 
		__FUNCTION__);
	return 0;
}
#endif

