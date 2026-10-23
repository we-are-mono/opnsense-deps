/*
 * cdx_ifstats_freebsd.c — Interface statistics (MURAM-based) for FreeBSD
 *
 * Port of cdx-5.03.1/cdx_ifstats.c.  Allocates a contiguous block of
 * FMan MURAM to hold per-interface packet/byte counters that FMan
 * hardware updates atomically during flow offload processing.
 *
 * Two pools of slots:
 *   - PPPoE interfaces: cdx_pppoe_iface_ifinfo (with timestamp)
 *   - All other interfaces: cdx_iface_ifinfo (without timestamp)
 *
 * Which slots are in use is kept in kernel memory, not as list links in
 * MURAM like the original, since FMan writes counters into that memory.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#include "portdefs.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "fm_ehash.h"

#include <contrib/ncsw/inc/Peripherals/fm_muram_ext.h>

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

DEFINE_SPINLOCK(dpa_statslist_lock);

/* Base of stats area (virtual MURAM address) */
static void *stats_mem;

/* Stats area physical MURAM offset */
static uint32_t stats_mem_phys;

#define NUM_IFSTATS_SLOTS (MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES)

/* Slots for PPPoE, then for all other interfaces, and which are in use */
static struct cdx_pppoe_iface_ifinfo *pppoe_slots;
static struct cdx_iface_ifinfo *ifstats_slots;
static uint8_t pppoe_slot_used[MAX_PPPoE_INTERFACES];
static uint8_t ifstats_slot_used[NUM_IFSTATS_SLOTS];

/* MURAM handle for cleanup */
static void *stats_muram_handle;

extern void *FmMurambaseAddr;

/*
 * cdxdrv_init_stats — Allocate MURAM and create free-lists.
 *
 * Called during CDX bridge init after the MURAM handle and
 * FmMurambaseAddr are set up.
 */
int
cdxdrv_init_stats(void *muram_handle)
{
	uint32_t size;

	size = (MAX_PPPoE_INTERFACES *
	    sizeof(struct cdx_pppoe_iface_ifinfo)) +
	    ((MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES) *
	    sizeof(struct cdx_iface_ifinfo));

	stats_mem = FM_MURAM_AllocMem(muram_handle, size, sizeof(uint64_t));
	if (stats_mem == NULL) {
		printf("cdx: cdxdrv_init_stats: unable to allocate MURAM "
		    "for iface stats, size %u\n", size);
		return (-1);
	}

	stats_muram_handle = muram_handle;
	stats_mem_phys = (uint32_t)((uint8_t *)stats_mem -
	    (uint8_t *)FmMurambaseAddr);

	printf("cdx: cdxdrv_init_stats: mem=%p phys=0x%x size=%u\n",
	    stats_mem, stats_mem_phys, size);

	/* DEFINE_SPINLOCK only declares the lock on FreeBSD (unlike real
	 * Linux, which statically initializes it) -- it still needs an
	 * explicit spin_lock_init before first use. This is the only
	 * caller of cdxdrv_init_stats, so init it here rather than adding
	 * a separate module-init function just for one lock. */
	spin_lock_init(&dpa_statslist_lock);

	spin_lock(&dpa_statslist_lock);
	pppoe_slots = (struct cdx_pppoe_iface_ifinfo *)stats_mem;
	ifstats_slots = (struct cdx_iface_ifinfo *)(pppoe_slots +
	    MAX_PPPoE_INTERFACES);
	memset(pppoe_slot_used, 0, sizeof(pppoe_slot_used));
	memset(ifstats_slot_used, 0, sizeof(ifstats_slot_used));
	spin_unlock(&dpa_statslist_lock);

	printf("cdx: cdxdrv_init_stats: %u PPPoE + %u regular slots\n",
	    MAX_PPPoE_INTERFACES, NUM_IFSTATS_SLOTS);

	return (0);
}

/*
 * alloc_iface_stats — Allocate a MURAM stats slot for an interface.
 *
 * Pops from the appropriate free-list and computes the rxstats_index
 * and txstats_index relative to stats_mem.  Also allocates a heap-side
 * last_stats snapshot for delta calculation.
 */
int
alloc_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface)
{

	iface->last_stats = kzalloc(sizeof(struct iface_stats), GFP_KERNEL);
	if (iface->last_stats == NULL) {
		DPA_ERROR("cdx: alloc_iface_stats: "
		    "memory alloc failed for last_stats\n");
		return (FAILURE);
	}

	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_ifinfo *pppoe_stats;
		uint32_t i;

		pppoe_stats = NULL;
		spin_lock(&dpa_statslist_lock);
		for (i = 0; i < MAX_PPPoE_INTERFACES; i++) {
			if (!pppoe_slot_used[i]) {
				pppoe_slot_used[i] = 1;
				pppoe_stats = &pppoe_slots[i];
				break;
			}
		}
		if (pppoe_stats != NULL) {
			memset(pppoe_stats, 0,
			    sizeof(struct cdx_pppoe_iface_ifinfo));
			iface->rxstats_index =
			    (((uint32_t)((uint8_t *)&pppoe_stats->stats.rxstats -
			    (uint8_t *)stats_mem) /
			    sizeof(struct en_ehash_stats_with_ts)) |
			    STATS_WITH_TS);
			iface->txstats_index =
			    (((uint32_t)((uint8_t *)&pppoe_stats->stats.txstats -
			    (uint8_t *)stats_mem) /
			    sizeof(struct en_ehash_stats_with_ts)) |
			    STATS_WITH_TS);
		}
		iface->stats = pppoe_stats;
		spin_unlock(&dpa_statslist_lock);
	} else {
		struct cdx_iface_ifinfo *ifstats;
		uint32_t i;

		ifstats = NULL;
		spin_lock(&dpa_statslist_lock);
		for (i = 0; i < NUM_IFSTATS_SLOTS; i++) {
			if (!ifstats_slot_used[i]) {
				ifstats_slot_used[i] = 1;
				ifstats = &ifstats_slots[i];
				break;
			}
		}
		if (ifstats != NULL) {
			memset(ifstats, 0, sizeof(struct cdx_iface_ifinfo));
			iface->rxstats_index =
			    ((uint32_t)((uint8_t *)&ifstats->stats.rxstats -
			    (uint8_t *)stats_mem) /
			    sizeof(struct en_ehash_stats));
			iface->txstats_index =
			    ((uint32_t)((uint8_t *)&ifstats->stats.txstats -
			    (uint8_t *)stats_mem) /
			    sizeof(struct en_ehash_stats));
		}
		iface->stats = ifstats;
		spin_unlock(&dpa_statslist_lock);
	}

	if (iface->stats == NULL) {
		kfree(iface->last_stats);
		iface->last_stats = NULL;
		DPA_ERROR("cdx: alloc_iface_stats: "
		    "no free stats slots for type 0x%x\n", dev_type);
		return (FAILURE);
	}

	return (SUCCESS);
}

/*
 * free_iface_stats — Return a MURAM stats slot to its pool.
 *
 * The pool comes from the slot's address, not dev_type: callers pass
 * if_flags, which also carries IF_STATS_ENABLED.  Freeing a slot that is
 * already free does nothing.
 */
void
free_iface_stats(uint32_t dev_type __unused, struct dpa_iface_info *iface)
{
	uintptr_t p, pppoe_base, if_base;

	if (iface->stats == NULL)
		return;

	p = (uintptr_t)iface->stats;
	pppoe_base = (uintptr_t)pppoe_slots;
	if_base = (uintptr_t)ifstats_slots;

	spin_lock(&dpa_statslist_lock);
	if (p >= pppoe_base && p < if_base) {
		pppoe_slot_used[(p - pppoe_base) /
		    sizeof(struct cdx_pppoe_iface_ifinfo)] = 0;
	} else if (p >= if_base && p < if_base +
	    NUM_IFSTATS_SLOTS * sizeof(struct cdx_iface_ifinfo)) {
		ifstats_slot_used[(p - if_base) /
		    sizeof(struct cdx_iface_ifinfo)] = 0;
	} else {
		DPA_ERROR("cdx: free_iface_stats: slot %p is not a stats "
		    "slot\n", iface->stats);
	}
	spin_unlock(&dpa_statslist_lock);

	iface->stats = NULL;

	if (iface->last_stats != NULL) {
		kfree(iface->last_stats);
		iface->last_stats = NULL;
	}
}

/*
 * get_logical_ifstats_base — Return the MURAM physical offset of the
 * stats area.  Used by cdx_ehash.c to compute 24-bit Action Descriptor
 * stats pointers.
 */
uint32_t
get_logical_ifstats_base(void)
{

	return (stats_mem_phys);
}

/*
 * cdxdrv_cleanup_stats — Free MURAM stats allocation.
 *
 * Called during CDX module unload.
 */
void
cdxdrv_cleanup_stats(void)
{

	if (stats_mem != NULL && stats_muram_handle != NULL) {
		FM_MURAM_FreeMem(stats_muram_handle, stats_mem);
		stats_mem = NULL;
		stats_muram_handle = NULL;
		printf("cdx: cdxdrv_cleanup_stats: freed MURAM stats\n");
	}
}
