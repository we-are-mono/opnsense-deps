/*
 * cdx_ifstats_freebsd.c — Interface statistics (MURAM-based) for FreeBSD
 *
 * Port of cdx-5.03.1/cdx_ifstats.c.  Allocates a contiguous block of
 * FMan MURAM to hold per-interface packet/byte counters that FMan
 * hardware updates atomically during flow offload processing.
 *
 * Two free-lists are maintained:
 *   - PPPoE interfaces: cdx_pppoe_iface_ifinfo (with timestamp)
 *   - All other interfaces: cdx_iface_ifinfo (without timestamp)
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
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

/* Free-list for all interfaces other than PPPoE */
static struct cdx_iface_ifinfo *ifstats_freelist;

/* Free-list for PPPoE */
static struct cdx_pppoe_iface_ifinfo *pppoe_ifstats_freelist;

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
	uint32_t ii;
	uint32_t num_log_ifaces;
	uint32_t size;
	struct cdx_pppoe_iface_ifinfo *pppoe_stats;
	struct cdx_iface_ifinfo *ifstats;

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

	spin_lock(&dpa_statslist_lock);

	/* Build PPPoE stats free-list */
	pppoe_ifstats_freelist = (struct cdx_pppoe_iface_ifinfo *)stats_mem;
	pppoe_stats = pppoe_ifstats_freelist;
	for (ii = 0; ii < MAX_PPPoE_INTERFACES; ii++) {
		if (ii != (MAX_PPPoE_INTERFACES - 1))
			pppoe_stats->next = (pppoe_stats + 1);
		else
			pppoe_stats->next = NULL;
		pppoe_stats++;
	}

	/* Build regular interface stats free-list */
	ifstats = (struct cdx_iface_ifinfo *)pppoe_stats;
	num_log_ifaces = MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES;

	ifstats_freelist = ifstats;
	for (ii = 0; ii < num_log_ifaces; ii++) {
		if (ii != (num_log_ifaces - 1))
			ifstats->next = (ifstats + 1);
		else
			ifstats->next = NULL;
		ifstats++;
	}

	spin_unlock(&dpa_statslist_lock);

	printf("cdx: cdxdrv_init_stats: %u PPPoE + %u regular slots\n",
	    MAX_PPPoE_INTERFACES, num_log_ifaces);

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

	iface->last_stats = kzalloc(sizeof(struct iface_stats), 0);
	if (iface->last_stats == NULL) {
		DPA_ERROR("cdx: alloc_iface_stats: "
		    "memory alloc failed for last_stats\n");
		return (FAILURE);
	}

	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_ifinfo *pppoe_stats;

		spin_lock(&dpa_statslist_lock);
		pppoe_stats = pppoe_ifstats_freelist;
		if (pppoe_stats != NULL) {
			pppoe_ifstats_freelist = pppoe_stats->next;
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

		spin_lock(&dpa_statslist_lock);
		ifstats = ifstats_freelist;
		if (ifstats != NULL) {
			ifstats_freelist = ifstats->next;
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
 * free_iface_stats — Return a MURAM stats slot to the free-list.
 */
void
free_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface)
{

	if (iface->stats == NULL)
		return;

	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_ifinfo *pppoe_stats;

		pppoe_stats =
		    (struct cdx_pppoe_iface_ifinfo *)iface->stats;
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
