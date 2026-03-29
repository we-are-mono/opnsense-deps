/*
 * cdx_dpa_cfg.c — DPA configuration accessor functions for FreeBSD
 *
 * Replaces the dpa_cfg.c stubs in cdx_dpa_stub.c with real implementations
 * that read from the fman_info global (populated by cdx_dpa_bridge.c +
 * cdx_dpa_init.c).
 *
 * On Linux, these functions are part of cdx-5.03.1/dpa_cfg.c which receives
 * configuration from userspace via ioctl.  On FreeBSD, the configuration
 * is built in-kernel by cdx_dpa_init.c, so these are pure read accessors.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021-2022 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "portdefs.h"
#include "cdx_ioctl.h"
#include "cdx_dpa_bridge.h"

/* NCSW internal header — need t_FmPcd for physicalMuramBase */
#include "fm_pcd.h"

/*
 * Suppress -Wmissing-prototypes for this file.  These accessor functions
 * have prototypes in the CDX headers (dpa_cfg.h / devman.h) that their
 * callers include.  This file doesn't include all of them to keep
 * dependencies minimal.
 */
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/* Global fman_info pointer (set by cdx_dpa_bridge_init) */
extern struct cdx_fman_info *fman_info;

/* ================================================================
 * PCD / FMan handle accessors
 * ================================================================ */

/*
 * dpa_get_pcdhandle — Return PCD handle for a given FMan index.
 */
void *
dpa_get_pcdhandle(uint32_t fm_index)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < cdx_num_fmans; ii++) {
		if (finfo->index == fm_index)
			return (finfo->pcd_handle);
		finfo++;
	}
	return (NULL);
}

/*
 * dpa_get_fm_ctx — Return fman_info pointer for a given FMan index.
 */
void *
dpa_get_fm_ctx(uint32_t fm_idx)
{

	if (fm_idx < cdx_num_fmans)
		return (fman_info + fm_idx);
	return (NULL);
}

/*
 * dpa_get_fm_MURAM_handle — Return MURAM handle and metadata.
 */
void *
dpa_get_fm_MURAM_handle(uint32_t fm_idx, uint64_t *phyBaseAddr,
    uint32_t *MuramSize)
{
	struct cdx_fman_info *finfo;

	if (fm_idx >= cdx_num_fmans)
		return (NULL);

	finfo = fman_info + fm_idx;
	if (phyBaseAddr != NULL)
		*phyBaseAddr = finfo->physicalMuramBase;
	if (MuramSize != NULL)
		*MuramSize = finfo->fmMuramMemSize;
	return (finfo->muram_handle);
}

/*
 * dpa_get_fm_timestamp — Return current kernel timestamp.
 *
 * On Linux this returns jiffies.  On FreeBSD we return ticks,
 * which serves the same purpose for connection aging.
 */
uint32_t
dpa_get_fm_timestamp(void *fm_ctx)
{

	return ((uint32_t)ticks);
}

/* ================================================================
 * Classification table lookup
 * ================================================================ */

/*
 * dpa_get_tdinfo — Find a hash table handle by FMan index, port, and type.
 *
 * Scans fman_info[].tbl_info[] for a matching table type whose port_idx
 * bitmask includes the specified port.  Returns the table handle (id).
 */
void *
dpa_get_tdinfo(uint32_t fm_index, uint32_t port_idx, uint32_t type)
{
	struct cdx_fman_info *finfo;
	struct table_info *tinfo;
	uint32_t ii, jj;

	finfo = fman_info;
	for (ii = 0; ii < cdx_num_fmans; ii++) {
		if (finfo->index == fm_index) {
			tinfo = finfo->tbl_info;
			for (jj = 0; jj < finfo->num_tables; jj++) {
				if ((tinfo->type == type) &&
				    (tinfo->port_idx & (1U << port_idx)))
					return (tinfo->id);
				tinfo++;
			}
			printf("cdx: dpa_get_tdinfo: no table type %u "
			    "at port %u fm %u\n", type, port_idx, fm_index);
			return (NULL);
		}
		finfo++;
	}
	printf("cdx: dpa_get_tdinfo: invalid fm_index %u\n", fm_index);
	return (NULL);
}

/* ================================================================
 * Port information lookup
 * ================================================================ */

/*
 * get_dpa_port_info — Find port_info by port name.
 */
struct cdx_port_info *
get_dpa_port_info(char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < cdx_num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;

		port_info = finfo->portinfo;
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0)
				return (port_info);
			port_info++;
		}
		finfo++;
	}
	return (NULL);
}

/*
 * get_dpa_port_name — Find port name by port ID.
 */
char *
get_dpa_port_name(uint32_t portid)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < cdx_num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;

		port_info = finfo->portinfo;
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (port_info->portid == portid)
				return (port_info->name);
			port_info++;
		}
		finfo++;
	}
	return (NULL);
}

/*
 * get_dpa_oh_iface_info — Populate OH interface info from port config.
 *
 * Searches fman_info->portinfo[] for a matching port name and copies
 * portid, max_dist, and dist_info into the caller's oh_iface_info.
 * Called from dpa_add_oh_if() in cdx_devman_freebsd.c.
 */
int
get_dpa_oh_iface_info(struct oh_iface_info *iface_info, char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < cdx_num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;

		port_info = finfo->portinfo;
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0) {
				iface_info->portid = port_info->portid;
				iface_info->max_dist = port_info->max_dist;
				iface_info->dist_info = port_info->dist_info;
				return (0);
			}
			port_info++;
		}
		finfo++;
	}
	return (-1);
}

/*
 * get_dpa_eth_iface_info — Populate Ethernet interface info from port config.
 *
 * Same as get_dpa_oh_iface_info but for Ethernet interfaces.
 * Called from add_incoming_iface_info() in cdx_devman_freebsd.c.
 */
int
get_dpa_eth_iface_info(struct eth_iface_info *iface_info, char *name)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < cdx_num_fmans; ii++) {
		struct cdx_port_info *port_info;
		uint32_t jj;

		port_info = finfo->portinfo;
		for (jj = 0; jj < finfo->max_ports; jj++) {
			if (strcmp(name, port_info->name) == 0) {
				iface_info->portid = port_info->portid;
				iface_info->max_dist = port_info->max_dist;
				iface_info->dist_info = port_info->dist_info;
				return (0);
			}
			port_info++;
		}
		finfo++;
	}
	return (-1);
}

/*
 * dpa_get_wan_port — Find the WAN port (10G) for a given FMan.
 */
int
dpa_get_wan_port(uint32_t fm_index, uint32_t *port_idx)
{
	uint32_t ii;
	struct cdx_fman_info *finfo;

	finfo = fman_info;
	for (ii = 0; ii < cdx_num_fmans; ii++) {
		if (finfo->index == fm_index) {
			struct cdx_port_info *port_info;
			uint32_t jj;

			port_info = finfo->portinfo;
			for (jj = 0; jj < finfo->max_ports; jj++) {
				if (port_info->type == 10) {
					*port_idx = port_info->portid;
					return (0);
				}
				port_info++;
			}
		}
		finfo++;
	}
	return (-1);
}

/* ================================================================
 * Memory management (DDR/MURAM)
 *
 * MURAM is Device memory on ARM64 (mapped via pmap_mapdev →
 * Device-nGnRnE).  The kernel's optimized memcpy uses NEON/STP
 * instructions that require Normal memory — they trigger alignment
 * faults on Device memory.  Use word-by-word volatile accesses.
 *
 * Size must be a multiple of 4 bytes (all MURAM structures are).
 * ================================================================ */

void *
create_ddr_and_copy_from_muram(void *muramptr, void **ddrptr, U32 size)
{
	volatile uint32_t *s = (volatile uint32_t *)muramptr;
	uint32_t *d;
	U32 nwords = size / 4;
	U32 i;

	*ddrptr = malloc(size, M_ASK, M_NOWAIT);
	if (*ddrptr == NULL) {
		DPA_ERROR("%s: malloc(%u) failed\n", __func__, size);
		return (NULL);
	}
	d = (uint32_t *)*ddrptr;
	for (i = 0; i < nwords; i++)
		d[i] = s[i];
	__asm __volatile("dsb sy" ::: "memory");
	return (*ddrptr);
}

void
copy_ddr_to_muram_and_free_ddr(void *muramptr, void **ddrptr, U32 size)
{
	volatile uint32_t *d = (volatile uint32_t *)muramptr;
	const uint32_t *s = (const uint32_t *)*ddrptr;
	U32 nwords = size / 4;
	U32 i;

	for (i = 0; i < nwords; i++)
		d[i] = s[i];
	__asm __volatile("dsb sy" ::: "memory");
	free(*ddrptr, M_ASK);
	*ddrptr = NULL;
}

/* ================================================================
 * PCD Frame Queue tracking
 *
 * Singly-linked list of PCD FQs created by devoh / cdx_reassm.
 * Used by find_pcd_fq_info() to avoid creating duplicate FQs for
 * the same FQID, and add_pcd_fq_info() to register new ones.
 * ================================================================ */

static struct dpa_fq *dpa_pcd_fq;

/*
 * find_pcd_fq_info — Check if a PCD FQID is already tracked.
 * Returns 0 if found, -1 if not.
 */
int
find_pcd_fq_info(uint32_t fqid)
{
	struct dpa_fq *fqinfo;

	for (fqinfo = dpa_pcd_fq; fqinfo != NULL; fqinfo = fqinfo->next) {
		if (fqinfo->fqid == fqid)
			return (0);
	}
	return (-1);
}

/*
 * add_pcd_fq_info — Prepend a PCD FQ to the tracked list.
 */
void
add_pcd_fq_info(struct dpa_fq *fq_info)
{

	fq_info->next = dpa_pcd_fq;
	dpa_pcd_fq = fq_info;
}
