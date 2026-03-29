/*
 * cdx_dpa_init.c — Cleanup helpers for CDX hash table state
 *
 * Hash table creation and fman_info population is now handled by
 * dpa_app (userspace) via FMC, with handles passed to CDX via the
 * CDX_CTRL_DPA_SET_PARAMS ioctl (cdx_dpa_takeover.c).
 *
 * This file retains only the cleanup functions needed by
 * cdx_dpa_bridge_destroy() to safely tear down state.
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2022 NXP
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <contrib/ncsw/inc/ncsw_ext.h>

/* SDK external hash table API (fm_ehash_freebsd.c) */
extern void ExternalHashTableDelete(t_Handle h_HashTbl);

/* Forward declarations for functions exported from this file */
void cdx_dpa_destroy(void);
void cdx_dpa_clear_handles(void);

/*
 * No standalone hash tables are created in-kernel.
 * The htable_handles array exists only for cdx_dpa_clear_handles()
 * compatibility with cdx_dpa_bridge_destroy().
 */
#define	HTABLE_COUNT	16
static t_Handle htable_handles[HTABLE_COUNT];

/*
 * Cleanup — delete any hash tables tracked in htable_handles[].
 * In the dpa_app model this array is always empty (tables are
 * tracked in fman_info->tbl_info[] instead), but we keep this
 * as a safety net.
 */
void
cdx_dpa_destroy(void)
{
	unsigned int i;

	for (i = 0; i < HTABLE_COUNT; i++) {
		if (htable_handles[i] != NULL) {
			ExternalHashTableDelete(htable_handles[i]);
			htable_handles[i] = NULL;
		}
	}
}

/*
 * Clear the htable_handles array without freeing.
 *
 * Called by cdx_dpa_bridge_destroy() after hash tables have been
 * freed through fman_info->tbl_info[].  Prevents double-free if
 * handles were ever shared between both tracking mechanisms.
 */
void
cdx_dpa_clear_handles(void)
{

	memset(htable_handles, 0, sizeof(htable_handles));
}
