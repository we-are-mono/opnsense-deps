/*
 * CDX sysctl stats — FreeBSD port
 *
 * Replaces procfs.c. Exposes CDX module statistics and FQID information
 * via sysctl dev.cdx.* instead of /proc/fqid_stats/.
 *
 * Per-FQID stats functions (cdx_init_fqid_procfs, cdx_create_dir_in_procfs,
 * cdx_create_type_fqid_info_in_procfs, cdx_remove_fqid_info_in_procfs)
 * are no-ops — they would create dynamic sysctl nodes for QMan queue
 * introspection.  This is a monitoring enhancement, not required for
 * data-plane operation.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2022 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/module.h>

#include "portdefs.h"
#include "cdx.h"

/* Forward declarations — exported to other CDX files */
void cdx_sysctl_init(void);
void cdx_sysctl_fini(void);
int cdx_init_fqid_procfs(void);
int cdx_create_dir_in_procfs(void **proc_dir_entry, char *name, uint32_t type);
void cdx_remove_fqid_info_in_procfs(uint32_t fqid);
int cdx_create_type_fqid_info_in_procfs(struct qman_fq *fq, uint32_t type,
    void *proc_entry, uint8_t *fq_alias_name);

/* ------------------------------------------------------------------
 * sysctl tree: dev.cdx.*
 * ------------------------------------------------------------------ */

static struct sysctl_ctx_list	cdx_sysctl_ctx;
static struct sysctl_oid	*cdx_sysctl_tree;

/* Counters exposed via sysctl */
static unsigned long cdx_stat_fci_commands;
static unsigned long cdx_stat_timer_ticks;

/* sysctl handler for active connections — reads the global atomic */
static int
sysctl_cdx_active_conn(SYSCTL_HANDLER_ARGS)
{
	unsigned long val;

	val = (unsigned long)atomic_read(&num_active_connections);
	return (sysctl_handle_long(oidp, &val, 0, req));
}

void
cdx_sysctl_init(void)
{
	struct sysctl_oid *stats_node;

	sysctl_ctx_init(&cdx_sysctl_ctx);

	cdx_sysctl_tree = SYSCTL_ADD_NODE(&cdx_sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_dev), OID_AUTO, "cdx",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, 0, "CDX data-plane module");

	/* dev.cdx.version */
	SYSCTL_ADD_STRING(&cdx_sysctl_ctx,
	    SYSCTL_CHILDREN(cdx_sysctl_tree), OID_AUTO, "version",
	    CTLFLAG_RD, __DECONST(char *, "5.03.1-fbsd"), 0,
	    "CDX module version");

	/* dev.cdx.stats.* */
	stats_node = SYSCTL_ADD_NODE(&cdx_sysctl_ctx,
	    SYSCTL_CHILDREN(cdx_sysctl_tree), OID_AUTO, "stats",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, 0, "CDX statistics");

	SYSCTL_ADD_PROC(&cdx_sysctl_ctx,
	    SYSCTL_CHILDREN(stats_node), OID_AUTO, "active_connections",
	    CTLTYPE_ULONG | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    NULL, 0, sysctl_cdx_active_conn, "LU",
	    "Number of active forwarding connections");

	SYSCTL_ADD_ULONG(&cdx_sysctl_ctx,
	    SYSCTL_CHILDREN(stats_node), OID_AUTO, "fci_commands",
	    CTLFLAG_RD, &cdx_stat_fci_commands,
	    "FCI commands processed");

	SYSCTL_ADD_ULONG(&cdx_sysctl_ctx,
	    SYSCTL_CHILDREN(stats_node), OID_AUTO, "timer_ticks",
	    CTLFLAG_RD, &cdx_stat_timer_ticks,
	    "Timer wheel ticks");
}

void
cdx_sysctl_fini(void)
{
	sysctl_ctx_free(&cdx_sysctl_ctx);
}

/* ------------------------------------------------------------------
 * Per-FQID statistics stubs
 *
 * These are called by devman.c / dpa_cfg.c to create per-FQID
 * /proc entries.  On FreeBSD, these would become dynamic sysctl
 * nodes under dev.cdx.fqid.*.  Currently no-ops — per-FQID stats
 * are a monitoring enhancement that doesn't affect data-plane
 * operation.
 * ------------------------------------------------------------------ */

int
cdx_init_fqid_procfs(void)
{
	return (0);
}

/*
 * Create a sub-directory in the FQID stats hierarchy.
 * type: TX_DIR, RX_DIR, PCD_DIR, SA_DIR
 */
static int procfs_dummy;

int
cdx_create_dir_in_procfs(void **proc_dir_entry, char *name, uint32_t type)
{
	/* Stub — returns a non-NULL dummy so callers don't error out */
	*proc_dir_entry = &procfs_dummy;
	return (0);
}

/* Remove per-FQID sysctl node */
void
cdx_remove_fqid_info_in_procfs(uint32_t fqid)
{
	/* Stub */
}

/* Create per-FQID sysctl node under the appropriate type directory */
int
cdx_create_type_fqid_info_in_procfs(struct qman_fq *fq, uint32_t type,
    void *proc_entry, uint8_t *fq_alias_name)
{
	/* Stub */
	return (0);
}
