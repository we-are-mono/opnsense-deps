/*
 * FCI sysctl stats — replaces Linux /proc/fci
 *
 * Exports FCI statistics under dev.fci.stats.*
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

/* Prototypes — called from fci_freebsd.c */
void fci_sysctl_init(unsigned long *tx_msg, unsigned long *rx_msg,
    unsigned long *tx_err, unsigned long *rx_err, unsigned long *mem_err);
void fci_sysctl_fini(void);

static struct sysctl_ctx_list fci_sysctl_ctx;
static struct sysctl_oid *fci_sysctl_tree;

void
fci_sysctl_init(unsigned long *tx_msg, unsigned long *rx_msg,
    unsigned long *tx_err, unsigned long *rx_err, unsigned long *mem_err)
{
	struct sysctl_oid *stats;

	sysctl_ctx_init(&fci_sysctl_ctx);

	fci_sysctl_tree = SYSCTL_ADD_NODE(&fci_sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_dev), OID_AUTO, "fci",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, 0, "FCI device");

	stats = SYSCTL_ADD_NODE(&fci_sysctl_ctx,
	    SYSCTL_CHILDREN(fci_sysctl_tree), OID_AUTO, "stats",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, 0, "FCI statistics");

	SYSCTL_ADD_ULONG(&fci_sysctl_ctx, SYSCTL_CHILDREN(stats),
	    OID_AUTO, "tx_msg", CTLFLAG_RD, tx_msg,
	    "Messages sent to userspace");

	SYSCTL_ADD_ULONG(&fci_sysctl_ctx, SYSCTL_CHILDREN(stats),
	    OID_AUTO, "rx_msg", CTLFLAG_RD, rx_msg,
	    "Messages received from userspace");

	SYSCTL_ADD_ULONG(&fci_sysctl_ctx, SYSCTL_CHILDREN(stats),
	    OID_AUTO, "tx_msg_err", CTLFLAG_RD, tx_err,
	    "Transmit errors");

	SYSCTL_ADD_ULONG(&fci_sysctl_ctx, SYSCTL_CHILDREN(stats),
	    OID_AUTO, "rx_msg_err", CTLFLAG_RD, rx_err,
	    "Receive errors");

	SYSCTL_ADD_ULONG(&fci_sysctl_ctx, SYSCTL_CHILDREN(stats),
	    OID_AUTO, "mem_alloc_err", CTLFLAG_RD, mem_err,
	    "Memory allocation errors");
}

void
fci_sysctl_fini(void)
{
	sysctl_ctx_free(&fci_sysctl_ctx);
}
