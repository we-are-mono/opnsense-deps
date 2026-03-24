/*
 * cmm_conn.h — PF state table polling and connection tracking
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_CONN_H
#define CMM_CONN_H

#include "cmm.h"
#include "cmm_route.h"

#define CONN_HASH_SIZE		16384

/* Connection flags */
#define CONN_F_OFFLOADED	0x01	/* programmed into CDX */
#define CONN_F_ORIG_DIR		0x02	/* offload original direction */
#define CONN_F_REP_DIR		0x04	/* offload reply direction */
#define CONN_F_HAS_NAT		0x08	/* reply tuples from PF_OUT (NAT) */

struct cmm_conn {
	struct list_head	hash_entry;	/* hash by original 5-tuple */

	/* Original direction 5-tuple (from PF_SK_STACK) */
	sa_family_t		af;
	uint8_t			proto;
	uint8_t			orig_saddr[16];
	uint8_t			orig_daddr[16];
	uint16_t		orig_sport;
	uint16_t		orig_dport;

	/* Reply direction (from PF_SK_STACK, reversed for NAT) */
	uint8_t			rep_saddr[16];
	uint8_t			rep_daddr[16];
	uint16_t		rep_sport;
	uint16_t		rep_dport;

	/* PF tracking */
	uint64_t		pf_id;
	uint32_t		pf_creatorid;
	uint8_t			pf_direction;

	/* NAT companion PF state (PF_OUT state for NAT connections) */
	uint64_t		pf_id_nat;
	uint32_t		pf_creatorid_nat;
	uint8_t			pf_has_nat_id;

	char			ifname[IFNAMSIZ];

	/* Offload state */
	int			flags;

	/* Routes for each direction */
	struct cmm_route	*orig_route;
	struct cmm_route	*rep_route;

};

/* Initialize connection table */
int cmm_conn_init(void);
void cmm_conn_fini(struct cmm_global *g);

/*
 * Handle push-based PF state events from /dev/pfnotify.
 * Called from the event loop when the pfnotify fd is readable.
 */
void cmm_conn_event(struct cmm_global *g);

/*
 * Periodic maintenance: retry offload for pending connections,
 * garbage-collect unreferenced routes, log stats.
 */
void cmm_conn_maintenance(struct cmm_global *g);

/* Remove all offloaded connections (e.g. on shutdown) */
void cmm_conn_deregister_all(struct cmm_global *g);

/* Deregister connections using a changed route, clearing their route pointers */
void cmm_route_invalidate_conns(struct cmm_global *g, struct cmm_route *rt);

/*
 * Sync CDX hardware flow counters into PF state table.
 * Queries per-flow stats from CDX and pushes deltas via pfnotify ioctl.
 */
void cmm_conn_stats_sync(struct cmm_global *g);

/*
 * Handle FCI async events (CDX conntrack timeout/FIN notifications).
 * Called from the top-level FCI event dispatcher in cmm.c.
 * Returns FCI_CB_CONTINUE for unrecognized events.
 */
int cmm_conn_fci_event(unsigned short fcode, unsigned short len,
    unsigned short *payload);

/*
 * Full offload state reset: deregister all connections from CDX,
 * flush routes and neighbors.  Connections stay in the table and
 * re-offload on the next maintenance cycle.  Used on interface
 * reassignment.
 */
void cmm_reset_offload_state(struct cmm_global *g);

#endif /* CMM_CONN_H */
