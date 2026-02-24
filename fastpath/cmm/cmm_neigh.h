/*
 * cmm_neigh.h — ARP/NDP neighbor resolution
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_NEIGH_H
#define CMM_NEIGH_H

#include "cmm.h"

#define NEIGH_HASH_SIZE		256

/* Neighbor states */
#define NEIGH_INCOMPLETE	0
#define NEIGH_RESOLVED		1
#define NEIGH_STALE		2
#define NEIGH_FAILED		3

struct cmm_neigh {
	struct list_head	entry;		/* hash bucket chain */
	int			refcount;
	sa_family_t		family;
	uint8_t			ipaddr[16];	/* network byte order */
	uint8_t			macaddr[ETHER_ADDR_LEN];
	int			ifindex;
	int			state;
};

/* Initialize neighbor table */
int cmm_neigh_init(void);
void cmm_neigh_fini(void);

/*
 * Get or create neighbor entry.  Resolves via route socket RTM_GET
 * with RTF_LLINFO.  Returns NULL if resolution fails.
 * Caller must call cmm_neigh_put() when done.
 */
struct cmm_neigh *cmm_neigh_get(struct cmm_global *g, sa_family_t af,
    const void *ip, int ifindex);

/* Release reference */
void cmm_neigh_put(struct cmm_neigh *neigh);

/* Invalidate all neighbors on a given interface */
void cmm_neigh_flush_ifindex(int ifindex);

/* Invalidate a specific neighbor (e.g. on ARP change) */
void cmm_neigh_invalidate(sa_family_t af, const void *ip);

#endif /* CMM_NEIGH_H */
