/*
 * cmm_route.h — Route lookup and caching
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_ROUTE_H
#define CMM_ROUTE_H

#include <net/route.h>

#include "cmm.h"
#include "cmm_neigh.h"

#define ROUTE_HASH_SIZE		256

struct cmm_route {
	struct list_head	entry;		/* hash bucket chain */
	int			refcount;
	sa_family_t		family;
	uint8_t			dst[16];	/* destination (net order) */
	uint8_t			gw[16];		/* gateway / next-hop */
	uint8_t			src[16];	/* preferred source */
	int			oif_index;	/* output interface index */
	int			iif_index;	/* input interface index (set by conn) */
	uint16_t		mtu;
	uint32_t		rt_flags;	/* RTF_GATEWAY, RTF_HOST, ... */
	uint32_t		fpp_id;		/* FPP route ID */
	int			fpp_programmed;	/* sent to CDX */
	struct cmm_neigh	*neigh;		/* resolved next-hop */
};

/* Initialize route cache */
int cmm_route_init(void);
void cmm_route_fini(void);

/*
 * Get route for destination.  Resolves via route socket RTM_GET.
 * Returns NULL if no route.  Caller must call cmm_route_put().
 */
struct cmm_route *cmm_route_get(struct cmm_global *g, sa_family_t af,
    const void *dst);

/* Release reference */
void cmm_route_put(struct cmm_route *rt);

/* Free routes with refcount 0 (call after connection sweep) */
void cmm_route_gc(struct cmm_global *g);

/* Handle routing socket changes — invalidate affected routes */
void cmm_route_handle_change(struct cmm_global *g, struct rt_msghdr *rtm);

/* Send route to CDX via FPP */
int cmm_route_send_fpp(struct cmm_global *g, struct cmm_route *rt,
    int action);

/* Invalidate all routes using a specific output interface */
void cmm_route_invalidate_by_oif(struct cmm_global *g, int oif_index);

/* Allocate a new unique route ID */
uint32_t cmm_route_alloc_id(struct cmm_global *g);

/* Deregister and free all cached routes (full reset) */
void cmm_route_flush_all(struct cmm_global *g);

#endif /* CMM_ROUTE_H */
