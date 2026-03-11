/*
 * cmm_route.c — Route lookup and caching
 *
 * Looks up routes via the PF_ROUTE socket (RTM_GET) and caches
 * results.  Monitors route changes via the same socket.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "cmm.h"
#include "cmm_route.h"
#include "cmm_conn.h"
#include "cmm_rtsock.h"
#include "cmm_itf.h"
#include "cmm_fe.h"
#include "cmm_tunnel.h"
#include "cmm_socket.h"

static struct list_head route_hash[ROUTE_HASH_SIZE];

static inline unsigned int
route_hash_index(sa_family_t af, const void *dst)
{
	if (af == AF_INET)
		return (jhash(dst, 4, 0) % ROUTE_HASH_SIZE);
	else
		return (jhash(dst, 16, 0) % ROUTE_HASH_SIZE);
}

static struct cmm_route *
route_find(sa_family_t af, const void *dst)
{
	struct list_head *bucket, *pos;
	struct cmm_route *rt;
	unsigned int h;
	int alen;

	h = route_hash_index(af, dst);
	bucket = &route_hash[h];
	alen = (af == AF_INET) ? 4 : 16;

	for (pos = list_first(bucket); pos != bucket; pos = list_next(pos)) {
		rt = container_of(pos, struct cmm_route, entry);
		if (rt->family == af && memcmp(rt->dst, dst, alen) == 0)
			return (rt);
	}
	return (NULL);
}

/*
 * Resolve route via RTM_GET.
 * Returns 0 on success, -1 on failure.
 */
static int
route_resolve(struct cmm_global *g, struct cmm_route *rt)
{
	char reply[1024];
	size_t replylen;
	struct rt_msghdr *rtm;
	struct cmm_rtsock_addrs addrs;

	if (rt->family == AF_INET) {
		struct sockaddr_in sin;

		memset(&sin, 0, sizeof(sin));
		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
		memcpy(&sin.sin_addr, rt->dst, 4);

		replylen = sizeof(reply);
		if (cmm_rtsock_get(g->rtsock_query_fd, (struct sockaddr *)&sin,
		    0, reply, &replylen) < 0)
			return (-1);
	} else {
		struct sockaddr_in6 sin6;

		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_len = sizeof(sin6);
		sin6.sin6_family = AF_INET6;
		memcpy(&sin6.sin6_addr, rt->dst, 16);

		replylen = sizeof(reply);
		if (cmm_rtsock_get(g->rtsock_query_fd, (struct sockaddr *)&sin6,
		    0, reply, &replylen) < 0)
			return (-1);
	}

	rtm = (struct rt_msghdr *)reply;
	cmm_rtsock_parse_addrs(rtm, &addrs);

	rt->rt_flags = rtm->rtm_flags;
	rt->mtu = rtm->rtm_rmx.rmx_mtu;

	/* Get output interface */
	if (addrs.ifp != NULL) {
		rt->oif_index = addrs.ifp->sdl_index;
	} else {
		rt->oif_index = rtm->rtm_index;
	}

	/* Get gateway */
	if ((rtm->rtm_flags & RTF_GATEWAY) && addrs.gateway != NULL) {
		if (addrs.gateway->sa_family == AF_INET) {
			struct sockaddr_in *gw;
			gw = (struct sockaddr_in *)addrs.gateway;
			memcpy(rt->gw, &gw->sin_addr, 4);
		} else if (addrs.gateway->sa_family == AF_INET6) {
			struct sockaddr_in6 *gw6;
			gw6 = (struct sockaddr_in6 *)addrs.gateway;
			memcpy(rt->gw, &gw6->sin6_addr, 16);
		}
	} else {
		/* Directly connected — next-hop is the destination */
		memcpy(rt->gw, rt->dst,
		    (rt->family == AF_INET) ? 4 : 16);
	}

	/* Get preferred source */
	if (addrs.ifa != NULL) {
		if (addrs.ifa->sa_family == AF_INET) {
			struct sockaddr_in *src;
			src = (struct sockaddr_in *)addrs.ifa;
			memcpy(rt->src, &src->sin_addr, 4);
		} else if (addrs.ifa->sa_family == AF_INET6) {
			struct sockaddr_in6 *src6;
			src6 = (struct sockaddr_in6 *)addrs.ifa;
			memcpy(rt->src, &src6->sin6_addr, 16);
		}
	}

	/* Clamp MTU to interface MTU if not set */
	if (rt->mtu == 0) {
		struct cmm_interface *itf;
		itf = cmm_itf_find_by_index(rt->oif_index);
		if (itf != NULL)
			rt->mtu = itf->mtu;
		if (rt->mtu == 0)
			rt->mtu = 1500;
	}

	return (0);
}

int
cmm_route_init(void)
{
	int i;

	for (i = 0; i < ROUTE_HASH_SIZE; i++)
		list_head_init(&route_hash[i]);
	return (0);
}

void
cmm_route_fini(void)
{
	struct cmm_route *rt;
	struct list_head *pos, *tmp;
	int i;

	for (i = 0; i < ROUTE_HASH_SIZE; i++) {
		pos = list_first(&route_hash[i]);
		while (pos != &route_hash[i]) {
			tmp = list_next(pos);
			rt = container_of(pos, struct cmm_route, entry);
			if (rt->neigh != NULL)
				cmm_neigh_put(rt->neigh);
			list_del(&rt->entry);
			free(rt);
			pos = tmp;
		}
	}
}

static int
route_id_in_use(uint32_t id)
{
	int i;

	for (i = 0; i < ROUTE_HASH_SIZE; i++) {
		struct list_head *pos;

		for (pos = list_first(&route_hash[i]);
		    pos != &route_hash[i]; pos = list_next(pos)) {
			struct cmm_route *rt;

			rt = container_of(pos, struct cmm_route, entry);
			if (rt->fpp_id == id)
				return (1);
		}
	}
	return (0);
}

uint32_t
cmm_route_alloc_id(struct cmm_global *g)
{
	uint32_t id;
	int tries;

	for (tries = 0; tries < 65536; tries++) {
		id = ++g->next_route_id;
		if (id == 0)
			id = ++g->next_route_id;
		if (!route_id_in_use(id))
			return (id);
	}
	return (0);	/* exhausted */
}

struct cmm_route *
cmm_route_get(struct cmm_global *g, sa_family_t af, const void *dst)
{
	struct cmm_route *rt;
	unsigned int h;
	int alen;

	rt = route_find(af, dst);
	if (rt != NULL) {
		rt->refcount++;
		return (rt);
	}

	/* Create and resolve */
	alen = (af == AF_INET) ? 4 : 16;
	rt = calloc(1, sizeof(*rt));
	if (rt == NULL)
		return (NULL);

	rt->family = af;
	memcpy(rt->dst, dst, alen);
	rt->fpp_id = cmm_route_alloc_id(g);
	if (rt->fpp_id == 0) {
		cmm_print(CMM_LOG_ERR, "route: route ID space exhausted");
		free(rt);
		return (NULL);
	}
	rt->entry.next = NULL;
	rt->entry.prev = NULL;

	h = route_hash_index(af, dst);
	list_add(&route_hash[h], &rt->entry);

	if (route_resolve(g, rt) < 0) {
		list_del(&rt->entry);
		free(rt);
		return (NULL);
	}

	/* Resolve next-hop neighbor */
	rt->neigh = cmm_neigh_get(g, af, rt->gw, rt->oif_index);

	if (rt->family == AF_INET) {
		char dbuf[INET_ADDRSTRLEN], gbuf[INET_ADDRSTRLEN];
		struct cmm_interface *itf;

		inet_ntop(AF_INET, rt->dst, dbuf, sizeof(dbuf));
		inet_ntop(AF_INET, rt->gw, gbuf, sizeof(gbuf));
		itf = cmm_itf_find_by_index(rt->oif_index);
		cmm_print(CMM_LOG_DEBUG,
		    "route: %s via %s dev %s mtu %u id %u neigh=%s",
		    dbuf, gbuf,
		    itf ? itf->ifname : "?",
		    rt->mtu, rt->fpp_id,
		    rt->neigh ? "resolved" : "pending");
	}

	rt->refcount = 1;
	return (rt);
}

void
cmm_route_put(struct cmm_route *rt)
{
	if (rt == NULL)
		return;
	if (rt->refcount > 0)
		rt->refcount--;
}

void
cmm_route_gc(struct cmm_global *g)
{
	struct cmm_route *rt;
	struct list_head *pos, *tmp;
	int i;

	for (i = 0; i < ROUTE_HASH_SIZE; i++) {
		pos = list_first(&route_hash[i]);
		while (pos != &route_hash[i]) {
			tmp = list_next(pos);
			rt = container_of(pos, struct cmm_route, entry);
			if (rt->refcount == 0) {
				if (rt->fpp_programmed)
					cmm_fe_route_deregister(g, rt);
				if (rt->neigh != NULL)
					cmm_neigh_put(rt->neigh);
				list_del(&rt->entry);
				free(rt);
			}
			pos = tmp;
		}
	}
}

void
cmm_route_handle_change(struct cmm_global *g, struct rt_msghdr *rtm)
{
	struct cmm_rtsock_addrs addrs;
	struct cmm_route *rt;
	struct list_head *pos;
	uint8_t old_gw[16];
	int old_oif, alen, i;

	cmm_rtsock_parse_addrs(rtm, &addrs);

	cmm_print(CMM_LOG_DEBUG, "route: RTM_%s flags=0x%x",
	    rtm->rtm_type == RTM_ADD ? "ADD" :
	    rtm->rtm_type == RTM_DELETE ? "DELETE" : "CHANGE",
	    rtm->rtm_flags);

	/*
	 * Re-resolve all cached routes.  This is conservative but safe.
	 * If the gateway or output interface changed, deregister the
	 * stale CDX route and all connections using it.  They will
	 * re-offload on the next poll cycle with the new path.
	 */
	for (i = 0; i < ROUTE_HASH_SIZE; i++) {
		for (pos = list_first(&route_hash[i]);
		    pos != &route_hash[i]; pos = list_next(pos)) {
			rt = container_of(pos, struct cmm_route, entry);

			/* Save old values before re-resolving */
			old_oif = rt->oif_index;
			memcpy(old_gw, rt->gw, sizeof(old_gw));

			/* Drop old neighbor, re-resolve */
			if (rt->neigh != NULL) {
				cmm_neigh_put(rt->neigh);
				rt->neigh = NULL;
			}
			route_resolve(g, rt);
			rt->neigh = cmm_neigh_get(g, rt->family,
			    rt->gw, rt->oif_index);

			/* If nothing changed, skip CDX invalidation */
			alen = (rt->family == AF_INET) ? 4 : 16;
			if (rt->oif_index == old_oif &&
			    memcmp(rt->gw, old_gw, alen) == 0)
				continue;

			/* Route changed — tear down stale CDX state */
			cmm_print(CMM_LOG_INFO,
			    "route: id=%u changed, deregistering",
			    rt->fpp_id);
			cmm_route_invalidate_conns(g, rt);
			cmm_fe_route_deregister(g, rt);
		}
	}

	/* Re-evaluate tunnel and socket registrations after route changes */
	cmm_tunnel_route_update(g);
	cmm_socket_route_update(g);
}

/*
 * Invalidate all cached routes whose output interface matches oif_index.
 * Deregisters CDX routes and tears down offloaded connections.
 * Used by LAGG failover to force re-offload through the new member port.
 */
void
cmm_route_invalidate_by_oif(struct cmm_global *g, int oif_index)
{
	struct cmm_route *rt;
	struct list_head *pos;
	int i, count = 0;

	for (i = 0; i < ROUTE_HASH_SIZE; i++) {
		for (pos = list_first(&route_hash[i]);
		    pos != &route_hash[i]; pos = list_next(pos)) {
			rt = container_of(pos, struct cmm_route, entry);

			if (rt->oif_index != oif_index &&
			    rt->iif_index != oif_index)
				continue;

			cmm_route_invalidate_conns(g, rt);
			cmm_fe_route_deregister(g, rt);
			count++;
		}
	}

	if (count > 0)
		cmm_print(CMM_LOG_INFO,
		    "route: invalidated %d route(s) on ifindex %d",
		    count, oif_index);
}

int
cmm_route_send_fpp(struct cmm_global *g, struct cmm_route *rt, int action)
{
	if (rt->neigh == NULL || rt->neigh->state != NEIGH_RESOLVED) {
		cmm_print(CMM_LOG_DEBUG,
		    "route: can't send FPP — neighbor not resolved");
		return (-1);
	}

	return (cmm_fe_route_register(g, rt));
}
