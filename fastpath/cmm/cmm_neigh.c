/*
 * cmm_neigh.c — ARP/NDP neighbor resolution
 *
 * Resolves next-hop IP addresses to MAC addresses by querying
 * FreeBSD's link-layer table via sysctl(NET_RT_FLAGS).
 *
 * On FreeBSD 13+, ARP/NDP entries live in a separate lltable,
 * not as cloned host routes in the FIB.  RTM_GET returns the
 * network route (no MAC), so we use sysctl to walk the lltable
 * directly — the same method arp(8) uses.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "cmm.h"
#include "cmm_neigh.h"
#include "cmm_itf.h"
#include "cmm_rtsock.h"

static struct list_head neigh_hash[NEIGH_HASH_SIZE];

static inline unsigned int
neigh_hash_index(sa_family_t af, const void *ip)
{
	if (af == AF_INET)
		return (jhash(ip, 4, 0) % NEIGH_HASH_SIZE);
	else
		return (jhash(ip, 16, 0) % NEIGH_HASH_SIZE);
}

static struct cmm_neigh *
neigh_find(sa_family_t af, const void *ip, int ifindex)
{
	struct list_head *bucket, *pos;
	struct cmm_neigh *neigh;
	unsigned int h;
	int alen;

	h = neigh_hash_index(af, ip);
	bucket = &neigh_hash[h];
	alen = (af == AF_INET) ? 4 : 16;

	for (pos = list_first(bucket); pos != bucket; pos = list_next(pos)) {
		neigh = container_of(pos, struct cmm_neigh, entry);
		if (neigh->family == af &&
		    neigh->ifindex == ifindex &&
		    memcmp(neigh->ipaddr, ip, alen) == 0)
			return (neigh);
	}
	return (NULL);
}

/*
 * Resolve neighbor by walking the kernel's link-layer table
 * via sysctl(NET_RT_FLAGS).  Each entry is an rt_msghdr followed
 * by sockaddrs: DST (sockaddr_in/in6) + GATEWAY (sockaddr_dl).
 *
 * Returns 0 on success, -1 on failure.
 */
static int
neigh_resolve(struct cmm_global *g __unused, struct cmm_neigh *neigh)
{
	int mib[6];
	size_t needed;
	char *buf, *next, *lim;
	struct rt_msghdr *rtm;
	struct cmm_rtsock_addrs addrs;

	/*
	 * PPPoE is point-to-point — no ARP.  The peer MAC is known
	 * from PPPoE session negotiation, stored in the interface.
	 */
	{
		struct cmm_interface *itf;

		itf = cmm_itf_find_by_index(neigh->ifindex);
		if (itf != NULL && (itf->itf_flags & ITF_F_PPPOE)) {
			memcpy(neigh->macaddr, itf->pppoe_peer_mac,
			    ETHER_ADDR_LEN);
			neigh->state = NEIGH_RESOLVED;
			return (0);
		}
	}

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = neigh->family;
	mib[4] = NET_RT_FLAGS;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		neigh->state = NEIGH_FAILED;
		return (-1);
	}

	if (needed == 0) {
		neigh->state = NEIGH_INCOMPLETE;
		return (-1);
	}

	buf = malloc(needed);
	if (buf == NULL) {
		neigh->state = NEIGH_FAILED;
		return (-1);
	}

	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
		free(buf);
		neigh->state = NEIGH_FAILED;
		return (-1);
	}

	lim = buf + needed;
	for (next = buf; next < lim; ) {
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_msglen == 0)
			break;
		next += rtm->rtm_msglen;

		cmm_rtsock_parse_addrs(rtm, &addrs);

		if (addrs.dst == NULL || addrs.gateway == NULL)
			continue;
		if (addrs.gateway->sa_family != AF_LINK)
			continue;

		/* Match destination IP */
		if (neigh->family == AF_INET) {
			struct sockaddr_in *sin;

			if (addrs.dst->sa_family != AF_INET)
				continue;
			sin = (struct sockaddr_in *)addrs.dst;
			if (memcmp(&sin->sin_addr, neigh->ipaddr, 4) != 0)
				continue;
		} else {
			struct sockaddr_in6 *sin6;

			if (addrs.dst->sa_family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)addrs.dst;
			if (memcmp(&sin6->sin6_addr, neigh->ipaddr, 16) != 0)
				continue;
		}

		/* Found — extract MAC from sockaddr_dl gateway */
		{
			struct sockaddr_dl *sdl;

			sdl = (struct sockaddr_dl *)addrs.gateway;
			if (sdl->sdl_alen != ETHER_ADDR_LEN)
				continue;

			memcpy(neigh->macaddr, LLADDR(sdl), ETHER_ADDR_LEN);
			neigh->state = NEIGH_RESOLVED;
			free(buf);
			return (0);
		}
	}

	free(buf);
	neigh->state = NEIGH_INCOMPLETE;
	return (-1);
}

int
cmm_neigh_init(void)
{
	int i;

	for (i = 0; i < NEIGH_HASH_SIZE; i++)
		list_head_init(&neigh_hash[i]);
	return (0);
}

void
cmm_neigh_fini(void)
{
	struct cmm_neigh *neigh;
	struct list_head *pos, *tmp;
	int i;

	for (i = 0; i < NEIGH_HASH_SIZE; i++) {
		pos = list_first(&neigh_hash[i]);
		while (pos != &neigh_hash[i]) {
			tmp = list_next(pos);
			neigh = container_of(pos, struct cmm_neigh, entry);
			list_del(&neigh->entry);
			free(neigh);
			pos = tmp;
		}
	}
}

struct cmm_neigh *
cmm_neigh_get(struct cmm_global *g, sa_family_t af,
    const void *ip, int ifindex)
{
	struct cmm_neigh *neigh;
	unsigned int h;
	int alen;

	neigh = neigh_find(af, ip, ifindex);
	if (neigh != NULL) {
		if (neigh->state == NEIGH_RESOLVED) {
			neigh->refcount++;
			return (neigh);
		}
		/* Try to re-resolve stale/incomplete entry */
		if (neigh_resolve(g, neigh) == 0) {
			neigh->refcount++;
			return (neigh);
		}
		/*
		 * Re-resolve failed.  If nobody holds a reference,
		 * remove the stale entry so a fresh one can be
		 * created on the next attempt.
		 */
		if (neigh->refcount == 0) {
			list_del(&neigh->entry);
			free(neigh);
		}
		return (NULL);
	}

	/* Create new entry */
	alen = (af == AF_INET) ? 4 : 16;
	neigh = calloc(1, sizeof(*neigh));
	if (neigh == NULL)
		return (NULL);

	neigh->family = af;
	memcpy(neigh->ipaddr, ip, alen);
	neigh->ifindex = ifindex;
	neigh->state = NEIGH_INCOMPLETE;
	neigh->entry.next = NULL;
	neigh->entry.prev = NULL;

	h = neigh_hash_index(af, ip);
	list_add(&neigh_hash[h], &neigh->entry);

	if (neigh_resolve(g, neigh) == 0) {
		if (af == AF_INET) {
			char abuf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, ip, abuf, sizeof(abuf));
			cmm_print(CMM_LOG_DEBUG,
			    "neigh: resolved %s -> "
			    "%02x:%02x:%02x:%02x:%02x:%02x",
			    abuf,
			    neigh->macaddr[0], neigh->macaddr[1],
			    neigh->macaddr[2], neigh->macaddr[3],
			    neigh->macaddr[4], neigh->macaddr[5]);
		}
		neigh->refcount++;
		return (neigh);
	}

	cmm_print(CMM_LOG_DEBUG, "neigh: resolution failed for ifindex=%d",
	    ifindex);
	return (NULL);
}

void
cmm_neigh_put(struct cmm_neigh *neigh)
{
	if (neigh == NULL)
		return;
	if (neigh->refcount > 0)
		neigh->refcount--;
}

void
cmm_neigh_flush_ifindex(int ifindex)
{
	struct cmm_neigh *neigh;
	struct list_head *pos;
	int i;

	for (i = 0; i < NEIGH_HASH_SIZE; i++) {
		for (pos = list_first(&neigh_hash[i]);
		    pos != &neigh_hash[i]; pos = list_next(pos)) {
			neigh = container_of(pos, struct cmm_neigh, entry);
			if (neigh->ifindex == ifindex)
				neigh->state = NEIGH_STALE;
		}
	}
}

void
cmm_neigh_flush_all(void)
{
	struct cmm_neigh *neigh;
	struct list_head *pos;
	int i;

	for (i = 0; i < NEIGH_HASH_SIZE; i++) {
		for (pos = list_first(&neigh_hash[i]);
		    pos != &neigh_hash[i]; pos = list_next(pos)) {
			neigh = container_of(pos, struct cmm_neigh, entry);
			neigh->state = NEIGH_STALE;
		}
	}
}

void
cmm_neigh_invalidate(sa_family_t af, const void *ip)
{
	struct cmm_neigh *neigh;
	unsigned int h;
	struct list_head *pos;
	int alen;

	h = neigh_hash_index(af, ip);
	alen = (af == AF_INET) ? 4 : 16;

	for (pos = list_first(&neigh_hash[h]); pos != &neigh_hash[h];
	    pos = list_next(pos)) {
		neigh = container_of(pos, struct cmm_neigh, entry);
		if (neigh->family == af &&
		    memcmp(neigh->ipaddr, ip, alen) == 0) {
			neigh->state = NEIGH_STALE;
			return;
		}
	}
}
