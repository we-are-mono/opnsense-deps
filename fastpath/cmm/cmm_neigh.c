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
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
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
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>
#include <netlink/netlink_snl_route_parsers.h>

#include "cmm.h"
#include "cmm_neigh.h"
#include "cmm_itf.h"
#include "cmm_pppoe.h"
#include "cmm_rtsock.h"

static struct list_head neigh_hash[NEIGH_HASH_TOTAL];

static inline unsigned int
neigh_hash_index(sa_family_t af, const void *ip)
{
	if (af == AF_INET)
		return (jhash(ip, 4, 0) % NEIGH_HASH_SIZE);
	else
		return (jhash(ip, 16, 0) % NEIGH_HASH_SIZE) + NEIGH_HASH_SIZE;
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

/* PPPoE is point-to-point, no ARP: the peer MAC comes from the session. */
static int
neigh_pppoe(struct cmm_neigh *neigh)
{
	struct cmm_interface *itf;

	itf = cmm_itf_find_by_index(neigh->ifindex);
	if (itf == NULL || !(itf->itf_flags & ITF_F_PPPOE))
		return (-1);
	memcpy(neigh->macaddr, itf->pppoe_peer_mac, ETHER_ADDR_LEN);
	neigh->state = NEIGH_RESOLVED;
	return (0);
}

/*
 * Copy the kernel's link-layer table for one address family via
 * sysctl(NET_RT_FLAGS), the same method arp(8) uses. Returns a buffer
 * to free(), or NULL with *len 0 when the table is empty.
 */
static char *
neigh_table(sa_family_t af, size_t *len, int *failed)
{
	int mib[6] = { CTL_NET, PF_ROUTE, 0, af, NET_RT_FLAGS, 0 };
	char *buf;

	*len = 0;
	*failed = 0;
	if (sysctl(mib, 6, NULL, len, NULL, 0) < 0) {
		*failed = 1;
		return (NULL);
	}
	if (*len == 0)
		return (NULL);
	buf = malloc(*len);
	if (buf == NULL || sysctl(mib, 6, buf, len, NULL, 0) < 0) {
		free(buf);
		*len = 0;
		*failed = 1;
		return (NULL);
	}
	return (buf);
}

/*
 * Find the neighbor in a copied table. Each entry is an rt_msghdr followed
 * by sockaddrs: DST (sockaddr_in/in6) + GATEWAY (sockaddr_dl).
 * Returns 0 and sets the MAC on success, -1 if it isn't there.
 */
static int
neigh_find_in_table(const char *buf, size_t len, struct cmm_neigh *neigh)
{
	const char *next, *lim;
	struct rt_msghdr *rtm;
	struct cmm_rtsock_addrs addrs;

	lim = buf + len;
	for (next = buf; next < lim; ) {
		rtm = (struct rt_msghdr *)(uintptr_t)next;
		if (rtm->rtm_msglen == 0)
			break;
		next += rtm->rtm_msglen;

		cmm_rtsock_parse_addrs(rtm, rtm->rtm_msglen, &addrs);

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
			return (0);
		}
	}
	return (-1);
}

/*
 * Resolve one neighbor from a fresh copy of the link-layer table.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
neigh_resolve(struct cmm_global *g, struct cmm_neigh *neigh)
{
	static time_t pppoe_retry;
	struct cmm_interface *itf;
	struct timespec ts;
	size_t len;
	char *buf;
	int failed, rc;

	if (neigh_pppoe(neigh) == 0)
		return (0);

	/* If the PPPoE session was missed when the link came up, look for it
	 * again here, at most once a second. */
	itf = cmm_itf_find_by_index(neigh->ifindex);
	if (itf != NULL && (itf->flags & IFF_UP) &&
	    !(itf->itf_flags & ITF_F_PPPOE) &&
	    strncmp(itf->ifname, "ppp", 3) == 0) {
		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (ts.tv_sec != pppoe_retry) {
			pppoe_retry = ts.tv_sec;
			cmm_pppoe_notify(g, itf);
			if (neigh_pppoe(neigh) == 0)
				return (0);
		}
	}

	buf = neigh_table(neigh->family, &len, &failed);
	if (buf == NULL) {
		neigh->state = failed ? NEIGH_FAILED : NEIGH_INCOMPLETE;
		return (-1);
	}
	rc = neigh_find_in_table(buf, len, neigh);
	free(buf);
	if (rc != 0)
		neigh->state = NEIGH_INCOMPLETE;
	return (rc);
}

int
cmm_neigh_init(void)
{
	int i;

	for (i = 0; i < NEIGH_HASH_TOTAL; i++)
		list_head_init(&neigh_hash[i]);
	return (0);
}

void
cmm_neigh_fini(void)
{
	struct cmm_neigh *neigh;
	struct list_head *pos, *tmp;
	int i;

	for (i = 0; i < NEIGH_HASH_TOTAL; i++) {
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

	for (i = 0; i < NEIGH_HASH_TOTAL; i++) {
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

	for (i = 0; i < NEIGH_HASH_TOTAL; i++) {
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

/*
 * Re-resolve every currently-resolved neighbor and report any whose
 * MAC changed.  A gateway MAC change (CARP failover, hardware swap)
 * never touches the routing table, so cmm_neigh_get()'s cache-hit
 * fast path would otherwise keep returning the stale MAC forever.
 * Callers still holding a reference to a changed entry are expected
 * to invalidate whatever used the old MAC.
 */
void
cmm_neigh_recheck_all(struct cmm_global *g __unused,
    void (*on_changed)(struct cmm_neigh *neigh, void *arg), void *arg)
{
	struct cmm_neigh *neigh;
	struct list_head *pos;
	uint8_t old_mac[ETHER_ADDR_LEN];
	char *table[2] = { NULL, NULL };
	size_t len[2] = { 0, 0 };
	int copied[2] = { 0, 0 };
	int i, f, failed;

	for (i = 0; i < NEIGH_HASH_TOTAL; i++) {
		for (pos = list_first(&neigh_hash[i]); pos != &neigh_hash[i];
		    pos = list_next(pos)) {
			neigh = container_of(pos, struct cmm_neigh, entry);

			if (neigh->state != NEIGH_RESOLVED)
				continue;

			memcpy(old_mac, neigh->macaddr, ETHER_ADDR_LEN);
			if (neigh_pppoe(neigh) != 0) {
				/* One copy of each family's table per pass. */
				f = (neigh->family == AF_INET6);
				if (!copied[f]) {
					table[f] = neigh_table(neigh->family,
					    &len[f], &failed);
					copied[f] = 1;
				}
				if (table[f] == NULL ||
				    neigh_find_in_table(table[f], len[f],
				    neigh) != 0) {
					/* No entry is not a new MAC: a device
					 * whose traffic is all offloaded gets
					 * nothing from the router, so its entry
					 * just expires. Keep the MAC, as ASK
					 * does. */
					continue;
				}
			}
			if (memcmp(old_mac, neigh->macaddr,
			    ETHER_ADDR_LEN) != 0)
				on_changed(neigh, arg);
		}
	}
	free(table[0]);
	free(table[1]);
}

/* --- Kernel neighbor events ---------------------------------------- */

/* With events working, the full poll only runs every this many passes. */
#define NEIGH_POLL_PASSES	10

static struct snl_state neigh_ss;
static int neigh_events_open;
static int neigh_events_lost;
/* For the counts file: events read, neighbors they updated, full polls. */
unsigned int cmm_neigh_nevents, cmm_neigh_nupdates, cmm_neigh_npolls;

/*
 * Subscribe to the kernel's neighbor events (RTM_NEWNEIGH/RTM_DELNEIGH),
 * as ASK does on Linux.  Returns the socket to watch, or -1.
 */
int
cmm_neigh_events_open(void)
{
	int group = RTNLGRP_NEIGH;

	if (!snl_init(&neigh_ss, NETLINK_ROUTE))
		return (-1);
	if (setsockopt(neigh_ss.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
	    &group, sizeof(group)) < 0 ||
	    fcntl(neigh_ss.fd, F_SETFL, O_NONBLOCK) < 0) {
		snl_free(&neigh_ss);
		return (-1);
	}
	neigh_events_open = 1;
	return (neigh_ss.fd);
}

void
cmm_neigh_events_close(void)
{
	if (neigh_events_open)
		snl_free(&neigh_ss);
	neigh_events_open = 0;
}

/*
 * A new or changed entry updates a neighbor in use. Expired entries are
 * not acted on, so a device whose traffic is all offloaded keeps its MAC.
 * Returns 1 when refused connections should be retried.
 */
static int
neigh_event(const struct snl_parsed_neigh *pn,
    void (*on_changed)(struct cmm_neigh *neigh, void *arg), void *arg)
{
	struct cmm_neigh *neigh;
	const void *ip, *mac;
	int was_resolved;

	if (pn->nda_dst == NULL || pn->nda_lladdr == NULL ||
	    NLA_DATA_LEN(pn->nda_lladdr) != ETHER_ADDR_LEN)
		return (0);
	if (pn->nda_dst->sa_family == AF_INET)
		ip = &((const struct sockaddr_in *)pn->nda_dst)->sin_addr;
	else if (pn->nda_dst->sa_family == AF_INET6)
		ip = &((const struct sockaddr_in6 *)pn->nda_dst)->sin6_addr;
	else
		return (0);

	neigh = neigh_find(pn->nda_dst->sa_family, ip, pn->nda_ifindex);
	if (neigh == NULL)
		return (0);

	mac = NLA_DATA(pn->nda_lladdr);
	was_resolved = (neigh->state == NEIGH_RESOLVED);
	if (was_resolved && memcmp(neigh->macaddr, mac, ETHER_ADDR_LEN) == 0)
		return (0);

	memcpy(neigh->macaddr, mac, ETHER_ADDR_LEN);
	neigh->state = NEIGH_RESOLVED;
	cmm_neigh_nupdates++;
	if (was_resolved)
		on_changed(neigh, arg);
	return (1);
}

/* Read every pending neighbor event. Returns 1 if any needs a retry. */
int
cmm_neigh_events_dispatch(
    void (*on_changed)(struct cmm_neigh *neigh, void *arg), void *arg)
{
	struct nlmsghdr *hdr;
	int retry = 0;

	errno = 0;
	while ((hdr = snl_read_message(&neigh_ss)) != NULL) {
		struct snl_parsed_neigh pn = {};

		cmm_neigh_nevents++;
		if (hdr->nlmsg_type == NL_RTM_NEWNEIGH &&
		    snl_parse_nlmsg(&neigh_ss, hdr, &snl_rtm_neigh_parser, &pn))
			retry |= neigh_event(&pn, on_changed, arg);
		snl_clear_lb(&neigh_ss);
	}
	/* The socket overflowed and events were lost: poll to catch up. */
	if (errno == ENOBUFS)
		neigh_events_lost = 1;
	return (retry);
}

/* Whether this maintenance pass should run the full neighbor poll. */
int
cmm_neigh_poll_due(void)
{
	static unsigned int passes;

	if (!neigh_events_open || neigh_events_lost ||
	    ++passes % NEIGH_POLL_PASSES == 0) {
		neigh_events_lost = 0;
		cmm_neigh_npolls++;
		return (1);
	}
	return (0);
}
