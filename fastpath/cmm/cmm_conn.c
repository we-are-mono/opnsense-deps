/*
 * cmm_conn.c — PF state table polling and connection tracking
 *
 * Maintains a local connection table driven by either:
 *   1. Push-based events from /dev/pfnotify (pf_notify.ko)
 *   2. Periodic polling via DIOCGETSTATESV2 (fallback/reconciliation)
 *
 * New connections are checked for offload eligibility and
 * programmed into CDX.  Expired connections are removed from CDX.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#define COMPAT_FREEBSD14	/* DIOCGETSTATESV2 */
#include <net/pfvar.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_conn.h"
#include "cmm_route.h"
#include "cmm_neigh.h"
#include "cmm_itf.h"
#include "cmm_fe.h"
#include "cmm_offload.h"
#include "cmm_bridge.h"
#include "cmm_deny.h"
#include "pf_notify.h"
#include "fpp_private.h"
#include "libfci.h"

#include <netinet/tcp_fsm.h>

#define CMM_MAX_STATE_BUF	(16 * 1024 * 1024)	/* 16 MB cap */
#define CMM_CONN_MAX		65536

static struct list_head conn_hash[CONN_HASH_SIZE];
static unsigned int conn_count;
static unsigned int conn_offloaded;

/*
 * Hash by original 5-tuple (proto, af, saddr, daddr, sport, dport).
 * Uses the STACK key which is identical for both the PF_IN and PF_OUT
 * states of a NAT connection, so both map to the same conn entry.
 */
static inline unsigned int
conn_hash_5tuple(sa_family_t af, uint8_t proto,
    const void *saddr, const void *daddr,
    uint16_t sport, uint16_t dport)
{
	uint32_t a, b, c;

	if (af == AF_INET) {
		uint32_t sa, da;

		memcpy(&sa, saddr, 4);
		memcpy(&da, daddr, 4);
		a = sa ^ ((uint32_t)proto << 16) ^ (uint32_t)sport;
		b = da ^ (uint32_t)dport;
		c = 0;
	} else {
		a = jhash(saddr, 16, (uint32_t)proto);
		b = jhash(daddr, 16, (uint32_t)sport);
		c = (uint32_t)dport;
	}

	return (jhash_3words(a, b, c, 0) % CONN_HASH_SIZE);
}

static struct cmm_conn *
conn_find_5tuple(sa_family_t af, uint8_t proto,
    const void *saddr, const void *daddr,
    uint16_t sport, uint16_t dport)
{
	struct list_head *bucket, *pos;
	struct cmm_conn *conn;
	unsigned int h;
	int alen;

	h = conn_hash_5tuple(af, proto, saddr, daddr, sport, dport);
	bucket = &conn_hash[h];
	alen = (af == AF_INET) ? 4 : 16;

	for (pos = list_first(bucket); pos != bucket; pos = list_next(pos)) {
		conn = container_of(pos, struct cmm_conn, hash_entry);
		if (conn->af == af &&
		    conn->proto == proto &&
		    conn->orig_sport == sport &&
		    conn->orig_dport == dport &&
		    memcmp(conn->orig_saddr, saddr, alen) == 0 &&
		    memcmp(conn->orig_daddr, daddr, alen) == 0)
			return (conn);
	}
	return (NULL);
}

static void
conn_remove(struct cmm_global *g, struct cmm_conn *conn)
{
	/* Deregister from CDX if offloaded */
	if (conn->flags & CONN_F_OFFLOADED) {
		if (conn->af == AF_INET)
			cmm_fe_ct4_deregister(g, conn);
		else
			cmm_fe_ct6_deregister(g, conn);
		if (conn_offloaded > 0)
			conn_offloaded--;
	}

	/* Release route references */
	if (conn->orig_route != NULL) {
		cmm_route_put(conn->orig_route);
		conn->orig_route = NULL;
	}
	if (conn->rep_route != NULL) {
		cmm_route_put(conn->rep_route);
		conn->rep_route = NULL;
	}

	list_del(&conn->hash_entry);
	free(conn);
	if (conn_count > 0)
		conn_count--;
}

/*
 * Resolve iif_index from the opposite route's output interface.
 * If the output goes through a bridge, look up the opposite route's
 * neighbor MAC in the bridge FDB to find the physical ingress port.
 * For non-bridge interfaces, returns oif_index unchanged.
 */
static int
resolve_iif_index(struct cmm_route *opp_route)
{
	struct cmm_interface *itf;
	int iif;

	iif = opp_route->oif_index;
	itf = cmm_itf_find_by_index(iif);
	if (itf != NULL && (itf->itf_flags & ITF_F_BRIDGE) &&
	    opp_route->neigh != NULL) {
		char port_name[IFNAMSIZ];
		struct cmm_interface *port;

		if (cmm_bridge_resolve_port(itf->ifindex,
		    opp_route->neigh->macaddr, port_name,
		    sizeof(port_name)) == 0) {
			port = cmm_itf_find_by_name(port_name);
			if (port != NULL)
				iif = port->ifindex;
		} else {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: bridge %s FDB miss for "
			    "mac=%02x:%02x:%02x:%02x:%02x:%02x",
			    itf->ifname,
			    opp_route->neigh->macaddr[0],
			    opp_route->neigh->macaddr[1],
			    opp_route->neigh->macaddr[2],
			    opp_route->neigh->macaddr[3],
			    opp_route->neigh->macaddr[4],
			    opp_route->neigh->macaddr[5]);
		}
	}
	return (iif);
}

/*
 * Try to offload a connection:
 * 1. Look up routes for both directions
 * 2. Resolve next-hop neighbors (retry-safe)
 * 3. Send routes to CDX
 * 4. Send conntrack to CDX
 *
 * Safe to call multiple times — skips steps already completed.
 */
static int
conn_try_offload(struct cmm_global *g, struct cmm_conn *conn)
{
	/* Look up route for original direction (dst = orig_daddr) */
	if (conn->orig_route == NULL)
		conn->orig_route = cmm_route_get(g, conn->af,
		    conn->orig_daddr);
	if (conn->orig_route == NULL) {
		cmm_print(CMM_LOG_DEBUG,
		    "conn: no route for original direction");
		return (-1);
	}

	/*
	 * Look up route for reply direction.
	 *
	 * CDX rewrites the reply packet before forwarding: for SNAT,
	 * it changes the destination from the NAT'd address back to
	 * the original source.  The route must deliver the rewritten
	 * packet, so look up orig_saddr (the real client address),
	 * not rep_daddr (the NAT'd address on the external wire).
	 *
	 * For non-NAT connections, orig_saddr == rep_daddr anyway.
	 */
	if (conn->rep_route == NULL)
		conn->rep_route = cmm_route_get(g, conn->af,
		    conn->orig_saddr);
	if (conn->rep_route == NULL) {
		cmm_print(CMM_LOG_DEBUG,
		    "conn: no route for reply direction");
		return (-1);
	}

	/* Re-attempt neighbor resolution if needed */
	if (conn->orig_route->neigh == NULL)
		conn->orig_route->neigh = cmm_neigh_get(g,
		    conn->orig_route->family,
		    conn->orig_route->gw,
		    conn->orig_route->oif_index);
	if (conn->rep_route->neigh == NULL)
		conn->rep_route->neigh = cmm_neigh_get(g,
		    conn->rep_route->family,
		    conn->rep_route->gw,
		    conn->rep_route->oif_index);

	/* Both routes need resolved neighbors */
	if (conn->orig_route->neigh == NULL ||
	    conn->orig_route->neigh->state != NEIGH_RESOLVED) {
		cmm_print(CMM_LOG_DEBUG,
		    "conn: orig neighbor not resolved");
		return (-1);
	}
	if (conn->rep_route->neigh == NULL ||
	    conn->rep_route->neigh->state != NEIGH_RESOLVED) {
		cmm_print(CMM_LOG_DEBUG,
		    "conn: reply neighbor not resolved");
		return (-1);
	}

	/*
	 * Set input interface for each route: the input for one direction
	 * is the output of the opposite direction.  CDX needs this to
	 * install flow classification entries on the correct FMan RX port.
	 */
	conn->orig_route->iif_index = resolve_iif_index(conn->rep_route);
	conn->rep_route->iif_index = resolve_iif_index(conn->orig_route);

	/* Send routes to CDX (idempotent if already programmed) */
	if (!conn->orig_route->fpp_programmed)
		cmm_fe_route_register(g, conn->orig_route);
	if (!conn->rep_route->fpp_programmed)
		cmm_fe_route_register(g, conn->rep_route);

	if (!conn->orig_route->fpp_programmed ||
	    !conn->rep_route->fpp_programmed) {
		cmm_print(CMM_LOG_DEBUG,
		    "conn: route FPP registration failed");
		return (-1);
	}

	/* Enable both directions */
	conn->flags |= CONN_F_ORIG_DIR | CONN_F_REP_DIR;

	/* Send conntrack to CDX */
	{
		int rc;

		if (conn->af == AF_INET)
			rc = cmm_fe_ct4_register(g, conn);
		else
			rc = cmm_fe_ct6_register(g, conn);
		if (rc == 0)
			conn_offloaded++;
		return (rc);
	}
}

/*
 * Extract connection 5-tuples from a PF state export entry.
 *
 * PF state keys:
 *   key[PF_SK_WIRE]  = wire-side addresses (post-NAT for SNAT/PF_OUT)
 *   key[PF_SK_STACK] = stack-side addresses (pre-NAT original endpoints)
 *
 * PF address indexing depends on direction:
 *   PF_IN:  addr[0] = src, addr[1] = dst
 *   PF_OUT: addr[0] = dst, addr[1] = src
 *
 * For non-NAT: wire == stack, direction is PF_IN.
 * For NAT:     wire has NAT'd addresses, stack has original endpoints.
 *              PF creates two states; we only use the PF_OUT state
 *              (identified by wire != stack) which has correct info.
 *
 * CDX needs:
 *   Original direction: addresses as they enter the INTERNAL interface
 *     (pre-NAT) — use STACK key (real endpoints)
 *   Reply direction: addresses as they enter the EXTERNAL interface
 *     (post-NAT reply) — use WIRE key reversed
 */
static void
conn_extract_tuples(struct cmm_conn *conn, const struct pf_state_export *pfs)
{
	const struct pf_state_key_export *wire, *stack;
	int alen, sidx, didx;

	wire = &pfs->key[PF_SK_WIRE];
	stack = &pfs->key[PF_SK_STACK];

	conn->af = pfs->af;
	conn->proto = pfs->proto;
	alen = (pfs->af == AF_INET) ? 4 : 16;

	/*
	 * PF stores addresses at direction-dependent indices:
	 *   PF_IN(1):  sidx=0, didx=1  (addr[0]=src, addr[1]=dst)
	 *   PF_OUT(2): sidx=1, didx=0  (addr[0]=dst, addr[1]=src)
	 */
	sidx = (pfs->direction == PF_IN) ? 0 : 1;
	didx = (pfs->direction == PF_IN) ? 1 : 0;

	/* Diagnostic: dump wire and stack keys */
	if (pfs->af == AF_INET) {
		char ws[INET_ADDRSTRLEN], wd[INET_ADDRSTRLEN];
		char ss[INET_ADDRSTRLEN], sd[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &wire->addr[sidx].v4, ws, sizeof(ws));
		inet_ntop(AF_INET, &wire->addr[didx].v4, wd, sizeof(wd));
		inet_ntop(AF_INET, &stack->addr[sidx].v4, ss, sizeof(ss));
		inet_ntop(AF_INET, &stack->addr[didx].v4, sd, sizeof(sd));
		cmm_print(CMM_LOG_DEBUG,
		    "conn: pf dir=%u "
		    "wire=[%s:%u -> %s:%u] "
		    "stack=[%s:%u -> %s:%u] %s",
		    pfs->direction,
		    ws, ntohs(wire->port[sidx]),
		    wd, ntohs(wire->port[didx]),
		    ss, ntohs(stack->port[sidx]),
		    sd, ntohs(stack->port[didx]),
		    (memcmp(wire, stack, sizeof(*wire)) == 0) ?
		    "SAME" : "DIFFER");
	}

	/*
	 * Original direction: use STACK key (pre-NAT real endpoints).
	 * These are the addresses on the internal wire where the
	 * initiating packet enters the gateway.
	 */
	memcpy(conn->orig_saddr, &stack->addr[sidx], alen);
	memcpy(conn->orig_daddr, &stack->addr[didx], alen);
	conn->orig_sport = stack->port[sidx];
	conn->orig_dport = stack->port[didx];

	/*
	 * Reply direction: use WIRE key, reversed.
	 * These are the addresses on the external wire where the
	 * reply packet enters the gateway.  For NAT, the wire key
	 * has the NAT'd source address which is what the remote
	 * server replies to.
	 */
	memcpy(conn->rep_saddr, &wire->addr[didx], alen);
	memcpy(conn->rep_daddr, &wire->addr[sidx], alen);
	conn->rep_sport = wire->port[didx];
	conn->rep_dport = wire->port[sidx];
}

int
cmm_conn_init(void)
{
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++)
		list_head_init(&conn_hash[i]);
	return (0);
}

void
cmm_conn_fini(struct cmm_global *g)
{
	struct cmm_conn *conn;
	struct list_head *pos, *tmp;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		pos = list_first(&conn_hash[i]);
		while (pos != &conn_hash[i]) {
			tmp = list_next(pos);
			conn = container_of(pos, struct cmm_conn, hash_entry);
			conn_remove(g, conn);
			pos = tmp;
		}
	}
}

void
cmm_conn_deregister_all(struct cmm_global *g)
{
	struct cmm_conn *conn;
	struct list_head *pos;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn, hash_entry);
			if (conn->flags & CONN_F_OFFLOADED) {
				if (conn->af == AF_INET)
					cmm_fe_ct4_deregister(g, conn);
				else
					cmm_fe_ct6_deregister(g, conn);
			}
		}
	}
}

/*
 * Deregister all connections using the given route from CDX, and clear
 * their route pointers.  Called when a route changes so that affected
 * connections will re-resolve and re-offload on the next poll cycle.
 */
void
cmm_route_invalidate_conns(struct cmm_global *g, struct cmm_route *rt)
{
	struct cmm_conn *conn;
	struct list_head *pos;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn, hash_entry);

			if (conn->orig_route != rt && conn->rep_route != rt)
				continue;

			/* Deregister from CDX */
			if (conn->flags & CONN_F_OFFLOADED) {
				if (conn->af == AF_INET)
					cmm_fe_ct4_deregister(g, conn);
				else
					cmm_fe_ct6_deregister(g, conn);
				conn->flags &= ~CONN_F_OFFLOADED;
				if (conn_offloaded > 0)
					conn_offloaded--;
			}

			/* Clear route pointers — next poll re-resolves */
			if (conn->orig_route != NULL) {
				cmm_route_put(conn->orig_route);
				conn->orig_route = NULL;
			}
			if (conn->rep_route != NULL) {
				cmm_route_put(conn->rep_route);
				conn->rep_route = NULL;
			}
		}
	}
}

/*
 * Full offload state reset: wipe all CDX tables, then clean up local
 * state.  Connections remain in the hash table — they will re-resolve
 * routes and re-offload on the next poll/event cycle.
 *
 * Uses cmm_fe_reset() (FPP_CMD_IPVx_RESET) for a guaranteed bulk
 * wipe of CDX conntracks and routes.  Per-connection deregister is
 * unreliable when reply tuples have diverged from CDX's stored state
 * (e.g. after NAT address change).
 *
 * Called on interface reassignment (RTM_NEWADDR / RTM_DELADDR) where
 * the routing topology has fundamentally changed.
 */
void
cmm_reset_offload_state(struct cmm_global *g)
{
	struct cmm_conn *conn;
	struct list_head *pos;
	int i;

	cmm_print(CMM_LOG_INFO,
	    "conn: full offload reset (interface reassignment)");

	/* 1. Wipe all CDX conntracks + routes in one shot */
	cmm_fe_reset(g);

	/* 2. Clear local offload flags and route references */
	for (i = 0; i < CONN_HASH_SIZE; i++) {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn, hash_entry);
			conn->flags &= ~CONN_F_OFFLOADED;
			if (conn->orig_route != NULL) {
				cmm_route_put(conn->orig_route);
				conn->orig_route = NULL;
			}
			if (conn->rep_route != NULL) {
				cmm_route_put(conn->rep_route);
				conn->rep_route = NULL;
			}
		}
	}
	conn_offloaded = 0;

	/* 3. Free local route cache (CDX already wiped — skip deregister) */
	cmm_route_flush_all_local();

	/* 4. Mark all neighbors stale (forces re-resolution) */
	cmm_neigh_flush_all();
}

/* --- Push-based event handling ------------------------------------ */

/*
 * Find a connection by PF state ID.
 * Linear scan is acceptable because DELETE events fire once per
 * connection lifetime.
 */
static struct cmm_conn *
conn_find_by_pfid(uint64_t id, uint32_t creatorid)
{
	struct list_head *pos;
	struct cmm_conn *conn;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn,
			    hash_entry);
			if (conn->pf_id == id &&
			    conn->pf_creatorid == creatorid)
				return (conn);
		}
	}
	return (NULL);
}

/*
 * Extract connection tuples from a pfn_event.
 * Same logic as conn_extract_tuples() but reads from pfn_event.
 */
static void
pfn_extract_tuples(struct cmm_conn *conn, const struct pfn_event *ev)
{
	int sidx, didx, alen;

	conn->af = ev->key[0].af;
	conn->proto = ev->key[0].proto;
	alen = (conn->af == AF_INET) ? 4 : 16;

	sidx = (ev->direction == PF_IN) ? 0 : 1;
	didx = (ev->direction == PF_IN) ? 1 : 0;

	/* Original direction: STACK key (index 1) */
	memcpy(conn->orig_saddr, ev->key[1].addr[sidx], alen);
	memcpy(conn->orig_daddr, ev->key[1].addr[didx], alen);
	conn->orig_sport = ev->key[1].port[sidx];
	conn->orig_dport = ev->key[1].port[didx];

	/* Reply direction: WIRE key (index 0), reversed */
	memcpy(conn->rep_saddr, ev->key[0].addr[didx], alen);
	memcpy(conn->rep_daddr, ev->key[0].addr[sidx], alen);
	conn->rep_sport = ev->key[0].port[didx];
	conn->rep_dport = ev->key[0].port[sidx];
}

/*
 * Check basic offload eligibility from pfn_event fields.
 * Mirrors cmm_offload_eligible() but reads from pfn_event.
 */
static int
pfn_event_eligible(const struct pfn_event *ev)
{
	uint8_t proto;
	sa_family_t af;
	int didx;

	proto = ev->key[0].proto;
	af = ev->key[0].af;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return (0);
	if (af != AF_INET && af != AF_INET6)
		return (0);
	if (strncmp(ev->ifname, "lo", 2) == 0)
		return (0);

	/* TCP: require ESTABLISHED, not in FIN states */
	if (proto == IPPROTO_TCP) {
		if (ev->src_state < TCPS_ESTABLISHED ||
		    ev->dst_state < TCPS_ESTABLISHED)
			return (0);
		if (ev->src_state >= TCPS_FIN_WAIT_1 ||
		    ev->dst_state >= TCPS_FIN_WAIT_1)
			return (0);
	}

	/* UDP: require bidirectional traffic */
	if (proto == IPPROTO_UDP) {
		if (ev->src_state == 0 || ev->dst_state == 0)
			return (0);
	}

	/* Skip multicast destinations (stack key) */
	didx = (ev->direction == PF_IN) ? 1 : 0;
	if (af == AF_INET) {
		uint32_t daddr;

		memcpy(&daddr, ev->key[1].addr[didx], 4);
		if (IN_MULTICAST(ntohl(daddr)))
			return (0);
	} else {
		if (IN6_IS_ADDR_MULTICAST(
		    (const struct in6_addr *)ev->key[1].addr[didx]))
			return (0);
	}

	/* Skip local addresses (stack key, both endpoints) */
	if (af == AF_INET) {
		if (cmm_itf_is_local_addr(AF_INET,
		    ev->key[1].addr[0]) ||
		    cmm_itf_is_local_addr(AF_INET,
		    ev->key[1].addr[1]))
			return (0);
	} else {
		if (cmm_itf_is_local_addr(AF_INET6,
		    ev->key[1].addr[0]) ||
		    cmm_itf_is_local_addr(AF_INET6,
		    ev->key[1].addr[1]))
			return (0);
	}

	return (1);
}

/*
 * Handle a READY event (state became offload-ready).
 * Creates or updates cmm_conn and attempts offload.
 */
static void
handle_pf_ready(struct cmm_global *g, const struct pfn_event *ev)
{
	struct cmm_conn *conn;
	int sidx, didx, alen, is_nat;
	uint8_t osaddr[16], odaddr[16];
	uint16_t osport, odport;
	sa_family_t af;
	uint8_t proto;

	if (!pfn_event_eligible(ev))
		return;

	proto = ev->key[0].proto;
	af = ev->key[0].af;
	sidx = (ev->direction == PF_IN) ? 0 : 1;
	didx = (ev->direction == PF_IN) ? 1 : 0;
	alen = (af == AF_INET) ? 4 : 16;
	is_nat = memcmp(&ev->key[0], &ev->key[1],
	    sizeof(struct pfn_state_key)) != 0;

	/* Extract original 5-tuple from STACK key */
	memset(osaddr, 0, sizeof(osaddr));
	memset(odaddr, 0, sizeof(odaddr));
	memcpy(osaddr, ev->key[1].addr[sidx], alen);
	memcpy(odaddr, ev->key[1].addr[didx], alen);
	osport = ev->key[1].port[sidx];
	odport = ev->key[1].port[didx];

	/* Check deny rules */
	/* TODO: cmm_deny_check takes pf_state_export, would need adapter.
	 * For now, deny rules are enforced by the reconciliation poll. */

	conn = conn_find_5tuple(af, proto, osaddr, odaddr, osport, odport);
	if (conn != NULL) {
		/* Existing connection — handle NAT upgrade */
		conn->last_seen_epoch = g->epoch;

		if (is_nat && !(conn->flags & CONN_F_HAS_NAT)) {
			cmm_print(CMM_LOG_INFO,
			    "conn: NAT upgrade from push event");

			if (conn->flags & CONN_F_OFFLOADED) {
				if (conn->af == AF_INET)
					cmm_fe_ct4_deregister(g, conn);
				else
					cmm_fe_ct6_deregister(g, conn);
				conn->flags &= ~CONN_F_OFFLOADED;
				if (conn_offloaded > 0)
					conn_offloaded--;
			}

			/* Update reply tuples from wire key */
			memcpy(conn->rep_saddr,
			    ev->key[0].addr[didx], alen);
			memcpy(conn->rep_daddr,
			    ev->key[0].addr[sidx], alen);
			conn->rep_sport = ev->key[0].port[didx];
			conn->rep_dport = ev->key[0].port[sidx];

			if (conn->rep_route != NULL) {
				cmm_route_put(conn->rep_route);
				conn->rep_route = NULL;
			}

			/* Save NAT companion PF state ID */
			conn->pf_id_nat = ev->id;
			conn->pf_creatorid_nat = ev->creatorid;
			conn->pf_has_nat_id = 1;

			conn->flags |= CONN_F_HAS_NAT;
		}

		if (!(conn->flags & CONN_F_OFFLOADED))
			conn_try_offload(g, conn);
		return;
	}

	/* New connection */
	if (conn_count >= CMM_CONN_MAX)
		return;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		return;

	pfn_extract_tuples(conn, ev);
	conn->pf_id = ev->id;
	conn->pf_creatorid = ev->creatorid;
	conn->pf_direction = ev->direction;
	strlcpy(conn->ifname, ev->ifname, sizeof(conn->ifname));
	conn->last_seen_epoch = g->epoch;
	conn->hash_entry.next = NULL;
	conn->hash_entry.prev = NULL;

	if (is_nat)
		conn->flags |= CONN_F_HAS_NAT;

	{
		unsigned int h;

		h = conn_hash_5tuple(conn->af, conn->proto,
		    conn->orig_saddr, conn->orig_daddr,
		    conn->orig_sport, conn->orig_dport);
		list_add(&conn_hash[h], &conn->hash_entry);
		conn_count++;
	}

	if (conn_try_offload(g, conn) < 0) {
		cmm_print(CMM_LOG_DEBUG,
		    "conn: offload deferred (route/neigh pending)");
	}
}

/*
 * Handle a DELETE event (PF state removed).
 */
static void
handle_pf_delete(struct cmm_global *g, const struct pfn_event *ev)
{
	struct cmm_conn *conn;

	conn = conn_find_by_pfid(ev->id, ev->creatorid);
	if (conn == NULL) {
		cmm_print(CMM_LOG_TRACE,
		    "conn: DELETE for unknown id=%016llx",
		    (unsigned long long)ev->id);
		return;
	}

	cmm_print(CMM_LOG_DEBUG, "conn: DELETE proto=%u%s (push)",
	    conn->proto,
	    (conn->flags & CONN_F_HAS_NAT) ? " NAT" : "");

	conn_remove(g, conn);
}

/*
 * Handle push-based events from /dev/pfnotify.
 * Drain loop reads all available events.
 */
void
cmm_conn_event(struct cmm_global *g)
{
	struct pfn_event ev;
	ssize_t n;

	for (;;) {
		n = read(g->pfnotify_fd, &ev, sizeof(ev));
		if (n != (ssize_t)sizeof(ev)) {
			if (n < 0 && (errno == EAGAIN ||
			    errno == EWOULDBLOCK))
				break;
			if (n == 0) {
				cmm_print(CMM_LOG_WARN,
				    "conn: /dev/pfnotify closed");
				break;
			}
			cmm_print(CMM_LOG_WARN,
			    "conn: short pfnotify read: %zd", n);
			break;
		}

		switch (ev.type) {
		case PFN_EVENT_INSERT:
			/*
			 * Log only.  Most TCP states are SYN_SENT
			 * at insert time — wait for READY.  If the
			 * state is already ready (pfsync import),
			 * the kernel will also fire a READY event.
			 */
			cmm_print(CMM_LOG_TRACE,
			    "conn: INSERT id=%016llx proto=%u",
			    (unsigned long long)ev.id,
			    ev.key[0].proto);
			break;

		case PFN_EVENT_READY:
			handle_pf_ready(g, &ev);
			break;

		case PFN_EVENT_DELETE:
			handle_pf_delete(g, &ev);
			break;

		default:
			cmm_print(CMM_LOG_WARN,
			    "conn: unknown pfnotify event %u",
			    ev.type);
			break;
		}
	}
}

void
cmm_conn_poll(struct cmm_global *g)
{
	struct pfioc_states_v2 ps;
	struct pf_state_export *states, *pfs;
	int count, i;
	uint32_t epoch;

	/* Increment epoch for garbage collection; skip 0 on wrap */
	epoch = ++g->epoch;
	if (epoch == 0)
		epoch = ++g->epoch;

	/* First pass: get required buffer size */
	memset(&ps, 0, sizeof(ps));
	ps.ps_req_version = PF_STATE_VERSION;
	ps.ps_len = 0;

	if (ioctl(g->pf_fd, DIOCGETSTATESV2, &ps) < 0) {
		cmm_print(CMM_LOG_WARN, "conn: DIOCGETSTATESV2 size: %s",
		    strerror(errno));
		return;
	}

	if (ps.ps_len == 0) {
		/* No states — sweep expired connections */
		goto sweep;
	}

	if (ps.ps_len > CMM_MAX_STATE_BUF) {
		cmm_print(CMM_LOG_WARN,
		    "conn: state buffer %zu bytes exceeds %d MB cap",
		    (size_t)ps.ps_len, CMM_MAX_STATE_BUF / (1024 * 1024));
		goto sweep;
	}

	/* Allocate and fetch */
	states = malloc(ps.ps_len);
	if (states == NULL) {
		cmm_print(CMM_LOG_ERR, "conn: malloc %d bytes failed",
		    ps.ps_len);
		return;
	}

	ps.ps_buf = states;
	if (ioctl(g->pf_fd, DIOCGETSTATESV2, &ps) < 0) {
		cmm_print(CMM_LOG_WARN, "conn: DIOCGETSTATESV2 fetch: %s",
		    strerror(errno));
		free(states);
		return;
	}

	count = ps.ps_len / sizeof(struct pf_state_export);
	cmm_print(CMM_LOG_TRACE, "conn: polled %d PF states", count);

	/*
	 * Process each state.
	 *
	 * PF creates two states per NAT connection: PF_IN (wire==stack,
	 * no NAT info) and PF_OUT (wire!=stack, has post-NAT addresses).
	 * Both share the same original 5-tuple (from the stack key), so
	 * we hash by original 5-tuple to merge them into one conn entry.
	 *
	 * When the PF_OUT state arrives for an existing conn created by
	 * PF_IN, we upgrade the reply tuples with the correct post-NAT
	 * addresses and re-offload.
	 */
	for (i = 0; i < count; i++) {
		struct cmm_conn *conn;
		const struct pf_state_key_export *wire, *stack;
		int sidx, didx, alen, is_nat;
		uint8_t osaddr[16], odaddr[16];
		uint16_t osport, odport;

		pfs = &states[i];

		/* Check offload eligibility */
		if (!cmm_offload_eligible(pfs))
			continue;

		/* Check deny rules */
		if (cmm_deny_check(pfs))
			continue;

		wire = &pfs->key[PF_SK_WIRE];
		stack = &pfs->key[PF_SK_STACK];
		alen = (pfs->af == AF_INET) ? 4 : 16;

		sidx = (pfs->direction == PF_IN) ? 0 : 1;
		didx = (pfs->direction == PF_IN) ? 1 : 0;
		is_nat = memcmp(wire, stack, sizeof(*wire)) != 0;

		/* Extract original 5-tuple from stack key */
		memset(osaddr, 0, sizeof(osaddr));
		memset(odaddr, 0, sizeof(odaddr));
		memcpy(osaddr, &stack->addr[sidx], alen);
		memcpy(odaddr, &stack->addr[didx], alen);
		osport = stack->port[sidx];
		odport = stack->port[didx];

		/* Look up by original 5-tuple */
		conn = conn_find_5tuple(pfs->af, pfs->proto,
		    osaddr, odaddr, osport, odport);
		if (conn != NULL) {
			conn->last_seen_epoch = epoch;

			/*
			 * NAT upgrade: PF_OUT state (wire != stack) has
			 * the correct post-NAT reply addresses.  If this
			 * conn was created from the PF_IN state (which
			 * has wire==stack, no NAT info), upgrade it.
			 */
			if (is_nat && !(conn->flags & CONN_F_HAS_NAT)) {
				cmm_print(CMM_LOG_INFO,
				    "conn: NAT upgrade from PF_OUT");

				/* Deregister old CDX entry */
				if (conn->flags & CONN_F_OFFLOADED) {
					if (conn->af == AF_INET)
						cmm_fe_ct4_deregister(g, conn);
					else
						cmm_fe_ct6_deregister(g, conn);
					conn->flags &= ~CONN_F_OFFLOADED;
					if (conn_offloaded > 0)
						conn_offloaded--;
				}

				/* Update reply tuples from wire key */
				memcpy(conn->rep_saddr,
				    &wire->addr[didx], alen);
				memcpy(conn->rep_daddr,
				    &wire->addr[sidx], alen);
				conn->rep_sport = wire->port[didx];
				conn->rep_dport = wire->port[sidx];

				/* Clear reply route — needs new lookup */
				if (conn->rep_route != NULL) {
					cmm_route_put(conn->rep_route);
					conn->rep_route = NULL;
				}

				/* Save NAT companion PF state ID */
				conn->pf_id_nat = pfs->id;
				conn->pf_creatorid_nat = pfs->creatorid;
				conn->pf_has_nat_id = 1;

				conn->flags |= CONN_F_HAS_NAT;

				if (pfs->af == AF_INET) {
					char rs[INET_ADDRSTRLEN];
					char rd[INET_ADDRSTRLEN];

					inet_ntop(AF_INET, conn->rep_saddr,
					    rs, sizeof(rs));
					inet_ntop(AF_INET, conn->rep_daddr,
					    rd, sizeof(rd));
					cmm_print(CMM_LOG_INFO,
					    "conn: NAT reply now "
					    "%s:%u -> %s:%u",
					    rs, ntohs(conn->rep_sport),
					    rd, ntohs(conn->rep_dport));
				}
			}

			/* Retry offload if not yet done */
			if (!(conn->flags & CONN_F_OFFLOADED))
				conn_try_offload(g, conn);
			continue;
		}

		/* New connection — create entry */
		if (conn_count >= CMM_CONN_MAX) {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: limit reached (%u)", conn_count);
			continue;
		}
		conn = calloc(1, sizeof(*conn));
		if (conn == NULL)
			continue;

		conn_extract_tuples(conn, pfs);
		conn->pf_id = pfs->id;
		conn->pf_creatorid = pfs->creatorid;
		conn->pf_direction = pfs->direction;
		strlcpy(conn->ifname, pfs->ifname, sizeof(conn->ifname));
		conn->last_seen_epoch = epoch;
		conn->hash_entry.next = NULL;
		conn->hash_entry.prev = NULL;

		if (is_nat)
			conn->flags |= CONN_F_HAS_NAT;

		/* Insert into hash table by original 5-tuple */
		{
			unsigned int h;
			h = conn_hash_5tuple(conn->af, conn->proto,
			    conn->orig_saddr, conn->orig_daddr,
			    conn->orig_sport, conn->orig_dport);
			list_add(&conn_hash[h], &conn->hash_entry);
			conn_count++;
		}

		/* Try to offload */
		if (conn_try_offload(g, conn) < 0) {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: offload deferred (route/neigh pending)");
		}
	}

	free(states);

sweep:
	/* Sweep: remove connections not seen in this epoch */
	{
		struct cmm_conn *conn;
		struct list_head *pos, *tmp;

		for (i = 0; i < CONN_HASH_SIZE; i++) {
			pos = list_first(&conn_hash[i]);
			while (pos != &conn_hash[i]) {
				tmp = list_next(pos);
				conn = container_of(pos, struct cmm_conn,
				    hash_entry);
				if (conn->last_seen_epoch != epoch) {
					cmm_print(CMM_LOG_DEBUG,
					    "conn: expired proto=%u%s",
					    conn->proto,
					    (conn->flags & CONN_F_HAS_NAT) ?
					    " (NAT)" : "");
					conn_remove(g, conn);
				}
				pos = tmp;
			}
		}
	}

	/* Free unreferenced routes */
	cmm_route_gc(g);

	/* Periodic stats (~10s at 1s poll) */
	{
		static unsigned int poll_count;

		if (++poll_count % 10 == 0)
			cmm_print(CMM_LOG_INFO,
			    "conn: %u tracked, %u offloaded",
			    conn_count, conn_offloaded);
	}
}

/* --- CDX flow counter sync to PF state table --------------------- */

/*
 * Flush a batch of counter entries to pf_notify via ioctl.
 */
static void
stats_sync_flush(struct cmm_global *g, struct pfn_counter_entry *entries,
    uint32_t count)
{
	struct pfn_counter_update upd;

	if (count == 0)
		return;

	upd.count = count;
	upd.pad = 0;
	upd.entries = entries;

	if (ioctl(g->pfnotify_fd, PFN_IOC_UPDATE_COUNTERS, &upd) < 0)
		cmm_print(CMM_LOG_WARN, "stats_sync: ioctl failed: %s",
		    strerror(errno));
}

void
cmm_conn_stats_sync(struct cmm_global *g)
{
	struct pfn_counter_entry batch[PFN_COUNTER_BATCH_MAX];
	fpp_stat_flow_status_cmd_t cmd;
	fpp_stat_flow_entry_response_t resp;
	unsigned short resp_len;
	struct cmm_conn *conn;
	struct list_head *pos;
	uint32_t n;
	int i, rc;

	if (g->pfnotify_fd < 0)
		return;

	n = 0;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn, hash_entry);

			if (!(conn->flags & CONN_F_OFFLOADED))
				continue;

			/* Build stat query for this flow's original 5-tuple */
			memset(&cmd, 0, sizeof(cmd));
			cmd.action = FPP_CMM_STAT_QUERY_RESET;
			cmd.ip_family = (conn->af == AF_INET) ? 4 : 6;
			cmd.Protocol = conn->proto;
			cmd.Sport = conn->orig_sport;
			cmd.Dport = conn->orig_dport;

			if (conn->af == AF_INET) {
				memcpy(&cmd.Saddr, conn->orig_saddr, 4);
				memcpy(&cmd.Daddr, conn->orig_daddr, 4);
			} else {
				memcpy(cmd.Saddr_v6, conn->orig_saddr, 16);
				memcpy(cmd.Daddr_v6, conn->orig_daddr, 16);
			}

			resp_len = sizeof(resp);
			rc = fci_cmd(g->fci_handle, FPP_CMD_STAT_FLOW,
			    (unsigned short *)&cmd, sizeof(cmd),
			    (unsigned short *)&resp, &resp_len);
			if (rc != 0)
				continue;
			if (resp.TotalPackets == 0 && resp.TotalBytes == 0)
				continue;

			/* Primary PF state */
			memset(&batch[n], 0, sizeof(batch[n]));
			batch[n].id = conn->pf_id;
			batch[n].creatorid = conn->pf_creatorid;
			batch[n].packets[0] = resp.TotalPackets;
			batch[n].bytes[0] = resp.TotalBytes;
			n++;

			/* NAT companion PF state (if present) */
			if (conn->pf_has_nat_id) {
				if (n >= PFN_COUNTER_BATCH_MAX)
					stats_sync_flush(g, batch, n),
					    n = 0;
				memset(&batch[n], 0, sizeof(batch[n]));
				batch[n].id = conn->pf_id_nat;
				batch[n].creatorid = conn->pf_creatorid_nat;
				batch[n].packets[0] = resp.TotalPackets;
				batch[n].bytes[0] = resp.TotalBytes;
				n++;
			}

			if (n >= PFN_COUNTER_BATCH_MAX) {
				stats_sync_flush(g, batch, n);
				n = 0;
			}
		}
	}

	/* Flush remaining */
	stats_sync_flush(g, batch, n);

	cmm_print(CMM_LOG_TRACE, "stats sync done");
}

/* --- FCI async event handling (CDX conntrack timeout) ------------- */

/*
 * Handle CDX conntrack timeout/FIN notifications.
 *
 * When CDX's timer wheel ages out a flow (idle > timeout) or detects
 * TCP FIN, it removes the flow from the FMan hash table and sends
 * CMD_IPV4_CONNTRACK_CHANGE or CMD_IPV6_CONNTRACK_CHANGE via FCI.
 *
 * We clear CONN_F_OFFLOADED so the next poll/event cycle can
 * re-offload if the PF state is still alive.  We do NOT call
 * cmm_fe_ct*_deregister() because CDX already removed the flow.
 */
int
cmm_conn_fci_event(unsigned short fcode, unsigned short len,
    unsigned short *payload)
{
	struct cmm_conn *conn;
	const char *reason;

	if (fcode == FPP_CMD_IPV4_CONNTRACK_CHANGE) {
		fpp_ct_cmd_t *cmd;

		if (len < sizeof(*cmd))
			return (FCI_CB_CONTINUE);

		cmd = (fpp_ct_cmd_t *)payload;

		if (cmd->action != FPP_ACTION_REMOVED &&
		    cmd->action != FPP_ACTION_TCP_FIN)
			return (FCI_CB_CONTINUE);

		reason = (cmd->action == FPP_ACTION_TCP_FIN) ?
		    "tcp_fin" : "timeout";

		conn = conn_find_5tuple(AF_INET, cmd->protocol,
		    &cmd->saddr, &cmd->daddr,
		    cmd->sport, cmd->dport);
		if (conn == NULL) {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: CDX removed unknown IPv4 flow (%s)",
			    reason);
			return (FCI_CB_CONTINUE);
		}

		if (conn->flags & CONN_F_OFFLOADED) {
			conn->flags &= ~CONN_F_OFFLOADED;
			if (conn_offloaded > 0)
				conn_offloaded--;
			cmm_print(CMM_LOG_INFO,
			    "conn: CDX removed IPv4 proto=%u (%s)"
			    " — will re-offload if PF state alive",
			    conn->proto, reason);
		}

		return (FCI_CB_CONTINUE);
	}

	if (fcode == FPP_CMD_IPV6_CONNTRACK_CHANGE) {
		fpp_ct6_cmd_t *cmd;

		if (len < sizeof(*cmd))
			return (FCI_CB_CONTINUE);

		cmd = (fpp_ct6_cmd_t *)payload;

		if (cmd->action != FPP_ACTION_REMOVED &&
		    cmd->action != FPP_ACTION_TCP_FIN)
			return (FCI_CB_CONTINUE);

		reason = (cmd->action == FPP_ACTION_TCP_FIN) ?
		    "tcp_fin" : "timeout";

		conn = conn_find_5tuple(AF_INET6, cmd->protocol,
		    cmd->saddr, cmd->daddr,
		    cmd->sport, cmd->dport);
		if (conn == NULL) {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: CDX removed unknown IPv6 flow (%s)",
			    reason);
			return (FCI_CB_CONTINUE);
		}

		if (conn->flags & CONN_F_OFFLOADED) {
			conn->flags &= ~CONN_F_OFFLOADED;
			if (conn_offloaded > 0)
				conn_offloaded--;
			cmm_print(CMM_LOG_INFO,
			    "conn: CDX removed IPv6 proto=%u (%s)"
			    " — will re-offload if PF state alive",
			    conn->proto, reason);
		}

		return (FCI_CB_CONTINUE);
	}

	return (FCI_CB_CONTINUE);
}
