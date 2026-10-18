/*
 * cmm_conn.c — PF state event handling and connection tracking
 *
 * Maintains a local connection table driven by push-based events
 * from /dev/pfnotify (pf_notify.ko).
 *
 * New connections are checked for offload eligibility and
 * programmed into CDX.  Expired connections are removed from CDX.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_conn.h"
#include "cmm_route.h"
#include "cmm_neigh.h"
#include "cmm_itf.h"
#include "cmm_lagg.h"
#include "cmm_fe.h"
#include "cmm_bridge.h"
#include "cmm_deny.h"
#include "pf_notify.h"
#include "fpp_private.h"
#include "libfci.h"

#include <netinet/tcp_fsm.h>

#ifndef PF_IN
#define PF_IN	1
#endif

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

/* --- Offload pin (pf_notify) ---------------------------------------- */

/*
 * Like ASK's IPS_PERMANENT: while a flow is in CDX its PF states are
 * pinned so PF never times them out, and CDX's own aging decides when
 * the flow is idle.  Without kernel support, stats sync keeps the
 * states alive instead.
 */
static int pin_supported;

static int shaper_reload(void);

/* Last pf timeouts given to CDX, so they're only resent on change. */
static int cdx_tcp_timeout, cdx_udp_timeout, cdx_udp_single_timeout;

static int
pf_timeout(int fd, int which)
{
	struct pfioc_tm tm;

	memset(&tm, 0, sizeof(tm));
	tm.timeout = which;
	if (ioctl(fd, DIOCGETTIMEOUT, &tm) < 0)
		return (-1);
	return (tm.seconds);
}

/*
 * Give CDX pf's idle timeouts, so a pinned flow leaves hardware when pf
 * would have timed it out (CDX defaults to Linux's TCP 5 days).
 */
static void
conn_sync_cdx_timeouts(struct cmm_global *g)
{
	fpp_timeout_cmd_t cmd;
	int fd, tcp, udp, udp_single;

	if (!pin_supported || g->fci_handle == NULL)
		return;

	fd = open("/dev/pf", O_RDONLY);
	if (fd < 0)
		return;
	tcp = pf_timeout(fd, PFTM_TCP_ESTABLISHED);
	udp = pf_timeout(fd, PFTM_UDP_MULTIPLE);
	udp_single = pf_timeout(fd, PFTM_UDP_SINGLE);
	close(fd);

	if (tcp > 0 && tcp != cdx_tcp_timeout) {
		memset(&cmd, 0, sizeof(cmd));
		cmd.protocol = IPPROTO_TCP;
		cmd.timeout_value1 = tcp;
		if (fci_write(g->fci_handle, FPP_CMD_IPV4_SET_TIMEOUT,
		    sizeof(cmd), (unsigned short *)&cmd) == 0) {
			cdx_tcp_timeout = tcp;
			/* Rare (startup or a pf change), so always logged. */
			cmm_print(CMM_LOG_WARN, "conn: CDX TCP timeout %ds", tcp);
		}
	}
	if (udp > 0 && udp_single > 0 && (udp != cdx_udp_timeout ||
	    udp_single != cdx_udp_single_timeout)) {
		memset(&cmd, 0, sizeof(cmd));
		cmd.protocol = IPPROTO_UDP;
		cmd.timeout_value1 = udp;
		cmd.timeout_value2 = udp_single;
		if (fci_write(g->fci_handle, FPP_CMD_IPV4_SET_TIMEOUT,
		    sizeof(cmd), (unsigned short *)&cmd) == 0) {
			cdx_udp_timeout = udp;
			cdx_udp_single_timeout = udp_single;
			cmm_print(CMM_LOG_WARN, "conn: CDX UDP timeout %ds/%ds",
			    udp, udp_single);
		}
	}
}

void
cmm_conn_pin_init(struct cmm_global *g)
{
	struct pfn_pin_update upd;

	/* An empty batch only asks whether the kernel can pin. */
	memset(&upd, 0, sizeof(upd));
	pin_supported = (ioctl(g->pfnotify_fd, PFN_IOC_SET_PIN, &upd) == 0);
	cmm_print(CMM_LOG_WARN, "conn: offload pin %s",
	    pin_supported ? "supported" :
	    "not supported, keeping flows alive from CDX counters");

	conn_sync_cdx_timeouts(g);
	shaper_reload();
}

/*
 * Pin (or unpin) the flow's PF states: the primary and, if known, the
 * companion.  Returns -1 if PF says the TCP flow is already closing, in
 * which case nothing is left pinned.
 */
static int
conn_pin(struct cmm_global *g, struct cmm_conn *conn, int pin)
{
	struct pfn_pin_entry e[2];
	struct pfn_pin_update upd;
	uint32_t i, n;

	if (!pin_supported || g->pfnotify_fd < 0)
		return (0);
	if (!pin && !(conn->flags & CONN_F_PINNED))
		return (0);

	memset(e, 0, sizeof(e));
	n = 0;
	e[n].id = conn->pf_id;
	e[n].creatorid = conn->pf_creatorid;
	e[n].pin = pin;
	n++;
	if (conn->pf_has_nat_id) {
		e[n].id = conn->pf_id_nat;
		e[n].creatorid = conn->pf_creatorid_nat;
		e[n].pin = pin;
		n++;
	}

	memset(&upd, 0, sizeof(upd));
	upd.count = n;
	upd.entries = e;
	if (ioctl(g->pfnotify_fd, PFN_IOC_SET_PIN, &upd) < 0) {
		/* Not pinned: stats sync keeps it alive the old way. */
		cmm_print(CMM_LOG_WARN, "conn: pin ioctl failed: %s",
		    strerror(errno));
		return (0);
	}

	if (!pin) {
		conn->flags &= ~CONN_F_PINNED;
		return (0);
	}

	conn->flags |= CONN_F_PINNED;
	for (i = 0; i < n; i++) {
		if (e[i].result == PFN_PIN_CLOSING) {
			conn_pin(g, conn, 0);
			return (-1);
		}
		/* A rule with its own timeout keeps the counter keep-alive,
		 * which follows that timeout exactly. */
		if (e[i].result == PFN_PIN_OWN_TIMEOUT) {
			conn_pin(g, conn, 0);
			return (0);
		}
	}
	return (0);
}

/*
 * The flow leaves CDX.  in_cdx says whether CDX still holds it (it
 * doesn't after its own aging removed it, or after a full reset).
 * Unpinning hands the PF states back to PF's own timeouts.
 */
static void
conn_offload_stop(struct cmm_global *g, struct cmm_conn *conn, int in_cdx)
{
	if (!(conn->flags & CONN_F_OFFLOADED))
		return;

	if (!in_cdx)
		conn->flags &= ~CONN_F_OFFLOADED;
	else if (conn->af == AF_INET)
		cmm_fe_ct4_deregister(g, conn);
	else
		cmm_fe_ct6_deregister(g, conn);
	if (conn_offloaded > 0)
		conn_offloaded--;

	conn_pin(g, conn, 0);
}

static void
conn_remove(struct cmm_global *g, struct cmm_conn *conn)
{
	/* Deregister from CDX if offloaded.  Unpinning matters when only the
	 * primary state went away - the companion would otherwise stay
	 * pinned forever. */
	conn_offload_stop(g, conn, 1);

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
 * Swap *rtp for the route to the same destination keyed on iif.
 */
static int
route_rekey(struct cmm_global *g, struct cmm_route **rtp, int iif)
{
	struct cmm_route *old = *rtp, *rt;

	rt = cmm_route_get(g, old->family, old->dst, old->oif_hint, iif);
	if (rt == NULL)
		return (-1);
	*rtp = rt;
	cmm_route_put(old);
	return (0);
}

/* --- Traffic shaper (ipfw dummynet) -------------------------------- */

/*
 * OPNsense's traffic shaper is ipfw pipes/queues matched per interface,
 * and CDX can't shape.  Flows through any interface a pipe/queue rule
 * names stay in software - coarser than ipfw's own match, but a shaped
 * flow can never skip its pipe.
 */
#define SHAPED_ITF_MAX	32

static char shaped_itf[SHAPED_ITF_MAX][IFNAMSIZ];
static int shaped_itf_count;
static int shaped_all;		/* a pipe/queue rule with no interface */

static int
itf_shaped(int ifindex)
{
	struct cmm_interface *itf;
	int i;

	if (shaped_all)
		return (1);
	if (shaped_itf_count == 0)
		return (0);
	itf = cmm_itf_find_by_index(ifindex);
	if (itf == NULL)
		return (0);
	for (i = 0; i < shaped_itf_count; i++)
		if (strcmp(itf->ifname, shaped_itf[i]) == 0)
			return (1);
	return (0);
}

/*
 * One line of "ipfw list": "<nr> pipe|queue <n> ... via|recv|xmit <if> ...".
 * Adds the interfaces it names to names[], or sets *all if it names none.
 */
static void
shaper_parse_line(char *line, char names[][IFNAMSIZ], int *n, int *all)
{
	char *tok, *last;
	int has_itf, i;

	if (strtok_r(line, " \t\n", &last) == NULL)
		return;				/* rule number */
	tok = strtok_r(NULL, " \t\n", &last);
	if (tok == NULL || (strcmp(tok, "pipe") != 0 &&
	    strcmp(tok, "queue") != 0))
		return;
	has_itf = 0;
	while ((tok = strtok_r(NULL, " \t\n", &last)) != NULL &&
	    strcmp(tok, "//") != 0) {
		if (strcmp(tok, "via") != 0 && strcmp(tok, "recv") != 0 &&
		    strcmp(tok, "xmit") != 0)
			continue;
		tok = strtok_r(NULL, " \t\n", &last);
		if (tok == NULL)
			break;
		has_itf = 1;
		if (strcmp(tok, "any") == 0) {
			*all = 1;
			continue;
		}
		for (i = 0; i < *n; i++)
			if (strcmp(names[i], tok) == 0)
				break;
		if (i == *n && *n < SHAPED_ITF_MAX)
			strlcpy(names[(*n)++], tok, IFNAMSIZ);
	}
	if (!has_itf)
		*all = 1;
}

/* Re-read ipfw's pipe/queue rules.  Returns 1 if the shaped set changed. */
static int
shaper_reload(void)
{
	char names[SHAPED_ITF_MAX][IFNAMSIZ];
	char line[1024];
	int n, all, i, changed;
	size_t len;
	u_int dummy;
	FILE *fp;

	n = 0;
	all = 0;

	/* No dummynet loaded means no shaping. */
	len = sizeof(dummy);
	if (sysctlbyname("net.inet.ip.dummynet.expire", &dummy, &len,
	    NULL, 0) == 0 &&
	    (fp = popen("/sbin/ipfw -q list 2>/dev/null", "r")) != NULL) {
		while (fgets(line, sizeof(line), fp) != NULL)
			shaper_parse_line(line, names, &n, &all);
		pclose(fp);
	}

	changed = (all != shaped_all || n != shaped_itf_count);
	for (i = 0; !changed && i < n; i++)
		if (strcmp(names[i], shaped_itf[i]) != 0)
			changed = 1;
	if (!changed)
		return (0);

	shaped_all = all;
	shaped_itf_count = n;
	memcpy(shaped_itf, names, sizeof(names));

	/* Rare (shaper config change), so always logged. */
	if (all)
		cmm_print(CMM_LOG_WARN,
		    "conn: traffic shaper covers all interfaces, not offloading");
	else if (n == 0)
		cmm_print(CMM_LOG_WARN, "conn: no traffic shaper interfaces");
	for (i = 0; !all && i < n; i++)
		cmm_print(CMM_LOG_WARN,
		    "conn: traffic shaper on %s, not offloading its flows",
		    shaped_itf[i]);
	return (1);
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
/* CDX can't place flows on a LAGG or VLAN it doesn't have registered,
 * e.g. while a LAGG is down or has no member up. */
static int
itf_offload_ready(int ifindex)
{
	struct cmm_interface *itf;

	itf = cmm_itf_find_by_index(ifindex);
	if (itf == NULL)
		return (1);
	if ((itf->itf_flags & ITF_F_LAGG) &&
	    !(itf->itf_flags & ITF_F_FPP_LAGG))
		return (0);
	if ((itf->itf_flags & ITF_F_VLAN) &&
	    !(itf->itf_flags & ITF_F_FPP_VLAN))
		return (0);
	return (1);
}

static int
conn_try_offload(struct cmm_global *g, struct cmm_conn *conn)
{
	/* Look up route for original direction (dst = orig_daddr) */
	if (conn->orig_route == NULL)
		conn->orig_route = cmm_route_get(g, conn->af,
		    conn->orig_daddr, conn->rt_ifindex, 0);
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
		    conn->orig_saddr, conn->rt_ifindex_rep, 0);
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
		if (conn->af == AF_INET) {
			char sb[INET_ADDRSTRLEN], db[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, conn->orig_saddr,
			    sb, sizeof(sb));
			inet_ntop(AF_INET, conn->orig_daddr,
			    db, sizeof(db));
			cmm_print(CMM_LOG_DEBUG,
			    "conn: reply neighbor not resolved "
			    "proto=%u %s->%s rep_oif=%d",
			    conn->proto, sb, db,
			    conn->rep_route->oif_index);
		} else {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: reply neighbor not resolved "
			    "rep_oif=%d",
			    conn->rep_route->oif_index);
		}
		return (-1);
	}

	/*
	 * The input for one direction is the output of the opposite
	 * direction.  CDX installs flows on the route's input port, so
	 * switch each direction to the route keyed on its input interface
	 * rather than setting it on a route other connections share.
	 */
	{
		int iif_orig = resolve_iif_index(conn->rep_route);
		int iif_rep = resolve_iif_index(conn->orig_route);

		if (conn->orig_route->iif_index != iif_orig &&
		    route_rekey(g, &conn->orig_route, iif_orig) != 0)
			return (-1);
		if (conn->rep_route->iif_index != iif_rep &&
		    route_rekey(g, &conn->rep_route, iif_rep) != 0)
			return (-1);
	}

	/* Each direction's input is the other's output, so this covers
	 * both ends of the flow. */
	if (!itf_offload_ready(conn->orig_route->oif_index) ||
	    !itf_offload_ready(conn->rep_route->oif_index)) {
		cmm_print(CMM_LOG_DEBUG,
		    "conn: interface not registered in CDX, not offloading");
		return (-1);
	}

	/* Both interfaces again: a shaper on either one needs every packet. */
	if (itf_shaped(conn->orig_route->oif_index) ||
	    itf_shaped(conn->rep_route->oif_index)) {
		cmm_print(CMM_LOG_DEBUG,
		    "conn: interface has a traffic shaper, not offloading");
		return (-1);
	}

	/* Send routes to CDX (idempotent if already programmed) */
	if (!conn->orig_route->fpp_programmed && !conn->orig_route->fpp_rejected)
		cmm_fe_route_register(g, conn->orig_route);
	if (!conn->rep_route->fpp_programmed && !conn->rep_route->fpp_rejected)
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
		if (rc != 0) {
			conn->flags |= CONN_F_CT_FAILED;
			return (rc);
		}
		conn->flags &= ~(CONN_F_CT_FAILED | CONN_F_IDLE);
		conn_offloaded++;

		/* A FIN already went through PF, so it can't be pinned -
		 * leave it to PF's closing timeouts. */
		if (conn_pin(g, conn, 1) < 0) {
			conn_offload_stop(g, conn, 1);
			conn->flags |= CONN_F_CLOSING;
			return (-1);
		}
		return (0);
	}
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
			conn_offload_stop(g, conn, 1);

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
			conn_offload_stop(g, conn, 0);
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
 * Same lookup, but by NAT-companion id instead of primary id. A
 * companion state closing (DELETE, live or missed) doesn't end the
 * connection - the primary keeps going - so callers use this only to
 * find and clear stale companion bookkeeping, never to conn_remove().
 */
static struct cmm_conn *
conn_find_by_nat_pfid(uint64_t id, uint32_t creatorid)
{
	struct list_head *pos;
	struct cmm_conn *conn;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn,
			    hash_entry);
			if (conn->pf_has_nat_id &&
			    conn->pf_id_nat == id &&
			    conn->pf_creatorid_nat == creatorid)
				return (conn);
		}
	}
	return (NULL);
}

/*
 * Clear stale NAT-companion bookkeeping on a connection whose companion
 * PF state is gone. Leaves the connection and its primary PF state
 * (and offload) untouched - only the companion fields are reset so
 * stats-sync stops re-querying a dead id forever.
 */
static void
conn_clear_nat_companion(struct cmm_conn *conn)
{
	conn->pf_id_nat = 0;
	conn->pf_creatorid_nat = 0;
	conn->pf_has_nat_id = 0;
	if (conn->flags & CONN_F_NAT_COMPANION)
		conn->flags &= ~(CONN_F_HAS_NAT | CONN_F_NAT_COMPANION);
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
	int sidx, didx, alen, is_nat, no_offload;
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
	no_offload = (ev->flags & PFN_EVF_NO_OFFLOAD) != 0;

	/* Extract original 5-tuple from STACK key */
	memset(osaddr, 0, sizeof(osaddr));
	memset(odaddr, 0, sizeof(odaddr));
	memcpy(osaddr, ev->key[1].addr[sidx], alen);
	memcpy(odaddr, ev->key[1].addr[didx], alen);
	osport = ev->key[1].port[sidx];
	odport = ev->key[1].port[didx];

	/* Check deny rules */
	if (cmm_deny_check_tuple(af, proto, osaddr, odaddr,
	    osport, odport, ev->ifname))
		return;

	conn = conn_find_5tuple(af, proto, osaddr, odaddr, osport, odport);
	if (conn != NULL) {
		/* One of the flow's states needs PF on every packet - take
		 * it back out of CDX if the other state got it there. */
		if (no_offload && !(conn->flags & CONN_F_NO_OFFLOAD)) {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: proto=%u needs PF (seq rewrite or dummynet), "
			    "not offloading", conn->proto);
			conn_offload_stop(g, conn, 1);
			conn->flags |= CONN_F_NO_OFFLOAD;
		}

		/* Existing connection — handle NAT upgrade. This is the
		 * normal, expected path for NAT'd connections (the companion
		 * PF_OUT state's READY event arriving after the connection's
		 * own creation) — confirmed both correct and routine on
		 * hardware, so this stays at DEBUG rather than a level that
		 * would log on nearly every NAT'd connection in production. */
		if (is_nat && !(conn->flags & CONN_F_HAS_NAT)) {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: NAT upgrade from push event");

			/* Re-offloading below pins the new state pair. */
			conn_offload_stop(g, conn, 1);

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

			/* Don't apply this event's rt_ifindex to the reply
			 * direction. FreeBSD pf uses one state per connection,
			 * so this is the same state's outbound route-to hint,
			 * not an independent decision for the reply path. */

			/* Save NAT companion PF state ID */
			conn->pf_id_nat = ev->id;
			conn->pf_creatorid_nat = ev->creatorid;
			conn->pf_has_nat_id = 1;

			conn->flags |= CONN_F_HAS_NAT | CONN_F_NAT_COMPANION;
		} else if (!is_nat && !conn->pf_has_nat_id &&
		    (ev->id != conn->pf_id ||
		    ev->creatorid != conn->pf_creatorid)) {
			/* The flow's other PF state became ready after this conn
			 * was created. Track it so stats-sync keeps it alive too,
			 * or PF expires it mid-flow (UDP: 30s). */
			conn->pf_id_nat = ev->id;
			conn->pf_creatorid_nat = ev->creatorid;
			conn->pf_has_nat_id = 1;

			/* Already in CDX: pin the new state too. */
			if ((conn->flags & CONN_F_PINNED) &&
			    conn_pin(g, conn, 1) < 0) {
				conn_offload_stop(g, conn, 1);
				conn->flags |= CONN_F_CLOSING;
			}
		}

		if (conn->flags & (CONN_F_CLOSING | CONN_F_NO_OFFLOAD))
			return;

		/* Traffic is back through PF after CDX aged the flow out. */
		conn->flags &= ~CONN_F_IDLE;
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
	conn->rt_ifindex = ev->rt_ifindex;
	/* rt_ifindex_rep stays 0 (calloc) - the reply path resolves via
	 * the normal FIB, not this connection's outbound route-to hint. */
	conn->hash_entry.next = NULL;
	conn->hash_entry.prev = NULL;

	if (is_nat)
		conn->flags |= CONN_F_HAS_NAT;
	if (no_offload)
		conn->flags |= CONN_F_NO_OFFLOAD;

	{
		unsigned int h;

		h = conn_hash_5tuple(conn->af, conn->proto,
		    conn->orig_saddr, conn->orig_daddr,
		    conn->orig_sport, conn->orig_dport);
		list_add(&conn_hash[h], &conn->hash_entry);
		conn_count++;
	}

	/* Tracked anyway, so the flow's other state can't offload it. */
	if (conn->flags & CONN_F_NO_OFFLOAD)
		return;

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
		/* Not a primary id - check whether it's a NAT companion
		 * closing on its own (e.g. asymmetric close) while the
		 * primary connection is still alive. That's not an
		 * unknown id, just stale bookkeeping to clear. */
		conn = conn_find_by_nat_pfid(ev->id, ev->creatorid);
		if (conn != NULL) {
			cmm_print(CMM_LOG_DEBUG,
			    "conn: proto=%u NAT companion closed, "
			    "clearing stale companion id", conn->proto);
			conn_clear_nat_companion(conn);
			return;
		}

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

/*
 * fpp_rejected is armed so the next route event re-resolves and
 * reprograms the holder (we-are-mono/ASK's FPP_NEEDS_UPDATE plays the
 * same role for its tunnels/sockets/SAs). Called from
 * cmm_route_handle_change() so a connection rejected only because
 * CDX didn't know its interface yet (issue #11's boot race: cmm
 * starting before WAN finishes its post-DHCP reconfiguration)
 * recovers as soon as a route event arrives, whatever event that is
 * - not bounded by CMM_MAINT_MS. Also called from the periodic
 * maintenance pass as a backstop for rejections with no dedicated
 * event (e.g. CDX-side transient failures).
 */
static void
conn_clear_ct_failed(void)
{
	struct cmm_conn *conn;
	struct list_head *pos;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn,
			    hash_entry);
			conn->flags &= ~CONN_F_CT_FAILED;
		}
	}
}

unsigned int
cmm_conn_retry_rejected(struct cmm_global *g)
{
	struct cmm_conn *conn;
	struct list_head *pos;
	int i;
	unsigned int retried = 0;

	/* Catch gateway MAC changes before retrying offload, so anything
	 * just invalidated re-offloads in this same pass. */
	cmm_route_check_neigh_changes(g);

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn,
			    hash_entry);
			/* Don't hammer CDX with a flow it just refused;
			 * maintenance clears the flag for the next try.  An
			 * idle flow waits for its next packet (READY) instead,
			 * and a closing one stays with PF. */
			if (!(conn->flags & (CONN_F_OFFLOADED | CONN_F_CT_FAILED |
			    CONN_F_IDLE | CONN_F_CLOSING | CONN_F_NO_OFFLOAD))) {
				int was_rejected =
				    (conn->orig_route != NULL &&
				    conn->orig_route->fpp_rejected) ||
				    (conn->rep_route != NULL &&
				    conn->rep_route->fpp_rejected);

				if (conn->orig_route != NULL)
					conn->orig_route->fpp_rejected = 0;
				if (conn->rep_route != NULL)
					conn->rep_route->fpp_rejected = 0;
				if (conn_try_offload(g, conn) == 0) {
					retried++;
					if (was_rejected)
						/* Always log recovery, so a boot-time rejection is easy to confirm fixed. */
						cmm_print(CMM_LOG_ERR,
						    "conn: route id=%u "
						    "recovered from earlier "
						    "CDX rejection, offload "
						    "now active",
						    conn->orig_route->fpp_id);
				}
			}
		}
	}

	return (retried);
}

/*
 * Periodic maintenance: retry offload for connections rejected for
 * reasons with no dedicated event (backstop for
 * cmm_conn_retry_rejected()'s event-driven callers), garbage-collect
 * unreferenced routes, and log stats.
 */
void
cmm_conn_maintenance(struct cmm_global *g)
{
	unsigned int retried;

	/* Catch gateway MAC changes before retrying offload, so anything
	 * just invalidated re-offloads in this same pass. */
	cmm_route_check_neigh_changes(g);

	/* Catch laggproto changes with no triggering event (see
	 * cmm_lagg_recheck_all()'s comment) before retrying offload, same
	 * reasoning as the MAC-change check above. */
	cmm_lagg_recheck_all(g);

	/* OPNsense can change pf's timeouts on any filter reload. */
	conn_sync_cdx_timeouts(g);

	/* A newly shaped interface takes its flows back out of CDX; the
	 * retry pass below re-offloads them once a shaper is removed. */
	if (shaper_reload()) {
		struct cmm_conn *conn;
		struct list_head *pos;
		int i;

		for (i = 0; i < CONN_HASH_SIZE; i++) {
			for (pos = list_first(&conn_hash[i]);
			    pos != &conn_hash[i]; pos = list_next(pos)) {
				conn = container_of(pos, struct cmm_conn,
				    hash_entry);
				if ((conn->flags & CONN_F_OFFLOADED) &&
				    (itf_shaped(conn->orig_route->oif_index) ||
				    itf_shaped(conn->rep_route->oif_index)))
					conn_offload_stop(g, conn, 1);
			}
		}
	}

	conn_clear_ct_failed();
	retried = cmm_conn_retry_rejected(g);

	if (retried > 0)
		cmm_print(CMM_LOG_INFO,
		    "conn: maintenance re-offloaded %u flows", retried);

	/* Free unreferenced routes */
	cmm_route_gc(g);

	cmm_print(CMM_LOG_INFO, "conn: %u tracked, %u offloaded",
	    conn_count, conn_offloaded);
}

/* --- CDX flow counter sync to PF state table --------------------- */

/* Conns marked CONN_F_ORPHAN during this stats sync pass. */
static unsigned int stats_orphans;

/*
 * Flush a batch of counter entries to pf_notify via ioctl.
 */
static void
stats_sync_flush(struct cmm_global *g, struct pfn_counter_entry *entries,
    uint32_t count)
{
	struct pfn_counter_update upd;
	struct cmm_conn *conn;
	uint32_t i;

	if (count == 0)
		return;

	upd.count = count;
	upd.pad = 0;
	upd.entries = entries;

	if (ioctl(g->pfnotify_fd, PFN_IOC_UPDATE_COUNTERS, &upd) < 0) {
		cmm_print(CMM_LOG_WARN, "stats_sync: ioctl failed: %s",
		    strerror(errno));
		return;
	}

	/* PF has no state for this id — it was already torn down and we
	 * missed the DELETE event (e.g. a full ring). Check the primary
	 * id first: a missing primary means the whole conn is orphaned.
	 * A missing NAT-companion id doesn't end the conn - the primary
	 * is unaffected - so that case only clears the stale companion
	 * bookkeeping instead of removing anything. */
	for (i = 0; i < count; i++) {
		if (!entries[i].missing)
			continue;
		conn = conn_find_by_pfid(entries[i].id, entries[i].creatorid);
		if (conn != NULL) {
			cmm_print(CMM_LOG_INFO,
			    "conn: proto=%u orphaned (PF state gone, "
			    "DELETE missed)", conn->proto);
			/* Removed after the scan: the caller may be standing
			 * on this conn mid-loop. */
			if (!(conn->flags & CONN_F_ORPHAN)) {
				conn->flags |= CONN_F_ORPHAN;
				stats_orphans++;
			}
			continue;
		}

		conn = conn_find_by_nat_pfid(entries[i].id,
		    entries[i].creatorid);
		if (conn == NULL)
			continue;
		cmm_print(CMM_LOG_DEBUG,
		    "conn: proto=%u NAT companion gone (DELETE missed), "
		    "clearing stale companion id", conn->proto);
		conn_clear_nat_companion(conn);
	}
}

/*
 * Per-tick cap on connections queried.  fci_cmd() blocks on a real
 * ioctl round-trip per connection, on the same thread that services
 * pfnotify/rtsock - querying the whole table in one call stalls both
 * for however long that takes.  1024 keeps a full lap (at a realistic
 * few thousand offloaded connections) well under pf's 30s single-
 * direction UDP timeout, so a slow lap can't cost a live connection
 * its PF state and force an avoidable re-offload.
 */
#define CMM_STATS_SYNC_MAX_PER_TICK	1024

static void conn_cdx_removed(struct cmm_conn *conn, const char *family,
    const char *reason);

/*
 * Read and reset CDX's counters for one direction of a flow. CDX keeps
 * separate counters for the original and reply directions.
 * Returns ENOENT if CDX no longer has the flow, -1 if the query failed.
 */
static int
conn_flow_stat(struct cmm_global *g, const struct cmm_conn *conn, int reply,
    uint64_t *packets, uint64_t *bytes)
{
	fpp_stat_flow_status_cmd_t cmd;
	fpp_stat_flow_entry_response_t resp;
	unsigned short resp_len;
	const uint8_t *saddr, *daddr;

	saddr = reply ? conn->rep_saddr : conn->orig_saddr;
	daddr = reply ? conn->rep_daddr : conn->orig_daddr;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_CMM_STAT_QUERY_RESET;
	cmd.ip_family = (conn->af == AF_INET) ? 4 : 6;
	cmd.Protocol = conn->proto;
	cmd.Sport = reply ? conn->rep_sport : conn->orig_sport;
	cmd.Dport = reply ? conn->rep_dport : conn->orig_dport;

	if (conn->af == AF_INET) {
		memcpy(&cmd.Saddr, saddr, 4);
		memcpy(&cmd.Daddr, daddr, 4);
	} else {
		memcpy(cmd.Saddr_v6, saddr, 16);
		memcpy(cmd.Daddr_v6, daddr, 16);
	}

	memset(&resp, 0, sizeof(resp));
	resp_len = sizeof(resp);
	if (fci_cmd(g->fci_handle, FPP_CMD_STAT_FLOW,
	    (unsigned short *)&cmd, sizeof(cmd),
	    (unsigned short *)&resp, &resp_len) != 0)
		return (-1);
	if (resp.ackstatus == FPP_ERR_FLOW_ENTRY_NOT_FOUND)
		return (ENOENT);
	if (resp.ackstatus != 0)
		return (-1);

	*packets = resp.TotalPackets;
	*bytes = resp.TotalBytes;
	return (0);
}

void
cmm_conn_stats_sync(struct cmm_global *g)
{
	struct pfn_counter_entry batch[PFN_COUNTER_BATCH_MAX];
	uint64_t pkts[2], bytes[2];
	struct cmm_conn *conn;
	struct list_head *pos;
	static unsigned int cursor;
	unsigned int start, i, matched;
	uint32_t n;
	int rc;

	if (g->pfnotify_fd < 0)
		return;

	if (cursor >= CONN_HASH_SIZE)
		cursor = 0;
	start = cursor;
	n = 0;
	matched = 0;

	i = start;
	do {
		for (pos = list_first(&conn_hash[i]);
		    pos != &conn_hash[i]; pos = list_next(pos)) {
			conn = container_of(pos, struct cmm_conn, hash_entry);

			if (!(conn->flags & CONN_F_OFFLOADED))
				continue;

			if (matched >= CMM_STATS_SYNC_MAX_PER_TICK)
				goto done_scan;
			matched++;

			/* Check both directions: a mostly one-way flow (e.g. a
			 * download) can show nothing in the original direction,
			 * and skipping it would let PF expire the flow. */
			rc = conn_flow_stat(g, conn, 0, &pkts[0], &bytes[0]);
			if (rc == ENOENT) {
				/* CDX already dropped it; its notice may still
				 * be on the way. */
				conn_cdx_removed(conn,
				    conn->af == AF_INET ? "IPv4" : "IPv6",
				    "gone at stats sync");
				continue;
			}
			if (rc != 0) {
				/* Query failed, so the flow may still be in
				 * CDX - don't leave its PF states pinned. */
				if (conn->flags & CONN_F_PINNED) {
					conn_offload_stop(g, conn, 1);
					conn->flags |= CONN_F_IDLE;
				}
				continue;
			}
			if (conn_flow_stat(g, conn, 1, &pkts[1], &bytes[1]) != 0)
				pkts[1] = bytes[1] = 0;
			if (pkts[0] == 0 && pkts[1] == 0)
				continue;

			/* Primary PF state */
			memset(&batch[n], 0, sizeof(batch[n]));
			batch[n].id = conn->pf_id;
			batch[n].creatorid = conn->pf_creatorid;
			batch[n].packets[0] = pkts[0];
			batch[n].packets[1] = pkts[1];
			batch[n].bytes[0] = bytes[0];
			batch[n].bytes[1] = bytes[1];
			n++;

			/* NAT companion PF state (if present). Traffic is
			 * credited to the primary only - one flow, one
			 * count. This entry just keeps its expire refreshed
			 * - still needed once a half-closed TCP flow has
			 * been unpinned by its FIN. */
			if (conn->pf_has_nat_id) {
				if (n >= PFN_COUNTER_BATCH_MAX)
					stats_sync_flush(g, batch, n),
					    n = 0;
				memset(&batch[n], 0, sizeof(batch[n]));
				batch[n].id = conn->pf_id_nat;
				batch[n].creatorid = conn->pf_creatorid_nat;
				n++;
			}

			if (n >= PFN_COUNTER_BATCH_MAX) {
				stats_sync_flush(g, batch, n);
				n = 0;
			}
		}

		i = (i + 1 == CONN_HASH_SIZE) ? 0 : i + 1;
	} while (i != start);

done_scan:
	/* Resume from here next tick - past the last bucket we finished,
	 * or the one we stopped mid-way through on hitting the cap. */
	cursor = i;

	/* Flush remaining */
	stats_sync_flush(g, batch, n);

	/* Now it's safe to remove conns whose PF state is gone. */
	if (stats_orphans > 0) {
		struct list_head *tmp;

		for (i = 0; i < CONN_HASH_SIZE; i++) {
			pos = list_first(&conn_hash[i]);
			while (pos != &conn_hash[i]) {
				tmp = list_next(pos);
				conn = container_of(pos, struct cmm_conn,
				    hash_entry);
				if (conn->flags & CONN_F_ORPHAN)
					conn_remove(g, conn);
				pos = tmp;
			}
		}
		stats_orphans = 0;
	}

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
 * Like ASK's cmmFeCtChange4(), this ends the flow's time in hardware.
 * CDX already removed it, so there's no deregister.  A pinned flow is
 * unpinned (PF times it out normally from now) and waits for its next
 * packet through PF to re-offload; without pinning, the retry pass
 * re-offloads it if the PF state is still alive.
 */
static void
conn_cdx_removed(struct cmm_conn *conn, const char *family,
    const char *reason)
{
	int was_pinned;

	if (!(conn->flags & CONN_F_OFFLOADED))
		return;

	was_pinned = conn->flags & CONN_F_PINNED;
	conn_offload_stop(&cmm_g, conn, 0);
	if (was_pinned)
		conn->flags |= CONN_F_IDLE;

	cmm_print(CMM_LOG_INFO, "conn: CDX removed %s proto=%u (%s)%s",
	    family, conn->proto, reason,
	    was_pinned ? ", unpinned" : ", will re-offload if PF state alive");
}

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

		conn_cdx_removed(conn, "IPv4", reason);

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

		conn_cdx_removed(conn, "IPv6", reason);

		return (FCI_CB_CONTINUE);
	}

	return (FCI_CB_CONTINUE);
}
