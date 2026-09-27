/*
 * cmm_lagg.c — LAGG interface offload
 *
 * Detects LAGG (link aggregation) interfaces and registers them with
 * CDX via FPP_CMD_LAGG_ENTRY so the hardware knows the LAGG-to-port
 * mapping for flow classification.  LAGG is transparent to header
 * manipulation — it only provides a traversable node so that
 * VLAN->LAGG->ETH resolution works.
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
#include <sys/event.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_lagg.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_lagg.h"
#include "cmm_itf.h"
#include "cmm_route.h"
#include "cmm_vlan.h"
#include "cmm_conn.h"

/* LAGG_MAX_PORTS is defined in <net/if_lagg.h> */

static int
cmm_lagg_register(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_lagg_cmd_t cmd;
	int rc, i;

	if (!(itf->itf_flags & ITF_F_LAGG))
		return (0);
	if (itf->itf_flags & ITF_F_FPP_LAGG) {
		cmm_print(CMM_LOG_DEBUG,
		    "lagg: skip %s — already registered in CDX",
		    itf->ifname);
		return (0);
	}
	if (itf->lagg_active_port[0] == '\0') {
		cmm_print(CMM_LOG_WARN,
		    "lagg: skip %s — no active member port",
		    itf->ifname);
		return (0);
	}
	/* laggproto broadcast used to be rejected here outright, since
	 * hardware offload picks one forwarding action per flow and
	 * broadcast's whole point is duplicating every packet to every
	 * member port. CDX now builds a per-flow REPLICATE_PKT chain
	 * (cdx_build_lagg_broadcast_replicas() in cdx_ehash.c, called
	 * from insert_entry_in_classif_table() for each flow as it's
	 * offloaded) reusing the same FMan mechanism IP multicast uses,
	 * so it's registered like any other LAGG - lagg_proto just needs
	 * to reach CDX so it knows to build the chain per flow. */

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_REGISTER;
	strlcpy(cmd.lagg_ifname, itf->ifname, sizeof(cmd.lagg_ifname));
	strlcpy(cmd.lagg_phy_ifname, itf->lagg_active_port,
	    sizeof(cmd.lagg_phy_ifname));
	memcpy(cmd.macaddr, itf->macaddr, ETHER_ADDR_LEN);
	cmd.lagg_proto = itf->lagg_proto;

	/* Populate member port list for multi-port hash entries */
	cmd.num_members = 0;
	for (i = 0; i < itf->lagg_num_members &&
	    i < FPP_LAGG_MAX_MEMBERS; i++) {
		strlcpy(cmd.member_ifnames[i], itf->lagg_members[i],
		    IFNAMSIZ);
		cmd.num_members++;
	}
	if (itf->lagg_num_members > FPP_LAGG_MAX_MEMBERS)
		cmm_print(CMM_LOG_WARN,
		    "lagg: %s has %d members, hardware offload only supports "
		    "%d - members beyond the first %d get no hardware TX/RX "
		    "matching or broadcast replication (silently limited to "
		    "software for those ports)", itf->ifname,
		    itf->lagg_num_members, FPP_LAGG_MAX_MEMBERS,
		    FPP_LAGG_MAX_MEMBERS);

	rc = fci_write(g->fci_handle, FPP_CMD_LAGG_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc == FPP_ERR_LAGG_ENTRY_ALREADY_REGISTERED) {
		cmm_print(CMM_LOG_DEBUG,
		    "lagg: %s already in CDX, reusing", itf->ifname);
	} else if (rc != 0) {
		cmm_print(CMM_LOG_WARN, "lagg: register %s failed: %d",
		    itf->ifname, rc);
		return (-1);
	}

	itf->itf_flags |= ITF_F_FPP_LAGG;
	cmm_print(CMM_LOG_INFO,
	    "lagg: registered %s (active=%s, %d members, proto=%u)",
	    itf->ifname, itf->lagg_active_port, cmd.num_members,
	    itf->lagg_proto);

	return (0);
}

static int
cmm_lagg_deregister(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_lagg_cmd_t cmd;
	int rc;

	if (!(itf->itf_flags & ITF_F_FPP_LAGG))
		return (0);

	/* CDX frees the LAGG's entry, so first drop everything that
	 * points at it: offloaded flows and the VLANs on top. */
	cmm_route_invalidate_by_oif(g, itf->ifindex);
	cmm_vlan_deregister_children(g, itf->ifindex);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_DEREGISTER;
	strlcpy(cmd.lagg_ifname, itf->ifname, sizeof(cmd.lagg_ifname));

	rc = fci_write(g->fci_handle, FPP_CMD_LAGG_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc != 0 && rc != FPP_ERR_LAGG_ENTRY_NOT_FOUND)
		cmm_print(CMM_LOG_WARN, "lagg: deregister %s failed: %d",
		    itf->ifname, rc);

	itf->itf_flags &= ~ITF_F_FPP_LAGG;
	cmm_print(CMM_LOG_INFO, "lagg: deregistered %s", itf->ifname);

	return (0);
}

/* Register the LAGG, then the VLANs on it, and retry the flows that
 * were torn down while it was gone. */
static void
lagg_bringup(struct cmm_global *g, struct cmm_interface *itf)
{
	cmm_lagg_register(g, itf);
	if (!(itf->itf_flags & ITF_F_FPP_LAGG))
		return;
	cmm_vlan_register_children(g, itf->ifindex);
	(void)cmm_conn_retry_rejected(g);
}

/*
 * Re-probe a LAGG interface and check if the active member changed.
 * If so, deregister from CDX, update the active port, re-register,
 * and invalidate all routes using this LAGG so flows re-offload
 * through the new member port.
 */
static void
cmm_lagg_failover(struct cmm_global *g, struct cmm_interface *itf)
{
	struct lagg_reqall ra;
	struct lagg_reqport rp[LAGG_MAX_PORTS];
	char new_port[IFNAMSIZ];
	int sd, i, found;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
		return;

	memset(&ra, 0, sizeof(ra));
	strlcpy(ra.ra_ifname, itf->ifname, sizeof(ra.ra_ifname));
	ra.ra_size = sizeof(rp);
	ra.ra_port = rp;
	memset(rp, 0, sizeof(rp));

	if (ioctl(sd, SIOCGLAGG, &ra) < 0) {
		close(sd);
		return;
	}
	close(sd);

	/* Collect new member list and check if active port changed
	 * or if the set of member ports changed (port added/removed). */
	new_port[0] = '\0';
	found = (ra.ra_ports < LAGG_MAX_PORTS) ? ra.ra_ports : LAGG_MAX_PORTS;

	char new_members[8][IFNAMSIZ];
	int new_num_members = 0;
	int current_still_active = 0;
	/* DISTRIBUTING is LACP's own signal that a port is actually
	 * cleared to carry egress traffic - a port can be link-up and
	 * mid-LACPDU-negotiation (ACTIVE) without DISTRIBUTING yet, and
	 * the switch drops frames sent out a port it hasn't finished
	 * bringing into the aggregate. lacp_isactive() only means "joined
	 * to the active aggregator", a weaker, earlier condition than
	 * lacp_isdistributing() - so for LACP, ACTIVE alone isn't safe
	 * to treat as "ready to send". failover/loadbalance/roundrobin
	 * never set DISTRIBUTING at all (if_lagg.c: "LACP has a different
	 * definition of active"), so for those protocols ACTIVE is
	 * already the right and only signal. */
	int lagg_flags_mask = (ra.ra_proto == LAGG_PROTO_LACP) ?
	    LAGG_PORT_DISTRIBUTING : LAGG_PORT_ACTIVE;

	for (i = 0; i < found; i++) {
		struct cmm_interface *port;

		cmm_print(CMM_LOG_DEBUG,
		    "lagg: %s port[%d]=%s flags=0x%x",
		    itf->ifname, i, rp[i].rp_portname, rp[i].rp_flags);

		/* LACP clears a dead port's flags a moment after its link
		 * goes down, so they can still look usable here.  Skip ports
		 * without link, the same test lagg itself uses. */
		port = cmm_itf_find_by_name(rp[i].rp_portname);
		if (port != NULL && port->link_state != LINK_STATE_UP)
			continue;

		/* Only collect members currently cleared to carry egress
		 * traffic - see lagg_flags_mask comment above. */
		if (new_num_members < 8 &&
		    (rp[i].rp_flags & lagg_flags_mask))
			strlcpy(new_members[new_num_members++],
			    rp[i].rp_portname, IFNAMSIZ);

		if (rp[i].rp_flags & LAGG_PORT_ACTIVE) {
			if (strcmp(rp[i].rp_portname,
			    itf->lagg_active_port) == 0)
				current_still_active = 1;
			if (new_port[0] == '\0')
				strlcpy(new_port, rp[i].rp_portname,
				    sizeof(new_port));
		}
	}

	/* Check if member set changed (port added or removed) */
	int members_changed = (new_num_members != itf->lagg_num_members);
	if (!members_changed) {
		int j;
		for (i = 0; i < new_num_members; i++) {
			int match = 0;
			for (j = 0; j < itf->lagg_num_members; j++) {
				if (strcmp(new_members[i],
				    itf->lagg_members[j]) == 0) {
					match = 1;
					break;
				}
			}
			if (!match) {
				members_changed = 1;
				break;
			}
		}
	}

	/* A laggproto change alone (same ports, same active port - e.g.
	 * loadbalance -> broadcast) has to force a re-register too, since
	 * cmm_lagg_register()'s decision to offload at all depends on
	 * lagg_proto, not just on which ports exist. */
	int proto_changed = (ra.ra_proto != itf->lagg_proto);

	if (current_still_active && !members_changed && !proto_changed) {
		cmm_print(CMM_LOG_DEBUG,
		    "lagg: %s current=%s still ACTIVE, members unchanged",
		    itf->ifname, itf->lagg_active_port);
		return;
	}

	/* Active port changed or member set changed — need to
	 * deregister, update, and re-register */
	if (!current_still_active && new_port[0] != '\0')
		cmm_print(CMM_LOG_INFO,
		    "lagg: failover %s: %s -> %s",
		    itf->ifname,
		    itf->lagg_active_port[0] ?
		        itf->lagg_active_port : "(none)",
		    new_port);
	else if (members_changed) {
		cmm_print(CMM_LOG_INFO,
		    "lagg: %s member set changed (%d -> %d members)",
		    itf->ifname, itf->lagg_num_members, new_num_members);
		/* For broadcast mode specifically: report every membership
		 * change against hardware replication's actual requirement
		 * (>=2 usable members - one carries the primary entry, at
		 * least one more gets a replica), not just a below/above-
		 * threshold check. A 3->2 change still replicates but has
		 * lost its margin; that's worth seeing plainly during
		 * testing (unplugging LAGG member cables one at a time), not
		 * folded into the same message as a fully healthy state.
		 * Logged here, at the same event a cable pull/plug already
		 * triggers - a state change, not a per-packet or per-flow
		 * condition, so this adds no steady-state log volume. */
		if (ra.ra_proto == LAGG_PROTO_BROADCAST) {
			/* "X of Y usable" against the LAGG's full configured
			 * port count (found - every port SIOCGLAGG reports as
			 * a member, regardless of link state), not just a
			 * before/after usable-count comparison - so a 3-of-4
			 * LAGG and a 2-of-2 LAGG are each reported against
			 * what they're actually supposed to have. */
			if (new_num_members < 2)
				cmm_print(CMM_LOG_WARN,
				    "lagg: %s broadcast mode: %d of %d "
				    "member(s) usable - hardware "
				    "replication needs at least 2, new "
				    "flows will offload to a single port "
				    "with no duplication until another "
				    "member returns", itf->ifname,
				    new_num_members, found);
			else if (new_num_members < found)
				cmm_print(CMM_LOG_WARN,
				    "lagg: %s broadcast mode: %d of %d "
				    "members usable - hardware replication "
				    "still active but running below full "
				    "membership", itf->ifname,
				    new_num_members, found);
			else
				cmm_print(CMM_LOG_INFO,
				    "lagg: %s broadcast mode: %d of %d "
				    "members usable - hardware replication "
				    "active", itf->ifname, new_num_members,
				    found);
		}
	}
	else if (proto_changed)
		cmm_print(CMM_LOG_INFO,
		    "lagg: %s protocol changed (%u -> %u)",
		    itf->ifname, itf->lagg_proto, ra.ra_proto);

	/* Deregister the old LAGG mapping from CDX (also tears down its
	 * offloaded flows and VLANs) */
	cmm_lagg_deregister(g, itf);

	/* Update the active port */
	if (!current_still_active) {
		strlcpy(itf->lagg_active_port, new_port,
		    sizeof(itf->lagg_active_port));
		if (new_port[0] != '\0')
			itf->parent_ifindex = if_nametoindex(new_port);
		else
			itf->parent_ifindex = 0;
	}

	/* Update member list */
	itf->lagg_num_members = new_num_members;
	for (i = 0; i < new_num_members; i++)
		strlcpy(itf->lagg_members[i], new_members[i], IFNAMSIZ);
	itf->lagg_proto = ra.ra_proto;

	/* Re-register with the updated member set (if any active) */
	if (itf->lagg_active_port[0] != '\0')
		lagg_bringup(g, itf);
}

/*
 * Check if a member port state change affects any LAGG interface.
 * Called from cmm_itf_handle_ifinfo() when IFF_RUNNING changes
 * on a non-LAGG interface.
 */
static int
lagg_member_check_cb(struct cmm_global *g, struct cmm_interface *lagg_itf)
{
	/* Re-probe this LAGG unconditionally — let failover() decide
	 * whether the active member actually changed. */
	cmm_lagg_failover(g, lagg_itf);
	return (0);
}

/* Seconds of extra re-checks after a member's link changes */
#define	LAGG_SETTLE_SECS	10
#define	LAGG_SETTLE_TIMER	7	/* kqueue timer ident, see cmm.c */

static int lagg_settle_left;

/*
 * A port that gets link only starts carrying traffic once LACP has
 * negotiated, a few seconds later, and that raises no event.  Re-check
 * every second for a while so the change is picked up promptly rather
 * than on the next maintenance pass.
 */
static void
lagg_settle_start(struct cmm_global *g)
{
	struct kevent kev;

	if (lagg_settle_left == 0) {
		EV_SET(&kev, LAGG_SETTLE_TIMER, EVFILT_TIMER, EV_ADD,
		    NOTE_MSECONDS, 1000, NULL);
		if (kevent(g->kq, &kev, 1, NULL, 0, NULL) < 0)
			return;
	}
	lagg_settle_left = LAGG_SETTLE_SECS;
}

void
cmm_lagg_settle_tick(struct cmm_global *g)
{
	struct kevent kev;

	cmm_itf_foreach_lagg(g, lagg_member_check_cb);
	if (lagg_settle_left > 0 && --lagg_settle_left == 0) {
		EV_SET(&kev, LAGG_SETTLE_TIMER, EVFILT_TIMER, EV_DELETE,
		    0, 0, NULL);
		(void)kevent(g->kq, &kev, 1, NULL, 0, NULL);
	}
}

void
cmm_lagg_member_check(struct cmm_global *g, struct cmm_interface *member_itf)
{

	/*
	 * We need to find which LAGG(s) this member belongs to.
	 * Iterate all LAGG interfaces and re-probe their membership.
	 * Check if this member is in any of them.
	 */

	/* Trigger failover check on all LAGGs — it's cheap (SIOCGLAGG
	 * per LAGG) and failover() is a no-op if nothing changed. */
	cmm_itf_foreach_lagg(g, lagg_member_check_cb);
	lagg_settle_start(g);
}

void
cmm_lagg_recheck_all(struct cmm_global *g)
{
	/* Same re-probe as cmm_lagg_member_check(), but run
	 * unconditionally from the maintenance timer instead of only on
	 * a member port's link-state change - see the comment on this
	 * function's declaration for why that event alone isn't enough. */
	cmm_itf_foreach_lagg(g, lagg_member_check_cb);
}

int
cmm_lagg_init(struct cmm_global *g)
{
	int rc;

	/* Reset all LAGG entries in CDX */
	rc = fci_write(g->fci_handle, FPP_CMD_LAGG_RESET, 0, NULL);
	if (rc != 0)
		cmm_print(CMM_LOG_WARN, "lagg: reset failed: %d", rc);

	/* Register all existing UP LAGG interfaces */
	cmm_itf_foreach_lagg(g, cmm_lagg_register);

	cmm_print(CMM_LOG_INFO, "lagg: initialized");
	return (0);
}

void
cmm_lagg_fini(struct cmm_global *g)
{
	cmm_itf_foreach_lagg(g, cmm_lagg_deregister);
}

void
cmm_lagg_notify(struct cmm_global *g, struct cmm_interface *itf)
{
	if (!(itf->itf_flags & ITF_F_LAGG))
		return;

	if ((itf->flags & IFF_UP) && !(itf->itf_flags & ITF_F_FPP_LAGG)) {
		lagg_bringup(g, itf);
		return;
	}
	if (!(itf->flags & IFF_UP) && (itf->itf_flags & ITF_F_FPP_LAGG)) {
		cmm_lagg_deregister(g, itf);
		return;
	}

	/* Already up and registered (or down and already deregistered) -
	 * this call can still mean something changed underneath: LACP
	 * fires if_link_state_change() on the LAGG itself whenever a
	 * member's DISTRIBUTING state flips (lacp_enable/disable_
	 * distributing() in ieee8023ad_lacp.c), which is exactly the
	 * signal cmm_lagg_failover() needs to re-probe membership. This
	 * is what actually catches most laggproto-lacp membership
	 * changes quickly; the maintenance-timer backstop
	 * (cmm_lagg_recheck_all()) exists for the rarer case a bare
	 * SIOCSLAGG protocol switch produces no event here at all. */
	if (itf->itf_flags & ITF_F_FPP_LAGG)
		cmm_lagg_failover(g, itf);
}
