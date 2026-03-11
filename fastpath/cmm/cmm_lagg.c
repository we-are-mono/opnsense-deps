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
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_lagg.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_lagg.h"
#include "cmm_itf.h"
#include "cmm_route.h"

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

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_REGISTER;
	strlcpy(cmd.lagg_ifname, itf->ifname, sizeof(cmd.lagg_ifname));
	strlcpy(cmd.lagg_phy_ifname, itf->lagg_active_port,
	    sizeof(cmd.lagg_phy_ifname));
	memcpy(cmd.macaddr, itf->macaddr, ETHER_ADDR_LEN);

	/* Populate member port list for multi-port hash entries */
	cmd.num_members = 0;
	for (i = 0; i < itf->lagg_num_members &&
	    i < FPP_LAGG_MAX_MEMBERS; i++) {
		strlcpy(cmd.member_ifnames[i], itf->lagg_members[i],
		    IFNAMSIZ);
		cmd.num_members++;
	}

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
	    "lagg: registered %s (active=%s, %d members)",
	    itf->ifname, itf->lagg_active_port, cmd.num_members);

	return (0);
}

static int
cmm_lagg_deregister(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_lagg_cmd_t cmd;
	int rc;

	if (!(itf->itf_flags & ITF_F_FPP_LAGG))
		return (0);

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

	for (i = 0; i < found; i++) {
		cmm_print(CMM_LOG_DEBUG,
		    "lagg: %s port[%d]=%s flags=0x%x",
		    itf->ifname, i, rp[i].rp_portname, rp[i].rp_flags);

		/* Collect all members */
		if (new_num_members < 8)
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

	if (current_still_active && !members_changed) {
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
	else if (members_changed)
		cmm_print(CMM_LOG_INFO,
		    "lagg: %s member set changed (%d -> %d members)",
		    itf->ifname, itf->lagg_num_members, new_num_members);

	/* Deregister the old LAGG mapping from CDX */
	cmm_lagg_deregister(g, itf);

	/* Invalidate all routes using this LAGG — tears down offloaded flows */
	cmm_route_invalidate_by_oif(g, itf->ifindex);

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

	/* Re-register with the updated member set (if any active) */
	if (itf->lagg_active_port[0] != '\0')
		cmm_lagg_register(g, itf);
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

	if ((itf->flags & IFF_UP) && !(itf->itf_flags & ITF_F_FPP_LAGG))
		cmm_lagg_register(g, itf);
	else if (!(itf->flags & IFF_UP) && (itf->itf_flags & ITF_F_FPP_LAGG))
		cmm_lagg_deregister(g, itf);
}
