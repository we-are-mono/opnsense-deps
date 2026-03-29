/*
 * cmm_pppoe.c — PPPoE session offload
 *
 * Detects PPPoE sessions via netgraph and registers them with CDX
 * so the hardware can strip/insert PPPoE headers in the fast path.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_pppoe.h>
#include <netgraph.h>

#include "cmm.h"
#include "cmm_pppoe.h"
#include "cmm_itf.h"

/*
 * Query the ng_pppoe node associated with a pppN interface to get
 * the PPPoE session parameters and the underlying physical interface.
 *
 * Netgraph topology for a PPPoE client session:
 *   ppp0: (ng_ppp) --[pppoe]--> ng_pppoe --[ethernet]--> ng_ether (dtsec3:)
 *
 * We walk: pppN: → list hooks → find the "pppoe" peer → that's the ng_pppoe
 * node → send NGM_PPPOE_GET_SESSION_INFO → then list ng_pppoe's hooks to
 * find "ethernet" peer → that's the ng_ether node → its name is the
 * physical interface.
 */
/*
 * Helper: list hooks on a netgraph node and find a peer of the given type.
 * Returns the peer's node ID in *peer_id and the peer's hook name in
 * peer_hook (caller provides NG_HOOKSIZ buffer).  Returns 0 on success.
 */
static int
ng_find_peer_by_type(int csock, const char *node_path, const char *type,
    uint32_t *peer_id, char *peer_hook)
{
	struct ng_mesg *resp = NULL;
	struct hooklist *hl;
	int i;

	if (NgSendMsg(csock, node_path, NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
	    NULL, 0) < 0)
		return (-1);

	if (NgAllocRecvMsg(csock, &resp, NULL) < 0 || resp == NULL)
		return (-1);

	hl = (struct hooklist *)resp->data;
	for (i = 0; i < (int)hl->nodeinfo.hooks; i++) {
		struct linkinfo *li = &hl->link[i];

		if (strcmp(li->nodeinfo.type, type) == 0) {
			*peer_id = li->nodeinfo.id;
			if (peer_hook != NULL)
				strlcpy(peer_hook, li->peerhook,
				    NG_HOOKSIZ);
			free(resp);
			return (0);
		}
	}

	free(resp);
	return (-1);
}

static int
pppoe_query_netgraph(struct cmm_interface *itf)
{
	int csock, dsock;
	char path[128];
	char pppoe_path[128];
	char session_hook[NG_HOOKSIZ];
	uint32_t ppp_id, pppoe_id;
	int rc = -1;

	if (NgMkSockNode(NULL, &csock, &dsock) < 0) {
		cmm_print(CMM_LOG_WARN,
		    "pppoe: NgMkSockNode failed: %s", strerror(errno));
		return (-1);
	}

	/*
	 * mpd5/OPNsense netgraph topology:
	 *   pppoe0 (ng_iface) → ng_ppp → ng_pppoe → ng_ether (dtsec3)
	 *
	 * Walk from the interface node through ng_ppp to ng_pppoe.
	 */
	snprintf(path, sizeof(path), "%s:", itf->ifname);

	/*
	 * Step 1: List hooks on the node to determine topology.
	 *
	 * OPNsense/mpd5 names the ng_pppoe node after the interface
	 * (e.g. "pppoe0"), so addressing "pppoe0:" in netgraph
	 * reaches the ng_pppoe node directly.  The LISTHOOKS response
	 * tells us the node's own type via nodeinfo.
	 */
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
	    NULL, 0) < 0) {
		cmm_print(CMM_LOG_DEBUG,
		    "pppoe: NGM_LISTHOOKS %s failed: %s",
		    path, strerror(errno));
		goto out;
	}

	{
		struct ng_mesg *lresp = NULL;
		struct hooklist *hl;
		int i;
		int found_session = 0;

		if (NgAllocRecvMsg(csock, &lresp, NULL) < 0 ||
		    lresp == NULL)
			goto out;

		hl = (struct hooklist *)lresp->data;

		if (strcmp(hl->nodeinfo.type, "pppoe") == 0) {
			/*
			 * We're directly on the ng_pppoe node.
			 * Find the session hook (any hook that isn't
			 * "ethernet") and the physical interface.
			 */
			snprintf(pppoe_path, sizeof(pppoe_path),
			    "[%x]:", hl->nodeinfo.id);

			for (i = 0; i < (int)hl->nodeinfo.hooks; i++) {
				struct linkinfo *li = &hl->link[i];

				if (strcmp(li->ourhook, "ethernet") == 0) {
					itf->pppoe_parent_ifindex =
					    if_nametoindex(
					    li->nodeinfo.name);
				} else if (!found_session) {
					strlcpy(session_hook, li->ourhook,
					    sizeof(session_hook));
					found_session = 1;
				}
			}
			free(lresp);
		} else {
			/*
			 * Not an ng_pppoe node — walk through peers.
			 * Try: iface → pppoe (direct), or
			 *      iface → ppp → pppoe (mpd5 with ng_ppp).
			 */
			int found = 0;

			for (i = 0; i < (int)hl->nodeinfo.hooks; i++) {
				struct linkinfo *li = &hl->link[i];

				if (strcmp(li->nodeinfo.type, "pppoe") == 0) {
					pppoe_id = li->nodeinfo.id;
					strlcpy(session_hook, li->peerhook,
					    sizeof(session_hook));
					found = 1;
					break;
				}
				if (strcmp(li->nodeinfo.type, "ppp") == 0)
					ppp_id = li->nodeinfo.id;
			}
			free(lresp);

			if (!found && ppp_id != 0) {
				char ppp_path[128];

				snprintf(ppp_path, sizeof(ppp_path),
				    "[%x]:", ppp_id);
				if (ng_find_peer_by_type(csock, ppp_path,
				    "pppoe", &pppoe_id, session_hook) < 0) {
					cmm_print(CMM_LOG_DEBUG,
					    "pppoe: %s no ng_pppoe found",
					    itf->ifname);
					goto out;
				}
				found = 1;
			}

			if (!found) {
				cmm_print(CMM_LOG_DEBUG,
				    "pppoe: %s no ng_pppoe in graph",
				    itf->ifname);
				goto out;
			}

			snprintf(pppoe_path, sizeof(pppoe_path),
			    "[%x]:", pppoe_id);

			/* Find physical interface from ng_pppoe hooks */
			{
				struct ng_mesg *hresp = NULL;
				struct hooklist *phl;
				int j;

				if (NgSendMsg(csock, pppoe_path,
				    NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
				    NULL, 0) < 0)
					goto out;
				if (NgAllocRecvMsg(csock, &hresp, NULL) < 0 ||
				    hresp == NULL)
					goto out;

				phl = (struct hooklist *)hresp->data;
				for (j = 0; j < (int)phl->nodeinfo.hooks;
				    j++) {
					struct linkinfo *pli = &phl->link[j];

					if (strcmp(pli->ourhook,
					    "ethernet") == 0) {
						itf->pppoe_parent_ifindex =
						    if_nametoindex(
						    pli->nodeinfo.name);
						break;
					}
				}
				free(hresp);
			}
		}

		if (!found_session &&
		    strcmp(hl->nodeinfo.type, "pppoe") == 0) {
			cmm_print(CMM_LOG_DEBUG,
			    "pppoe: %s no session hook found",
			    itf->ifname);
			goto out;
		}
	}

	/* Step 2: Query session info from ng_pppoe */
	{
		struct ngpppoe_init_data qmsg;
		struct ng_mesg *sresp;
		struct ngpppoe_session_info *si;

		memset(&qmsg, 0, sizeof(qmsg));
		strlcpy(qmsg.hook, session_hook, sizeof(qmsg.hook));
		qmsg.data_len = 0;

		if (NgSendMsg(csock, pppoe_path, NGM_PPPOE_COOKIE,
		    NGM_PPPOE_GET_SESSION_INFO, &qmsg, sizeof(qmsg)) < 0) {
			cmm_print(CMM_LOG_DEBUG,
			    "pppoe: GET_SESSION_INFO for %s failed: %s",
			    itf->ifname, strerror(errno));
			goto out;
		}

		sresp = NULL;
		if (NgAllocRecvMsg(csock, &sresp, NULL) < 0 ||
		    sresp == NULL) {
			cmm_print(CMM_LOG_DEBUG,
			    "pppoe: recv SESSION_INFO failed");
			goto out;
		}

		si = (struct ngpppoe_session_info *)sresp->data;
		itf->pppoe_session_id = si->session_id;
		memcpy(itf->pppoe_peer_mac, si->peer_mac, ETHER_ADDR_LEN);

		/* State 7 = PPPOE_CONNECTED, State 6 = PPPOE_NEWCONNECTED */
		if (si->state < 6) {
			cmm_print(CMM_LOG_DEBUG,
			    "pppoe: %s session not connected (state=%u)",
			    itf->ifname, si->state);
			free(sresp);
			goto out;
		}
		free(sresp);
	}

	if (itf->pppoe_parent_ifindex != 0)
		rc = 0;

out:
	close(csock);
	close(dsock);
	return (rc);
}

void
itf_detect_pppoe(struct cmm_interface *itf)
{
	/* PPP interfaces are named pppN or pppoeN (OPNsense/mpd5) */
	if (strncmp(itf->ifname, "ppp", 3) != 0)
		return;

	if (pppoe_query_netgraph(itf) == 0) {
		itf->itf_flags |= ITF_F_PPPOE;
		cmm_print(CMM_LOG_INFO,
		    "pppoe: %s detected — session_id=%u "
		    "peer=%02x:%02x:%02x:%02x:%02x:%02x parent_idx=%d",
		    itf->ifname,
		    itf->pppoe_session_id,
		    itf->pppoe_peer_mac[0], itf->pppoe_peer_mac[1],
		    itf->pppoe_peer_mac[2], itf->pppoe_peer_mac[3],
		    itf->pppoe_peer_mac[4], itf->pppoe_peer_mac[5],
		    itf->pppoe_parent_ifindex);
	}
}

static int
cmm_pppoe_register(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_pppoe_cmd_t cmd;
	struct cmm_interface *parent;
	int rc;

	if (!(itf->itf_flags & ITF_F_PPPOE))
		return (0);
	if (itf->itf_flags & ITF_F_FPP_PPPOE)
		return (0);
	if (itf->pppoe_session_id == 0)
		return (0);

	parent = cmm_itf_find_by_index(itf->pppoe_parent_ifindex);
	if (parent == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "pppoe: %s parent idx=%d not found",
		    itf->ifname, itf->pppoe_parent_ifindex);
		return (-1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_REGISTER;
	cmd.sessionid = htons(itf->pppoe_session_id);
	memcpy(cmd.macaddr, itf->pppoe_peer_mac, ETHER_ADDR_LEN);
	strlcpy(cmd.phy_intf, parent->ifname, sizeof(cmd.phy_intf));
	strlcpy(cmd.log_intf, itf->ifname, sizeof(cmd.log_intf));

	rc = fci_write(g->fci_handle, FPP_CMD_PPPOE_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc == FPP_ERR_PPPOE_ENTRY_ALREADY_REGISTERED) {
		cmm_print(CMM_LOG_DEBUG,
		    "pppoe: %s already in CDX, reusing", itf->ifname);
	} else if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "pppoe: register %s failed: %d", itf->ifname, rc);
		return (-1);
	}

	itf->itf_flags |= ITF_F_FPP_PPPOE;
	cmm_print(CMM_LOG_INFO,
	    "pppoe: registered %s (session=%u parent=%s)",
	    itf->ifname, itf->pppoe_session_id, parent->ifname);

	return (0);
}

static int
cmm_pppoe_deregister(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_pppoe_cmd_t cmd;
	struct cmm_interface *parent;
	int rc;

	if (!(itf->itf_flags & ITF_F_FPP_PPPOE))
		return (0);

	parent = cmm_itf_find_by_index(itf->pppoe_parent_ifindex);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_DEREGISTER;
	cmd.sessionid = htons(itf->pppoe_session_id);
	memcpy(cmd.macaddr, itf->pppoe_peer_mac, ETHER_ADDR_LEN);
	strlcpy(cmd.log_intf, itf->ifname, sizeof(cmd.log_intf));
	if (parent != NULL)
		strlcpy(cmd.phy_intf, parent->ifname, sizeof(cmd.phy_intf));

	rc = fci_write(g->fci_handle, FPP_CMD_PPPOE_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc != 0 && rc != FPP_ERR_PPPOE_ENTRY_NOT_FOUND)
		cmm_print(CMM_LOG_WARN,
		    "pppoe: deregister %s failed: %d", itf->ifname, rc);

	itf->itf_flags &= ~ITF_F_FPP_PPPOE;
	cmm_print(CMM_LOG_INFO,
	    "pppoe: deregistered %s (session=%u)",
	    itf->ifname, itf->pppoe_session_id);

	return (0);
}

int
cmm_pppoe_init(struct cmm_global *g)
{
	cmm_itf_foreach_pppoe(g, cmm_pppoe_register);
	cmm_print(CMM_LOG_INFO, "pppoe: initialized");
	return (0);
}

void
cmm_pppoe_fini(struct cmm_global *g)
{
	cmm_itf_foreach_pppoe(g, cmm_pppoe_deregister);
}

void
cmm_pppoe_notify(struct cmm_global *g, struct cmm_interface *itf)
{
	/*
	 * PPPoE sessions can come and go.  If the interface is up and we
	 * haven't detected a PPPoE session yet, try now (the session may
	 * have just connected).
	 */
	if ((itf->flags & IFF_UP) && !(itf->itf_flags & ITF_F_PPPOE)) {
		itf_detect_pppoe(itf);
	}

	/*
	 * If the session was detected, check if the session parameters
	 * changed (reconnect with new session_id).
	 */
	if ((itf->flags & IFF_UP) && (itf->itf_flags & ITF_F_PPPOE)) {
		uint16_t old_sid = itf->pppoe_session_id;

		/* Re-query to detect session changes */
		if (pppoe_query_netgraph(itf) == 0 &&
		    itf->pppoe_session_id != old_sid &&
		    (itf->itf_flags & ITF_F_FPP_PPPOE)) {
			/* Session changed — deregister old, register new */
			cmm_print(CMM_LOG_INFO,
			    "pppoe: %s session changed %u -> %u",
			    itf->ifname, old_sid,
			    itf->pppoe_session_id);
			itf->pppoe_session_id = old_sid;  /* restore for dereg */
			cmm_pppoe_deregister(g, itf);
			pppoe_query_netgraph(itf);  /* re-read new params */
		}

		if (!(itf->itf_flags & ITF_F_FPP_PPPOE))
			cmm_pppoe_register(g, itf);
	}

	/* Interface went down — deregister */
	if (!(itf->flags & IFF_UP) && (itf->itf_flags & ITF_F_FPP_PPPOE))
		cmm_pppoe_deregister(g, itf);

	/* Clear PPPoE detection if interface went down */
	if (!(itf->flags & IFF_UP) && (itf->itf_flags & ITF_F_PPPOE)) {
		itf->itf_flags &= ~ITF_F_PPPOE;
		itf->pppoe_session_id = 0;
		memset(itf->pppoe_peer_mac, 0, ETHER_ADDR_LEN);
		itf->pppoe_parent_ifindex = 0;
	}
}
