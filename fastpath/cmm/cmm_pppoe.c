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
#include <netgraph/ng_iface.h>
#include <netgraph/ng_pppoe.h>
#include <netgraph.h>

#include "cmm.h"
#include "cmm_pppoe.h"
#include "cmm_itf.h"
#include "cmm_route.h"
#include "cmm_conn.h"

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
 * Find an interface's ng_iface node. mpd5 renames the interface
 * (ng0 -> pppoe0) but the node keeps its old name.
 */
static int
ng_find_iface_node(int csock, const char *ifname, char *path, size_t len)
{
	struct ng_mesg *resp = NULL, *nresp;
	struct namelist *nl;
	char npath[NG_PATHSIZ];
	uint32_t i;
	int rc = -1;

	if (NgSendMsg(csock, ".:", NGM_GENERIC_COOKIE, NGM_LISTNODES,
	    NULL, 0) < 0)
		return (-1);
	if (NgAllocRecvMsg(csock, &resp, NULL) < 0 || resp == NULL)
		return (-1);

	nl = (struct namelist *)resp->data;
	for (i = 0; i < nl->numnames && rc != 0; i++) {
		if (strcmp(nl->nodeinfo[i].type, "iface") != 0)
			continue;
		snprintf(npath, sizeof(npath), "[%x]:", nl->nodeinfo[i].id);
		if (NgSendMsg(csock, npath, NGM_IFACE_COOKIE,
		    NGM_IFACE_GET_IFNAME, NULL, 0) < 0)
			continue;
		nresp = NULL;
		if (NgAllocRecvMsg(csock, &nresp, NULL) < 0 || nresp == NULL)
			continue;
		if (strncmp(nresp->data, ifname, IFNAMSIZ) == 0) {
			strlcpy(path, npath, len);
			rc = 0;
		}
		free(nresp);
	}
	free(resp);
	return (rc);
}

/*
 * Search outward from a node for the ng_pppoe node, through whatever mpd5
 * puts in between (tcpmss, ppp, tee).
 */
static int
ng_find_pppoe(int csock, uint32_t start, uint32_t *pppoe_id,
    char *session_hook)
{
	uint32_t seen[16];
	char npath[NG_PATHSIZ];
	int head = 0, tail = 0, i, j;

	seen[tail++] = start;
	while (head < tail) {
		struct ng_mesg *resp = NULL;
		struct hooklist *hl;

		snprintf(npath, sizeof(npath), "[%x]:", seen[head++]);
		if (NgSendMsg(csock, npath, NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
		    NULL, 0) < 0)
			continue;
		if (NgAllocRecvMsg(csock, &resp, NULL) < 0 || resp == NULL)
			continue;

		hl = (struct hooklist *)resp->data;
		for (i = 0; i < (int)hl->nodeinfo.hooks; i++) {
			struct linkinfo *li = &hl->link[i];

			if (strcmp(li->nodeinfo.type, "pppoe") == 0) {
				*pppoe_id = li->nodeinfo.id;
				strlcpy(session_hook, li->peerhook,
				    NG_HOOKSIZ);
				free(resp);
				return (0);
			}
			/* Stay on the session path, away from NICs and sockets. */
			if (strcmp(li->nodeinfo.type, "ether") == 0 ||
			    strcmp(li->nodeinfo.type, "socket") == 0)
				continue;
			for (j = 0; j < tail; j++)
				if (seen[j] == li->nodeinfo.id)
					break;
			if (j == tail && tail < (int)(sizeof(seen) / sizeof(seen[0])))
				seen[tail++] = li->nodeinfo.id;
		}
		free(resp);
	}
	return (-1);
}

static int
pppoe_query_netgraph(struct cmm_interface *itf)
{
	int csock, dsock;
	char path[128];
	char pppoe_path[128];
	char session_hook[NG_HOOKSIZ];
	uint32_t pppoe_id;
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
		/*
		 * OPNsense names that node only when the interface is set up.
		 * After a reconnect mpd5 makes a new, unnamed one, so start
		 * from the interface's own node instead.
		 */
		if (ng_find_iface_node(csock, itf->ifname, path,
		    sizeof(path)) != 0 ||
		    NgSendMsg(csock, path, NGM_GENERIC_COOKIE, NGM_LISTHOOKS,
		    NULL, 0) < 0) {
			cmm_print(CMM_LOG_DEBUG,
			    "pppoe: %s no netgraph node found",
			    itf->ifname);
			goto out;
		}
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
			/* Not an ng_pppoe node — search through its peers. */
			uint32_t self = hl->nodeinfo.id;

			free(lresp);
			if (ng_find_pppoe(csock, self, &pppoe_id,
			    session_hook) != 0) {
				cmm_print(CMM_LOG_DEBUG,
				    "pppoe: %s no ng_pppoe in graph",
				    itf->ifname);
				goto out;
			}
			found_session = 1;

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

		if (!found_session) {
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

	/* Routes set up while the session was away go again on the new one,
	 * now rather than at the next maintenance pass. */
	cmm_route_invalidate_by_oif(g, itf->ifindex);
	(void)cmm_conn_retry_rejected(g);

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

	/* Take routes off the session first, or CDX keeps them pointing at
	 * an interface it no longer has. */
	cmm_route_invalidate_by_oif(g, itf->ifindex);

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
