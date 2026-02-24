/*
 * cmm_fe.c — Forward engine: programs CDX hash tables via FCI
 *
 * Builds FPP command structures and sends them to CDX via the
 * already-ported libfci library.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "cmm.h"
#include "cmm_fe.h"
#include "cmm_conn.h"
#include "cmm_route.h"
#include "cmm_itf.h"
#include "cmm_bridge.h"

/* Conntrack command flags (from Linux forward_engine.c) */
#define CTCMD_FLAGS_ORIG_DISABLED	(1 << 0)
#define CTCMD_FLAGS_REP_DISABLED	(1 << 1)

int
cmm_fe_reset(struct cmm_global *g)
{
	int rc;

	if (g->fci_handle == NULL)
		return (-1);

	cmm_print(CMM_LOG_INFO, "fe: resetting CDX tables");

	rc = fci_write(g->fci_handle, FPP_CMD_IPV4_RESET, 0, NULL);
	if (rc != 0)
		cmm_print(CMM_LOG_WARN, "fe: IPv4 reset failed: %d", rc);

	rc = fci_write(g->fci_handle, FPP_CMD_IPV6_RESET, 0, NULL);
	if (rc != 0)
		cmm_print(CMM_LOG_WARN, "fe: IPv6 reset failed: %d", rc);

	return (0);
}

int
cmm_fe_route_register(struct cmm_global *g, struct cmm_route *rt)
{
	fpp_rt_cmd_t cmd;
	struct cmm_interface *itf, *iif;
	int rc;

	if (rt->neigh == NULL || rt->neigh->state != NEIGH_RESOLVED)
		return (-1);

	itf = cmm_itf_find_by_index(rt->oif_index);
	if (itf == NULL)
		return (-1);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_REGISTER;
	cmd.mtu = rt->mtu;
	memcpy(cmd.dst_mac, rt->neigh->macaddr, ETHER_ADDR_LEN);
	cmd.id = rt->fpp_id;

	/*
	 * Bridge port resolution: when the output interface is a
	 * bridge, CDX needs the physical member port name, not the
	 * bridge device.  Query the bridge FDB for the destination
	 * MAC to find the egress port.
	 */
	if (itf->itf_flags & ITF_F_BRIDGE) {
		char port_name[IFNAMSIZ];

		if (cmm_bridge_resolve_port(itf->ifindex,
		    rt->neigh->macaddr, port_name,
		    sizeof(port_name)) == 0) {
			strlcpy(cmd.output_device, port_name,
			    sizeof(cmd.output_device));
			cmm_print(CMM_LOG_DEBUG,
			    "fe: bridge %s → port %s for route id=%u",
			    itf->ifname, port_name, rt->fpp_id);
		} else {
			cmm_print(CMM_LOG_WARN,
			    "fe: bridge %s FDB lookup failed for "
			    "mac=%02x:%02x:%02x:%02x:%02x:%02x",
			    itf->ifname,
			    rt->neigh->macaddr[0], rt->neigh->macaddr[1],
			    rt->neigh->macaddr[2], rt->neigh->macaddr[3],
			    rt->neigh->macaddr[4], rt->neigh->macaddr[5]);
			return (-1);
		}
	} else {
		strlcpy(cmd.output_device, itf->ifname,
		    sizeof(cmd.output_device));
	}

	/*
	 * Input device: the interface where packets arrive before being
	 * forwarded via this route.  Set by conn_try_offload() from the
	 * opposite direction's output interface.  CDX uses this to install
	 * flow classification entries on the correct FMan RX port.
	 */
	if (rt->iif_index != 0) {
		iif = cmm_itf_find_by_index(rt->iif_index);

		if (iif == NULL) {
			/*
			 * Not in CMM table.  Try kernel directly to handle
			 * late-discovered interfaces.
			 */
			char fallback[IFNAMSIZ];

			if (if_indextoname(rt->iif_index, fallback) != NULL) {
				cmm_print(CMM_LOG_WARN,
				    "fe: route id=%u iif idx=%d (%s) "
				    "not in CMM table, using kernel name",
				    rt->fpp_id, rt->iif_index, fallback);
				strlcpy(cmd.input_device, fallback,
				    sizeof(cmd.input_device));
				strlcpy(cmd.underlying_input_device, fallback,
				    sizeof(cmd.underlying_input_device));
			} else {
				cmm_print(CMM_LOG_WARN,
				    "fe: route id=%u iif idx=%d "
				    "does not exist",
				    rt->fpp_id, rt->iif_index);
				return (-1);
			}
		} else if (iif->itf_flags & ITF_F_BRIDGE) {
			/*
			 * Input is a bridge — CDX only knows physical ports.
			 * resolve_iif_index() tried FDB first; if we still
			 * have a bridge here, FDB resolution failed.
			 */
			cmm_print(CMM_LOG_WARN,
			    "fe: route id=%u input %s is a bridge "
			    "(FDB lookup failed), deferring",
			    rt->fpp_id, iif->ifname);
			return (-1);
		} else {
			strlcpy(cmd.input_device, iif->ifname,
			    sizeof(cmd.input_device));
			strlcpy(cmd.underlying_input_device, iif->ifname,
			    sizeof(cmd.underlying_input_device));
		}
	} else {
		cmm_print(CMM_LOG_DEBUG,
		    "fe: route id=%u has iif_index=0", rt->fpp_id);
	}

	if (rt->family == AF_INET) {
		memcpy(&cmd.dst_addr[0], rt->dst, 4);
	} else {
		memcpy(cmd.dst_addr, rt->dst, 16);
	}

	rc = fci_write(g->fci_handle, FPP_CMD_IP_ROUTE,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc == FPP_ERR_RT_ENTRY_ALREADY_REGISTERED) {
		/* Stale entry from previous session — accept it */
		cmm_print(CMM_LOG_DEBUG,
		    "fe: route id=%u already in CDX, reusing", rt->fpp_id);
	} else if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "fe: route register failed: %d (id=%u)", rc, rt->fpp_id);
		return (-1);
	}

	rt->fpp_programmed = 1;

	cmm_print(CMM_LOG_DEBUG,
	    "fe: route registered id=%u out=%s in=%s "
	    "mac=%02x:%02x:%02x:%02x:%02x:%02x mtu=%u",
	    rt->fpp_id, itf->ifname,
	    cmd.input_device[0] ? cmd.input_device : "(none)",
	    rt->neigh->macaddr[0], rt->neigh->macaddr[1],
	    rt->neigh->macaddr[2], rt->neigh->macaddr[3],
	    rt->neigh->macaddr[4], rt->neigh->macaddr[5],
	    rt->mtu);

	return (0);
}

int
cmm_fe_route_deregister(struct cmm_global *g, struct cmm_route *rt)
{
	fpp_rt_cmd_t cmd;
	int rc;

	if (!rt->fpp_programmed)
		return (0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_DEREGISTER;
	cmd.id = rt->fpp_id;

	rc = fci_write(g->fci_handle, FPP_CMD_IP_ROUTE,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "fe: route deregister failed: %d (id=%u)",
		    rc, rt->fpp_id);
	}

	rt->fpp_programmed = 0;
	return (rc == 0 ? 0 : -1);
}

int
cmm_fe_ct4_register(struct cmm_global *g, struct cmm_conn *conn)
{
	fpp_ct_cmd_t cmd;
	int rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_REGISTER;
	cmd.protocol = conn->proto;

	memcpy(&cmd.saddr, conn->orig_saddr, 4);
	memcpy(&cmd.daddr, conn->orig_daddr, 4);
	cmd.sport = conn->orig_sport;
	cmd.dport = conn->orig_dport;

	memcpy(&cmd.saddr_reply, conn->rep_saddr, 4);
	memcpy(&cmd.daddr_reply, conn->rep_daddr, 4);
	cmd.sport_reply = conn->rep_sport;
	cmd.dport_reply = conn->rep_dport;

	if (conn->orig_route != NULL)
		cmd.route_id = conn->orig_route->fpp_id;
	if (conn->rep_route != NULL)
		cmd.route_id_reply = conn->rep_route->fpp_id;

	if (!(conn->flags & CONN_F_ORIG_DIR))
		cmd.flags |= CTCMD_FLAGS_ORIG_DISABLED;
	if (!(conn->flags & CONN_F_REP_DIR))
		cmd.flags |= CTCMD_FLAGS_REP_DISABLED;

	rc = fci_write(g->fci_handle, FPP_CMD_IPV4_CONNTRACK,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc == FPP_ERR_CT_ENTRY_ALREADY_REGISTERED) {
		/*
		 * Stale entry from a previous CMM session (CDX module
		 * stayed loaded).  Deregister the old entry and retry
		 * so we get fresh route IDs and parameters.
		 */
		cmm_print(CMM_LOG_DEBUG,
		    "fe: ct4 already exists, replacing");
		cmd.action = FPP_ACTION_DEREGISTER;
		fci_write(g->fci_handle, FPP_CMD_IPV4_CONNTRACK,
		    sizeof(cmd), (unsigned short *)&cmd);
		cmd.action = FPP_ACTION_REGISTER;
		rc = fci_write(g->fci_handle, FPP_CMD_IPV4_CONNTRACK,
		    sizeof(cmd), (unsigned short *)&cmd);
	}
	if (rc != 0) {
		cmm_print(CMM_LOG_WARN, "fe: ct4 register failed: %d", rc);
		return (-1);
	}

	conn->flags |= CONN_F_OFFLOADED;

	{
		char os[INET_ADDRSTRLEN], od[INET_ADDRSTRLEN];
		char rs[INET_ADDRSTRLEN], rd[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, conn->orig_saddr, os, sizeof(os));
		inet_ntop(AF_INET, conn->orig_daddr, od, sizeof(od));
		inet_ntop(AF_INET, conn->rep_saddr, rs, sizeof(rs));
		inet_ntop(AF_INET, conn->rep_daddr, rd, sizeof(rd));
		cmm_print(CMM_LOG_INFO,
		    "fe: ct4 offloaded %s orig=%s:%u->%s:%u "
		    "reply=%s:%u->%s:%u",
		    conn->proto == IPPROTO_TCP ? "TCP" : "UDP",
		    os, ntohs(conn->orig_sport),
		    od, ntohs(conn->orig_dport),
		    rs, ntohs(conn->rep_sport),
		    rd, ntohs(conn->rep_dport));
	}

	return (0);
}

int
cmm_fe_ct4_deregister(struct cmm_global *g, struct cmm_conn *conn)
{
	fpp_ct_cmd_t cmd;
	int rc;

	if (!(conn->flags & CONN_F_OFFLOADED))
		return (0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_DEREGISTER;
	cmd.protocol = conn->proto;

	memcpy(&cmd.saddr, conn->orig_saddr, 4);
	memcpy(&cmd.daddr, conn->orig_daddr, 4);
	cmd.sport = conn->orig_sport;
	cmd.dport = conn->orig_dport;

	memcpy(&cmd.saddr_reply, conn->rep_saddr, 4);
	memcpy(&cmd.daddr_reply, conn->rep_daddr, 4);
	cmd.sport_reply = conn->rep_sport;
	cmd.dport_reply = conn->rep_dport;

	rc = fci_write(g->fci_handle, FPP_CMD_IPV4_CONNTRACK,
	    sizeof(cmd), (unsigned short *)&cmd);

	conn->flags &= ~CONN_F_OFFLOADED;

	{
		char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, conn->orig_saddr, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET, conn->orig_daddr, dbuf, sizeof(dbuf));
		cmm_print(CMM_LOG_INFO,
		    "fe: ct4 removed %s %s:%u -> %s:%u (rc=%d)",
		    conn->proto == IPPROTO_TCP ? "TCP" : "UDP",
		    sbuf, ntohs(conn->orig_sport),
		    dbuf, ntohs(conn->orig_dport), rc);
	}

	return (rc == 0 ? 0 : -1);
}

int
cmm_fe_ct6_register(struct cmm_global *g, struct cmm_conn *conn)
{
	fpp_ct6_cmd_t cmd;
	int rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_REGISTER;
	cmd.protocol = conn->proto;

	memcpy(cmd.saddr, conn->orig_saddr, 16);
	memcpy(cmd.daddr, conn->orig_daddr, 16);
	cmd.sport = conn->orig_sport;
	cmd.dport = conn->orig_dport;

	memcpy(cmd.saddr_reply, conn->rep_saddr, 16);
	memcpy(cmd.daddr_reply, conn->rep_daddr, 16);
	cmd.sport_reply = conn->rep_sport;
	cmd.dport_reply = conn->rep_dport;

	if (conn->orig_route != NULL)
		cmd.route_id = conn->orig_route->fpp_id;
	if (conn->rep_route != NULL)
		cmd.route_id_reply = conn->rep_route->fpp_id;

	rc = fci_write(g->fci_handle, FPP_CMD_IPV6_CONNTRACK,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc == FPP_ERR_CT_ENTRY_ALREADY_REGISTERED) {
		cmm_print(CMM_LOG_DEBUG,
		    "fe: ct6 already exists, replacing");
		cmd.action = FPP_ACTION_DEREGISTER;
		fci_write(g->fci_handle, FPP_CMD_IPV6_CONNTRACK,
		    sizeof(cmd), (unsigned short *)&cmd);
		cmd.action = FPP_ACTION_REGISTER;
		rc = fci_write(g->fci_handle, FPP_CMD_IPV6_CONNTRACK,
		    sizeof(cmd), (unsigned short *)&cmd);
	}
	if (rc != 0) {
		cmm_print(CMM_LOG_WARN, "fe: ct6 register failed: %d", rc);
		return (-1);
	}

	conn->flags |= CONN_F_OFFLOADED;
	cmm_print(CMM_LOG_INFO, "fe: ct6 offloaded %s",
	    conn->proto == IPPROTO_TCP ? "TCP" : "UDP");

	return (0);
}

int
cmm_fe_ct6_deregister(struct cmm_global *g, struct cmm_conn *conn)
{
	fpp_ct6_cmd_t cmd;
	int rc;

	if (!(conn->flags & CONN_F_OFFLOADED))
		return (0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_DEREGISTER;
	cmd.protocol = conn->proto;

	memcpy(cmd.saddr, conn->orig_saddr, 16);
	memcpy(cmd.daddr, conn->orig_daddr, 16);
	cmd.sport = conn->orig_sport;
	cmd.dport = conn->orig_dport;

	memcpy(cmd.saddr_reply, conn->rep_saddr, 16);
	memcpy(cmd.daddr_reply, conn->rep_daddr, 16);
	cmd.sport_reply = conn->rep_sport;
	cmd.dport_reply = conn->rep_dport;

	rc = fci_write(g->fci_handle, FPP_CMD_IPV6_CONNTRACK,
	    sizeof(cmd), (unsigned short *)&cmd);

	conn->flags &= ~CONN_F_OFFLOADED;
	cmm_print(CMM_LOG_INFO, "fe: ct6 removed (rc=%d)", rc);

	return (rc == 0 ? 0 : -1);
}
