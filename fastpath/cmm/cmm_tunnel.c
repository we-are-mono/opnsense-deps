/*
 * cmm_tunnel.c — Tunnel interface offload
 *
 * Detects gif(4) and gre(4) tunnel interfaces, resolves routes to
 * remote endpoints, and registers tunnels with CDX via
 * FPP_CMD_TUNNEL_ADD/DEL for hardware offload.
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
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_tunnel.h"
#include "cmm_itf.h"
#include "cmm_route.h"
#include "cmm_fe.h"
#include "cmm_ctrl.h"

/* ------------------------------------------------------------------ */
/* Tunnel detection (called from cmm_itf.c)                           */
/* ------------------------------------------------------------------ */

/*
 * Probe an interface for tunnel membership.
 * Checks name prefix (gif/gre) and retrieves tunnel endpoints via ioctl.
 * On success, populates tunnel fields and sets ITF_F_TUNNEL.
 */
void
itf_detect_tunnel(struct cmm_interface *itf, int sd)
{
	struct ifreq ifr;
	struct sockaddr_in *sin;
	int is_gif, is_gre;

	is_gif = (strncmp(itf->ifname, "gif", 3) == 0);
	is_gre = (strncmp(itf->ifname, "gre", 3) == 0);

	if (!is_gif && !is_gre)
		return;

	/*
	 * Try IPv4 tunnel endpoints first (SIOCGIFPSRCADDR).
	 * If that fails or returns AF_UNSPEC, try IPv6.
	 */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, itf->ifname, sizeof(ifr.ifr_name));

	if (ioctl(sd, SIOCGIFPSRCADDR, &ifr) == 0 &&
	    ifr.ifr_addr.sa_family == AF_INET) {
		/* IPv4 outer tunnel */
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		memcpy(itf->tnl_local, &sin->sin_addr, 4);

		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, itf->ifname, sizeof(ifr.ifr_name));
		if (ioctl(sd, SIOCGIFPDSTADDR, &ifr) < 0)
			return;
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		memcpy(itf->tnl_remote, &sin->sin_addr, 4);

		itf->tnl_family = AF_INET;

		if (is_gif) {
			itf->tnl_mode = TNL_6O4;
		} else {
			/* GRE over IPv4 — no CDX mode available */
			cmm_print(CMM_LOG_WARN,
			    "tunnel: %s gre/IPv4 not supported by CDX",
			    itf->ifname);
			return;
		}
	} else {
		/* Try IPv6 outer tunnel */
		struct in6_ifreq ifr6;
		struct sockaddr_in6 *sin6;

		memset(&ifr6, 0, sizeof(ifr6));
		strlcpy(ifr6.ifr_name, itf->ifname, sizeof(ifr6.ifr_name));

		if (ioctl(sd, SIOCGIFPSRCADDR_IN6, &ifr6) < 0)
			return;
		if (ifr6.ifr_addr.sin6_family != AF_INET6)
			return;

		sin6 = &ifr6.ifr_addr;
		memcpy(itf->tnl_local, &sin6->sin6_addr, 16);

		memset(&ifr6, 0, sizeof(ifr6));
		strlcpy(ifr6.ifr_name, itf->ifname, sizeof(ifr6.ifr_name));
		if (ioctl(sd, SIOCGIFPDSTADDR_IN6, &ifr6) < 0)
			return;
		sin6 = &ifr6.ifr_addr;
		memcpy(itf->tnl_remote, &sin6->sin6_addr, 16);

		itf->tnl_family = AF_INET6;

		if (is_gif)
			itf->tnl_mode = TNL_4O6;
		else
			itf->tnl_mode = TNL_GRE_IPV6;
	}

	itf->itf_flags |= ITF_F_TUNNEL;

	if (itf->tnl_family == AF_INET) {
		char lbuf[INET_ADDRSTRLEN], rbuf[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, itf->tnl_local, lbuf, sizeof(lbuf));
		inet_ntop(AF_INET, itf->tnl_remote, rbuf, sizeof(rbuf));
		cmm_print(CMM_LOG_INFO,
		    "tunnel: %s mode=%u (%s) local=%s remote=%s",
		    itf->ifname, itf->tnl_mode,
		    itf->tnl_mode == TNL_6O4 ? "6o4" : "?",
		    lbuf, rbuf);
	} else {
		char lbuf[INET6_ADDRSTRLEN], rbuf[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, itf->tnl_local, lbuf, sizeof(lbuf));
		inet_ntop(AF_INET6, itf->tnl_remote, rbuf, sizeof(rbuf));
		cmm_print(CMM_LOG_INFO,
		    "tunnel: %s mode=%u (%s) local=%s remote=%s",
		    itf->ifname, itf->tnl_mode,
		    itf->tnl_mode == TNL_4O6 ? "4o6" :
		    itf->tnl_mode == TNL_GRE_IPV6 ? "gre6" : "?",
		    lbuf, rbuf);
	}
}

/* ------------------------------------------------------------------ */
/* CDX registration                                                    */
/* ------------------------------------------------------------------ */

static int
cmm_tunnel_register(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_tunnel_create_cmd_t cmd;
	struct cmm_route *rt;
	int alen, rc;

	if (!(itf->itf_flags & ITF_F_TUNNEL))
		return (0);
	if (itf->itf_flags & ITF_F_FPP_TNL)
		return (0);

	alen = (itf->tnl_family == AF_INET) ? 4 : 16;

	/* Verify endpoints are configured */
	{
		uint8_t zero[16] = {0};

		if (memcmp(itf->tnl_remote, zero, alen) == 0) {
			cmm_print(CMM_LOG_DEBUG,
			    "tunnel: %s remote endpoint not configured",
			    itf->ifname);
			return (-1);
		}
	}

	/* Resolve route to remote endpoint */
	rt = cmm_route_get(g, itf->tnl_family, itf->tnl_remote);
	if (rt == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "tunnel: %s no route to remote endpoint",
		    itf->ifname);
		return (-1);
	}

	/* Ensure route is programmed in CDX */
	if (!rt->fpp_programmed) {
		if (cmm_fe_route_register(g, rt) < 0) {
			cmm_print(CMM_LOG_DEBUG,
			    "tunnel: %s route not ready (neighbor?)",
			    itf->ifname);
			cmm_route_put(rt);
			return (-1);
		}
	}

	/* Build FPP_CMD_TUNNEL_ADD */
	memset(&cmd, 0, sizeof(cmd));
	strlcpy(cmd.name, itf->ifname, sizeof(cmd.name));
	memcpy(cmd.local, itf->tnl_local, alen);
	memcpy(cmd.remote, itf->tnl_remote, alen);
	cmd.mode = itf->tnl_mode;
	cmd.secure = 0;
	cmd.encap_limit = 0;
	cmd.hop_limit = 64;
	cmd.flow_info = 0;
	cmd.frag_off = 0;
	cmd.enabled = 1;
	cmd.route_id = rt->fpp_id;
	cmd.mtu = itf->mtu;
	cmd.tunnel_flags = 0;

	rc = fci_write(g->fci_handle, FPP_CMD_TUNNEL_ADD,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc == FPP_ERR_TNL_ALREADY_CREATED) {
		cmm_print(CMM_LOG_DEBUG,
		    "tunnel: %s already in CDX, reusing", itf->ifname);
	} else if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "tunnel: register %s failed: %d", itf->ifname, rc);
		cmm_route_put(rt);
		return (-1);
	}

	itf->itf_flags |= ITF_F_FPP_TNL;
	itf->tnl_route = rt;

	cmm_print(CMM_LOG_INFO,
	    "tunnel: registered %s (mode=%u route_id=%u mtu=%u)",
	    itf->ifname, itf->tnl_mode, rt->fpp_id, itf->mtu);

	return (0);
}

static int
cmm_tunnel_deregister(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_tunnel_del_cmd_t cmd;
	int rc;

	if (!(itf->itf_flags & ITF_F_FPP_TNL))
		return (0);

	memset(&cmd, 0, sizeof(cmd));
	strlcpy(cmd.name, itf->ifname, sizeof(cmd.name));

	rc = fci_write(g->fci_handle, FPP_CMD_TUNNEL_DEL,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc != 0 && rc != FPP_ERR_TNL_ENTRY_NOT_FOUND)
		cmm_print(CMM_LOG_WARN,
		    "tunnel: deregister %s failed: %d", itf->ifname, rc);

	itf->itf_flags &= ~ITF_F_FPP_TNL;

	if (itf->tnl_route != NULL) {
		cmm_route_put(itf->tnl_route);
		itf->tnl_route = NULL;
	}

	cmm_print(CMM_LOG_INFO, "tunnel: deregistered %s", itf->ifname);

	return (0);
}

/* ------------------------------------------------------------------ */
/* foreach callbacks (must be defined before callers)                  */
/* ------------------------------------------------------------------ */

static int
tunnel_register_if_up(struct cmm_global *g, struct cmm_interface *itf)
{

	if ((itf->flags & IFF_UP) && !(itf->itf_flags & ITF_F_FPP_TNL))
		cmm_tunnel_register(g, itf);
	return (0);
}

static int
tunnel_deregister_wrap(struct cmm_global *g, struct cmm_interface *itf)
{

	cmm_tunnel_deregister(g, itf);
	return (0);
}

static int
tunnel_recheck(struct cmm_global *g, struct cmm_interface *itf)
{

	if (!(itf->flags & IFF_UP))
		return (0);

	if (itf->itf_flags & ITF_F_FPP_TNL) {
		/*
		 * Already registered — route may have changed.
		 * Deregister and re-register to pick up the new route.
		 */
		cmm_tunnel_deregister(g, itf);
		cmm_tunnel_register(g, itf);
	} else {
		/* Not yet registered — route may now be available */
		cmm_tunnel_register(g, itf);
	}

	return (0);
}

/* ------------------------------------------------------------------ */
/* Event handlers                                                      */
/* ------------------------------------------------------------------ */

void
cmm_tunnel_notify(struct cmm_global *g, struct cmm_interface *itf)
{

	if (!(itf->itf_flags & ITF_F_TUNNEL))
		return;

	if ((itf->flags & IFF_UP) && !(itf->itf_flags & ITF_F_FPP_TNL))
		cmm_tunnel_register(g, itf);
	else if (!(itf->flags & IFF_UP) && (itf->itf_flags & ITF_F_FPP_TNL))
		cmm_tunnel_deregister(g, itf);
}

void
cmm_tunnel_route_update(struct cmm_global *g)
{

	cmm_itf_foreach_tunnel(g, tunnel_recheck);
}

/* ------------------------------------------------------------------ */
/* Init / Fini                                                         */
/* ------------------------------------------------------------------ */

int
cmm_tunnel_init(struct cmm_global *g)
{

	/* Register all existing UP tunnel interfaces */
	cmm_itf_foreach_tunnel(g, tunnel_register_if_up);

	cmm_print(CMM_LOG_INFO, "tunnel: initialized");
	return (0);
}

void
cmm_tunnel_fini(struct cmm_global *g)
{

	cmm_itf_foreach_tunnel(g, tunnel_deregister_wrap);
}

/* ------------------------------------------------------------------ */
/* Control socket handlers                                             */
/* ------------------------------------------------------------------ */

static void
ctrl_send_resp(int fd, int16_t rc)
{
	struct cmm_ctrl_resp resp;

	resp.rc = rc;
	resp.len = 0;
	write(fd, &resp, sizeof(resp));
}

void
cmm_tunnel_ctrl_add(struct cmm_global *g, int client_fd,
    const void *payload, uint16_t len)
{
	char name[IFNAMSIZ];
	struct cmm_interface *itf;
	int rc;

	if (len < 1 || len > IFNAMSIZ) {
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_BAD_LEN);
		return;
	}

	memset(name, 0, sizeof(name));
	memcpy(name, payload, len);
	name[IFNAMSIZ - 1] = '\0';

	itf = cmm_itf_find_by_name(name);
	if (itf == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "tunnel: ctrl add: interface '%s' not found", name);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	/* If not yet detected as tunnel, try detection */
	if (!(itf->itf_flags & ITF_F_TUNNEL)) {
		int sd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sd >= 0) {
			itf_detect_tunnel(itf, sd);
			close(sd);
		}
	}

	if (!(itf->itf_flags & ITF_F_TUNNEL)) {
		cmm_print(CMM_LOG_WARN,
		    "tunnel: ctrl add: %s is not a tunnel", name);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	rc = cmm_tunnel_register(g, itf);
	ctrl_send_resp(client_fd, (rc == 0) ? 0 : CMM_CTRL_ERR_FCI_FAIL);
}

void
cmm_tunnel_ctrl_del(struct cmm_global *g, int client_fd,
    const void *payload, uint16_t len)
{
	char name[IFNAMSIZ];
	struct cmm_interface *itf;

	if (len < 1 || len > IFNAMSIZ) {
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_BAD_LEN);
		return;
	}

	memset(name, 0, sizeof(name));
	memcpy(name, payload, len);
	name[IFNAMSIZ - 1] = '\0';

	itf = cmm_itf_find_by_name(name);
	if (itf == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "tunnel: ctrl del: interface '%s' not found", name);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	cmm_tunnel_deregister(g, itf);
	ctrl_send_resp(client_fd, 0);
}
