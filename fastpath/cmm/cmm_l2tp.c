/*
 * cmm_l2tp.c — L2TP tunnel interface offload
 *
 * Command-driven management of L2TP sessions.  Each session ties an
 * interface to a UDP socket with tunnel/session IDs.  CMM allocates
 * the socket, programs CDX via FPP_CMD_L2TP_ITF_ADD/DEL, and tracks
 * state in the interface table.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_l2tp.h"
#include "cmm_itf.h"
#include "cmm_socket.h"
#include "cmm_route.h"
#include "cmm_fe.h"
#include "cmm_ctrl.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void
ctrl_send_resp(int fd, int16_t rc)
{
	struct cmm_ctrl_resp resp;

	resp.rc = rc;
	resp.len = 0;
	write(fd, &resp, sizeof(resp));
}

/*
 * Register an L2TP interface in CDX.
 *
 * Allocates a UDP socket for the tunnel transport, programs it in CDX,
 * then registers the L2TP interface itself via FPP_CMD_L2TP_ITF_ADD.
 */
static int
l2tp_register(struct cmm_global *g, struct cmm_interface *itf,
    const struct cmm_ctrl_l2tp_add *cmd)
{
	fpp_l2tp_itf_add_cmd_t fcmd;
	struct cmm_socket *sk;
	uint16_t sock_id;
	int rc;

	/* Allocate a socket ID */
	sock_id = cmm_socket_next_id();
	if (sock_id == 0) {
		cmm_print(CMM_LOG_ERR,
		    "l2tp: %s: no free socket IDs", cmd->ifname);
		return (-1);
	}

	/* Allocate and populate socket */
	sk = calloc(1, sizeof(*sk));
	if (sk == NULL) {
		cmm_print(CMM_LOG_ERR,
		    "l2tp: %s: malloc failed", cmd->ifname);
		return (-1);
	}

	sk->id = sock_id;
	sk->af = cmd->af;
	sk->proto = IPPROTO_UDP;
	sk->type = CMM_SOCK_TYPE_LANWAN;
	sk->mode = CMM_SOCK_MODE_CONNECTED;
	memcpy(sk->saddr, cmd->local_addr, 16);
	memcpy(sk->daddr, cmd->peer_addr, 16);
	sk->sport = cmd->local_port;
	sk->dport = cmd->peer_port;
	sk->queue = cmd->queue;
	sk->dscp = cmd->dscp;

	/* Resolve route to peer */
	sk->route = cmm_route_get(g, sk->af, sk->daddr);
	if (sk->route == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "l2tp: %s: no route to peer", cmd->ifname);
		free(sk);
		return (-1);
	}

	/* Ensure route is registered in CDX */
	if (!sk->route->fpp_programmed) {
		if (sk->route->neigh == NULL ||
		    sk->route->neigh->state != NEIGH_RESOLVED) {
			cmm_print(CMM_LOG_WARN,
			    "l2tp: %s: neighbor not resolved",
			    cmd->ifname);
			cmm_route_put(sk->route);
			free(sk);
			return (-1);
		}
		if (cmm_fe_route_register(g, sk->route) < 0) {
			cmm_print(CMM_LOG_WARN,
			    "l2tp: %s: route registration failed",
			    cmd->ifname);
			cmm_route_put(sk->route);
			free(sk);
			return (-1);
		}
	}

	/* Program socket in CDX */
	if (cmm_socket_fpp_open(g, sk) < 0) {
		cmm_route_put(sk->route);
		free(sk);
		return (-1);
	}

	/* Add socket to global list */
	cmm_socket_add(sk);

	/* Register L2TP interface in CDX */
	memset(&fcmd, 0, sizeof(fcmd));
	strlcpy(fcmd.ifname, cmd->ifname, sizeof(fcmd.ifname));
	fcmd.sock_id = sock_id;
	fcmd.local_tun_id = cmd->local_tun_id;
	fcmd.peer_tun_id = cmd->peer_tun_id;
	fcmd.local_ses_id = cmd->local_ses_id;
	fcmd.peer_ses_id = cmd->peer_ses_id;
	fcmd.options = cmd->options;

	rc = fci_write(g->fci_handle, FPP_CMD_L2TP_ITF_ADD,
	    sizeof(fcmd), (unsigned short *)&fcmd);
	if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "l2tp: %s: FPP_CMD_L2TP_ITF_ADD failed: %d",
		    cmd->ifname, rc);
		/* Rollback socket */
		cmm_socket_fpp_close(g, sk);
		cmm_socket_remove(sk);
		if (sk->route != NULL)
			cmm_route_put(sk->route);
		free(sk);
		return (-1);
	}

	/* Update interface state */
	itf->itf_flags |= ITF_F_L2TP | ITF_F_FPP_L2TP;
	itf->l2tp_local_tun_id = cmd->local_tun_id;
	itf->l2tp_peer_tun_id = cmd->peer_tun_id;
	itf->l2tp_local_ses_id = cmd->local_ses_id;
	itf->l2tp_peer_ses_id = cmd->peer_ses_id;
	itf->l2tp_options = cmd->options;
	itf->l2tp_sock_id = sock_id;

	cmm_print(CMM_LOG_INFO,
	    "l2tp: %s registered (sock=%u tun=%u/%u ses=%u/%u)",
	    cmd->ifname, sock_id,
	    cmd->local_tun_id, cmd->peer_tun_id,
	    cmd->local_ses_id, cmd->peer_ses_id);

	return (0);
}

/*
 * Deregister an L2TP interface from CDX.
 * Sends FPP_CMD_L2TP_ITF_DEL, then tears down the associated socket.
 */
static void
l2tp_deregister(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_l2tp_itf_del_cmd_t fcmd;
	struct cmm_socket *sk;
	int rc;

	if (!(itf->itf_flags & ITF_F_L2TP))
		return;

	/* Deregister L2TP interface from CDX */
	if (itf->itf_flags & ITF_F_FPP_L2TP) {
		memset(&fcmd, 0, sizeof(fcmd));
		strlcpy(fcmd.ifname, itf->ifname, sizeof(fcmd.ifname));

		rc = fci_write(g->fci_handle, FPP_CMD_L2TP_ITF_DEL,
		    sizeof(fcmd), (unsigned short *)&fcmd);
		if (rc != 0)
			cmm_print(CMM_LOG_WARN,
			    "l2tp: %s: FPP_CMD_L2TP_ITF_DEL failed: %d",
			    itf->ifname, rc);
	}

	/* Tear down associated socket */
	sk = cmm_socket_find(itf->l2tp_sock_id);
	if (sk != NULL) {
		cmm_socket_fpp_close(g, sk);
		if (sk->route != NULL) {
			cmm_route_put(sk->route);
			sk->route = NULL;
		}
		cmm_socket_remove(sk);
		free(sk);
	}

	cmm_print(CMM_LOG_INFO, "l2tp: %s deregistered", itf->ifname);

	/* Clear interface state */
	itf->itf_flags &= ~(ITF_F_L2TP | ITF_F_FPP_L2TP);
	itf->l2tp_local_tun_id = 0;
	itf->l2tp_peer_tun_id = 0;
	itf->l2tp_local_ses_id = 0;
	itf->l2tp_peer_ses_id = 0;
	itf->l2tp_options = 0;
	itf->l2tp_sock_id = 0;
}

/* ------------------------------------------------------------------ */
/* Control socket handlers                                             */
/* ------------------------------------------------------------------ */

void
cmm_l2tp_ctrl_add(struct cmm_global *g, int client_fd,
    const void *payload, uint16_t len)
{
	const struct cmm_ctrl_l2tp_add *cmd = payload;
	struct cmm_interface *itf;
	char name[IFNAMSIZ];

	if (len < sizeof(*cmd)) {
		cmm_print(CMM_LOG_WARN,
		    "l2tp: ctrl add: bad payload len %u (want %zu)",
		    len, sizeof(*cmd));
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_BAD_LEN);
		return;
	}

	/* Sanitize interface name */
	memset(name, 0, sizeof(name));
	memcpy(name, cmd->ifname,
	    sizeof(cmd->ifname) < IFNAMSIZ ? sizeof(cmd->ifname) : IFNAMSIZ);
	name[IFNAMSIZ - 1] = '\0';

	/* Validate address family */
	if (cmd->af != AF_INET && cmd->af != AF_INET6) {
		cmm_print(CMM_LOG_WARN,
		    "l2tp: ctrl add: %s: unsupported af %d", name, cmd->af);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	/* Find interface */
	itf = cmm_itf_find_by_name(name);
	if (itf == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "l2tp: ctrl add: interface '%s' not found", name);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	/* Check not already registered */
	if (itf->itf_flags & ITF_F_L2TP) {
		cmm_print(CMM_LOG_WARN,
		    "l2tp: ctrl add: %s already registered", name);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	/* Check FCI handle */
	if (g->fci_handle == NULL) {
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_NO_FCI);
		return;
	}

	if (l2tp_register(g, itf, cmd) < 0) {
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_FCI_FAIL);
		return;
	}

	ctrl_send_resp(client_fd, 0);
}

void
cmm_l2tp_ctrl_del(struct cmm_global *g, int client_fd,
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
		    "l2tp: ctrl del: interface '%s' not found", name);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	if (!(itf->itf_flags & ITF_F_L2TP)) {
		cmm_print(CMM_LOG_WARN,
		    "l2tp: ctrl del: %s not an L2TP interface", name);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	l2tp_deregister(g, itf);
	ctrl_send_resp(client_fd, 0);
}

/* ------------------------------------------------------------------ */
/* Init / Fini                                                         */
/* ------------------------------------------------------------------ */

static int
l2tp_deregister_wrap(struct cmm_global *g, struct cmm_interface *itf)
{

	l2tp_deregister(g, itf);
	return (0);
}

int
cmm_l2tp_init(struct cmm_global *g __unused)
{

	cmm_print(CMM_LOG_INFO, "l2tp: initialized");
	return (0);
}

void
cmm_l2tp_fini(struct cmm_global *g)
{

	cmm_itf_foreach_l2tp(g, l2tp_deregister_wrap);
}
