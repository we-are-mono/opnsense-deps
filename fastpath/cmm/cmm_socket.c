/*
 * cmm_socket.c — Socket acceleration module
 *
 * Command-driven registration of sockets for hardware offload via CDX.
 * Receives OPEN/CLOSE/UPDATE commands from cmmctl via the CMM control
 * socket, resolves routes, and programs CDX via FPP_CMD_IPV4/6_SOCK_*.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_socket.h"
#include "cmm_ctrl.h"
#include "cmm_route.h"
#include "cmm_fe.h"

static struct cmm_socket_list socket_list =
    STAILQ_HEAD_INITIALIZER(socket_list);
static int socket_count;

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

struct cmm_socket *
cmm_socket_find(uint16_t id)
{
	struct cmm_socket *sk;

	STAILQ_FOREACH(sk, &socket_list, entry) {
		if (sk->id == id)
			return (sk);
	}
	return (NULL);
}

uint16_t
cmm_socket_next_id(void)
{
	uint16_t id;

	for (id = 1; id != 0; id++) {
		if (cmm_socket_find(id) == NULL)
			return (id);
	}
	return (0);	/* exhausted */
}

void
cmm_socket_add(struct cmm_socket *sk)
{

	STAILQ_INSERT_TAIL(&socket_list, sk, entry);
	socket_count++;
}

void
cmm_socket_remove(struct cmm_socket *sk)
{

	STAILQ_REMOVE(&socket_list, sk, cmm_socket, entry);
	socket_count--;
}

/* ------------------------------------------------------------------ */
/* FPP command helpers                                                  */
/* ------------------------------------------------------------------ */

int
cmm_socket_fpp_open(struct cmm_global *g, struct cmm_socket *sk)
{
	int rc;

	if (sk->route == NULL || sk->route->fpp_id == 0)
		return (-1);

	if (sk->af == AF_INET) {
		fpp_socket4_open_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));
		cmd.id = sk->id;
		cmd.type = sk->type;
		cmd.mode = sk->mode;
		memcpy(&cmd.saddr, sk->saddr, 4);
		memcpy(&cmd.daddr, sk->daddr, 4);
		cmd.sport = sk->sport;
		cmd.dport = sk->dport;
		cmd.proto = sk->proto;
		cmd.queue = sk->queue;
		cmd.dscp = sk->dscp;
		cmd.route_id = sk->route->fpp_id;

		rc = fci_write(g->fci_handle, FPP_CMD_IPV4_SOCK_OPEN,
		    sizeof(cmd), (unsigned short *)&cmd);

		if (rc == FPP_ERR_SOCK_ALREADY_OPENED_WITH_OTHER_ID ||
		    rc == FPP_ERR_SOCKID_ALREADY_USED) {
			/* Stale entry — close and retry */
			fpp_socket4_close_cmd_t ccmd;

			memset(&ccmd, 0, sizeof(ccmd));
			ccmd.id = sk->id;
			fci_write(g->fci_handle, FPP_CMD_IPV4_SOCK_CLOSE,
			    sizeof(ccmd), (unsigned short *)&ccmd);
			rc = fci_write(g->fci_handle, FPP_CMD_IPV4_SOCK_OPEN,
			    sizeof(cmd), (unsigned short *)&cmd);
		}
	} else {
		fpp_socket6_open_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));
		cmd.id = sk->id;
		cmd.type = sk->type;
		cmd.mode = sk->mode;
		memcpy(cmd.saddr, sk->saddr, 16);
		memcpy(cmd.daddr, sk->daddr, 16);
		cmd.sport = sk->sport;
		cmd.dport = sk->dport;
		cmd.proto = sk->proto;
		cmd.queue = sk->queue;
		cmd.dscp = sk->dscp;
		cmd.route_id = sk->route->fpp_id;

		rc = fci_write(g->fci_handle, FPP_CMD_IPV6_SOCK_OPEN,
		    sizeof(cmd), (unsigned short *)&cmd);

		if (rc == FPP_ERR_SOCK_ALREADY_OPENED_WITH_OTHER_ID ||
		    rc == FPP_ERR_SOCKID_ALREADY_USED) {
			fpp_socket6_close_cmd_t ccmd;

			memset(&ccmd, 0, sizeof(ccmd));
			ccmd.id = sk->id;
			fci_write(g->fci_handle, FPP_CMD_IPV6_SOCK_CLOSE,
			    sizeof(ccmd), (unsigned short *)&ccmd);
			rc = fci_write(g->fci_handle, FPP_CMD_IPV6_SOCK_OPEN,
			    sizeof(cmd), (unsigned short *)&cmd);
		}
	}

	if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "socket: id=%u open failed: FPP error %d", sk->id, rc);
		return (-1);
	}

	sk->fpp_programmed = 1;
	cmm_print(CMM_LOG_INFO, "socket: id=%u opened (%s %s)",
	    sk->id,
	    sk->af == AF_INET ? "IPv4" : "IPv6",
	    sk->proto == IPPROTO_TCP ? "TCP" : "UDP");
	return (0);
}

void
cmm_socket_fpp_close(struct cmm_global *g, struct cmm_socket *sk)
{
	int rc;

	if (!sk->fpp_programmed)
		return;

	if (sk->af == AF_INET) {
		fpp_socket4_close_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));
		cmd.id = sk->id;
		rc = fci_write(g->fci_handle, FPP_CMD_IPV4_SOCK_CLOSE,
		    sizeof(cmd), (unsigned short *)&cmd);
	} else {
		fpp_socket6_close_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));
		cmd.id = sk->id;
		rc = fci_write(g->fci_handle, FPP_CMD_IPV6_SOCK_CLOSE,
		    sizeof(cmd), (unsigned short *)&cmd);
	}

	sk->fpp_programmed = 0;
	cmm_print(CMM_LOG_INFO, "socket: id=%u closed (rc=%d)",
	    sk->id, rc);
}

static int
socket_fpp_update(struct cmm_global *g, struct cmm_socket *sk)
{
	int rc;

	if (!sk->fpp_programmed || sk->route == NULL)
		return (-1);

	if (sk->af == AF_INET) {
		fpp_socket4_update_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));
		cmd.id = sk->id;
		memcpy(&cmd.saddr, sk->saddr, 4);
		cmd.sport = sk->sport;
		cmd.queue = sk->queue;
		cmd.dscp = sk->dscp;
		cmd.route_id = sk->route->fpp_id;

		rc = fci_write(g->fci_handle, FPP_CMD_IPV4_SOCK_UPDATE,
		    sizeof(cmd), (unsigned short *)&cmd);
	} else {
		fpp_socket6_update_cmd_t cmd;

		memset(&cmd, 0, sizeof(cmd));
		cmd.id = sk->id;
		memcpy(cmd.saddr, sk->saddr, 16);
		cmd.sport = sk->sport;
		cmd.queue = sk->queue;
		cmd.dscp = sk->dscp;
		cmd.route_id = sk->route->fpp_id;

		rc = fci_write(g->fci_handle, FPP_CMD_IPV6_SOCK_UPDATE,
		    sizeof(cmd), (unsigned short *)&cmd);
	}

	if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "socket: id=%u update failed: FPP error %d",
		    sk->id, rc);
		return (-1);
	}

	cmm_print(CMM_LOG_DEBUG, "socket: id=%u updated", sk->id);
	return (0);
}

/* ------------------------------------------------------------------ */
/* Init / fini                                                         */
/* ------------------------------------------------------------------ */

int
cmm_socket_init(void)
{
	STAILQ_INIT(&socket_list);
	socket_count = 0;
	cmm_print(CMM_LOG_INFO, "socket: initialized");
	return (0);
}

void
cmm_socket_fini(struct cmm_global *g)
{
	struct cmm_socket *sk, *tmp;

	STAILQ_FOREACH_SAFE(sk, &socket_list, entry, tmp) {
		cmm_socket_fpp_close(g, sk);
		if (sk->route != NULL)
			cmm_route_put(sk->route);
		STAILQ_REMOVE(&socket_list, sk, cmm_socket, entry);
		free(sk);
	}
	socket_count = 0;
	cmm_print(CMM_LOG_INFO, "socket: shutdown");
}

/* ------------------------------------------------------------------ */
/* Control socket handlers                                             */
/* ------------------------------------------------------------------ */

void
cmm_socket_ctrl_open(struct cmm_global *g, int client_fd,
    const void *payload, uint16_t len)
{
	const struct cmm_ctrl_socket_open *cmd = payload;
	struct cmm_socket *sk;
	int alen;
	static const uint8_t zeros[16];

	/* Validate payload */
	if (len < sizeof(*cmd)) {
		cmm_print(CMM_LOG_WARN, "socket: open: bad payload len %u",
		    len);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_BAD_LEN);
		return;
	}

	/* Validate parameters */
	if (cmd->id == 0) {
		cmm_print(CMM_LOG_WARN, "socket: open: invalid id 0");
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	if (cmd->af != AF_INET && cmd->af != AF_INET6) {
		cmm_print(CMM_LOG_WARN,
		    "socket: open: unsupported af %d", cmd->af);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	if (cmd->proto != IPPROTO_TCP && cmd->proto != IPPROTO_UDP) {
		cmm_print(CMM_LOG_WARN,
		    "socket: open: unsupported proto %d", cmd->proto);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	if (cmd->type != CMM_SOCK_TYPE_LANWAN) {
		cmm_print(CMM_LOG_WARN,
		    "socket: open: unsupported type %d", cmd->type);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	alen = (cmd->af == AF_INET) ? 4 : 16;

	/* Destination address is required */
	if (memcmp(cmd->daddr, zeros, alen) == 0) {
		cmm_print(CMM_LOG_WARN, "socket: open: daddr required");
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD);
		return;
	}

	/* Check for duplicate ID */
	if (cmm_socket_find(cmd->id) != NULL) {
		cmm_print(CMM_LOG_WARN,
		    "socket: open: id=%u already exists", cmd->id);
		ctrl_send_resp(client_fd, FPP_ERR_SOCKID_ALREADY_USED);
		return;
	}

	/* Check socket limit */
	if (socket_count >= CMM_SOCKET_MAX) {
		cmm_print(CMM_LOG_WARN, "socket: open: limit reached (%d)",
		    CMM_SOCKET_MAX);
		ctrl_send_resp(client_fd, FPP_ERR_TOO_MANY_SOCKET_OPEN);
		return;
	}

	/* Allocate and populate */
	sk = calloc(1, sizeof(*sk));
	if (sk == NULL) {
		cmm_print(CMM_LOG_ERR, "socket: open: malloc failed");
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_FCI_FAIL);
		return;
	}

	sk->id = cmd->id;
	sk->af = cmd->af;
	sk->proto = cmd->proto;
	sk->type = cmd->type;
	sk->mode = cmd->mode;
	memcpy(sk->saddr, cmd->saddr, 16);
	memcpy(sk->daddr, cmd->daddr, 16);
	sk->sport = cmd->sport;
	sk->dport = cmd->dport;
	sk->queue = cmd->queue;
	sk->dscp = cmd->dscp;

	/* Resolve route to destination */
	sk->route = cmm_route_get(g, sk->af, sk->daddr);
	if (sk->route == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "socket: open: id=%u no route to destination", sk->id);
		free(sk);
		ctrl_send_resp(client_fd, FPP_ERR_NO_ROUTE_TO_SOCK);
		return;
	}

	/* Ensure route is registered in CDX */
	if (!sk->route->fpp_programmed) {
		if (sk->route->neigh == NULL ||
		    sk->route->neigh->state != NEIGH_RESOLVED) {
			cmm_print(CMM_LOG_WARN,
			    "socket: open: id=%u neighbor not resolved",
			    sk->id);
			cmm_route_put(sk->route);
			free(sk);
			ctrl_send_resp(client_fd, FPP_ERR_NO_ROUTE_TO_SOCK);
			return;
		}
		if (cmm_fe_route_register(g, sk->route) < 0) {
			cmm_print(CMM_LOG_WARN,
			    "socket: open: id=%u route registration failed",
			    sk->id);
			cmm_route_put(sk->route);
			free(sk);
			ctrl_send_resp(client_fd, FPP_ERR_NO_ROUTE_TO_SOCK);
			return;
		}
	}

	/* Program CDX */
	if (cmm_socket_fpp_open(g, sk) < 0) {
		cmm_route_put(sk->route);
		free(sk);
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_FCI_FAIL);
		return;
	}

	/* Success — add to list */
	cmm_socket_add(sk);

	{
		char dbuf[INET6_ADDRSTRLEN];
		inet_ntop(sk->af, sk->daddr, dbuf, sizeof(dbuf));
		cmm_print(CMM_LOG_INFO,
		    "socket: id=%u registered → %s:%u route_id=%u",
		    sk->id, dbuf, ntohs(sk->dport), sk->route->fpp_id);
	}

	ctrl_send_resp(client_fd, 0);
}

void
cmm_socket_ctrl_close(struct cmm_global *g, int client_fd,
    const void *payload, uint16_t len)
{
	const struct cmm_ctrl_socket_close *cmd = payload;
	struct cmm_socket *sk;

	if (len < sizeof(*cmd)) {
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_BAD_LEN);
		return;
	}

	sk = cmm_socket_find(cmd->id);
	if (sk == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "socket: close: id=%u not found", cmd->id);
		ctrl_send_resp(client_fd, FPP_ERR_SOCKID_UNKNOWN);
		return;
	}

	/* Deregister from CDX */
	cmm_socket_fpp_close(g, sk);

	/* Release route reference */
	if (sk->route != NULL) {
		cmm_route_put(sk->route);
		sk->route = NULL;
	}

	/* Remove from list and free */
	cmm_socket_remove(sk);
	free(sk);

	cmm_print(CMM_LOG_INFO, "socket: id=%u removed", cmd->id);
	ctrl_send_resp(client_fd, 0);
}

void
cmm_socket_ctrl_update(struct cmm_global *g, int client_fd,
    const void *payload, uint16_t len)
{
	const struct cmm_ctrl_socket_update *cmd = payload;
	struct cmm_socket *sk;
	static const uint8_t zeros[16];

	if (len < sizeof(*cmd)) {
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_BAD_LEN);
		return;
	}

	sk = cmm_socket_find(cmd->id);
	if (sk == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "socket: update: id=%u not found", cmd->id);
		ctrl_send_resp(client_fd, FPP_ERR_SOCKID_UNKNOWN);
		return;
	}

	/* Apply changes (sentinels mean "no change") */
	if (cmd->sport != 0xFFFF)
		sk->sport = cmd->sport;
	if (cmd->queue != 0xFF)
		sk->queue = cmd->queue;
	if (cmd->dscp != 0xFFFF)
		sk->dscp = cmd->dscp;
	if (memcmp(cmd->saddr, zeros, sizeof(cmd->saddr)) != 0) {
		memcpy(sk->saddr, cmd->saddr, 16);
		/* If saddr was set, switch to connected mode */
		sk->mode = CMM_SOCK_MODE_CONNECTED;
	}

	/* Send update to CDX */
	if (socket_fpp_update(g, sk) < 0) {
		ctrl_send_resp(client_fd, CMM_CTRL_ERR_FCI_FAIL);
		return;
	}

	cmm_print(CMM_LOG_INFO, "socket: id=%u updated", sk->id);
	ctrl_send_resp(client_fd, 0);
}

/* ------------------------------------------------------------------ */
/* Route change callback                                               */
/* ------------------------------------------------------------------ */

void
cmm_socket_route_update(struct cmm_global *g)
{
	struct cmm_socket *sk;
	int reprogram = 0;

	STAILQ_FOREACH(sk, &socket_list, entry) {
		if (sk->route == NULL)
			continue;

		/* Route still valid in CDX — nothing to do */
		if (sk->route->fpp_programmed && sk->fpp_programmed)
			continue;

		/* Route was invalidated — deregister socket from CDX */
		if (sk->fpp_programmed) {
			cmm_print(CMM_LOG_INFO,
			    "socket: id=%u route changed, deregistering",
			    sk->id);
			cmm_socket_fpp_close(g, sk);
		}

		/* Re-register route if needed */
		if (!sk->route->fpp_programmed) {
			if (sk->route->neigh == NULL ||
			    sk->route->neigh->state != NEIGH_RESOLVED) {
				cmm_print(CMM_LOG_DEBUG,
				    "socket: id=%u neighbor not resolved yet",
				    sk->id);
				continue;
			}
			if (cmm_fe_route_register(g, sk->route) < 0) {
				cmm_print(CMM_LOG_WARN,
				    "socket: id=%u route re-register failed",
				    sk->id);
				continue;
			}
		}

		/* Re-open socket with updated route */
		if (cmm_socket_fpp_open(g, sk) == 0) {
			cmm_print(CMM_LOG_INFO,
			    "socket: id=%u reprogrammed with route_id=%u",
			    sk->id, sk->route->fpp_id);
			reprogram++;
		}
	}

	if (reprogram > 0)
		cmm_print(CMM_LOG_DEBUG,
		    "socket: reprogrammed %d socket(s) after route change",
		    reprogram);
}
