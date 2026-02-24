/*
 * cmm_socket.h — Socket acceleration module
 *
 * Command-driven registration of sockets for hardware offload.
 * External tools (cmmctl) register specific sockets via the CMM
 * control socket; CMM resolves routes and programs CDX.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_SOCKET_H
#define CMM_SOCKET_H

#include <sys/queue.h>
#include <sys/socket.h>
#include <stdint.h>

#define CMM_SOCKET_MAX		256	/* max concurrent sockets */

/* Socket types (match CDX control_socket.h) */
#define CMM_SOCK_TYPE_LANWAN	0

/* Socket modes */
#define CMM_SOCK_MODE_UNCONNECTED	0	/* 3-tuple: daddr/dport/proto */
#define CMM_SOCK_MODE_CONNECTED		1	/* 5-tuple: full */

struct cmm_global;
struct cmm_route;

struct cmm_socket {
	STAILQ_ENTRY(cmm_socket) entry;
	uint16_t	id;		/* socket ID (1–65535) */
	sa_family_t	af;		/* AF_INET / AF_INET6 */
	uint8_t		proto;		/* IPPROTO_TCP / IPPROTO_UDP */
	uint8_t		type;		/* CMM_SOCK_TYPE_LANWAN */
	uint8_t		mode;		/* connected / unconnected */
	uint8_t		saddr[16];	/* source address (net order) */
	uint8_t		daddr[16];	/* destination address (net order) */
	uint16_t	sport;		/* source port (net order) */
	uint16_t	dport;		/* destination port (net order) */
	uint8_t		queue;		/* QoS queue (0–19) */
	uint16_t	dscp;		/* DSCP value (0–63) */
	struct cmm_route *route;	/* resolved route for daddr */
	int		fpp_programmed;	/* registered in CDX */
};

STAILQ_HEAD(cmm_socket_list, cmm_socket);

/*
 * Control protocol payload structures.
 * Sent from cmmctl → CMM daemon via CMM_CTRL_CMD_SOCKET_* commands.
 */
struct cmm_ctrl_socket_open {
	uint16_t	id;
	uint8_t		type;		/* 0=lanwan */
	uint8_t		mode;		/* 0=unconnected, 1=connected */
	uint8_t		af;		/* AF_INET=2, AF_INET6=28 */
	uint8_t		proto;		/* IPPROTO_TCP=6, IPPROTO_UDP=17 */
	uint16_t	sport;		/* network byte order, 0=any */
	uint16_t	dport;		/* network byte order */
	uint8_t		queue;		/* QoS queue (0=default) */
	uint8_t		pad1;
	uint16_t	dscp;		/* DSCP (0=default) */
	uint16_t	pad2;
	uint8_t		saddr[16];	/* source address */
	uint8_t		daddr[16];	/* destination address */
};

struct cmm_ctrl_socket_close {
	uint16_t	id;
	uint16_t	pad;
};

struct cmm_ctrl_socket_update {
	uint16_t	id;
	uint16_t	sport;		/* 0xFFFF = no change */
	uint8_t		queue;		/* 0xFF = no change */
	uint8_t		pad1;
	uint16_t	dscp;		/* 0xFFFF = no change */
	uint8_t		saddr[16];	/* all-zeros = no change */
};

int	cmm_socket_init(void);
void	cmm_socket_fini(struct cmm_global *g);

/* Control socket handlers */
void	cmm_socket_ctrl_open(struct cmm_global *g, int client_fd,
	    const void *payload, uint16_t len);
void	cmm_socket_ctrl_close(struct cmm_global *g, int client_fd,
	    const void *payload, uint16_t len);
void	cmm_socket_ctrl_update(struct cmm_global *g, int client_fd,
	    const void *payload, uint16_t len);

/* Called from cmm_route_handle_change() after route invalidation */
void	cmm_socket_route_update(struct cmm_global *g);

/*
 * Internal APIs for use by other CMM modules (L2TP, etc.).
 * These allow modules to manage sockets programmatically without
 * going through the external control socket protocol.
 */
struct cmm_socket *cmm_socket_find(uint16_t id);
uint16_t cmm_socket_next_id(void);
void	cmm_socket_add(struct cmm_socket *sk);
void	cmm_socket_remove(struct cmm_socket *sk);
int	cmm_socket_fpp_open(struct cmm_global *g, struct cmm_socket *sk);
void	cmm_socket_fpp_close(struct cmm_global *g, struct cmm_socket *sk);

#endif /* CMM_SOCKET_H */
