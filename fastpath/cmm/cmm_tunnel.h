/*
 * cmm_tunnel.h — Tunnel interface offload
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_TUNNEL_H
#define CMM_TUNNEL_H

#include "cmm.h"

struct cmm_interface;

/* Initialize tunnel subsystem — registers existing UP tunnels */
int	cmm_tunnel_init(struct cmm_global *g);

/* Deregister all tunnels from CDX */
void	cmm_tunnel_fini(struct cmm_global *g);

/* Called when interface flags change — register/deregister as needed */
void	cmm_tunnel_notify(struct cmm_global *g, struct cmm_interface *itf);

/* Called on route changes — re-evaluate pending/active tunnels */
void	cmm_tunnel_route_update(struct cmm_global *g);

/* Control socket handlers for CMM_CTRL_CMD_TNL_ADD/DEL */
void	cmm_tunnel_ctrl_add(struct cmm_global *g, int client_fd,
	    const void *payload, uint16_t len);
void	cmm_tunnel_ctrl_del(struct cmm_global *g, int client_fd,
	    const void *payload, uint16_t len);

#endif /* CMM_TUNNEL_H */
