/*
 * cmm_l2tp.h — L2TP tunnel interface offload
 *
 * Command-driven L2TP session management.  External tools (cmmctl)
 * send session descriptors via the CMM control socket; CMM allocates
 * a UDP socket, programs CDX, and tracks state.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_L2TP_H
#define CMM_L2TP_H

struct cmm_global;

int	cmm_l2tp_init(struct cmm_global *g);
void	cmm_l2tp_fini(struct cmm_global *g);

/* Control socket handlers */
void	cmm_l2tp_ctrl_add(struct cmm_global *g, int client_fd,
	    const void *payload, uint16_t len);
void	cmm_l2tp_ctrl_del(struct cmm_global *g, int client_fd,
	    const void *payload, uint16_t len);

#endif /* CMM_L2TP_H */
