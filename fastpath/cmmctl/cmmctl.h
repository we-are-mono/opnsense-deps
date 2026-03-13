/*
 * cmmctl.h — CMM control tool shared definitions
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMMCTL_H
#define CMMCTL_H

#include <stdint.h>
#include "cmm_ctrl.h"

/* Connect to CMM control socket.  Returns fd or -1 on error. */
int	ctrl_connect(void);
void	ctrl_disconnect(int fd);

/*
 * Send an FPP command through the CMM control socket.
 * Returns 0 on success, fills *rc with FPP/CMM result code.
 * On success with response data: resp_buf/resp_len filled.
 * resp_buf may be NULL if no response data is expected.
 */
int	ctrl_command(int fd, uint16_t cmd, const void *payload,
	    uint16_t payload_len, int16_t *rc, void *resp_buf,
	    uint16_t *resp_len);

/* Sub-command handlers */
int	cmmctl_qm_main(int argc, char **argv, int fd);
int	cmmctl_tunnel_main(int argc, char **argv, int fd);
int	cmmctl_stat_main(int argc, char **argv, int fd);
int	cmmctl_ff_main(int argc, char **argv, int fd);
int	cmmctl_socket_main(int argc, char **argv, int fd);
int	cmmctl_bridge_main(int argc, char **argv, int fd);
int	cmmctl_pktcap_main(int argc, char **argv, int fd);
int	cmmctl_prf_main(int argc, char **argv, int fd);
int	cmmctl_natpt_main(int argc, char **argv, int fd);
int	cmmctl_icc_main(int argc, char **argv, int fd);
int	cmmctl_l2tp_main(int argc, char **argv, int fd);
int	cmmctl_macvlan_main(int argc, char **argv, int fd);
int	cmmctl_tx_main(int argc, char **argv, int fd);
int	cmmctl_mc4_main(int argc, char **argv, int fd);
int	cmmctl_mc6_main(int argc, char **argv, int fd);

#endif /* CMMCTL_H */
