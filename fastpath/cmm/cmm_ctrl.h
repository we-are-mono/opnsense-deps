/*
 * cmm_ctrl.h — CMM control socket protocol definitions
 *
 * Binary protocol over Unix domain socket for external tools
 * (e.g., cmmctl) to send FPP commands through CMM to CDX.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_CTRL_H
#define CMM_CTRL_H

#include <net/if.h>
#include <stdint.h>

#define CMM_CTRL_SOCK		"/var/run/cmm.sock"
#define CMM_CTRL_MAX_PAYLOAD	512	/* matches FCI_MSG_MAX_PAYLOAD */
#define CMM_CTRL_MAX_CLIENTS	4

/*
 * Request: client → CMM daemon.
 * Followed by `len` bytes of FPP command payload.
 */
struct cmm_ctrl_hdr {
	uint16_t cmd;		/* FPP command code */
	uint16_t len;		/* payload length in bytes */
};

/*
 * Response: CMM daemon → client.
 * rc:  0 = success, >0 = FPP error code, <0 = CMM error
 * Followed by `len` bytes of FPP response data.
 */
struct cmm_ctrl_resp {
	int16_t  rc;		/* result code */
	uint16_t len;		/* response payload length */
};

/* CMM error codes (rc < 0) */
#define CMM_CTRL_ERR_UNKNOWN_CMD	(-1)
#define CMM_CTRL_ERR_FCI_FAIL		(-2)
#define CMM_CTRL_ERR_NO_FCI		(-3)
#define CMM_CTRL_ERR_BAD_LEN		(-4)

/* CMM-internal control commands (above FPP range) */
#define CMM_CTRL_CMD_BASE		0xF000
#define CMM_CTRL_CMD_TNL_ADD		0xF001	/* payload: char name[IFNAMSIZ] */
#define CMM_CTRL_CMD_TNL_DEL		0xF002	/* payload: char name[IFNAMSIZ] */
#define CMM_CTRL_CMD_SOCKET_OPEN	0xF010	/* payload: cmm_ctrl_socket_open */
#define CMM_CTRL_CMD_SOCKET_CLOSE	0xF011	/* payload: cmm_ctrl_socket_close */
#define CMM_CTRL_CMD_SOCKET_UPDATE	0xF012	/* payload: cmm_ctrl_socket_update */
#define CMM_CTRL_CMD_L2TP_ADD		0xF020	/* payload: cmm_ctrl_l2tp_add */
#define CMM_CTRL_CMD_L2TP_DEL		0xF021	/* payload: char name[IFNAMSIZ] */

/*
 * L2TP session create payload.
 * All L2TP parameters must be provided — there is no kernel L2TP
 * driver to query them from.
 */
struct cmm_ctrl_l2tp_add {
	char		ifname[IFNAMSIZ];	/* interface name */
	uint8_t		af;			/* AF_INET=2, AF_INET6=28 */
	uint8_t		pad1;
	uint16_t	local_port;		/* network byte order */
	uint16_t	peer_port;		/* network byte order */
	uint16_t	local_tun_id;
	uint16_t	peer_tun_id;
	uint16_t	local_ses_id;
	uint16_t	peer_ses_id;
	uint16_t	options;		/* L2TP option flags */
	uint16_t	dscp;
	uint8_t		queue;
	uint8_t		pad2;
	uint8_t		local_addr[16];		/* IPv4 in first 4, IPv6 full */
	uint8_t		peer_addr[16];		/* same */
};

struct cmm_global;

int	cmm_ctrl_init(struct cmm_global *g);
void	cmm_ctrl_fini(struct cmm_global *g);
void	cmm_ctrl_accept(struct cmm_global *g);
void	cmm_ctrl_dispatch(struct cmm_global *g, int client_fd);

#endif /* CMM_CTRL_H */
