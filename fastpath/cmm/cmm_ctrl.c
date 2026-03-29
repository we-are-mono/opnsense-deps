/*
 * cmm_ctrl.c — CMM control socket server
 *
 * Accepts connections on a Unix domain socket and forwards
 * FPP commands to CDX via FCI.  Used by cmmctl and other tools.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_ctrl.h"
#include "cmm_tunnel.h"
#include "cmm_l2tp.h"
#include "cmm_socket.h"
#include "cmm_mcast.h"

/* kqueue udata tags — cast to void * for EV_SET */
#define CMM_UDATA_CTRL_LISTEN	((void *)(uintptr_t)1)
#define CMM_UDATA_CTRL_CLIENT	((void *)(uintptr_t)2)

/*
 * Command whitelist — only these FPP commands may be sent
 * from external tools through the control socket.
 */
static const uint16_t ctrl_whitelist[] = {
	/* QM configuration */
	FPP_CMD_QM_QOSENABLE,
	FPP_CMD_QM_RESET,
	FPP_CMD_QM_SHAPER_CFG,
#ifdef LS1043
	FPP_CMD_QM_WBFQ_CFG,
	FPP_CMD_QM_CQ_CFG,
	FPP_CMD_QM_CHNL_ASSIGN,
	FPP_CMD_QM_DSCP_FQ_MAP_STATUS,
	FPP_CMD_QM_DSCP_FQ_MAP_CFG,
	FPP_CMD_QM_DSCP_FQ_MAP_RESET,
	FPP_CMD_QM_FF_RATE,
#endif
	FPP_CMD_QM_EXPT_RATE,
	FPP_CMD_QM_INGRESS_POLICER_ENABLE,
	FPP_CMD_QM_INGRESS_POLICER_CONFIG,
	FPP_CMD_QM_INGRESS_POLICER_RESET,
	/* QM queries */
	FPP_CMD_QM_QUERY,
	FPP_CMD_QM_QUERY_EXPT_RATE,
#ifdef LS1043
	FPP_CMD_QM_QUERY_FF_RATE,
	FPP_CMD_QM_QUERY_IFACE_DSCP_FQID_MAP,
#endif
	FPP_CMD_QM_CQ_STATS,
	FPP_CMD_QM_INGRESS_POLICER_QUERY_STATS,
	/* Tunnel queries (FCI passthrough to CDX) */
	FPP_CMD_TUNNEL_QUERY,
	FPP_CMD_TUNNEL_QUERY_CONT,
	/* Statistics */
	FPP_CMD_STAT_ENABLE,
	FPP_CMD_STAT_QUEUE,
	FPP_CMD_STAT_INTERFACE_PKT,
	FPP_CMD_STAT_CONNECTION,
	FPP_CMD_STAT_PPPOE_STATUS,
	FPP_CMD_STAT_PPPOE_ENTRY,
	FPP_CMD_STAT_BRIDGE_STATUS,
	FPP_CMD_STAT_BRIDGE_ENTRY,
	FPP_CMD_STAT_IPSEC_STATUS,
	FPP_CMD_STAT_IPSEC_ENTRY,
	FPP_CMD_STAT_VLAN_STATUS,
	FPP_CMD_STAT_VLAN_ENTRY,
	FPP_CMD_STAT_TUNNEL_STATUS,
	FPP_CMD_STAT_TUNNEL_ENTRY,
	FPP_CMD_STAT_FLOW,
	FPP_CMD_IPR_V4_STATS,
	FPP_CMD_IPR_V6_STATS,
	/* L2 Bridge */
	FPP_CMD_RX_L2BRIDGE_ENABLE,
	FPP_CMD_RX_L2BRIDGE_ADD,
	FPP_CMD_RX_L2BRIDGE_REMOVE,
	FPP_CMD_RX_L2BRIDGE_QUERY_STATUS,
	FPP_CMD_RX_L2BRIDGE_QUERY_ENTRY,
	FPP_CMD_RX_L2FLOW_ENTRY,
	FPP_CMD_RX_L2BRIDGE_MODE,
	FPP_CMD_RX_L2BRIDGE_FLOW_TIMEOUT,
	FPP_CMD_RX_L2BRIDGE_FLOW_RESET,
	/* Fast-forward control */
	FPP_CMD_IPV4_FF_CONTROL,
	FPP_CMD_IPSEC_FRAG_CFG,
	/* Socket statistics */
	FPP_CMD_SOCKETSTATS_STATUS,
	FPP_CMD_SOCKETSTATS_ENTRY,
	/* Packet capture */
	FPP_CMD_PKTCAP_IFSTATUS,
	FPP_CMD_PKTCAP_FLF,
	FPP_CMD_PKTCAP_SLICE,
	FPP_CMD_PKTCAP_QUERY,
	/* NAT-PT */
	FPP_CMD_NATPT_OPEN,
	FPP_CMD_NATPT_CLOSE,
	FPP_CMD_NATPT_QUERY,
	/* ICC (ingress congestion control) */
	FPP_CMD_ICC_RESET,
	FPP_CMD_ICC_THRESHOLD,
	FPP_CMD_ICC_ADD_DELETE,
	FPP_CMD_ICC_QUERY,
	/* MACVLAN (virtual MAC interfaces) */
	FPP_CMD_MACVLAN_ENTRY,
	FPP_CMD_MACVLAN_RESET,
	/* PPPoE */
	FPP_CMD_PPPOE_ENTRY,
	FPP_CMD_PPPOE_GET_IDLE,
	/* L2TP */
	FPP_CMD_L2TP_ITF_ADD,
	FPP_CMD_L2TP_ITF_DEL,
#ifdef LS1043
	/* TX DSCP to VLAN PCP mapping */
	FPP_CMD_DSCP_VLANPCP_MAP_STATUS,
	FPP_CMD_DSCP_VLANPCP_MAP_CFG,
	FPP_CMD_QUERY_IFACE_DSCP_VLANPCP_MAP,
#endif
	/* Trace / profiling */
	FPP_CMD_TRC_ON,
	FPP_CMD_TRC_OFF,
	FPP_CMD_TRC_SWITCH,
	FPP_CMD_TRC_DMEM,
	FPP_CMD_TRC_SETMASK,
	FPP_CMD_TRC_SHOW,
	FPP_CMD_TRC_BSYCPU,
	FPP_CMD_TRC_STATUS,
};

static int
ctrl_cmd_allowed(uint16_t cmd)
{
	unsigned int i;

	for (i = 0; i < sizeof(ctrl_whitelist) / sizeof(ctrl_whitelist[0]);
	    i++) {
		if (ctrl_whitelist[i] == cmd)
			return (1);
	}
	return (0);
}

/*
 * Read exactly `len` bytes from a stream socket.
 * Returns len on success, 0 on clean close, -1 on error.
 */
static ssize_t
read_exact(int fd, void *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t n = read(fd, (char *)buf + done, len - done);
		if (n <= 0)
			return (n);
		done += n;
	}
	return ((ssize_t)done);
}

/*
 * Write exactly `len` bytes to a stream socket.
 * Returns len on success, -1 on error.
 */
static ssize_t
write_exact(int fd, const void *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t n = write(fd, (const char *)buf + done, len - done);
		if (n < 0)
			return (-1);
		done += n;
	}
	return ((ssize_t)done);
}

static void
ctrl_close_client(struct cmm_global *g, int fd)
{
	struct kevent kev;
	int i;

	EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	kevent(g->kq, &kev, 1, NULL, 0, NULL);
	close(fd);

	for (i = 0; i < CMM_CTRL_MAX_CLIENTS; i++) {
		if (g->ctrl_clients[i] == fd) {
			g->ctrl_clients[i] = -1;
			break;
		}
	}

	cmm_print(CMM_LOG_DEBUG, "ctrl: client fd=%d closed", fd);
}

int
cmm_ctrl_init(struct cmm_global *g)
{
	struct sockaddr_un sun;
	int fd, i;

	for (i = 0; i < CMM_CTRL_MAX_CLIENTS; i++)
		g->ctrl_clients[i] = -1;
	g->ctrl_listen_fd = -1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		cmm_print(CMM_LOG_ERR, "ctrl: socket: %s", strerror(errno));
		return (-1);
	}

	/* Remove stale socket from previous unclean exit */
	unlink(CMM_CTRL_SOCK);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, CMM_CTRL_SOCK, sizeof(sun.sun_path));

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		cmm_print(CMM_LOG_ERR, "ctrl: bind %s: %s",
		    CMM_CTRL_SOCK, strerror(errno));
		close(fd);
		return (-1);
	}

	/* Enforce root-only access regardless of umask */
	if (chmod(CMM_CTRL_SOCK, S_IRUSR | S_IWUSR) < 0)
		cmm_print(CMM_LOG_WARN, "ctrl: chmod %s: %s",
		    CMM_CTRL_SOCK, strerror(errno));

	if (listen(fd, CMM_CTRL_MAX_CLIENTS) < 0) {
		cmm_print(CMM_LOG_ERR, "ctrl: listen: %s", strerror(errno));
		close(fd);
		unlink(CMM_CTRL_SOCK);
		return (-1);
	}

	g->ctrl_listen_fd = fd;
	cmm_print(CMM_LOG_INFO, "ctrl: listening on %s", CMM_CTRL_SOCK);
	return (0);
}

void
cmm_ctrl_fini(struct cmm_global *g)
{
	int i;

	for (i = 0; i < CMM_CTRL_MAX_CLIENTS; i++) {
		if (g->ctrl_clients[i] >= 0) {
			close(g->ctrl_clients[i]);
			g->ctrl_clients[i] = -1;
		}
	}

	if (g->ctrl_listen_fd >= 0) {
		close(g->ctrl_listen_fd);
		g->ctrl_listen_fd = -1;
		unlink(CMM_CTRL_SOCK);
	}
}

void
cmm_ctrl_accept(struct cmm_global *g)
{
	struct kevent kev;
	int fd, i, slot;

	fd = accept(g->ctrl_listen_fd, NULL, NULL);
	if (fd < 0) {
		cmm_print(CMM_LOG_WARN, "ctrl: accept: %s", strerror(errno));
		return;
	}

	/* Find a free client slot */
	slot = -1;
	for (i = 0; i < CMM_CTRL_MAX_CLIENTS; i++) {
		if (g->ctrl_clients[i] < 0) {
			slot = i;
			break;
		}
	}

	if (slot < 0) {
		cmm_print(CMM_LOG_WARN, "ctrl: too many clients, rejecting");
		close(fd);
		return;
	}

	g->ctrl_clients[slot] = fd;

	/*
	 * Keep client sockets blocking.  The control protocol is
	 * request-response with small payloads (< 512 bytes) on a
	 * Unix domain socket — reads/writes are effectively atomic.
	 * Non-blocking would break read_exact()/write_exact() which
	 * loop without EAGAIN handling.  kqueue only dispatches when
	 * data is available, so blocking reads won't stall the loop.
	 *
	 * Set a receive timeout to bound how long a misbehaving
	 * client can block the event loop (e.g. sends header but
	 * never sends payload).
	 */
	{
		struct timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, CMM_UDATA_CTRL_CLIENT);
	if (kevent(g->kq, &kev, 1, NULL, 0, NULL) < 0) {
		cmm_print(CMM_LOG_ERR, "ctrl: kevent add client: %s",
		    strerror(errno));
		close(fd);
		g->ctrl_clients[slot] = -1;
		return;
	}

	cmm_print(CMM_LOG_DEBUG, "ctrl: client fd=%d connected (slot %d)",
	    fd, slot);
}

void
cmm_ctrl_dispatch(struct cmm_global *g, int client_fd)
{
	struct cmm_ctrl_hdr hdr;
	struct cmm_ctrl_resp resp;
	/* Aligned buffer for FCI — fci_cmd takes unsigned short * */
	uint16_t cmd_buf[CMM_CTRL_MAX_PAYLOAD / 2];
	uint16_t resp_buf[CMM_CTRL_MAX_PAYLOAD / 2];
	unsigned short resp_len;
	int rc;

	/* Read request header */
	if (read_exact(client_fd, &hdr, sizeof(hdr)) <= 0) {
		ctrl_close_client(g, client_fd);
		return;
	}

	/* Validate payload length */
	if (hdr.len > CMM_CTRL_MAX_PAYLOAD) {
		cmm_print(CMM_LOG_WARN, "ctrl: bad payload len %u", hdr.len);
		resp.rc = CMM_CTRL_ERR_BAD_LEN;
		resp.len = 0;
		write_exact(client_fd, &resp, sizeof(resp));
		ctrl_close_client(g, client_fd);
		return;
	}

	/* Read payload */
	if (hdr.len > 0) {
		if (read_exact(client_fd, cmd_buf, hdr.len) <= 0) {
			ctrl_close_client(g, client_fd);
			return;
		}
	}

	/*
	 * Multicast commands — CMM maintains a shadow table and
	 * forwards to CDX via FCI.  Not FPP whitelist passthrough.
	 */
	switch (hdr.cmd) {
	case FPP_CMD_MC4_MULTICAST:
		cmm_mcast_ctrl_mc4(g, client_fd, cmd_buf, hdr.len);
		return;
	case FPP_CMD_MC4_RESET:
		cmm_mcast_ctrl_mc4_reset(g, client_fd);
		return;
	case FPP_CMD_MC6_MULTICAST:
		cmm_mcast_ctrl_mc6(g, client_fd, cmd_buf, hdr.len);
		return;
	case FPP_CMD_MC6_RESET:
		cmm_mcast_ctrl_mc6_reset(g, client_fd);
		return;
	default:
		break;
	}

	/*
	 * CMM-internal commands (above FPP range).
	 * These are CMM's own control protocol, not FPP passthrough,
	 * so they are intentionally exempt from the FPP whitelist.
	 * The socket is chmod 0600 (root-only); no additional
	 * authentication is needed.
	 */
	if (hdr.cmd >= CMM_CTRL_CMD_BASE) {
		switch (hdr.cmd) {
		case CMM_CTRL_CMD_TNL_ADD:
			cmm_tunnel_ctrl_add(g, client_fd, cmd_buf, hdr.len);
			return;
		case CMM_CTRL_CMD_TNL_DEL:
			cmm_tunnel_ctrl_del(g, client_fd, cmd_buf, hdr.len);
			return;
		case CMM_CTRL_CMD_SOCKET_OPEN:
			cmm_socket_ctrl_open(g, client_fd, cmd_buf, hdr.len);
			return;
		case CMM_CTRL_CMD_SOCKET_CLOSE:
			cmm_socket_ctrl_close(g, client_fd, cmd_buf, hdr.len);
			return;
		case CMM_CTRL_CMD_SOCKET_UPDATE:
			cmm_socket_ctrl_update(g, client_fd, cmd_buf, hdr.len);
			return;
		case CMM_CTRL_CMD_L2TP_ADD:
			cmm_l2tp_ctrl_add(g, client_fd, cmd_buf, hdr.len);
			return;
		case CMM_CTRL_CMD_L2TP_DEL:
			cmm_l2tp_ctrl_del(g, client_fd, cmd_buf, hdr.len);
			return;
		default:
			cmm_print(CMM_LOG_WARN,
			    "ctrl: unknown internal cmd 0x%04x", hdr.cmd);
			resp.rc = CMM_CTRL_ERR_UNKNOWN_CMD;
			resp.len = 0;
			write_exact(client_fd, &resp, sizeof(resp));
			return;
		}
	}

	/* Whitelist check */
	if (!ctrl_cmd_allowed(hdr.cmd)) {
		cmm_print(CMM_LOG_WARN,
		    "ctrl: rejected cmd 0x%04x (not whitelisted)", hdr.cmd);
		resp.rc = CMM_CTRL_ERR_UNKNOWN_CMD;
		resp.len = 0;
		write_exact(client_fd, &resp, sizeof(resp));
		return;
	}

	/* Check FCI handle */
	if (g->fci_handle == NULL) {
		resp.rc = CMM_CTRL_ERR_NO_FCI;
		resp.len = 0;
		write_exact(client_fd, &resp, sizeof(resp));
		return;
	}

	/* Forward to CDX via FCI */
	resp_len = sizeof(resp_buf);
	rc = fci_cmd(g->fci_handle, hdr.cmd,
	    (unsigned short *)cmd_buf, hdr.len,
	    (unsigned short *)resp_buf, &resp_len);

	if (rc < 0) {
		cmm_print(CMM_LOG_WARN,
		    "ctrl: fci_cmd 0x%04x failed: %s",
		    hdr.cmd, strerror(errno));
		resp.rc = CMM_CTRL_ERR_FCI_FAIL;
		resp.len = 0;
		write_exact(client_fd, &resp, sizeof(resp));
		return;
	}

	/* Send response back to client — forward FPP error code */
	resp.rc = (resp_len >= 2) ? (int16_t)resp_buf[0] : 0;
	resp.len = resp_len;
	if (write_exact(client_fd, &resp, sizeof(resp)) < 0) {
		ctrl_close_client(g, client_fd);
		return;
	}
	if (resp_len > 0) {
		if (write_exact(client_fd, resp_buf, resp_len) < 0) {
			ctrl_close_client(g, client_fd);
			return;
		}
	}

	cmm_print(CMM_LOG_TRACE, "ctrl: cmd 0x%04x len=%u → rc=%d rsp=%u",
	    hdr.cmd, hdr.len, rc, resp_len);
}
