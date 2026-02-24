/*
 * cmmctl.c — CMM control tool
 *
 * CLI tool that connects to CMM's Unix domain socket and
 * sends FPP commands for QoS, statistics, and other modules.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cmmctl.h"

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

int
ctrl_connect(void)
{
	struct sockaddr_un sun;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "cmmctl: socket: %s\n", strerror(errno));
		return (-1);
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, CMM_CTRL_SOCK, sizeof(sun.sun_path));

	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		fprintf(stderr, "cmmctl: connect %s: %s\n",
		    CMM_CTRL_SOCK, strerror(errno));
		close(fd);
		return (-1);
	}

	return (fd);
}

void
ctrl_disconnect(int fd)
{

	close(fd);
}

int
ctrl_command(int fd, uint16_t cmd, const void *payload,
    uint16_t payload_len, int16_t *rc, void *resp_buf,
    uint16_t *resp_len)
{
	struct cmm_ctrl_hdr hdr;
	struct cmm_ctrl_resp resp;

	/* Send request */
	hdr.cmd = cmd;
	hdr.len = payload_len;
	if (write_exact(fd, &hdr, sizeof(hdr)) < 0) {
		fprintf(stderr, "cmmctl: write header: %s\n",
		    strerror(errno));
		return (-1);
	}
	if (payload_len > 0 && payload != NULL) {
		if (write_exact(fd, payload, payload_len) < 0) {
			fprintf(stderr, "cmmctl: write payload: %s\n",
			    strerror(errno));
			return (-1);
		}
	}

	/* Read response */
	if (read_exact(fd, &resp, sizeof(resp)) <= 0) {
		fprintf(stderr, "cmmctl: read response: %s\n",
		    strerror(errno));
		return (-1);
	}

	*rc = resp.rc;

	if (resp.len > 0) {
		if (resp_buf != NULL && resp_len != NULL &&
		    *resp_len >= resp.len) {
			if (read_exact(fd, resp_buf, resp.len) <= 0) {
				fprintf(stderr, "cmmctl: read data: %s\n",
				    strerror(errno));
				return (-1);
			}
			*resp_len = resp.len;
		} else {
			/* Drain response data we don't need */
			char drain[512];
			uint16_t left = resp.len;
			while (left > 0) {
				uint16_t chunk = left > sizeof(drain) ?
				    sizeof(drain) : left;
				if (read_exact(fd, drain, chunk) <= 0)
					return (-1);
				left -= chunk;
			}
			if (resp_len != NULL)
				*resp_len = 0;
		}
	} else {
		if (resp_len != NULL)
			*resp_len = 0;
	}

	return (0);
}

struct cmmctl_cmd {
	const char	*name;
	int		(*handler)(int argc, char **argv, int fd);
	const char	*desc;
};

static struct cmmctl_cmd commands[] = {
	{ "qm",     cmmctl_qm_main,     "QoS / Queue Manager" },
	{ "tunnel", cmmctl_tunnel_main, "Tunnel offload" },
	{ "stat",   cmmctl_stat_main,   "Statistics" },
	{ "ff",     cmmctl_ff_main,     "Fast-forward control" },
	{ "socket", cmmctl_socket_main, "Socket acceleration" },
	{ "bridge", cmmctl_bridge_main, "L2 bridge offload" },
	{ "pktcap", cmmctl_pktcap_main, "Packet capture" },
	{ "prf",    cmmctl_prf_main,    "FPP trace / profiling" },
	{ "natpt",  cmmctl_natpt_main,  "NAT-PT translation" },
	{ "icc",    cmmctl_icc_main,   "Ingress congestion control" },
	{ "l2tp",   cmmctl_l2tp_main,  "L2TP tunnel interfaces" },
	{ "macvlan", cmmctl_macvlan_main, "Virtual MAC interfaces" },
	{ "tx",     cmmctl_tx_main,    "TX DSCP to VLAN PCP mapping" },
	{ NULL, NULL, NULL }
};

static void
usage(void)
{
	struct cmmctl_cmd *c;

	fprintf(stderr, "usage: cmmctl <command> [args...]\n\n");
	fprintf(stderr, "Commands:\n");
	for (c = commands; c->name != NULL; c++)
		fprintf(stderr, "  %-10s  %s\n", c->name, c->desc);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct cmmctl_cmd *c;
	int fd, rc;

	if (argc < 2)
		usage();

	for (c = commands; c->name != NULL; c++) {
		if (strcmp(argv[1], c->name) == 0)
			break;
	}
	if (c->name == NULL) {
		fprintf(stderr, "cmmctl: unknown command '%s'\n", argv[1]);
		usage();
	}

	fd = ctrl_connect();
	if (fd < 0)
		return (1);

	rc = c->handler(argc - 2, argv + 2, fd);

	ctrl_disconnect(fd);
	return (rc);
}
