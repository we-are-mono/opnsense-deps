/*
 * cmmctl_tunnel.c — Tunnel offload commands
 *
 * CLI interface for tunnel add/del/show through the CMM
 * control socket.  Add/del use CMM-internal commands;
 * show queries CDX directly via FPP_CMD_TUNNEL_QUERY.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmmctl.h"
#include "fpp.h"

static const char *
tnl_mode_str(uint8_t mode)
{
	static const char *names[] = {
		[0] = "ethipoip6",
		[1] = "6o4",
		[2] = "4o6",
		[3] = "ethipoip4",
		[4] = "gre6",
	};

	if (mode < sizeof(names) / sizeof(names[0]) && names[mode] != NULL)
		return (names[mode]);
	return ("unknown");
}

static void
print_tunnel(const fpp_tunnel_query_cmd_t *q)
{
	char lbuf[INET6_ADDRSTRLEN], rbuf[INET6_ADDRSTRLEN];
	int is_v6;

	/*
	 * Determine address family from mode:
	 *   6o4 (mode 1) → IPv4 outer
	 *   4o6 (mode 2), gre6 (mode 4) → IPv6 outer
	 *   ethipoip6 (mode 0), ethipoip4 (mode 3) → IPv6/IPv4 respectively
	 */
	is_v6 = (q->mode != 1 && q->mode != 3);

	if (is_v6) {
		inet_ntop(AF_INET6, q->local, lbuf, sizeof(lbuf));
		inet_ntop(AF_INET6, q->remote, rbuf, sizeof(rbuf));
	} else {
		inet_ntop(AF_INET, q->local, lbuf, sizeof(lbuf));
		inet_ntop(AF_INET, q->remote, rbuf, sizeof(rbuf));
	}

	printf("%-16s mode=%-8s enabled=%u route_id=%-4u mtu=%u\n",
	    q->name, tnl_mode_str(q->mode),
	    q->enabled, q->route_id, q->mtu);
	printf("  local  %s\n", lbuf);
	printf("  remote %s\n", rbuf);
	if (q->hop_limit)
		printf("  hop_limit=%u", q->hop_limit);
	if (q->secure)
		printf("  secure=%u", q->secure);
	if (q->hop_limit || q->secure)
		printf("\n");
}

static int
tnl_show(int argc, char **argv, int fd)
{
	fpp_tunnel_query_cmd_t cmd, resp;
	uint16_t resp_len;
	int16_t rc;
	int first = 1;
	int count = 0;

	memset(&cmd, 0, sizeof(cmd));
	if (argc > 0)
		strlcpy(cmd.name, argv[0], sizeof(cmd.name));

	for (;;) {
		uint16_t qcmd;

		qcmd = first ? FPP_CMD_TUNNEL_QUERY :
		    FPP_CMD_TUNNEL_QUERY_CONT;
		first = 0;

		resp_len = sizeof(resp);
		if (ctrl_command(fd, qcmd, &cmd, sizeof(cmd),
		    &rc, &resp, &resp_len) < 0)
			return (1);

		if (rc != 0) {
			if (count == 0 && argc > 0)
				fprintf(stderr, "tunnel '%s' not found\n",
				    argv[0]);
			break;
		}

		if (resp_len < sizeof(resp)) {
			fprintf(stderr, "short response (%u < %zu)\n",
			    resp_len, sizeof(resp));
			break;
		}

		print_tunnel(&resp);
		count++;

		/* For single-name query, stop after first match */
		if (argc > 0)
			break;

		/* Prepare for QUERY_CONT */
		memset(&cmd, 0, sizeof(cmd));
		strlcpy(cmd.name, resp.name, sizeof(cmd.name));
	}

	if (count == 0 && argc == 0)
		printf("No tunnels registered in CDX.\n");

	return (0);
}

static int
tnl_add(int argc, char **argv, int fd)
{
	char name[IFNAMSIZ];
	int16_t rc;

	if (argc < 1) {
		fprintf(stderr, "usage: cmmctl tunnel add <ifname>\n");
		return (1);
	}

	memset(name, 0, sizeof(name));
	strlcpy(name, argv[0], sizeof(name));

	if (ctrl_command(fd, CMM_CTRL_CMD_TNL_ADD, name,
	    (uint16_t)strlen(name) + 1, &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "tunnel add %s failed: rc=%d\n",
		    argv[0], rc);
		return (1);
	}

	printf("tunnel %s registered\n", argv[0]);
	return (0);
}

static int
tnl_del(int argc, char **argv, int fd)
{
	char name[IFNAMSIZ];
	int16_t rc;

	if (argc < 1) {
		fprintf(stderr, "usage: cmmctl tunnel del <ifname>\n");
		return (1);
	}

	memset(name, 0, sizeof(name));
	strlcpy(name, argv[0], sizeof(name));

	if (ctrl_command(fd, CMM_CTRL_CMD_TNL_DEL, name,
	    (uint16_t)strlen(name) + 1, &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "tunnel del %s failed: rc=%d\n",
		    argv[0], rc);
		return (1);
	}

	printf("tunnel %s deregistered\n", argv[0]);
	return (0);
}

static void
tunnel_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl tunnel <command> [args]\n\n"
	    "Commands:\n"
	    "  add <ifname>     Register tunnel interface in CDX\n"
	    "  del <ifname>     Deregister tunnel interface from CDX\n"
	    "  show [name]      Show registered tunnels\n");
}

int
cmmctl_tunnel_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		tunnel_usage();
		return (1);
	}

	if (strcmp(argv[0], "add") == 0)
		return (tnl_add(argc - 1, argv + 1, fd));
	if (strcmp(argv[0], "del") == 0)
		return (tnl_del(argc - 1, argv + 1, fd));
	if (strcmp(argv[0], "show") == 0)
		return (tnl_show(argc - 1, argv + 1, fd));

	fprintf(stderr, "cmmctl tunnel: unknown sub-command '%s'\n", argv[0]);
	tunnel_usage();
	return (1);
}
