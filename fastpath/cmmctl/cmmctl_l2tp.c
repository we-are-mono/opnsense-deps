/*
 * cmmctl_l2tp.c — L2TP tunnel interface CLI sub-commands
 *
 * cmmctl l2tp add <ifname> <af> <local-addr> <peer-addr>
 *         <local-port> <peer-port> <local-tun-id> <peer-tun-id>
 *         <local-ses-id> <peer-ses-id> [options [dscp [queue]]]
 * cmmctl l2tp del <ifname>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmmctl.h"
#include "fpp.h"

static void
l2tp_usage(void)
{

	fprintf(stderr,
	    "usage: cmmctl l2tp <command>\n\n"
	    "Commands:\n"
	    "  add <ifname> <inet|inet6> <local-addr> <peer-addr>\n"
	    "      <local-port> <peer-port> <local-tun-id> <peer-tun-id>\n"
	    "      <local-ses-id> <peer-ses-id> [options [dscp [queue]]]\n"
	    "  del <ifname>\n\n"
	    "Examples:\n"
	    "  cmmctl l2tp add l2tpeth0 inet 10.0.0.1 10.0.0.2 "
	    "1701 1701 100 200 300 400\n"
	    "  cmmctl l2tp del l2tpeth0\n");
}

static int
l2tp_add(int fd, int argc, char **argv)
{
	struct cmm_ctrl_l2tp_add cmd;
	int16_t rc;
	unsigned int tmp;
	sa_family_t af;

	if (argc < 10) {
		fprintf(stderr,
		    "usage: cmmctl l2tp add <ifname> <inet|inet6> "
		    "<local-addr> <peer-addr>\n"
		    "       <local-port> <peer-port> "
		    "<local-tun-id> <peer-tun-id>\n"
		    "       <local-ses-id> <peer-ses-id> "
		    "[options [dscp [queue]]]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	/* Interface name */
	strlcpy(cmd.ifname, argv[0], sizeof(cmd.ifname));

	/* Address family */
	if (strcmp(argv[1], "inet") == 0)
		af = AF_INET;
	else if (strcmp(argv[1], "inet6") == 0)
		af = AF_INET6;
	else {
		fprintf(stderr, "invalid address family: %s "
		    "(use inet or inet6)\n", argv[1]);
		return (1);
	}
	cmd.af = af;

	/* Local address */
	if (inet_pton(af, argv[2], cmd.local_addr) != 1) {
		fprintf(stderr, "invalid local address: %s\n", argv[2]);
		return (1);
	}

	/* Peer address */
	if (inet_pton(af, argv[3], cmd.peer_addr) != 1) {
		fprintf(stderr, "invalid peer address: %s\n", argv[3]);
		return (1);
	}

	/* Ports (convert to network byte order) */
	if (sscanf(argv[4], "%u", &tmp) != 1 || tmp > 65535) {
		fprintf(stderr, "invalid local port: %s\n", argv[4]);
		return (1);
	}
	cmd.local_port = htons((uint16_t)tmp);

	if (sscanf(argv[5], "%u", &tmp) != 1 || tmp > 65535) {
		fprintf(stderr, "invalid peer port: %s\n", argv[5]);
		return (1);
	}
	cmd.peer_port = htons((uint16_t)tmp);

	/* Tunnel IDs */
	if (sscanf(argv[6], "%u", &tmp) != 1 || tmp > 65535) {
		fprintf(stderr, "invalid local tunnel ID: %s\n", argv[6]);
		return (1);
	}
	cmd.local_tun_id = (uint16_t)tmp;

	if (sscanf(argv[7], "%u", &tmp) != 1 || tmp > 65535) {
		fprintf(stderr, "invalid peer tunnel ID: %s\n", argv[7]);
		return (1);
	}
	cmd.peer_tun_id = (uint16_t)tmp;

	/* Session IDs */
	if (sscanf(argv[8], "%u", &tmp) != 1 || tmp > 65535) {
		fprintf(stderr, "invalid local session ID: %s\n", argv[8]);
		return (1);
	}
	cmd.local_ses_id = (uint16_t)tmp;

	if (sscanf(argv[9], "%u", &tmp) != 1 || tmp > 65535) {
		fprintf(stderr, "invalid peer session ID: %s\n", argv[9]);
		return (1);
	}
	cmd.peer_ses_id = (uint16_t)tmp;

	/* Optional: options, dscp, queue */
	if (argc > 10) {
		if (sscanf(argv[10], "%u", &tmp) != 1) {
			fprintf(stderr, "invalid options: %s\n", argv[10]);
			return (1);
		}
		cmd.options = (uint16_t)tmp;
	}
	if (argc > 11) {
		if (sscanf(argv[11], "%u", &tmp) != 1 || tmp > 63) {
			fprintf(stderr, "invalid dscp: %s\n", argv[11]);
			return (1);
		}
		cmd.dscp = (uint16_t)tmp;
	}
	if (argc > 12) {
		if (sscanf(argv[12], "%u", &tmp) != 1 || tmp > 255) {
			fprintf(stderr, "invalid queue: %s\n", argv[12]);
			return (1);
		}
		cmd.queue = (uint8_t)tmp;
	}

	if (ctrl_command(fd, CMM_CTRL_CMD_L2TP_ADD, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "l2tp add %s: error %d\n", cmd.ifname, rc);
		return (1);
	}

	printf("l2tp: %s added (tun=%u/%u ses=%u/%u)\n",
	    cmd.ifname,
	    cmd.local_tun_id, cmd.peer_tun_id,
	    cmd.local_ses_id, cmd.peer_ses_id);
	return (0);
}

static int
l2tp_del(int fd, int argc, char **argv)
{
	char name[IFNAMSIZ];
	int16_t rc;

	if (argc < 1) {
		fprintf(stderr, "usage: cmmctl l2tp del <ifname>\n");
		return (1);
	}

	memset(name, 0, sizeof(name));
	strlcpy(name, argv[0], sizeof(name));

	if (ctrl_command(fd, CMM_CTRL_CMD_L2TP_DEL, name, sizeof(name),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "l2tp del %s: error %d\n", name, rc);
		return (1);
	}

	printf("l2tp: %s deleted\n", name);
	return (0);
}

int
cmmctl_l2tp_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		l2tp_usage();
		return (1);
	}

	if (strcmp(argv[0], "add") == 0)
		return (l2tp_add(fd, argc - 1, argv + 1));
	if (strcmp(argv[0], "del") == 0)
		return (l2tp_del(fd, argc - 1, argv + 1));

	fprintf(stderr, "unknown l2tp command: %s\n", argv[0]);
	l2tp_usage();
	return (1);
}
