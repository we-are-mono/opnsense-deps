/*
 * cmmctl_bridge.c — L2 bridge commands for cmmctl
 *
 * FCI passthrough to CDX's L2 bridge module.
 *
 * Syntax:
 *   cmmctl bridge enable <interface>
 *   cmmctl bridge disable <interface>
 *   cmmctl bridge mode auto|manual
 *   cmmctl bridge timeout <seconds>
 *   cmmctl bridge add srcmac=<MAC> dstmac=<MAC> input=<if> output=<if>
 *                     [ethertype=<N>] [prio=<N>]
 *   cmmctl bridge remove srcmac=<MAC> dstmac=<MAC> input=<if>
 *   cmmctl bridge show flows|status
 *   cmmctl bridge reset
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmmctl.h"
#include "fpp.h"

static int
parse_macaddr(const char *str, uint8_t *mac)
{
	unsigned int m[6];
	int n;

	n = sscanf(str, "%x:%x:%x:%x:%x:%x",
	    &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
	if (n != 6)
		return (-1);
	for (n = 0; n < 6; n++)
		mac[n] = (uint8_t)m[n];
	return (0);
}

/* ------------------------------------------------------------------ */
/* enable / disable                                                    */
/* ------------------------------------------------------------------ */

static int
cmd_enable(int argc, char **argv, int fd, int enable)
{
	fpp_l2_bridge_enable_cmd_t cmd;
	int16_t rc;

	if (argc < 1) {
		fprintf(stderr, "usage: cmmctl bridge %s <interface>\n",
		    enable ? "enable" : "disable");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.enable_flag = enable ? 1 : 0;
	strlcpy(cmd.input_name, argv[0], sizeof(cmd.input_name));

	if (ctrl_command(fd, FPP_CMD_RX_L2BRIDGE_ENABLE,
	    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "bridge %s %s: error %d\n",
		    enable ? "enable" : "disable", argv[0], rc);
		return (1);
	}

	printf("bridge %s on %s\n",
	    enable ? "enabled" : "disabled", argv[0]);
	return (0);
}

/* ------------------------------------------------------------------ */
/* mode                                                                */
/* ------------------------------------------------------------------ */

static int
cmd_mode(int argc, char **argv, int fd)
{
	fpp_l2_bridge_control_cmd_t cmd;
	int16_t rc;

	if (argc < 1) {
		fprintf(stderr, "usage: cmmctl bridge mode auto|manual\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	if (strcmp(argv[0], "auto") == 0)
		cmd.mode_timeout = FPP_L2_BRIDGE_MODE_AUTO;
	else if (strcmp(argv[0], "manual") == 0)
		cmd.mode_timeout = FPP_L2_BRIDGE_MODE_MANUAL;
	else {
		fprintf(stderr, "bridge mode: expected 'auto' or 'manual'\n");
		return (1);
	}

	if (ctrl_command(fd, FPP_CMD_RX_L2BRIDGE_MODE,
	    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "bridge mode: error %d\n", rc);
		return (1);
	}

	printf("bridge mode set to %s\n", argv[0]);
	return (0);
}

/* ------------------------------------------------------------------ */
/* timeout                                                             */
/* ------------------------------------------------------------------ */

static int
cmd_timeout(int argc, char **argv, int fd)
{
	fpp_l2_bridge_control_cmd_t cmd;
	char *endp;
	unsigned long val;
	int16_t rc;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl bridge timeout <seconds>\n");
		return (1);
	}

	val = strtoul(argv[0], &endp, 10);
	if (argv[0] == endp || *endp != '\0' || val == 0 || val > 65535) {
		fprintf(stderr, "bridge timeout: invalid value '%s' "
		    "(1-65535)\n", argv[0]);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.mode_timeout = (uint16_t)val;

	if (ctrl_command(fd, FPP_CMD_RX_L2BRIDGE_FLOW_TIMEOUT,
	    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "bridge timeout: error %d\n", rc);
		return (1);
	}

	printf("bridge flow timeout set to %lus\n", val);
	return (0);
}

/* ------------------------------------------------------------------ */
/* add / remove static entries                                         */
/* ------------------------------------------------------------------ */

/*
 * Parse key=value pairs from argv.
 * Returns 0 on success, -1 on bad syntax.
 */
static int
cmd_add(int argc, char **argv, int fd)
{
	fpp_l2_bridge_add_entry_cmd_t cmd;
	int16_t rc;
	int i;
	int have_src = 0, have_dst = 0, have_in = 0, have_out = 0;

	if (argc < 4) {
		fprintf(stderr,
		    "usage: cmmctl bridge add srcmac=<MAC> dstmac=<MAC> "
		    "input=<if> output=<if> [ethertype=<N>] [prio=<N>]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	for (i = 0; i < argc; i++) {
		char *eq = strchr(argv[i], '=');
		if (eq == NULL) {
			fprintf(stderr, "bridge add: expected key=value, "
			    "got '%s'\n", argv[i]);
			return (1);
		}
		*eq = '\0';
		char *key = argv[i];
		char *val = eq + 1;

		if (strcmp(key, "srcmac") == 0) {
			if (parse_macaddr(val, cmd.srcaddr) < 0) {
				fprintf(stderr, "bridge add: bad srcmac '%s'\n",
				    val);
				return (1);
			}
			have_src = 1;
		} else if (strcmp(key, "dstmac") == 0) {
			if (parse_macaddr(val, cmd.destaddr) < 0) {
				fprintf(stderr, "bridge add: bad dstmac '%s'\n",
				    val);
				return (1);
			}
			have_dst = 1;
		} else if (strcmp(key, "input") == 0) {
			strlcpy(cmd.input_name, val, sizeof(cmd.input_name));
			have_in = 1;
		} else if (strcmp(key, "output") == 0) {
			strlcpy(cmd.output_name, val, sizeof(cmd.output_name));
			have_out = 1;
		} else if (strcmp(key, "ethertype") == 0) {
			cmd.ethertype = htons((uint16_t)strtoul(val, NULL, 0));
		} else if (strcmp(key, "prio") == 0) {
			cmd.pkt_priority = (uint16_t)strtoul(val, NULL, 0);
		} else {
			fprintf(stderr, "bridge add: unknown key '%s'\n", key);
			return (1);
		}
	}

	if (!have_src || !have_dst || !have_in || !have_out) {
		fprintf(stderr, "bridge add: srcmac, dstmac, input, and "
		    "output are required\n");
		return (1);
	}

	if (ctrl_command(fd, FPP_CMD_RX_L2BRIDGE_ADD,
	    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "bridge add: error %d\n", rc);
		return (1);
	}

	printf("bridge entry added\n");
	return (0);
}

static int
cmd_remove(int argc, char **argv, int fd)
{
	fpp_l2_bridge_remove_entry_cmd_t cmd;
	int16_t rc;
	int i;
	int have_src = 0, have_dst = 0, have_in = 0;

	if (argc < 3) {
		fprintf(stderr,
		    "usage: cmmctl bridge remove srcmac=<MAC> dstmac=<MAC> "
		    "input=<if>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	for (i = 0; i < argc; i++) {
		char *eq = strchr(argv[i], '=');
		if (eq == NULL) {
			fprintf(stderr, "bridge remove: expected key=value, "
			    "got '%s'\n", argv[i]);
			return (1);
		}
		*eq = '\0';
		char *key = argv[i];
		char *val = eq + 1;

		if (strcmp(key, "srcmac") == 0) {
			if (parse_macaddr(val, cmd.srcaddr) < 0) {
				fprintf(stderr,
				    "bridge remove: bad srcmac '%s'\n", val);
				return (1);
			}
			have_src = 1;
		} else if (strcmp(key, "dstmac") == 0) {
			if (parse_macaddr(val, cmd.destaddr) < 0) {
				fprintf(stderr,
				    "bridge remove: bad dstmac '%s'\n", val);
				return (1);
			}
			have_dst = 1;
		} else if (strcmp(key, "input") == 0) {
			strlcpy(cmd.input_name, val, sizeof(cmd.input_name));
			have_in = 1;
		} else {
			fprintf(stderr, "bridge remove: unknown key '%s'\n",
			    key);
			return (1);
		}
	}

	if (!have_src || !have_dst || !have_in) {
		fprintf(stderr, "bridge remove: srcmac, dstmac, and input "
		    "are required\n");
		return (1);
	}

	if (ctrl_command(fd, FPP_CMD_RX_L2BRIDGE_REMOVE,
	    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "bridge remove: error %d\n", rc);
		return (1);
	}

	printf("bridge entry removed\n");
	return (0);
}

/* ------------------------------------------------------------------ */
/* show status / show flows                                            */
/* ------------------------------------------------------------------ */

static int
cmd_show_status(int fd)
{
	fpp_l2_bridge_query_status_response_t resp;
	uint16_t rlen;
	int16_t rc;
	int first = 1;

	while (1) {
		rlen = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_RX_L2BRIDGE_QUERY_STATUS,
		    NULL, 0, &rc, &resp, &rlen) < 0)
			return (1);

		if (rc != 0 || rlen < sizeof(resp))
			break;

		if (resp.eof)
			break;

		if (first) {
			printf("%-16s %s\n", "Interface", "Status");
			printf("%-16s %s\n", "---------", "------");
			first = 0;
		}

		printf("%-16s %s\n",
		    resp.ifname,
		    resp.status ? "ON" : "OFF");
	}

	if (first)
		printf("No bridge interfaces configured\n");

	return (0);
}

static int
cmd_show_flows(int fd)
{
	fpp_l2_bridge_query_entry_response_t resp;
	uint16_t rlen;
	int16_t rc;
	int count = 0;

	printf("%-17s  %-17s  %-6s  %-16s  %-16s  %s\n",
	    "Src MAC", "Dst MAC", "Etype", "Input", "Output", "Prio");
	printf("%-17s  %-17s  %-6s  %-16s  %-16s  %s\n",
	    "---------", "---------", "-----", "-----", "------", "----");

	while (1) {
		rlen = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_RX_L2BRIDGE_QUERY_ENTRY,
		    NULL, 0, &rc, &resp, &rlen) < 0)
			return (1);

		if (rc != 0 || rlen < sizeof(resp))
			break;

		if (resp.eof)
			break;

		printf("%02x:%02x:%02x:%02x:%02x:%02x  "
		    "%02x:%02x:%02x:%02x:%02x:%02x  "
		    "0x%04x  %-16s  %-16s  %u\n",
		    resp.srcaddr[0], resp.srcaddr[1],
		    resp.srcaddr[2], resp.srcaddr[3],
		    resp.srcaddr[4], resp.srcaddr[5],
		    resp.destaddr[0], resp.destaddr[1],
		    resp.destaddr[2], resp.destaddr[3],
		    resp.destaddr[4], resp.destaddr[5],
		    ntohs(resp.ethertype),
		    resp.input_name[0] ? resp.input_name : "-",
		    resp.output_name[0] ? resp.output_name : "-",
		    resp.pkt_priority);

		count++;
	}

	printf("\n%d flow(s)\n", count);
	return (0);
}

static int
cmd_show(int argc, char **argv, int fd)
{
	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl bridge show flows|status\n");
		return (1);
	}

	if (strcmp(argv[0], "status") == 0)
		return (cmd_show_status(fd));
	else if (strcmp(argv[0], "flows") == 0)
		return (cmd_show_flows(fd));
	else {
		fprintf(stderr,
		    "bridge show: expected 'flows' or 'status'\n");
		return (1);
	}
}

/* ------------------------------------------------------------------ */
/* reset                                                               */
/* ------------------------------------------------------------------ */

static int
cmd_reset(int fd)
{
	int16_t rc;

	if (ctrl_command(fd, FPP_CMD_RX_L2BRIDGE_FLOW_RESET,
	    NULL, 0, &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "bridge reset: error %d\n", rc);
		return (1);
	}

	printf("bridge flows reset\n");
	return (0);
}

/* ------------------------------------------------------------------ */
/* Main dispatch                                                       */
/* ------------------------------------------------------------------ */

static void
bridge_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl bridge <subcommand> [args...]\n\n"
	    "Subcommands:\n"
	    "  enable <interface>      Enable L2 bridging on interface\n"
	    "  disable <interface>     Disable L2 bridging on interface\n"
	    "  mode auto|manual        Set bridge mode\n"
	    "  timeout <seconds>       Set flow timeout (1-65535)\n"
	    "  add srcmac=... dstmac=... input=... output=...\n"
	    "                          Add static bridge entry\n"
	    "  remove srcmac=... dstmac=... input=...\n"
	    "                          Remove bridge entry\n"
	    "  show flows|status       Show bridge flows or status\n"
	    "  reset                   Reset all bridge flows\n");
}

int
cmmctl_bridge_main(int argc, char **argv, int fd)
{
	if (argc < 1) {
		bridge_usage();
		return (1);
	}

	if (strcmp(argv[0], "enable") == 0)
		return (cmd_enable(argc - 1, argv + 1, fd, 1));
	else if (strcmp(argv[0], "disable") == 0)
		return (cmd_enable(argc - 1, argv + 1, fd, 0));
	else if (strcmp(argv[0], "mode") == 0)
		return (cmd_mode(argc - 1, argv + 1, fd));
	else if (strcmp(argv[0], "timeout") == 0)
		return (cmd_timeout(argc - 1, argv + 1, fd));
	else if (strcmp(argv[0], "add") == 0)
		return (cmd_add(argc - 1, argv + 1, fd));
	else if (strcmp(argv[0], "remove") == 0)
		return (cmd_remove(argc - 1, argv + 1, fd));
	else if (strcmp(argv[0], "show") == 0)
		return (cmd_show(argc - 1, argv + 1, fd));
	else if (strcmp(argv[0], "reset") == 0)
		return (cmd_reset(fd));
	else {
		fprintf(stderr, "bridge: unknown subcommand '%s'\n",
		    argv[0]);
		bridge_usage();
		return (1);
	}
}
