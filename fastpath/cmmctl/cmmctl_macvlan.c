/*
 * cmmctl_macvlan.c — MACVLAN CLI sub-commands
 *
 * cmmctl macvlan reset                              Clear all entries
 * cmmctl macvlan add <macvlan_if> <phy_if> <mac>    Register entry
 * cmmctl macvlan del <macvlan_if> <phy_if> <mac>    Deregister entry
 * cmmctl macvlan query                              List all entries
 *
 * CDX status: No control_macvlan.c handler exists in CDX — all commands
 * currently return ERR_UNKNOWN_COMMAND.  The CLI is ready for when
 * a CDX MACVLAN handler is implemented.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>

#include "cmmctl.h"
#include "fpp.h"

static const char *
macvlan_strerror(int16_t rc)
{

	switch ((uint16_t)rc) {
	case FPP_ERR_UNKNOWN_COMMAND:
		return ("command not supported by CDX (no MACVLAN handler)");
	case FPP_ERR_MACVLAN_ENTRY_ALREADY_REGISTERED:
		return ("entry already registered");
	case FPP_ERR_MACVLAN_ENTRY_NOT_FOUND:
		return ("entry not found");
	case FPP_ERR_MACVLAN_ENTRY_INVALID:
		return ("invalid entry");
	default:
		return (NULL);
	}
}

static void
macvlan_errmsg(const char *cmd, int16_t rc)
{
	const char *msg;

	msg = macvlan_strerror(rc);
	if (msg != NULL)
		fprintf(stderr, "%s: %s (0x%04x)\n", cmd, msg,
		    (unsigned)(uint16_t)rc);
	else
		fprintf(stderr, "%s: error 0x%04x\n", cmd,
		    (unsigned)(uint16_t)rc);
}

static int
parse_mac(const char *s, unsigned char *out)
{
	unsigned int m[6];
	int i;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x",
	    &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
		return (-1);
	for (i = 0; i < 6; i++) {
		if (m[i] > 0xff)
			return (-1);
		out[i] = (unsigned char)m[i];
	}
	return (0);
}

static void
macvlan_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl macvlan <command>\n\n"
	    "Commands:\n"
	    "  reset                              Clear all MACVLAN entries\n"
	    "  add <macvlan_if> <phy_if> <mac>    Register entry\n"
	    "  del <macvlan_if> <phy_if> <mac>    Deregister entry\n"
	    "  query                              List all entries\n"
	    "\n"
	    "<mac> format: xx:xx:xx:xx:xx:xx\n");
}

/* ---- reset ------------------------------------------------------------- */

static int
cmd_reset(int fd)
{
	int16_t rc;

	if (ctrl_command(fd, FPP_CMD_MACVLAN_RESET, NULL, 0,
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		macvlan_errmsg("macvlan reset", rc);
		return (1);
	}

	printf("MACVLAN entries cleared\n");
	return (0);
}

/* ---- add / del --------------------------------------------------------- */

static int
cmd_add_del(int argc, char **argv, int fd, uint16_t action)
{
	fpp_macvlan_cmd_t cmd;
	const char *actstr;
	int16_t rc;

	actstr = (action == FPP_ACTION_REGISTER) ? "add" : "del";

	if (argc < 3) {
		fprintf(stderr,
		    "usage: cmmctl macvlan %s"
		    " <macvlan_if> <phy_if> <mac>\n", actstr);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = action;

	if (strlen(argv[0]) >= IFNAMSIZ) {
		fprintf(stderr, "macvlan %s: interface name too long: %s\n",
		    actstr, argv[0]);
		return (1);
	}
	strlcpy(cmd.macvlan_ifname, argv[0], sizeof(cmd.macvlan_ifname));

	if (strlen(argv[1]) >= IFNAMSIZ) {
		fprintf(stderr,
		    "macvlan %s: physical interface name too long: %s\n",
		    actstr, argv[1]);
		return (1);
	}
	strlcpy(cmd.macvlan_phy_ifname, argv[1],
	    sizeof(cmd.macvlan_phy_ifname));

	if (parse_mac(argv[2], cmd.macaddr) < 0) {
		fprintf(stderr, "macvlan %s: invalid MAC address '%s'\n",
		    actstr, argv[2]);
		return (1);
	}

	if (ctrl_command(fd, FPP_CMD_MACVLAN_ENTRY, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		macvlan_errmsg(actstr, rc);
		return (1);
	}

	printf("MACVLAN entry %sed\n",
	    (action == FPP_ACTION_REGISTER) ? "add" : "remov");
	return (0);
}

/* ---- query ------------------------------------------------------------- */

static int
cmd_query(int fd)
{
	fpp_macvlan_cmd_t cmd, resp;
	uint16_t resp_len;
	int16_t rc;
	int count;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_QUERY;

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_MACVLAN_ENTRY, &cmd, sizeof(cmd),
	    &rc, &resp, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		if ((uint16_t)rc == FPP_ERR_MACVLAN_ENTRY_NOT_FOUND) {
			printf("No MACVLAN entries\n");
			return (0);
		}
		macvlan_errmsg("macvlan query", rc);
		return (1);
	}

	if (resp_len < sizeof(resp)) {
		fprintf(stderr, "macvlan query: short response (%u bytes)\n",
		    resp_len);
		return (1);
	}

	printf("MACVLAN interfaces:\n");
	count = 0;
	do {
		printf("  Interface: %.*s  Physical: %.*s"
		    "  HWaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
		    IFNAMSIZ, resp.macvlan_ifname,
		    IFNAMSIZ, resp.macvlan_phy_ifname,
		    resp.macaddr[0], resp.macaddr[1],
		    resp.macaddr[2], resp.macaddr[3],
		    resp.macaddr[4], resp.macaddr[5]);
		count++;

		memset(&cmd, 0, sizeof(cmd));
		cmd.action = FPP_ACTION_QUERY_CONT;

		resp_len = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_MACVLAN_ENTRY, &cmd, sizeof(cmd),
		    &rc, &resp, &resp_len) < 0)
			break;
	} while (rc == 0 && resp_len >= sizeof(resp));

	printf("Total MACVLAN entries: %d\n", count);
	return (0);
}

/* ---- main dispatcher --------------------------------------------------- */

int
cmmctl_macvlan_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		macvlan_usage();
		return (1);
	}

	if (strcmp(argv[0], "reset") == 0)
		return (cmd_reset(fd));

	if (strcmp(argv[0], "add") == 0)
		return (cmd_add_del(argc - 1, argv + 1, fd,
		    FPP_ACTION_REGISTER));

	if (strcmp(argv[0], "del") == 0)
		return (cmd_add_del(argc - 1, argv + 1, fd,
		    FPP_ACTION_DEREGISTER));

	if (strcmp(argv[0], "query") == 0)
		return (cmd_query(fd));

	fprintf(stderr, "unknown macvlan command: %s\n", argv[0]);
	macvlan_usage();
	return (1);
}
