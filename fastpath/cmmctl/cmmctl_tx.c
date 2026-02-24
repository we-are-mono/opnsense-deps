/*
 * cmmctl_tx.c -- TX DSCP to VLAN PCP mapping CLI sub-commands
 *
 * cmmctl tx enable <ifname>
 * cmmctl tx disable <ifname>
 * cmmctl tx map <ifname> <dscp> <pcp>
 * cmmctl tx query <ifname>
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmmctl.h"
#include "fpp.h"

static void
tx_usage(void)
{

	fprintf(stderr,
	    "usage: cmmctl tx <command>\n\n"
	    "Commands:\n"
	    "  enable <ifname>              Enable DSCP to VLAN PCP mapping\n"
	    "  disable <ifname>             Disable DSCP to VLAN PCP mapping\n"
	    "  map <ifname> <dscp> <pcp>    Map DSCP group (0-7) to VLAN PCP (0-7)\n"
	    "  query <ifname>               Show mapping status and configuration\n\n"
	    "DSCP groups: 0=DSCP 0-7, 1=DSCP 8-15, ..., 7=DSCP 56-63\n");
}

static int
tx_enable_disable(int fd, const char *ifname, int enable)
{
	fpp_dscp_vlanpcp_map_t cmd;
	int16_t rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.status = enable ? 1 : 0;
	strlcpy((char *)cmd.ifname, ifname, sizeof(cmd.ifname));

	if (ctrl_command(fd, FPP_CMD_DSCP_VLANPCP_MAP_STATUS, &cmd,
	    sizeof(cmd), &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "tx %s %s: error %d\n",
		    enable ? "enable" : "disable", ifname, rc);
		return (1);
	}

	printf("tx: DSCP to VLAN PCP mapping %s on %s\n",
	    enable ? "enabled" : "disabled", ifname);
	return (0);
}

static int
tx_map(int fd, int argc, char **argv)
{
	fpp_dscp_vlanpcp_map_t cmd;
	int16_t rc;
	unsigned int dscp, pcp;

	if (argc < 3) {
		fprintf(stderr,
		    "usage: cmmctl tx map <ifname> <dscp> <pcp>\n"
		    "  dscp: DSCP group 0-7 (top 3 bits)\n"
		    "  pcp:  VLAN PCP value 0-7\n");
		return (1);
	}

	if (sscanf(argv[1], "%u", &dscp) != 1 || dscp > 7) {
		fprintf(stderr, "invalid DSCP group: %s (must be 0-7)\n",
		    argv[1]);
		return (1);
	}

	if (sscanf(argv[2], "%u", &pcp) != 1 || pcp > 7) {
		fprintf(stderr, "invalid VLAN PCP: %s (must be 0-7)\n",
		    argv[2]);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.ifname, argv[0], sizeof(cmd.ifname));
	cmd.dscp = (uint8_t)dscp;
	cmd.vlan_pcp = (uint8_t)pcp;

	if (ctrl_command(fd, FPP_CMD_DSCP_VLANPCP_MAP_CFG, &cmd,
	    sizeof(cmd), &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "tx map %s dscp %u pcp %u: error %d\n",
		    argv[0], dscp, pcp, rc);
		return (1);
	}

	printf("tx: %s DSCP %u-%u -> VLAN PCP %u\n",
	    argv[0], dscp * 8, dscp * 8 + 7, pcp);
	return (0);
}

static int
tx_query(int fd, int argc, char **argv)
{
	fpp_query_dscp_vlanpcp_map_cmd_t cmd, resp;
	uint16_t resp_len;
	int16_t rc;
	int i;

	if (argc < 1) {
		fprintf(stderr, "usage: cmmctl tx query <ifname>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	strlcpy((char *)cmd.ifname, argv[0], sizeof(cmd.ifname));

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_QUERY_IFACE_DSCP_VLANPCP_MAP, &cmd,
	    sizeof(cmd), &rc, &resp, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "tx query %s: error %d\n", argv[0], rc);
		return (1);
	}

	printf("%s: DSCP to VLAN PCP mapping %s\n", argv[0],
	    resp.enable ? "enabled" : "disabled");

	if (resp.enable) {
		printf("  DSCP group  DSCP range  VLAN PCP\n");
		for (i = 0; i <= MAX_VLAN_PCP; i++)
			printf("  %d           %2d-%-2d       %u\n",
			    i, i * 8, i * 8 + 7, resp.vlan_pcp[i]);
	}

	return (0);
}

int
cmmctl_tx_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		tx_usage();
		return (1);
	}

	if (strcmp(argv[0], "enable") == 0) {
		if (argc < 2) {
			fprintf(stderr,
			    "usage: cmmctl tx enable <ifname>\n");
			return (1);
		}
		return (tx_enable_disable(fd, argv[1], 1));
	}

	if (strcmp(argv[0], "disable") == 0) {
		if (argc < 2) {
			fprintf(stderr,
			    "usage: cmmctl tx disable <ifname>\n");
			return (1);
		}
		return (tx_enable_disable(fd, argv[1], 0));
	}

	if (strcmp(argv[0], "map") == 0)
		return (tx_map(fd, argc - 1, argv + 1));

	if (strcmp(argv[0], "query") == 0)
		return (tx_query(fd, argc - 1, argv + 1));

	fprintf(stderr, "unknown tx command: %s\n", argv[0]);
	tx_usage();
	return (1);
}
