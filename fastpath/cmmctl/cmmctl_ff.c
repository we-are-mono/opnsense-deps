/*
 * cmmctl_ff.c — Fast-forward control CLI sub-commands
 *
 * cmmctl ff enable              Enable fast-forward offload
 * cmmctl ff disable             Disable fast-forward offload
 * cmmctl ff ipsec-frag enable   Enable IPsec pre-fragmentation
 * cmmctl ff ipsec-frag disable  Disable IPsec pre-fragmentation
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <stdio.h>
#include <string.h>

#include "cmmctl.h"
#include "fpp.h"

static void
ff_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl ff <command>\n\n"
	    "Commands:\n"
	    "  enable                Enable fast-forward offload\n"
	    "  disable               Disable fast-forward offload\n"
	    "  ipsec-frag enable     Enable IPsec pre-fragmentation\n"
	    "  ipsec-frag disable    Disable IPsec pre-fragmentation\n");
}

static int
ff_control(int fd, int enable)
{
	fpp_ff_ctrl_cmd_t cmd;
	int16_t rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.enable = enable ? 1 : 0;

	if (ctrl_command(fd, FPP_CMD_IPV4_FF_CONTROL, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "ff %s: error %d\n",
		    enable ? "enable" : "disable", rc);
		return (1);
	}

	printf("fast-forward %s\n", enable ? "enabled" : "disabled");
	return (0);
}

static int
ff_ipsec_frag(int fd, int enable)
{
	fpp_ipsec_cmd_t cmd;
	int16_t rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.pre_frag_en = enable ? 1 : 0;

	if (ctrl_command(fd, FPP_CMD_IPSEC_FRAG_CFG, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "ipsec-frag %s: error %d\n",
		    enable ? "enable" : "disable", rc);
		return (1);
	}

	printf("IPsec pre-fragmentation %s\n",
	    enable ? "enabled" : "disabled");
	return (0);
}

int
cmmctl_ff_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		ff_usage();
		return (1);
	}

	if (strcmp(argv[0], "enable") == 0)
		return (ff_control(fd, 1));

	if (strcmp(argv[0], "disable") == 0)
		return (ff_control(fd, 0));

	if (strcmp(argv[0], "ipsec-frag") == 0) {
		if (argc < 2) {
			fprintf(stderr,
			    "usage: cmmctl ff ipsec-frag enable|disable\n");
			return (1);
		}
		if (strcmp(argv[1], "enable") == 0)
			return (ff_ipsec_frag(fd, 1));
		if (strcmp(argv[1], "disable") == 0)
			return (ff_ipsec_frag(fd, 0));
		fprintf(stderr, "unknown ipsec-frag action: %s\n", argv[1]);
		return (1);
	}

	fprintf(stderr, "unknown ff command: %s\n", argv[0]);
	ff_usage();
	return (1);
}
