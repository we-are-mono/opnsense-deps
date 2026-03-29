/*
 * cmmctl_mcast.c — Multicast group offload control
 *
 * cmmctl mc4 add <dst_ip> <src_ip> <input_if> <output_if>
 * cmmctl mc4 remove <dst_ip> <src_ip> <output_if>
 * cmmctl mc4 query
 * cmmctl mc4 reset
 * cmmctl mc6 add <dst_ip6> <src_ip6> <input_if> <output_if>
 * cmmctl mc6 remove <dst_ip6> <src_ip6> <output_if>
 * cmmctl mc6 query
 * cmmctl mc6 reset
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
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cmmctl.h"

/* FPP command codes — must match cmm_mcast.h */
#define FPP_CMD_MC4_MULTICAST	0x0701
#define FPP_CMD_MC4_RESET	0x0702
#define FPP_CMD_MC6_MULTICAST	0x0703
#define FPP_CMD_MC6_RESET	0x0704

/* Actions */
#define MC_ACTION_ADD		0
#define MC_ACTION_REMOVE	1

/* MC4Output/MC6Output — wire format, must match dpa_control_mc.h */
struct mc_output {
	uint32_t	timer;
	char		output_device[IFNAMSIZ];
	uint8_t		shaper_mask;
	uint8_t		uc_bit:1,
			q_bit:1,
			rsvd:6;
	uint8_t		uc_mac[ETHER_ADDR_LEN];
	uint8_t		queue;
	char		new_output_device[IFNAMSIZ];
	uint8_t		ifbit:1,
			rsvd1:7;
	uint8_t		padding[2];
} __packed;

/* MC4Command wire format */
struct mc4_cmd {
	uint16_t	action;
	uint8_t		src_addr_mask;
	uint8_t		mode:1,
			queue:5,
			rsvd:2;
	uint32_t	src_addr;
	uint32_t	dst_addr;
	uint32_t	num_output;
	char		input_device[IFNAMSIZ];
	struct mc_output output_list[5];
} __packed;

/* MC6Command wire format */
struct mc6_cmd {
	uint16_t	action;
	uint8_t		mode:1,
			queue:5,
			rsvd:2;
	uint8_t		src_mask_len;
	uint32_t	src_addr[4];
	uint32_t	dst_addr[4];
	uint32_t	num_output;
	char		input_device[IFNAMSIZ];
	struct mc_output output_list[5];
} __packed;

static void
mc4_usage(void)
{

	fprintf(stderr,
	    "usage: cmmctl mc4 add <dst_ip> <src_ip> <input_if> <output_if>\n"
	    "       cmmctl mc4 remove <dst_ip> <src_ip> <output_if>\n"
	    "       cmmctl mc4 query\n"
	    "       cmmctl mc4 reset\n");
}

static void
mc6_usage(void)
{

	fprintf(stderr,
	    "usage: cmmctl mc6 add <dst_ip6> <src_ip6> <input_if> <output_if>\n"
	    "       cmmctl mc6 remove <dst_ip6> <src_ip6> <output_if>\n"
	    "       cmmctl mc6 query\n"
	    "       cmmctl mc6 reset\n");
}

static void
mc4_print_entry(const struct mc4_cmd *cmd)
{
	char dst[INET_ADDRSTRLEN], src[INET_ADDRSTRLEN];
	int i;

	inet_ntop(AF_INET, &cmd->dst_addr, dst, sizeof(dst));
	inet_ntop(AF_INET, &cmd->src_addr, src, sizeof(src));

	printf("  group %s src %s input %s mode=%s queue=%u\n",
	    dst, src,
	    cmd->input_device[0] ? cmd->input_device : "(none)",
	    cmd->mode ? "bridged" : "routed",
	    cmd->queue);

	for (i = 0; i < (int)cmd->num_output && i < 5; i++) {
		printf("    listener[%d]: %s", i,
		    cmd->output_list[i].output_device);
		if (cmd->output_list[i].uc_bit)
			printf(" uc_mac=%02x:%02x:%02x:%02x:%02x:%02x",
			    cmd->output_list[i].uc_mac[0],
			    cmd->output_list[i].uc_mac[1],
			    cmd->output_list[i].uc_mac[2],
			    cmd->output_list[i].uc_mac[3],
			    cmd->output_list[i].uc_mac[4],
			    cmd->output_list[i].uc_mac[5]);
		printf("\n");
	}
}

static void
mc6_print_entry(const struct mc6_cmd *cmd)
{
	char dst[INET6_ADDRSTRLEN], src[INET6_ADDRSTRLEN];
	int i;

	inet_ntop(AF_INET6, cmd->dst_addr, dst, sizeof(dst));
	inet_ntop(AF_INET6, cmd->src_addr, src, sizeof(src));

	printf("  group %s src %s input %s mode=%s queue=%u\n",
	    dst, src,
	    cmd->input_device[0] ? cmd->input_device : "(none)",
	    cmd->mode ? "bridged" : "routed",
	    cmd->queue);

	for (i = 0; i < (int)cmd->num_output && i < 5; i++) {
		printf("    listener[%d]: %s", i,
		    cmd->output_list[i].output_device);
		if (cmd->output_list[i].uc_bit)
			printf(" uc_mac=%02x:%02x:%02x:%02x:%02x:%02x",
			    cmd->output_list[i].uc_mac[0],
			    cmd->output_list[i].uc_mac[1],
			    cmd->output_list[i].uc_mac[2],
			    cmd->output_list[i].uc_mac[3],
			    cmd->output_list[i].uc_mac[4],
			    cmd->output_list[i].uc_mac[5]);
		printf("\n");
	}
}

int
cmmctl_mc4_main(int argc, char **argv, int fd)
{
	struct mc4_cmd cmd;
	int16_t rc;
	uint16_t resp_len;
	uint8_t resp_buf[512];

	if (argc < 1) {
		mc4_usage();
		return (1);
	}

	if (strcmp(argv[0], "add") == 0) {
		if (argc < 5) {
			mc4_usage();
			return (1);
		}
		memset(&cmd, 0, sizeof(cmd));
		cmd.action = MC_ACTION_ADD;
		if (inet_pton(AF_INET, argv[1], &cmd.dst_addr) != 1) {
			fprintf(stderr, "invalid dst address: %s\n", argv[1]);
			return (1);
		}
		if (inet_pton(AF_INET, argv[2], &cmd.src_addr) != 1) {
			fprintf(stderr, "invalid src address: %s\n", argv[2]);
			return (1);
		}
		strlcpy(cmd.input_device, argv[3], sizeof(cmd.input_device));
		cmd.num_output = 1;
		strlcpy(cmd.output_list[0].output_device, argv[4],
		    sizeof(cmd.output_list[0].output_device));

		if (ctrl_command(fd, FPP_CMD_MC4_MULTICAST,
		    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
			return (1);
		if (rc != 0) {
			fprintf(stderr, "mc4 add failed: rc=%d\n", rc);
			return (1);
		}
		printf("mc4 group added\n");
		return (0);

	} else if (strcmp(argv[0], "remove") == 0) {
		if (argc < 4) {
			mc4_usage();
			return (1);
		}
		memset(&cmd, 0, sizeof(cmd));
		cmd.action = MC_ACTION_REMOVE;
		if (inet_pton(AF_INET, argv[1], &cmd.dst_addr) != 1) {
			fprintf(stderr, "invalid dst address: %s\n", argv[1]);
			return (1);
		}
		if (inet_pton(AF_INET, argv[2], &cmd.src_addr) != 1) {
			fprintf(stderr, "invalid src address: %s\n", argv[2]);
			return (1);
		}
		cmd.num_output = 1;
		strlcpy(cmd.output_list[0].output_device, argv[3],
		    sizeof(cmd.output_list[0].output_device));

		if (ctrl_command(fd, FPP_CMD_MC4_MULTICAST,
		    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
			return (1);
		if (rc != 0) {
			fprintf(stderr, "mc4 remove failed: rc=%d\n", rc);
			return (1);
		}
		printf("mc4 group removed\n");
		return (0);

	} else if (strcmp(argv[0], "query") == 0) {
		memset(&cmd, 0, sizeof(cmd));
		cmd.action = 6;	/* FPP_ACTION_QUERY */
		resp_len = sizeof(resp_buf);
		if (ctrl_command(fd, FPP_CMD_MC4_MULTICAST,
		    &cmd, sizeof(cmd), &rc, resp_buf, &resp_len) < 0)
			return (1);

		if (rc != 0 && rc != 2 /* ERR_UNKNOWN_COMMAND */) {
			printf("MC4 groups:\n");
			mc4_print_entry((struct mc4_cmd *)resp_buf);

			/* Continue querying */
			while (rc == 0) {
				cmd.action = 7;	/* FPP_ACTION_QUERY_CONT */
				resp_len = sizeof(resp_buf);
				if (ctrl_command(fd, FPP_CMD_MC4_MULTICAST,
				    &cmd, sizeof(cmd), &rc, resp_buf,
				    &resp_len) < 0)
					return (1);
				if (rc == 0)
					mc4_print_entry(
					    (struct mc4_cmd *)resp_buf);
			}
		} else if (rc == 0) {
			printf("MC4 groups:\n");
			mc4_print_entry((struct mc4_cmd *)resp_buf);
			cmd.action = 7;
			while (1) {
				resp_len = sizeof(resp_buf);
				if (ctrl_command(fd, FPP_CMD_MC4_MULTICAST,
				    &cmd, sizeof(cmd), &rc, resp_buf,
				    &resp_len) < 0)
					return (1);
				if (rc != 0)
					break;
				mc4_print_entry(
				    (struct mc4_cmd *)resp_buf);
			}
		} else {
			printf("No MC4 groups\n");
		}
		return (0);

	} else if (strcmp(argv[0], "reset") == 0) {
		if (ctrl_command(fd, FPP_CMD_MC4_RESET,
		    NULL, 0, &rc, NULL, NULL) < 0)
			return (1);
		if (rc != 0) {
			fprintf(stderr, "mc4 reset failed: rc=%d\n", rc);
			return (1);
		}
		printf("mc4 groups reset\n");
		return (0);
	}

	mc4_usage();
	return (1);
}

int
cmmctl_mc6_main(int argc, char **argv, int fd)
{
	struct mc6_cmd cmd;
	int16_t rc;
	uint16_t resp_len;
	uint8_t resp_buf[512];

	if (argc < 1) {
		mc6_usage();
		return (1);
	}

	if (strcmp(argv[0], "add") == 0) {
		if (argc < 5) {
			mc6_usage();
			return (1);
		}
		memset(&cmd, 0, sizeof(cmd));
		cmd.action = MC_ACTION_ADD;
		if (inet_pton(AF_INET6, argv[1], cmd.dst_addr) != 1) {
			fprintf(stderr, "invalid dst address: %s\n", argv[1]);
			return (1);
		}
		if (inet_pton(AF_INET6, argv[2], cmd.src_addr) != 1) {
			fprintf(stderr, "invalid src address: %s\n", argv[2]);
			return (1);
		}
		strlcpy(cmd.input_device, argv[3], sizeof(cmd.input_device));
		cmd.num_output = 1;
		strlcpy(cmd.output_list[0].output_device, argv[4],
		    sizeof(cmd.output_list[0].output_device));

		if (ctrl_command(fd, FPP_CMD_MC6_MULTICAST,
		    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
			return (1);
		if (rc != 0) {
			fprintf(stderr, "mc6 add failed: rc=%d\n", rc);
			return (1);
		}
		printf("mc6 group added\n");
		return (0);

	} else if (strcmp(argv[0], "remove") == 0) {
		if (argc < 4) {
			mc6_usage();
			return (1);
		}
		memset(&cmd, 0, sizeof(cmd));
		cmd.action = MC_ACTION_REMOVE;
		if (inet_pton(AF_INET6, argv[1], cmd.dst_addr) != 1) {
			fprintf(stderr, "invalid dst address: %s\n", argv[1]);
			return (1);
		}
		if (inet_pton(AF_INET6, argv[2], cmd.src_addr) != 1) {
			fprintf(stderr, "invalid src address: %s\n", argv[2]);
			return (1);
		}
		cmd.num_output = 1;
		strlcpy(cmd.output_list[0].output_device, argv[3],
		    sizeof(cmd.output_list[0].output_device));

		if (ctrl_command(fd, FPP_CMD_MC6_MULTICAST,
		    &cmd, sizeof(cmd), &rc, NULL, NULL) < 0)
			return (1);
		if (rc != 0) {
			fprintf(stderr, "mc6 remove failed: rc=%d\n", rc);
			return (1);
		}
		printf("mc6 group removed\n");
		return (0);

	} else if (strcmp(argv[0], "query") == 0) {
		memset(&cmd, 0, sizeof(cmd));
		cmd.action = 6;	/* FPP_ACTION_QUERY */
		resp_len = sizeof(resp_buf);
		if (ctrl_command(fd, FPP_CMD_MC6_MULTICAST,
		    &cmd, sizeof(cmd), &rc, resp_buf, &resp_len) < 0)
			return (1);

		if (rc == 0) {
			printf("MC6 groups:\n");
			mc6_print_entry((struct mc6_cmd *)resp_buf);
			cmd.action = 7;
			while (1) {
				resp_len = sizeof(resp_buf);
				if (ctrl_command(fd, FPP_CMD_MC6_MULTICAST,
				    &cmd, sizeof(cmd), &rc, resp_buf,
				    &resp_len) < 0)
					return (1);
				if (rc != 0)
					break;
				mc6_print_entry(
				    (struct mc6_cmd *)resp_buf);
			}
		} else {
			printf("No MC6 groups\n");
		}
		return (0);

	} else if (strcmp(argv[0], "reset") == 0) {
		if (ctrl_command(fd, FPP_CMD_MC6_RESET,
		    NULL, 0, &rc, NULL, NULL) < 0)
			return (1);
		if (rc != 0) {
			fprintf(stderr, "mc6 reset failed: rc=%d\n", rc);
			return (1);
		}
		printf("mc6 groups reset\n");
		return (0);
	}

	mc6_usage();
	return (1);
}
