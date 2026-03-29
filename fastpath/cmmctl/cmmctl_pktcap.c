/*
 * cmmctl_pktcap.c — Packet capture CLI sub-commands
 *
 * cmmctl pktcap status <port> enable|disable
 * cmmctl pktcap slice <port> <40-1518>
 * cmmctl pktcap filter <port> "<bpf_expression>"
 * cmmctl pktcap filter <port> reset
 * cmmctl pktcap query
 *
 * <port> is a CDX port index (0-7).
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/bpf.h>

#include "cmmctl.h"
#include "fpp.h"

#define MIN_SLICE_VALUE		40
#define MAX_SLICE_VALUE		1518
#define SNAP_LENGTH		96
#define PKTCAP_MAX_PORTS	8

#define PKTCAP_IFSTATUS_ENABLE	0x1
#define PKTCAP_IFSTATUS_DISABLE	0x0

/*
 * Validate a compiled BPF filter for FLF compatibility.
 *
 * The FPP BPF interpreter supports a subset of BPF instructions.
 * This function checks that the filter only uses supported opcodes,
 * has valid jump targets, and ends with a BPF_RET instruction.
 *
 * Ported from Linux module_pktcap.c Check_BPFfilter().
 *
 * Returns 0 if valid, -1 if invalid.
 */
static int
check_bpf_filter(struct bpf_insn *filter, int flen)
{
	struct bpf_insn *ftest;
	int pc;

	if (flen == 0 || flen > 3 * MAX_FLF_INSTRUCTIONS)
		return (-1);

	for (pc = 0; pc < flen; pc++) {
		ftest = &filter[pc];

		switch (ftest->code) {
		/* ALU operations */
		case BPF_ALU|BPF_ADD|BPF_K:
		case BPF_ALU|BPF_ADD|BPF_X:
		case BPF_ALU|BPF_SUB|BPF_K:
		case BPF_ALU|BPF_SUB|BPF_X:
		case BPF_ALU|BPF_MUL|BPF_K:
		case BPF_ALU|BPF_MUL|BPF_X:
		case BPF_ALU|BPF_DIV|BPF_X:
		case BPF_ALU|BPF_AND|BPF_K:
		case BPF_ALU|BPF_AND|BPF_X:
		case BPF_ALU|BPF_OR|BPF_K:
		case BPF_ALU|BPF_OR|BPF_X:
		case BPF_ALU|BPF_LSH|BPF_K:
		case BPF_ALU|BPF_LSH|BPF_X:
		case BPF_ALU|BPF_RSH|BPF_K:
		case BPF_ALU|BPF_RSH|BPF_X:
		case BPF_ALU|BPF_NEG:
		/* Load/store operations */
		case BPF_LD|BPF_W|BPF_ABS:
		case BPF_LD|BPF_H|BPF_ABS:
		case BPF_LD|BPF_B|BPF_ABS:
		case BPF_LD|BPF_W|BPF_LEN:
		case BPF_LD|BPF_W|BPF_IND:
		case BPF_LD|BPF_H|BPF_IND:
		case BPF_LD|BPF_B|BPF_IND:
		case BPF_LD|BPF_IMM:
		case BPF_LDX|BPF_W|BPF_LEN:
		case BPF_LDX|BPF_B|BPF_MSH:
		case BPF_LDX|BPF_IMM:
		case BPF_MISC|BPF_TAX:
		case BPF_MISC|BPF_TXA:
		/* Return */
		case BPF_RET|BPF_K:
		case BPF_RET|BPF_A:
			break;

		/* Division by constant — check for zero */
		case BPF_ALU|BPF_DIV|BPF_K:
			if (ftest->k == 0)
				return (-1);
			break;

		/* Memory access — check bounds */
		case BPF_LD|BPF_MEM:
		case BPF_LDX|BPF_MEM:
		case BPF_ST:
		case BPF_STX:
			if (ftest->k >= BPF_MEMWORDS)
				return (-1);
			break;

		/* Unconditional jump — check target */
		case BPF_JMP|BPF_JA:
			if (ftest->k >= (unsigned int)(flen - pc - 1))
				return (-1);
			break;

		/* Conditional jumps — check both targets */
		case BPF_JMP|BPF_JEQ|BPF_K:
		case BPF_JMP|BPF_JEQ|BPF_X:
		case BPF_JMP|BPF_JGE|BPF_K:
		case BPF_JMP|BPF_JGE|BPF_X:
		case BPF_JMP|BPF_JGT|BPF_K:
		case BPF_JMP|BPF_JGT|BPF_X:
		case BPF_JMP|BPF_JSET|BPF_K:
		case BPF_JMP|BPF_JSET|BPF_X:
			if ((unsigned int)pc + ftest->jt + 1 >=
			    (unsigned int)flen ||
			    (unsigned int)pc + ftest->jf + 1 >=
			    (unsigned int)flen)
				return (-1);
			break;

		default:
			return (-1);
		}
	}

	/* Must end with a RET instruction */
	return (BPF_CLASS(filter[flen - 1].code) == BPF_RET) ? 0 : -1;
}

/* ---- Sub-command handlers ---- */

static int
cmd_status(int argc, char **argv, int fd)
{
	fpp_pktcap_status_cmd_t cmd;
	int16_t rc;
	int port_id;
	int enable;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl pktcap status <port> enable|disable\n");
		return (1);
	}

	if (!isdigit((unsigned char)argv[0][0])) {
		fprintf(stderr, "pktcap status: port must be numeric (0-7)\n");
		return (1);
	}
	port_id = atoi(argv[0]);
	if (port_id < 0 || port_id >= PKTCAP_MAX_PORTS) {
		fprintf(stderr, "pktcap status: port %d out of range (0-7)\n",
		    port_id);
		return (1);
	}

	if (strcmp(argv[1], "enable") == 0)
		enable = 1;
	else if (strcmp(argv[1], "disable") == 0)
		enable = 0;
	else {
		fprintf(stderr,
		    "usage: cmmctl pktcap status <port> enable|disable\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_PKTCAP_STATUS;
	cmd.ifindex = (uint8_t)port_id;
	cmd.status = enable ? PKTCAP_IFSTATUS_ENABLE : PKTCAP_IFSTATUS_DISABLE;

	if (ctrl_command(fd, FPP_CMD_PKTCAP_IFSTATUS, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "pktcap status: CDX error %d\n", rc);
		return (1);
	}

	printf("port %d capture %s\n", port_id,
	    enable ? "enabled" : "disabled");
	return (0);
}

static int
cmd_slice(int argc, char **argv, int fd)
{
	fpp_pktcap_slice_cmd_t cmd;
	int16_t rc;
	int port_id;
	int slice;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl pktcap slice <port> <40-1518>\n");
		return (1);
	}

	if (!isdigit((unsigned char)argv[0][0])) {
		fprintf(stderr, "pktcap slice: port must be numeric (0-7)\n");
		return (1);
	}
	port_id = atoi(argv[0]);
	if (port_id < 0 || port_id >= PKTCAP_MAX_PORTS) {
		fprintf(stderr, "pktcap slice: port %d out of range (0-7)\n",
		    port_id);
		return (1);
	}

	if (!isdigit((unsigned char)argv[1][0])) {
		fprintf(stderr,
		    "pktcap slice: value must be numeric (%d-%d)\n",
		    MIN_SLICE_VALUE, MAX_SLICE_VALUE);
		return (1);
	}
	slice = atoi(argv[1]);
	if (slice < MIN_SLICE_VALUE || slice > MAX_SLICE_VALUE) {
		fprintf(stderr,
		    "pktcap slice: value %d out of range (%d-%d)\n",
		    slice, MIN_SLICE_VALUE, MAX_SLICE_VALUE);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_PKTCAP_SLICE;
	cmd.ifindex = (uint8_t)port_id;
	cmd.slice = (uint16_t)slice;

	if (ctrl_command(fd, FPP_CMD_PKTCAP_SLICE, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "pktcap slice: CDX error %d\n", rc);
		return (1);
	}

	printf("port %d slice set to %d\n", port_id, slice);
	return (0);
}

static int
cmd_filter(int argc, char **argv, int fd)
{
	fpp_pktcap_flf_cmd_t cmd;
	int16_t rc;
	int port_id;
	struct bpf_program bpf = { 0, NULL };
	pcap_t *pd = NULL;
	int fgmts, seqno, length;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl pktcap filter <port> <expression>\n"
		    "       cmmctl pktcap filter <port> reset\n");
		return (1);
	}

	if (!isdigit((unsigned char)argv[0][0])) {
		fprintf(stderr, "pktcap filter: port must be numeric (0-7)\n");
		return (1);
	}
	port_id = atoi(argv[0]);
	if (port_id < 0 || port_id >= PKTCAP_MAX_PORTS) {
		fprintf(stderr,
		    "pktcap filter: port %d out of range (0-7)\n", port_id);
		return (1);
	}

	/* Handle "reset" */
	if (strcmp(argv[1], "reset") == 0) {
		memset(&cmd, 0, sizeof(cmd));
		cmd.flen = 0;
		cmd.ifindex = (uint8_t)port_id;

		if (ctrl_command(fd, FPP_CMD_PKTCAP_FLF, &cmd, sizeof(cmd),
		    &rc, NULL, NULL) < 0)
			return (1);

		if (rc != 0 && rc != 1402) {
			/* 1402 = ERR_PKTCAP_FLF_RESET, expected */
			fprintf(stderr, "pktcap filter: CDX error %d\n", rc);
			return (1);
		}

		printf("port %d filter reset\n", port_id);
		return (0);
	}

	/* Compile BPF filter string */
	if (strlen(argv[1]) >= 1024) {
		fprintf(stderr, "pktcap filter: expression too long\n");
		return (1);
	}

	pd = pcap_open_dead(DLT_EN10MB, SNAP_LENGTH);
	if (pd == NULL) {
		fprintf(stderr, "pktcap filter: pcap_open_dead failed\n");
		return (1);
	}

	if (pcap_compile(pd, &bpf, argv[1], 1, 0) < 0) {
		fprintf(stderr, "pktcap filter: invalid expression: %s\n",
		    pcap_geterr(pd));
		pcap_close(pd);
		return (1);
	}

	/* Single BPF_RET instruction = filter reset */
	if (bpf.bf_len == 1 && BPF_CLASS(bpf.bf_insns[0].code) == BPF_RET) {
		pcap_freecode(&bpf);
		pcap_close(pd);

		memset(&cmd, 0, sizeof(cmd));
		cmd.flen = 0;
		cmd.ifindex = (uint8_t)port_id;

		if (ctrl_command(fd, FPP_CMD_PKTCAP_FLF, &cmd, sizeof(cmd),
		    &rc, NULL, NULL) < 0)
			return (1);

		printf("port %d filter reset (trivial accept)\n", port_id);
		return (0);
	}

	/* Validate BPF instructions for FLF compatibility */
	if (check_bpf_filter(bpf.bf_insns, (int)bpf.bf_len) != 0) {
		fprintf(stderr,
		    "pktcap filter: filter uses unsupported BPF opcodes\n");
		pcap_freecode(&bpf);
		pcap_close(pd);
		return (1);
	}

	/* Calculate fragments */
	fgmts = 1;
	length = (int)bpf.bf_len;
	if (length > MAX_FLF_INSTRUCTIONS) {
		fgmts = length / MAX_FLF_INSTRUCTIONS;
		if (length % MAX_FLF_INSTRUCTIONS)
			fgmts++;
		length = MAX_FLF_INSTRUCTIONS;
	}

	/* Send fragments */
	for (seqno = 0; seqno < fgmts; seqno++) {
		int offset = seqno * MAX_FLF_INSTRUCTIONS;
		int remaining = (int)bpf.bf_len - offset;
		int count = remaining > MAX_FLF_INSTRUCTIONS ?
		    MAX_FLF_INSTRUCTIONS : remaining;

		memset(&cmd, 0, sizeof(cmd));
		cmd.ifindex = (uint8_t)port_id;
		cmd.flen = (uint16_t)count;
		cmd.mfg = (uint8_t)(((fgmts - (seqno + 1) > 0) << 3) |
		    (seqno & 0x7));
		memcpy(cmd.filter, &bpf.bf_insns[offset],
		    count * sizeof(struct bpf_insn));

		if (ctrl_command(fd, FPP_CMD_PKTCAP_FLF, &cmd, sizeof(cmd),
		    &rc, NULL, NULL) < 0) {
			pcap_freecode(&bpf);
			pcap_close(pd);
			return (1);
		}

		if (rc != 0) {
			fprintf(stderr,
			    "pktcap filter: CDX error %d (fragment %d/%d)\n",
			    rc, seqno + 1, fgmts);
			/* Reset filter on error */
			memset(&cmd, 0, sizeof(cmd));
			cmd.flen = 0;
			cmd.ifindex = (uint8_t)port_id;
			ctrl_command(fd, FPP_CMD_PKTCAP_FLF, &cmd,
			    sizeof(cmd), &rc, NULL, NULL);
			pcap_freecode(&bpf);
			pcap_close(pd);
			return (1);
		}
	}

	printf("port %d filter set (%u BPF instructions, %d fragment%s)\n",
	    port_id, bpf.bf_len, fgmts, fgmts > 1 ? "s" : "");

	pcap_freecode(&bpf);
	pcap_close(pd);
	return (0);
}

static int
cmd_query(int argc, char **argv, int fd)
{
	/*
	 * CDX response format: [2-byte FPP error code][data...].
	 * Allocate a buffer large enough for the error code prefix
	 * plus the actual query data.
	 */
	uint8_t raw[2 + PKTCAP_MAX_PORTS * sizeof(fpp_pktcap_query_cmd_t)];
	fpp_pktcap_query_cmd_t *resp;
	uint16_t resp_len;
	int16_t rc;
	uint16_t fpp_rc;
	int i;

	(void)argc;
	(void)argv;

	resp_len = sizeof(raw);
	if (ctrl_command(fd, FPP_CMD_PKTCAP_QUERY, NULL, 0,
	    &rc, raw, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "pktcap query: CMM error %d\n", rc);
		return (1);
	}

	/* Check FPP error code (first 2 bytes of CDX response) */
	if (resp_len < 2) {
		fprintf(stderr, "pktcap query: empty response\n");
		return (1);
	}

	memcpy(&fpp_rc, raw, sizeof(fpp_rc));
	if (fpp_rc != 0) {
		fprintf(stderr, "pktcap query: CDX error %u\n", fpp_rc);
		return (1);
	}

	if (resp_len < sizeof(raw)) {
		fprintf(stderr,
		    "pktcap query: short response (%u bytes)\n", resp_len);
		return (1);
	}

	/* Query data starts after the 2-byte error code */
	resp = (fpp_pktcap_query_cmd_t *)(raw + 2);

	printf("%-6s  %-8s  %s\n", "Port", "Status", "Slice");
	printf("%-6s  %-8s  %s\n", "----", "------", "-----");
	for (i = 0; i < PKTCAP_MAX_PORTS; i++) {
		printf("%-6d  %-8s  %u\n", i,
		    resp[i].status ? "enabled" : "off",
		    resp[i].slice);
	}

	return (0);
}

/* ---- Main dispatcher ---- */

static void
pktcap_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl pktcap <command> [args...]\n\n"
	    "Commands:\n"
	    "  status <port> enable|disable    Enable/disable capture\n"
	    "  slice <port> <40-1518>          Set capture slice size\n"
	    "  filter <port> <expression>      Set BPF filter\n"
	    "  filter <port> reset             Clear BPF filter\n"
	    "  query                           Show capture status\n");
}

int
cmmctl_pktcap_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		pktcap_usage();
		return (1);
	}

	if (strcmp(argv[0], "status") == 0)
		return (cmd_status(argc - 1, argv + 1, fd));

	if (strcmp(argv[0], "slice") == 0)
		return (cmd_slice(argc - 1, argv + 1, fd));

	if (strcmp(argv[0], "filter") == 0)
		return (cmd_filter(argc - 1, argv + 1, fd));

	if (strcmp(argv[0], "query") == 0)
		return (cmd_query(argc - 1, argv + 1, fd));

	fprintf(stderr, "unknown pktcap command: %s\n", argv[0]);
	pktcap_usage();
	return (1);
}
