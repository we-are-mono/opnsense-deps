/*
 * cmmctl_natpt.c — NAT-PT CLI sub-commands
 *
 * cmmctl natpt open <sock_a> <sock_b> [6to4] [4to6]
 * cmmctl natpt close <sock_a> <sock_b>
 * cmmctl natpt query <sock_a> <sock_b>
 *
 * Socket IDs are numeric (0-65535), matching sockets previously
 * registered via "cmmctl socket open".
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmmctl.h"
#include "fpp.h"

static int
parse_sock_id(const char *s, uint16_t *out)
{
	char *endp;
	unsigned long val;

	val = strtoul(s, &endp, 0);
	if (s == endp || *endp != '\0' || val > 65535)
		return (-1);
	*out = (uint16_t)val;
	return (0);
}

/* ---- Sub-command handlers ---- */

static int
cmd_open(int argc, char **argv, int fd)
{
	fpp_natpt_open_cmd_t cmd;
	uint8_t raw[2];
	uint16_t resp_len, fpp_rc;
	uint16_t sock_a, sock_b;
	int16_t rc;
	int i;

	if (argc < 3) {
		fprintf(stderr,
		    "usage: cmmctl natpt open <sock_a> <sock_b>"
		    " [6to4] [4to6]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	if (parse_sock_id(argv[0], &sock_a) < 0) {
		fprintf(stderr, "natpt open: invalid socket_a '%s'\n",
		    argv[0]);
		return (1);
	}
	if (parse_sock_id(argv[1], &sock_b) < 0) {
		fprintf(stderr, "natpt open: invalid socket_b '%s'\n",
		    argv[1]);
		return (1);
	}
	cmd.socket_a = sock_a;
	cmd.socket_b = sock_b;

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "6to4") == 0)
			cmd.control |= FPP_NATPT_CONTROL_6to4;
		else if (strcmp(argv[i], "4to6") == 0)
			cmd.control |= FPP_NATPT_CONTROL_4to6;
		else {
			fprintf(stderr,
			    "natpt open: unknown flag '%s'\n", argv[i]);
			return (1);
		}
	}

	if (cmd.control == 0) {
		fprintf(stderr,
		    "natpt open: must specify 6to4 and/or 4to6\n");
		return (1);
	}

	resp_len = sizeof(raw);
	if (ctrl_command(fd, FPP_CMD_NATPT_OPEN, &cmd, sizeof(cmd),
	    &rc, raw, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "natpt open: CMM error %d\n", rc);
		return (1);
	}

	if (resp_len >= 2) {
		memcpy(&fpp_rc, raw, sizeof(fpp_rc));
		if (fpp_rc != 0) {
			fprintf(stderr, "natpt open: CDX error %u\n", fpp_rc);
			return (1);
		}
	}

	printf("natpt opened: socket_a=%u socket_b=%u%s%s\n",
	    cmd.socket_a, cmd.socket_b,
	    (cmd.control & FPP_NATPT_CONTROL_6to4) ? " 6to4" : "",
	    (cmd.control & FPP_NATPT_CONTROL_4to6) ? " 4to6" : "");
	return (0);
}

static int
cmd_close(int argc, char **argv, int fd)
{
	fpp_natpt_close_cmd cmd;
	uint8_t raw[2];
	uint16_t resp_len, fpp_rc;
	uint16_t sock_a, sock_b;
	int16_t rc;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl natpt close <sock_a> <sock_b>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	if (parse_sock_id(argv[0], &sock_a) < 0) {
		fprintf(stderr, "natpt close: invalid socket_a '%s'\n",
		    argv[0]);
		return (1);
	}
	if (parse_sock_id(argv[1], &sock_b) < 0) {
		fprintf(stderr, "natpt close: invalid socket_b '%s'\n",
		    argv[1]);
		return (1);
	}
	cmd.socket_a = sock_a;
	cmd.socket_b = sock_b;

	resp_len = sizeof(raw);
	if (ctrl_command(fd, FPP_CMD_NATPT_CLOSE, &cmd, sizeof(cmd),
	    &rc, raw, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "natpt close: CMM error %d\n", rc);
		return (1);
	}

	if (resp_len >= 2) {
		memcpy(&fpp_rc, raw, sizeof(fpp_rc));
		if (fpp_rc != 0) {
			fprintf(stderr, "natpt close: CDX error %u\n",
			    fpp_rc);
			return (1);
		}
	}

	printf("natpt closed: socket_a=%u socket_b=%u\n",
	    cmd.socket_a, cmd.socket_b);
	return (0);
}

static int
cmd_query(int argc, char **argv, int fd)
{
	fpp_natpt_query_cmd_t cmd;
	uint8_t raw[sizeof(fpp_natpt_query_response_t)];
	fpp_natpt_query_response_t *resp;
	uint16_t resp_len;
	uint16_t sock_a, sock_b;
	int16_t rc;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl natpt query <sock_a> <sock_b>\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	if (parse_sock_id(argv[0], &sock_a) < 0) {
		fprintf(stderr, "natpt query: invalid socket_a '%s'\n",
		    argv[0]);
		return (1);
	}
	if (parse_sock_id(argv[1], &sock_b) < 0) {
		fprintf(stderr, "natpt query: invalid socket_b '%s'\n",
		    argv[1]);
		return (1);
	}
	cmd.socket_a = sock_a;
	cmd.socket_b = sock_b;

	resp_len = sizeof(raw);
	if (ctrl_command(fd, FPP_CMD_NATPT_QUERY, &cmd, sizeof(cmd),
	    &rc, raw, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "natpt query: CMM error %d\n", rc);
		return (1);
	}

	if (resp_len < sizeof(fpp_natpt_query_response_t)) {
		fprintf(stderr,
		    "natpt query: short response (%u bytes, expected %zu)\n",
		    resp_len, sizeof(fpp_natpt_query_response_t));
		return (1);
	}

	resp = (fpp_natpt_query_response_t *)raw;

	if (resp->retcode != 0) {
		fprintf(stderr, "natpt query: CDX error %u\n", resp->retcode);
		return (1);
	}

	printf("NAT-PT Entry:\n");
	printf("  Socket A: %u, Socket B: %u%s%s%s\n",
	    resp->socket_a, resp->socket_b,
	    (resp->control & FPP_NATPT_CONTROL_6to4) ? ", 6to4" : "",
	    (resp->control & FPP_NATPT_CONTROL_4to6) ? ", 4to6" : "",
	    (resp->control & FPP_NATPT_CONTROL_TCPFIN) ? ", TCP_FIN" : "");
	printf("  IPv6 Received:    %" PRIu64 "\n", resp->stat_v6_received);
	printf("  IPv6 Transmitted: %" PRIu64 "\n",
	    resp->stat_v6_transmitted);
	printf("  IPv6 Dropped:     %" PRIu64 "\n", resp->stat_v6_dropped);
	printf("  IPv6 Sent to ACP: %" PRIu64 "\n",
	    resp->stat_v6_sent_to_ACP);
	printf("  IPv4 Received:    %" PRIu64 "\n", resp->stat_v4_received);
	printf("  IPv4 Transmitted: %" PRIu64 "\n",
	    resp->stat_v4_transmitted);
	printf("  IPv4 Dropped:     %" PRIu64 "\n", resp->stat_v4_dropped);
	printf("  IPv4 Sent to ACP: %" PRIu64 "\n",
	    resp->stat_v4_sent_to_ACP);

	return (0);
}

/* ---- Main dispatcher ---- */

static void
natpt_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl natpt <command> [args...]\n\n"
	    "Commands:\n"
	    "  open <sock_a> <sock_b> [6to4] [4to6]    "
	    "Open NAT-PT pair\n"
	    "  close <sock_a> <sock_b>                  "
	    "Close NAT-PT pair\n"
	    "  query <sock_a> <sock_b>                  "
	    "Query NAT-PT pair\n");
}

int
cmmctl_natpt_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		natpt_usage();
		return (1);
	}

	if (strcmp(argv[0], "open") == 0)
		return (cmd_open(argc - 1, argv + 1, fd));

	if (strcmp(argv[0], "close") == 0)
		return (cmd_close(argc - 1, argv + 1, fd));

	if (strcmp(argv[0], "query") == 0)
		return (cmd_query(argc - 1, argv + 1, fd));

	fprintf(stderr, "unknown natpt command: %s\n", argv[0]);
	natpt_usage();
	return (1);
}
