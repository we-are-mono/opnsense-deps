/*
 * cmmctl_socket.c — Socket acceleration CLI sub-commands
 *
 * cmmctl socket open id=<N> proto=tcp|udp daddr=<IP> dport=<port>
 *                    [saddr=<IP>] [sport=<port>] [queue=<N>] [dscp=<N>]
 * cmmctl socket close id=<N>
 * cmmctl socket update id=<N> [saddr=<IP>] [sport=<port>]
 *                      [queue=<N>] [dscp=<N>]
 * cmmctl socket show
 *
 * open/close/update use CMM-internal commands (CMM_CTRL_CMD_SOCKET_*).
 * show queries CDX directly via FPP_CMD_SOCKETSTATS_STATUS/ENTRY.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
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
#include "cmm_socket.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * Parse key=value from argv.  Returns value pointer or NULL.
 */
static const char *
find_kv(int argc, char **argv, const char *key)
{
	int i;
	size_t klen = strlen(key);

	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], key, klen) == 0 &&
		    argv[i][klen] == '=')
			return (argv[i] + klen + 1);
	}
	return (NULL);
}

/*
 * Parse an IP address, auto-detect AF_INET vs AF_INET6.
 * Stores in dst[16] (IPv4 in first 4 bytes, zeroed rest).
 * Returns AF_INET, AF_INET6, or 0 on error.
 */
static int
parse_addr(const char *str, uint8_t *dst)
{
	struct in_addr in4;
	struct in6_addr in6;

	memset(dst, 0, 16);

	if (inet_pton(AF_INET, str, &in4) == 1) {
		memcpy(dst, &in4, 4);
		return (AF_INET);
	}
	if (inet_pton(AF_INET6, str, &in6) == 1) {
		memcpy(dst, &in6, 16);
		return (AF_INET6);
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* open                                                                */
/* ------------------------------------------------------------------ */

static int
socket_open(int argc, char **argv, int fd)
{
	struct cmm_ctrl_socket_open cmd;
	const char *val;
	int af;
	int16_t rc;

	memset(&cmd, 0, sizeof(cmd));

	/* id (required) */
	val = find_kv(argc, argv, "id");
	if (val == NULL) {
		fprintf(stderr, "socket open: id=<N> required\n");
		return (1);
	}
	cmd.id = (uint16_t)atoi(val);
	if (cmd.id == 0) {
		fprintf(stderr, "socket open: id must be 1–65535\n");
		return (1);
	}

	/* proto (required) */
	val = find_kv(argc, argv, "proto");
	if (val == NULL) {
		fprintf(stderr, "socket open: proto=tcp|udp required\n");
		return (1);
	}
	if (strcmp(val, "tcp") == 0)
		cmd.proto = IPPROTO_TCP;
	else if (strcmp(val, "udp") == 0)
		cmd.proto = IPPROTO_UDP;
	else {
		fprintf(stderr, "socket open: proto must be tcp or udp\n");
		return (1);
	}

	/* daddr (required) */
	val = find_kv(argc, argv, "daddr");
	if (val == NULL) {
		fprintf(stderr, "socket open: daddr=<IP> required\n");
		return (1);
	}
	af = parse_addr(val, cmd.daddr);
	if (af == 0) {
		fprintf(stderr, "socket open: invalid daddr '%s'\n", val);
		return (1);
	}
	cmd.af = (uint8_t)af;

	/* dport (required) */
	val = find_kv(argc, argv, "dport");
	if (val == NULL) {
		fprintf(stderr, "socket open: dport=<port> required\n");
		return (1);
	}
	cmd.dport = htons((uint16_t)atoi(val));

	/* saddr (optional — sets connected mode) */
	val = find_kv(argc, argv, "saddr");
	if (val != NULL) {
		int saf = parse_addr(val, cmd.saddr);
		if (saf == 0) {
			fprintf(stderr, "socket open: invalid saddr '%s'\n",
			    val);
			return (1);
		}
		if (saf != af) {
			fprintf(stderr,
			    "socket open: saddr/daddr AF mismatch\n");
			return (1);
		}
		cmd.mode = CMM_SOCK_MODE_CONNECTED;
	} else {
		cmd.mode = CMM_SOCK_MODE_UNCONNECTED;
	}

	/* sport (optional) */
	val = find_kv(argc, argv, "sport");
	if (val != NULL)
		cmd.sport = htons((uint16_t)atoi(val));

	/* queue (optional) */
	val = find_kv(argc, argv, "queue");
	if (val != NULL)
		cmd.queue = (uint8_t)atoi(val);

	/* dscp (optional) */
	val = find_kv(argc, argv, "dscp");
	if (val != NULL)
		cmd.dscp = (uint16_t)atoi(val);

	/* type always LANWAN for now */
	cmd.type = CMM_SOCK_TYPE_LANWAN;

	/* Send to CMM */
	if (ctrl_command(fd, CMM_CTRL_CMD_SOCKET_OPEN, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "socket open: error %d\n", rc);
		return (1);
	}

	printf("socket id=%u opened\n", cmd.id);
	return (0);
}

/* ------------------------------------------------------------------ */
/* close                                                               */
/* ------------------------------------------------------------------ */

static int
socket_close(int argc, char **argv, int fd)
{
	struct cmm_ctrl_socket_close cmd;
	const char *val;
	int16_t rc;

	memset(&cmd, 0, sizeof(cmd));

	val = find_kv(argc, argv, "id");
	if (val == NULL) {
		fprintf(stderr, "socket close: id=<N> required\n");
		return (1);
	}
	cmd.id = (uint16_t)atoi(val);

	if (ctrl_command(fd, CMM_CTRL_CMD_SOCKET_CLOSE, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "socket close: error %d\n", rc);
		return (1);
	}

	printf("socket id=%u closed\n", cmd.id);
	return (0);
}

/* ------------------------------------------------------------------ */
/* update                                                              */
/* ------------------------------------------------------------------ */

static int
socket_update(int argc, char **argv, int fd)
{
	struct cmm_ctrl_socket_update cmd;
	const char *val;
	int16_t rc;

	memset(&cmd, 0, sizeof(cmd));

	/* Sentinel defaults = no change */
	cmd.sport = 0xFFFF;
	cmd.queue = 0xFF;
	cmd.dscp = 0xFFFF;

	/* id (required) */
	val = find_kv(argc, argv, "id");
	if (val == NULL) {
		fprintf(stderr, "socket update: id=<N> required\n");
		return (1);
	}
	cmd.id = (uint16_t)atoi(val);

	/* saddr (optional) */
	val = find_kv(argc, argv, "saddr");
	if (val != NULL) {
		if (parse_addr(val, cmd.saddr) == 0) {
			fprintf(stderr, "socket update: invalid saddr '%s'\n",
			    val);
			return (1);
		}
	}

	/* sport (optional) */
	val = find_kv(argc, argv, "sport");
	if (val != NULL)
		cmd.sport = htons((uint16_t)atoi(val));

	/* queue (optional) */
	val = find_kv(argc, argv, "queue");
	if (val != NULL)
		cmd.queue = (uint8_t)atoi(val);

	/* dscp (optional) */
	val = find_kv(argc, argv, "dscp");
	if (val != NULL)
		cmd.dscp = (uint16_t)atoi(val);

	if (ctrl_command(fd, CMM_CTRL_CMD_SOCKET_UPDATE, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		fprintf(stderr, "socket update: error %d\n", rc);
		return (1);
	}

	printf("socket id=%u updated\n", cmd.id);
	return (0);
}

/* ------------------------------------------------------------------ */
/* show                                                                */
/* ------------------------------------------------------------------ */

static int
socket_show(int fd)
{
	fpp_socketstats_status_cmd_t cmd;
	fpp_socketstats_entry_response_t resp;
	uint16_t resp_len;
	int16_t rc;
	int count = 0;

	/*
	 * Query CDX for socket stats.  The STATUS command starts
	 * iteration; ENTRY returns batches of up to 10 sockets.
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.start_sock_id = 0;
	cmd.end_sock_id = 0xFFFF;

	/* STATUS initializes the query */
	if (ctrl_command(fd, FPP_CMD_SOCKETSTATS_STATUS, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);

	if (rc != 0) {
		if (rc == FPP_ERR_STAT_FEATURE_NOT_ENABLED) {
			printf("Socket statistics not enabled in CDX.\n");
			return (0);
		}
		fprintf(stderr, "socket show: STATUS error %d\n", rc);
		return (1);
	}

	/* Iterate entries */
	for (;;) {
		int i;

		resp_len = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_SOCKETSTATS_ENTRY, NULL, 0,
		    &rc, &resp, &resp_len) < 0)
			return (1);

		if (rc != 0)
			break;

		if (resp_len < 8)	/* at least header */
			break;

		for (i = 0; i < resp.socket_no && i < MAX_SOCKET_IN_MSG; i++) {
			fpp_socketstats_t *s = &resp.socket_stats[i];

			printf("socket id=%-5u  rx_pkts=%-10u  tx_pkts=%-10u\n",
			    s->sock_id,
			    s->total_packets_received,
			    s->total_packets_transmitted);
			count++;
		}

		if (resp.eof)
			break;
	}

	if (count == 0)
		printf("No sockets registered in CDX.\n");

	return (0);
}

/* ------------------------------------------------------------------ */
/* Main dispatcher                                                     */
/* ------------------------------------------------------------------ */

static void
socket_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl socket <command> [args]\n\n"
	    "Commands:\n"
	    "  open id=<N> proto=tcp|udp daddr=<IP> dport=<port>\n"
	    "       [saddr=<IP>] [sport=<port>] [queue=<N>] [dscp=<N>]\n"
	    "                        Register socket for acceleration\n"
	    "  close id=<N>          Deregister socket\n"
	    "  update id=<N> [saddr=<IP>] [sport=<port>] [queue=<N>] [dscp=<N>]\n"
	    "                        Update socket parameters\n"
	    "  show                  Show socket statistics from CDX\n");
}

int
cmmctl_socket_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		socket_usage();
		return (1);
	}

	if (strcmp(argv[0], "open") == 0)
		return (socket_open(argc - 1, argv + 1, fd));
	if (strcmp(argv[0], "close") == 0)
		return (socket_close(argc - 1, argv + 1, fd));
	if (strcmp(argv[0], "update") == 0)
		return (socket_update(argc - 1, argv + 1, fd));
	if (strcmp(argv[0], "show") == 0)
		return (socket_show(fd));

	fprintf(stderr, "cmmctl socket: unknown sub-command '%s'\n",
	    argv[0]);
	socket_usage();
	return (1);
}
