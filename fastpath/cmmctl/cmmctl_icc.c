/*
 * cmmctl_icc.c — Ingress Congestion Control CLI sub-commands
 *
 * cmmctl icc reset
 * cmmctl icc threshold <bmu1> <bmu2>
 * cmmctl icc add <iface> <type> [args...]
 * cmmctl icc delete <iface> <type> [args...]
 * cmmctl icc query [<iface>]
 *
 * Interface numbers are 0-2 (matching CDX ICC interface IDs).
 *
 * CDX status: No control_icc.c handler exists in CDX — all commands
 * currently return ERR_UNKNOWN_COMMAND.  The CLI is ready for when
 * a CDX ICC handler is implemented.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cmmctl.h"
#include "fpp.h"

#define ICC_NUM_INTERFACES	3

#define ICC_ACTION_ADD		0
#define ICC_ACTION_DELETE	1

#define ICC_ACTION_QUERY	0
#define ICC_ACTION_QUERY_CONT	1

#define ICC_TABLETYPE_ETHERTYPE	0
#define ICC_TABLETYPE_PROTOCOL	1
#define ICC_TABLETYPE_DSCP	2
#define ICC_TABLETYPE_SADDR	3
#define ICC_TABLETYPE_DADDR	4
#define ICC_TABLETYPE_SADDR6	5
#define ICC_TABLETYPE_DADDR6	6
#define ICC_TABLETYPE_PORT	7
#define ICC_TABLETYPE_VLAN	8

/* ---- Helpers ---- */

static int
parse_uint(const char *s, uint32_t maxval, uint32_t *out)
{
	char *endp;
	unsigned long val;

	val = strtoul(s, &endp, 0);
	if (s == endp || *endp != '\0' || val > maxval)
		return (-1);
	*out = (uint32_t)val;
	return (0);
}

/*
 * Parse "N" or "N-M" range.  Both values must be <= maxval
 * and from <= to.
 */
static int
parse_range(const char *s, uint32_t maxval, uint32_t *from, uint32_t *to)
{
	char *endp;
	unsigned long fromval, toval;

	fromval = strtoul(s, &endp, 0);
	if (s == endp)
		return (-1);
	if (*endp == '-') {
		const char *p = endp + 1;
		toval = strtoul(p, &endp, 0);
		if (p == endp || *endp != '\0')
			return (-1);
	} else if (*endp == '\0') {
		toval = fromval;
	} else {
		return (-1);
	}

	if (toval < fromval || toval > maxval)
		return (-1);
	*from = (uint32_t)fromval;
	*to = (uint32_t)toval;
	return (0);
}

static inline void
setbit(uint8_t *bits, unsigned int idx)
{

	bits[idx >> 3] |= 1 << (idx & 7);
}

static inline int
testbit(const uint8_t *bits, unsigned int idx)
{

	return ((bits[idx >> 3] >> (idx & 7)) & 1);
}

static const char *
icc_strerror(int16_t rc)
{

	switch ((uint16_t)rc) {
	case FPP_ERR_UNKNOWN_COMMAND:
		return ("command not supported by CDX (no ICC handler)");
	case FPP_ERR_ICC_TOO_MANY_ENTRIES:
		return ("too many entries");
	case FPP_ERR_ICC_ENTRY_ALREADY_EXISTS:
		return ("entry already exists");
	case FPP_ERR_ICC_ENTRY_NOT_FOUND:
		return ("entry not found");
	case FPP_ERR_ICC_THRESHOLD_OUT_OF_RANGE:
		return ("threshold value out of range");
	case FPP_ERR_ICC_INVALID_MASKLEN:
		return ("invalid mask length");
	default:
		return (NULL);
	}
}

static void
icc_errmsg(const char *cmd, int16_t rc)
{
	const char *msg;

	msg = icc_strerror(rc);
	if (msg != NULL)
		fprintf(stderr, "icc %s: %s (0x%04x)\n", cmd, msg,
		    (unsigned)(uint16_t)rc);
	else
		fprintf(stderr, "icc %s: error 0x%04x\n", cmd,
		    (unsigned)(uint16_t)rc);
}

/* ---- Sub-command handlers ---- */

static int
cmd_reset(int fd)
{
	fpp_icc_reset_cmd_t cmd;
	uint8_t raw[2];
	uint16_t resp_len, fpp_rc;
	int16_t rc;

	memset(&cmd, 0, sizeof(cmd));
	resp_len = sizeof(raw);
	if (ctrl_command(fd, FPP_CMD_ICC_RESET, &cmd, sizeof(cmd),
	    &rc, raw, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		icc_errmsg("reset", rc);
		return (1);
	}

	if (resp_len >= 2) {
		memcpy(&fpp_rc, raw, sizeof(fpp_rc));
		if (fpp_rc != 0) {
			icc_errmsg("reset", (int16_t)fpp_rc);
			return (1);
		}
	}

	printf("icc reset\n");
	return (0);
}

static int
cmd_threshold(int argc, char **argv, int fd)
{
	fpp_icc_threshold_cmd_t cmd;
	uint8_t raw[2];
	uint16_t resp_len, fpp_rc;
	uint32_t bmu1, bmu2;
	int16_t rc;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl icc threshold <bmu1> <bmu2>\n");
		return (1);
	}

	if (parse_uint(argv[0], 1024, &bmu1) < 0) {
		fprintf(stderr,
		    "icc threshold: invalid bmu1 value '%s'\n", argv[0]);
		return (1);
	}
	if (parse_uint(argv[1], 1024, &bmu2) < 0) {
		fprintf(stderr,
		    "icc threshold: invalid bmu2 value '%s'\n", argv[1]);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.bmu1_threshold = (uint16_t)bmu1;
	cmd.bmu2_threshold = (uint16_t)bmu2;

	resp_len = sizeof(raw);
	if (ctrl_command(fd, FPP_CMD_ICC_THRESHOLD, &cmd, sizeof(cmd),
	    &rc, raw, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		icc_errmsg("threshold", rc);
		return (1);
	}

	if (resp_len >= 2) {
		memcpy(&fpp_rc, raw, sizeof(fpp_rc));
		if (fpp_rc != 0) {
			icc_errmsg("threshold", (int16_t)fpp_rc);
			return (1);
		}
	}

	printf("icc threshold: bmu1=%u bmu2=%u\n", bmu1, bmu2);
	return (0);
}

static int
cmd_add_delete(int argc, char **argv, int fd, uint16_t action)
{
	fpp_icc_add_delete_cmd_t cmd;
	uint8_t raw[2];
	uint16_t resp_len, fpp_rc;
	uint32_t iface, val1, val2;
	int16_t rc;
	const char *actstr = (action == ICC_ACTION_ADD) ? "add" : "delete";
	int arg;

	if (argc < 3) {
		fprintf(stderr,
		    "usage: cmmctl icc %s <iface> <type> [args...]\n"
		    "\n"
		    "Types:\n"
		    "  ethertype <value>\n"
		    "  protocol <proto> [<proto>...]\n"
		    "  dscp <value> [<value>...]\n"
		    "  saddr <ip> [<masklen>]\n"
		    "  daddr <ip> [<masklen>]\n"
		    "  saddr6 <ip6> [<prefixlen>]\n"
		    "  daddr6 <ip6> [<prefixlen>]\n"
		    "  port <sport-range> <dport-range>\n"
		    "  sport <port-range>\n"
		    "  dport <port-range>\n"
		    "  vlan <id-range> [<prio-range>]\n",
		    actstr);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = action;

	if (parse_uint(argv[0], ICC_NUM_INTERFACES - 1, &iface) < 0) {
		fprintf(stderr,
		    "icc %s: invalid interface '%s' (0-%d)\n",
		    actstr, argv[0], ICC_NUM_INTERFACES - 1);
		return (1);
	}
	cmd.interface = (uint8_t)iface;

	if (strcasecmp(argv[1], "ethertype") == 0) {
		if (argc != 3) {
			fprintf(stderr,
			    "usage: cmmctl icc %s <iface>"
			    " ethertype <value>\n", actstr);
			return (1);
		}
		cmd.table_type = ICC_TABLETYPE_ETHERTYPE;
		if (parse_uint(argv[2], 0xffff, &val1) < 0) {
			fprintf(stderr,
			    "icc %s: invalid ethertype '%s'\n",
			    actstr, argv[2]);
			return (1);
		}
		cmd.ethertype.type = (uint16_t)val1;

	} else if (strcasecmp(argv[1], "protocol") == 0) {
		cmd.table_type = ICC_TABLETYPE_PROTOCOL;
		for (arg = 2; arg < argc; arg++) {
			if (parse_range(argv[arg], 255, &val1, &val2) < 0) {
				fprintf(stderr,
				    "icc %s: invalid protocol '%s'\n",
				    actstr, argv[arg]);
				return (1);
			}
			for (; val1 <= val2; val1++)
				setbit(cmd.protocol.ipproto, val1);
		}

	} else if (strcasecmp(argv[1], "dscp") == 0) {
		cmd.table_type = ICC_TABLETYPE_DSCP;
		for (arg = 2; arg < argc; arg++) {
			if (parse_range(argv[arg], 63, &val1, &val2) < 0) {
				fprintf(stderr,
				    "icc %s: invalid dscp value '%s'\n",
				    actstr, argv[arg]);
				return (1);
			}
			for (; val1 <= val2; val1++)
				setbit(cmd.dscp.dscp_value, val1);
		}

	} else if (strcasecmp(argv[1], "saddr") == 0 ||
	    strcasecmp(argv[1], "daddr") == 0) {
		if (argc < 3 || argc > 4) {
			fprintf(stderr,
			    "usage: cmmctl icc %s <iface>"
			    " %s <ip> [<masklen>]\n", actstr, argv[1]);
			return (1);
		}
		cmd.table_type = (strcasecmp(argv[1], "saddr") == 0) ?
		    ICC_TABLETYPE_SADDR : ICC_TABLETYPE_DADDR;
		{
			uint32_t v4tmp;
			if (inet_pton(AF_INET, argv[2], &v4tmp) != 1) {
				fprintf(stderr,
				    "icc %s: invalid IPv4 address '%s'\n",
				    actstr, argv[2]);
				return (1);
			}
			cmd.ipaddr.v4_addr = v4tmp;
		}
		if (argc == 4) {
			if (parse_uint(argv[3], 32, &val1) < 0 ||
			    val1 == 0) {
				fprintf(stderr,
				    "icc %s: invalid mask length '%s'\n",
				    actstr, argv[3]);
				return (1);
			}
			cmd.ipaddr.v4_masklen = (uint8_t)val1;
		} else {
			cmd.ipaddr.v4_masklen = 32;
		}

	} else if (strcasecmp(argv[1], "saddr6") == 0 ||
	    strcasecmp(argv[1], "daddr6") == 0) {
		if (argc < 3 || argc > 4) {
			fprintf(stderr,
			    "usage: cmmctl icc %s <iface>"
			    " %s <ip6> [<prefixlen>]\n", actstr, argv[1]);
			return (1);
		}
		cmd.table_type = (strcasecmp(argv[1], "saddr6") == 0) ?
		    ICC_TABLETYPE_SADDR6 : ICC_TABLETYPE_DADDR6;
		{
			uint32_t v6tmp[4];
			if (inet_pton(AF_INET6, argv[2], v6tmp) != 1) {
				fprintf(stderr,
				    "icc %s: invalid IPv6 address '%s'\n",
				    actstr, argv[2]);
				return (1);
			}
			memcpy(cmd.ipv6addr.v6_addr, v6tmp, 16);
		}
		if (argc == 4) {
			if (parse_uint(argv[3], 128, &val1) < 0 ||
			    val1 == 0) {
				fprintf(stderr,
				    "icc %s: invalid prefix length '%s'\n",
				    actstr, argv[3]);
				return (1);
			}
			cmd.ipv6addr.v6_masklen = (uint8_t)val1;
		} else {
			cmd.ipv6addr.v6_masklen = 128;
		}

	} else if (strcasecmp(argv[1], "port") == 0) {
		if (argc != 4) {
			fprintf(stderr,
			    "usage: cmmctl icc %s <iface>"
			    " port <sport-range> <dport-range>\n", actstr);
			return (1);
		}
		cmd.table_type = ICC_TABLETYPE_PORT;
		if (parse_range(argv[2], 0xffff, &val1, &val2) < 0) {
			fprintf(stderr,
			    "icc %s: invalid source port '%s'\n",
			    actstr, argv[2]);
			return (1);
		}
		cmd.port.sport_from = (uint16_t)val1;
		cmd.port.sport_to = (uint16_t)val2;
		if (parse_range(argv[3], 0xffff, &val1, &val2) < 0) {
			fprintf(stderr,
			    "icc %s: invalid dest port '%s'\n",
			    actstr, argv[3]);
			return (1);
		}
		cmd.port.dport_from = (uint16_t)val1;
		cmd.port.dport_to = (uint16_t)val2;

	} else if (strcasecmp(argv[1], "sport") == 0) {
		if (argc != 3) {
			fprintf(stderr,
			    "usage: cmmctl icc %s <iface>"
			    " sport <port-range>\n", actstr);
			return (1);
		}
		cmd.table_type = ICC_TABLETYPE_PORT;
		if (parse_range(argv[2], 0xffff, &val1, &val2) < 0) {
			fprintf(stderr,
			    "icc %s: invalid source port '%s'\n",
			    actstr, argv[2]);
			return (1);
		}
		cmd.port.sport_from = (uint16_t)val1;
		cmd.port.sport_to = (uint16_t)val2;
		cmd.port.dport_from = 0;
		cmd.port.dport_to = 65535;

	} else if (strcasecmp(argv[1], "dport") == 0) {
		if (argc != 3) {
			fprintf(stderr,
			    "usage: cmmctl icc %s <iface>"
			    " dport <port-range>\n", actstr);
			return (1);
		}
		cmd.table_type = ICC_TABLETYPE_PORT;
		if (parse_range(argv[2], 0xffff, &val1, &val2) < 0) {
			fprintf(stderr,
			    "icc %s: invalid dest port '%s'\n",
			    actstr, argv[2]);
			return (1);
		}
		cmd.port.dport_from = (uint16_t)val1;
		cmd.port.dport_to = (uint16_t)val2;
		cmd.port.sport_from = 0;
		cmd.port.sport_to = 65535;

	} else if (strcasecmp(argv[1], "vlan") == 0) {
		if (argc < 3 || argc > 4) {
			fprintf(stderr,
			    "usage: cmmctl icc %s <iface>"
			    " vlan <id-range> [<prio-range>]\n", actstr);
			return (1);
		}
		cmd.table_type = ICC_TABLETYPE_VLAN;
		if (parse_range(argv[2], 8191, &val1, &val2) < 0) {
			fprintf(stderr,
			    "icc %s: invalid VLAN ID '%s'\n",
			    actstr, argv[2]);
			return (1);
		}
		cmd.vlan.vlan_from = (uint16_t)val1;
		cmd.vlan.vlan_to = (uint16_t)val2;
		if (argc == 4) {
			if (parse_range(argv[3], 7, &val1, &val2) < 0) {
				fprintf(stderr,
				    "icc %s: invalid VLAN priority '%s'\n",
				    actstr, argv[3]);
				return (1);
			}
		} else {
			val1 = 0;
			val2 = 7;
		}
		cmd.vlan.prio_from = (uint16_t)val1;
		cmd.vlan.prio_to = (uint16_t)val2;

	} else {
		fprintf(stderr,
		    "icc %s: unknown table type '%s'\n", actstr, argv[1]);
		return (1);
	}

	resp_len = sizeof(raw);
	if (ctrl_command(fd, FPP_CMD_ICC_ADD_DELETE, &cmd, sizeof(cmd),
	    &rc, raw, &resp_len) < 0)
		return (1);

	if (rc != 0) {
		icc_errmsg(actstr, rc);
		return (1);
	}

	if (resp_len >= 2) {
		memcpy(&fpp_rc, raw, sizeof(fpp_rc));
		if (fpp_rc != 0) {
			icc_errmsg(actstr, (int16_t)fpp_rc);
			return (1);
		}
	}

	printf("icc %s: interface %u ok\n", actstr, iface);
	return (0);
}

/* ---- Query ---- */

/*
 * Format a bitmask as coalesced ranges.  E.g., bits 1,2,3,6,7
 * becomes "1-3 6-7".
 */
static void
print_bitmask(const uint8_t *bits, unsigned int maxbit)
{
	unsigned int i, j;
	int first = 1;

	for (i = 0; i <= maxbit; i++) {
		if (!testbit(bits, i))
			continue;
		j = i + 1;
		while (j <= maxbit && testbit(bits, j))
			j++;
		j--;
		if (!first)
			printf(" ");
		if (j == i)
			printf("%u", i);
		else
			printf("%u-%u", i, j);
		first = 0;
		i = j;
	}
}

static void
print_entry(const fpp_icc_query_reply_t *r)
{
	char buf[INET6_ADDRSTRLEN];

	switch (r->table_type) {
	case ICC_TABLETYPE_ETHERTYPE:
		printf("  Ethertype: 0x%04x\n", r->ethertype.type);
		break;
	case ICC_TABLETYPE_PROTOCOL:
		printf("  Protocols: ");
		print_bitmask(r->protocol.ipproto, 255);
		printf("\n");
		break;
	case ICC_TABLETYPE_DSCP:
		printf("  DSCP values: ");
		print_bitmask(r->dscp.dscp_value, 63);
		printf("\n");
		break;
	case ICC_TABLETYPE_SADDR:
	case ICC_TABLETYPE_DADDR:
		{
			uint32_t v4tmp;
			memcpy(&v4tmp, &r->ipaddr.v4_addr, sizeof(v4tmp));
			printf("  IPv4 %s: %s/%u\n",
			    r->table_type == ICC_TABLETYPE_SADDR ?
			    "Source" : "Dest",
			    inet_ntop(AF_INET, &v4tmp,
			    buf, sizeof(buf)),
			    r->ipaddr.v4_masklen);
		}
		break;
	case ICC_TABLETYPE_SADDR6:
	case ICC_TABLETYPE_DADDR6:
		{
			uint32_t v6tmp[4];
			memcpy(v6tmp, r->ipv6addr.v6_addr, 16);
			printf("  IPv6 %s: %s/%u\n",
			    r->table_type == ICC_TABLETYPE_SADDR6 ?
			    "Source" : "Dest",
			    inet_ntop(AF_INET6, v6tmp,
			    buf, sizeof(buf)),
			    r->ipv6addr.v6_masklen);
		}
		break;
	case ICC_TABLETYPE_PORT:
		printf("  Ports: src %u-%u / dst %u-%u\n",
		    r->port.sport_from, r->port.sport_to,
		    r->port.dport_from, r->port.dport_to);
		break;
	case ICC_TABLETYPE_VLAN:
		printf("  VLAN: ID %u-%u / priority %u-%u\n",
		    r->vlan.vlan_from, r->vlan.vlan_to,
		    r->vlan.prio_from, r->vlan.prio_to);
		break;
	default:
		printf("  Unknown table_type %u\n", r->table_type);
		break;
	}
}

static int
cmd_query(int argc, char **argv, int fd)
{
	fpp_icc_query_cmd_t cmd;
	uint8_t raw[sizeof(fpp_icc_query_reply_t)];
	fpp_icc_query_reply_t *resp;
	uint16_t resp_len;
	uint32_t iface_from, iface_to, iface;
	int16_t rc;

	if (argc > 1) {
		fprintf(stderr,
		    "usage: cmmctl icc query [<iface>]\n");
		return (1);
	}

	if (argc == 1) {
		if (parse_uint(argv[0], ICC_NUM_INTERFACES - 1,
		    &iface_from) < 0) {
			fprintf(stderr,
			    "icc query: invalid interface '%s' (0-%d)\n",
			    argv[0], ICC_NUM_INTERFACES - 1);
			return (1);
		}
		iface_to = iface_from;
	} else {
		iface_from = 0;
		iface_to = ICC_NUM_INTERFACES - 1;
	}

	resp = (fpp_icc_query_reply_t *)raw;

	for (iface = iface_from; iface <= iface_to; iface++) {
		uint16_t action = ICC_ACTION_QUERY;

		printf("ICC interface %u --\n", iface);

		for (;;) {
			memset(&cmd, 0, sizeof(cmd));
			cmd.action = action;
			cmd.interface = (uint8_t)iface;

			resp_len = sizeof(raw);
			if (ctrl_command(fd, FPP_CMD_ICC_QUERY,
			    &cmd, sizeof(cmd),
			    &rc, raw, &resp_len) < 0)
				return (1);

			if (rc != 0) {
				icc_errmsg("query", rc);
				return (1);
			}

			if (resp_len < 6) {
				/* Need at least rtncode + query_result +
				 * interface + table_type */
				break;
			}

			if (resp->query_result != 0 ||
			    resp->interface != iface)
				break;

			print_entry(resp);
			action = ICC_ACTION_QUERY_CONT;
		}

		printf("-------------\n\n");
	}

	return (0);
}

/* ---- Main dispatcher ---- */

static void
icc_usage(void)
{
	fprintf(stderr,
	    "usage: cmmctl icc <command> [args...]\n\n"
	    "Commands:\n"
	    "  reset                              "
	    "Reset ICC state\n"
	    "  threshold <bmu1> <bmu2>            "
	    "Set buffer thresholds (0-1024)\n"
	    "  add <iface> <type> [args...]       "
	    "Add classification rule\n"
	    "  delete <iface> <type> [args...]    "
	    "Delete classification rule\n"
	    "  query [<iface>]                    "
	    "Query ICC rules\n");
}

int
cmmctl_icc_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		icc_usage();
		return (1);
	}

	if (strcmp(argv[0], "reset") == 0)
		return (cmd_reset(fd));

	if (strcmp(argv[0], "threshold") == 0)
		return (cmd_threshold(argc - 1, argv + 1, fd));

	if (strcmp(argv[0], "add") == 0)
		return (cmd_add_delete(argc - 1, argv + 1, fd,
		    ICC_ACTION_ADD));

	if (strcmp(argv[0], "delete") == 0)
		return (cmd_add_delete(argc - 1, argv + 1, fd,
		    ICC_ACTION_DELETE));

	if (strcmp(argv[0], "query") == 0)
		return (cmd_query(argc - 1, argv + 1, fd));

	fprintf(stderr, "unknown icc command: %s\n", argv[0]);
	icc_usage();
	return (1);
}
