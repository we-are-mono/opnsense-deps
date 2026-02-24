/*
 * cmmctl_stat.c — Statistics commands for cmmctl
 *
 * Pure FCI passthrough — queries CDX hardware counters via the CMM
 * control socket.  No CMM-side state; CDX's control_stat.c handles
 * all stat commands directly.
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

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/*
 * Reconstruct a 64-bit byte counter from the split [2] array
 * used by FPP stat responses: [0] = low 32 bits, [1] = high 32 bits.
 */
static uint64_t
bytes64(const uint32_t b[2])
{

	return ((uint64_t)b[1] << 32) | b[0];
}

/*
 * Parse optional "reset" keyword at end of argv.
 * Returns FPP_CMM_STAT_QUERY_RESET if present, FPP_CMM_STAT_QUERY otherwise.
 * Sets *consumed to 1 if "reset" was consumed, 0 otherwise.
 */
static uint16_t
parse_action(int argc, char **argv, int *consumed)
{

	*consumed = 0;
	if (argc > 0 && strcmp(argv[argc - 1], "reset") == 0) {
		*consumed = 1;
		return (FPP_CMM_STAT_QUERY_RESET);
	}
	return (FPP_CMM_STAT_QUERY);
}

/*
 * Map interface name to CDX interface number.
 * Accepts "dtsecN" (returns N) or raw numeric string.
 */
static int
parse_iface(const char *name, uint16_t *iface_num)
{
	char *endptr;
	unsigned long v;

	if (strncmp(name, "dtsec", 5) == 0 && name[5] != '\0') {
		v = strtoul(name + 5, &endptr, 10);
		if (*endptr == '\0' && v <= 9) {
			*iface_num = (uint16_t)v;
			return (0);
		}
	}

	/* Try raw number */
	v = strtoul(name, &endptr, 0);
	if (name != endptr && *endptr == '\0' && v <= 65535) {
		*iface_num = (uint16_t)v;
		return (0);
	}

	return (-1);
}

/* ------------------------------------------------------------------ */
/* enable / disable                                                   */
/* ------------------------------------------------------------------ */

struct stat_feature {
	const char	*name;
	uint32_t	bitmask;
};

static const struct stat_feature features[] = {
	{ "queue",	FPP_STAT_QUEUE_BITMASK },
	{ "interface",	FPP_STAT_INTERFACE_BITMASK },
	{ "pppoe",	FPP_STAT_PPPOE_BITMASK },
	{ "bridge",	FPP_STAT_BRIDGE_BITMASK },
	{ "ipsec",	FPP_STAT_IPSEC_BITMASK },
	{ "vlan",	FPP_STAT_VLAN_BITMASK },
	{ "tunnel",	FPP_STAT_TUNNEL_BITMASK },
	{ "flow",	FPP_STAT_FLOW_BITMASK },
	{ NULL, 0 }
};

static int
stat_enable(int argc, char **argv, int fd, uint16_t action)
{
	fpp_stat_enable_cmd_t cmd;
	const struct stat_feature *f;
	int16_t rc;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl stat enable|disable <feature>\n"
		    "features: queue interface pppoe bridge ipsec "
		    "vlan tunnel flow\n");
		return (1);
	}

	for (f = features; f->name != NULL; f++) {
		if (strcasecmp(argv[0], f->name) == 0)
			break;
	}
	if (f->name == NULL) {
		fprintf(stderr, "stat: unknown feature '%s'\n", argv[0]);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = action;
	cmd.bitmask = f->bitmask;

	if (ctrl_command(fd, FPP_CMD_STAT_ENABLE, &cmd, sizeof(cmd),
	    &rc, NULL, NULL) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "stat %s %s: error %d\n",
		    action == FPP_CMM_STAT_ENABLE ? "enable" : "disable",
		    argv[0], rc);
		return (1);
	}

	printf("stat %s %s: ok\n",
	    action == FPP_CMM_STAT_ENABLE ? "enable" : "disable",
	    argv[0]);
	return (0);
}

/* ------------------------------------------------------------------ */
/* conn                                                               */
/* ------------------------------------------------------------------ */

static int
stat_conn(int argc, char **argv, int fd)
{
	fpp_stat_connection_cmd_t cmd;
	fpp_stat_conn_response_t resp;
	uint16_t resp_len;
	int16_t rc;
	int consumed;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = parse_action(argc, argv, &consumed);

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_STAT_CONNECTION, &cmd, sizeof(cmd),
	    &rc, &resp, &resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "stat conn: error %d\n", rc);
		return (1);
	}
	if (resp_len < sizeof(resp)) {
		fprintf(stderr, "stat conn: short response (%u < %zu)\n",
		    resp_len, sizeof(resp));
		return (1);
	}

	printf("Active connections:  %u\n", resp.num_active_connections);
	printf("Max active:          %u\n", resp.max_active_connections);
	return (0);
}

/* ------------------------------------------------------------------ */
/* iface                                                              */
/* ------------------------------------------------------------------ */

static int
stat_iface(int argc, char **argv, int fd)
{
	fpp_stat_interface_cmd_t cmd;
	fpp_stat_interface_pkt_response_t resp;
	uint16_t resp_len;
	int16_t rc;
	int consumed;
	uint16_t iface_num;

	if (argc < 1) {
		fprintf(stderr,
		    "usage: cmmctl stat iface <dtsecN|num> [reset]\n");
		return (1);
	}

	if (parse_iface(argv[0], &iface_num) < 0) {
		fprintf(stderr, "stat iface: invalid interface '%s'\n",
		    argv[0]);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = parse_action(argc - 1, argv + 1, &consumed);
	cmd.interface = iface_num;

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_STAT_INTERFACE_PKT, &cmd, sizeof(cmd),
	    &rc, &resp, &resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "stat iface %s: error %d\n", argv[0], rc);
		return (1);
	}
	if (resp_len < sizeof(resp)) {
		fprintf(stderr, "stat iface: short response (%u < %zu)\n",
		    resp_len, sizeof(resp));
		return (1);
	}

	printf("Interface %s (CDX %u):\n", argv[0], iface_num);
	printf("  RX packets:  %u\n", resp.total_pkts_received);
	printf("  TX packets:  %u\n", resp.total_pkts_transmitted);
	printf("  RX bytes:    %llu\n",
	    (unsigned long long)bytes64(resp.total_bytes_received));
	printf("  TX bytes:    %llu\n",
	    (unsigned long long)bytes64(resp.total_bytes_transmitted));
	return (0);
}

/* ------------------------------------------------------------------ */
/* queue                                                              */
/* ------------------------------------------------------------------ */

static int
stat_queue(int argc, char **argv, int fd)
{
	fpp_stat_queue_cmd_t cmd;
	fpp_stat_queue_response_t resp;
	uint16_t resp_len;
	int16_t rc;
	int consumed;
	uint16_t iface_num;
	unsigned long qnum;
	char *endptr;

	if (argc < 2) {
		fprintf(stderr,
		    "usage: cmmctl stat queue <dtsecN|num> <queue> [reset]\n");
		return (1);
	}

	if (parse_iface(argv[0], &iface_num) < 0) {
		fprintf(stderr, "stat queue: invalid interface '%s'\n",
		    argv[0]);
		return (1);
	}

	qnum = strtoul(argv[1], &endptr, 0);
	if (argv[1] == endptr || qnum > 65535) {
		fprintf(stderr, "stat queue: invalid queue number '%s'\n",
		    argv[1]);
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = parse_action(argc - 2, argv + 2, &consumed);
	cmd.interface = iface_num;
	cmd.queue = (uint16_t)qnum;

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_STAT_QUEUE, &cmd, sizeof(cmd),
	    &rc, &resp, &resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "stat queue %s %lu: error %d\n",
		    argv[0], qnum, rc);
		return (1);
	}
	if (resp_len < sizeof(resp)) {
		fprintf(stderr, "stat queue: short response (%u < %zu)\n",
		    resp_len, sizeof(resp));
		return (1);
	}

	printf("Interface %s queue %lu:\n", argv[0], qnum);
	printf("  Peak queue occupancy:  %u\n", resp.peak_queue_occ);
	printf("  Emitted packets:       %u\n", resp.emitted_pkts);
	printf("  Dropped packets:       %u\n", resp.dropped_pkts);
	return (0);
}

/* ------------------------------------------------------------------ */
/* vlan (two-phase STATUS/ENTRY iteration)                            */
/* ------------------------------------------------------------------ */

static void
print_vlan_entry(const fpp_stat_vlan_entry_response_t *e)
{

	printf("  VLAN %-4u  %-16s on %-16s\n",
	    e->vlanID, e->vlanifname, e->phyifname);
	printf("    RX packets:  %-10u  TX packets:  %u\n",
	    e->total_packets_received, e->total_packets_transmitted);
	printf("    RX bytes:    %-10llu  TX bytes:    %llu\n",
	    (unsigned long long)bytes64(e->total_bytes_received),
	    (unsigned long long)bytes64(e->total_bytes_transmitted));
}

static int
stat_vlan(int argc, char **argv, int fd)
{
	fpp_stat_vlan_status_cmd_t cmd;
	fpp_stat_vlan_entry_response_t entry;
	uint16_t resp_len;
	int16_t rc;
	int consumed, count;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = parse_action(argc, argv, &consumed);

	/* Phase 1: STATUS — initializes CDX-side iterator */
	resp_len = 0;
	if (ctrl_command(fd, FPP_CMD_STAT_VLAN_STATUS, &cmd, sizeof(cmd),
	    &rc, NULL, &resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "stat vlan: error %d\n", rc);
		return (1);
	}

	/* Phase 2: ENTRY — iterate until eof */
	count = 0;
	for (;;) {
		memset(&entry, 0, sizeof(entry));
		resp_len = sizeof(entry);
		if (ctrl_command(fd, FPP_CMD_STAT_VLAN_ENTRY, NULL, 0,
		    &rc, &entry, &resp_len) < 0)
			return (1);
		if (rc != 0 || entry.eof)
			break;
		if (resp_len < sizeof(entry))
			break;
		print_vlan_entry(&entry);
		count++;
	}

	if (count == 0)
		printf("No VLAN entries.\n");
	return (0);
}

/* ------------------------------------------------------------------ */
/* tunnel (two-phase STATUS/ENTRY iteration)                          */
/* ------------------------------------------------------------------ */

static void
print_tunnel_entry(const fpp_stat_tunnel_entry_response_t *e)
{

	printf("  %-16s\n", e->if_name);
	printf("    RX packets:  %-10u  TX packets:  %u\n",
	    e->total_packets_received, e->total_packets_transmitted);
	printf("    RX bytes:    %-10llu  TX bytes:    %llu\n",
	    (unsigned long long)bytes64(e->total_bytes_received),
	    (unsigned long long)bytes64(e->total_bytes_transmitted));
}

static int
stat_tunnel(int argc, char **argv, int fd)
{
	fpp_stat_tunnel_status_cmd_t cmd;
	fpp_stat_tunnel_entry_response_t entry;
	uint16_t resp_len;
	int16_t rc;
	int consumed, count, argidx;

	memset(&cmd, 0, sizeof(cmd));

	/* Optional: tunnel name filter */
	argidx = 0;
	if (argc > 0 && strcmp(argv[0], "reset") != 0) {
		strlcpy(cmd.if_name, argv[0], sizeof(cmd.if_name));
		argidx = 1;
	}

	cmd.action = parse_action(argc - argidx, argv + argidx, &consumed);

	/* Phase 1: STATUS */
	resp_len = 0;
	if (ctrl_command(fd, FPP_CMD_STAT_TUNNEL_STATUS, &cmd, sizeof(cmd),
	    &rc, NULL, &resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "stat tunnel: error %d\n", rc);
		return (1);
	}

	/* Phase 2: ENTRY — iterate until eof */
	count = 0;
	for (;;) {
		memset(&entry, 0, sizeof(entry));
		resp_len = sizeof(entry);
		if (ctrl_command(fd, FPP_CMD_STAT_TUNNEL_ENTRY, NULL, 0,
		    &rc, &entry, &resp_len) < 0)
			return (1);
		if (rc != 0 || entry.eof)
			break;
		if (resp_len < sizeof(entry))
			break;
		print_tunnel_entry(&entry);
		count++;
	}

	if (count == 0)
		printf("No tunnel entries.\n");
	return (0);
}

/* ------------------------------------------------------------------ */
/* ipsec (two-phase STATUS/ENTRY iteration)                           */
/* ------------------------------------------------------------------ */

static void
print_ipsec_entry(const fpp_stat_ipsec_entry_response_t *e)
{
	char buf[INET6_ADDRSTRLEN];
	const char *proto_str;

	proto_str = (e->proto == 50) ? "ESP" :
	    (e->proto == 51) ? "AH" : "?";

	if (e->family == 4)
		inet_ntop(AF_INET, e->dst_ip, buf, sizeof(buf));
	else
		inet_ntop(AF_INET6, e->dst_ip, buf, sizeof(buf));

	printf("  %s SPI=0x%08x dst=%s SAGD=%u",
	    proto_str, e->spi, buf, e->sagd);
#if defined(LS1043)
	if (e->seqOverflow)
		printf(" seqOverflow=%u", e->seqOverflow);
#endif
	printf("\n");
	printf("    Packets: %u  Bytes: %llu\n",
	    e->total_pkts_processed,
	    (unsigned long long)bytes64(e->total_bytes_processed));
}

static int
stat_ipsec(int argc, char **argv, int fd)
{
	fpp_stat_ipsec_status_cmd_t cmd;
	fpp_stat_ipsec_entry_response_t entry;
	uint16_t resp_len;
	int16_t rc;
	int consumed, count;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = parse_action(argc, argv, &consumed);

	/* Phase 1: STATUS */
	resp_len = 0;
	if (ctrl_command(fd, FPP_CMD_STAT_IPSEC_STATUS, &cmd, sizeof(cmd),
	    &rc, NULL, &resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "stat ipsec: error %d\n", rc);
		return (1);
	}

	/* Phase 2: ENTRY — iterate until eof */
	count = 0;
	for (;;) {
		memset(&entry, 0, sizeof(entry));
		resp_len = sizeof(entry);
		if (ctrl_command(fd, FPP_CMD_STAT_IPSEC_ENTRY, NULL, 0,
		    &rc, &entry, &resp_len) < 0)
			return (1);
		if (rc != 0 || entry.eof)
			break;
		if (resp_len < sizeof(entry))
			break;
		print_ipsec_entry(&entry);
		count++;
	}

	if (count == 0)
		printf("No IPsec SA entries.\n");
	return (0);
}

/* ------------------------------------------------------------------ */
/* flow (single 5-tuple query)                                        */
/* ------------------------------------------------------------------ */

static int
stat_flow(int argc, char **argv, int fd)
{
	fpp_stat_flow_status_cmd_t cmd;
	fpp_stat_flow_entry_response_t resp;
	uint16_t resp_len;
	int16_t rc;
	int consumed;
	unsigned long proto, sport, dport;
	char *endptr;
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];

	if (argc < 5) {
		fprintf(stderr,
		    "usage: cmmctl stat flow <proto> <sip> <dip> "
		    "<sport> <dport> [reset]\n");
		return (1);
	}

	memset(&cmd, 0, sizeof(cmd));

	/* Protocol */
	proto = strtoul(argv[0], &endptr, 0);
	if (argv[0] == endptr || proto > 255) {
		fprintf(stderr, "stat flow: invalid protocol '%s'\n",
		    argv[0]);
		return (1);
	}
	cmd.Protocol = (uint8_t)proto;

	/* Source IP */
	if (inet_pton(AF_INET, argv[1], &cmd.Saddr) == 1) {
		cmd.ip_family = 4;
	} else if (inet_pton(AF_INET6, argv[1], cmd.Saddr_v6) == 1) {
		cmd.ip_family = 6;
	} else {
		fprintf(stderr, "stat flow: invalid source IP '%s'\n",
		    argv[1]);
		return (1);
	}

	/* Dest IP — must match family */
	if (cmd.ip_family == 4) {
		if (inet_pton(AF_INET, argv[2], &cmd.Daddr) != 1) {
			fprintf(stderr,
			    "stat flow: invalid dest IPv4 '%s'\n", argv[2]);
			return (1);
		}
	} else {
		if (inet_pton(AF_INET6, argv[2], cmd.Daddr_v6) != 1) {
			fprintf(stderr,
			    "stat flow: invalid dest IPv6 '%s'\n", argv[2]);
			return (1);
		}
	}

	/* Source port */
	sport = strtoul(argv[3], &endptr, 0);
	if (argv[3] == endptr || sport > 65535) {
		fprintf(stderr, "stat flow: invalid source port '%s'\n",
		    argv[3]);
		return (1);
	}
	cmd.Sport = (uint16_t)sport;

	/* Dest port */
	dport = strtoul(argv[4], &endptr, 0);
	if (argv[4] == endptr || dport > 65535) {
		fprintf(stderr, "stat flow: invalid dest port '%s'\n",
		    argv[4]);
		return (1);
	}
	cmd.Dport = (uint16_t)dport;

	cmd.action = (uint8_t)parse_action(argc - 5, argv + 5, &consumed);

	resp_len = sizeof(resp);
	if (ctrl_command(fd, FPP_CMD_STAT_FLOW, &cmd, sizeof(cmd),
	    &rc, &resp, &resp_len) < 0)
		return (1);
	if (rc != 0) {
		fprintf(stderr, "stat flow: error %d (flow not found?)\n", rc);
		return (1);
	}
	if (resp_len < sizeof(resp)) {
		fprintf(stderr, "stat flow: short response (%u < %zu)\n",
		    resp_len, sizeof(resp));
		return (1);
	}

	if (resp.ip_family == 4) {
		inet_ntop(AF_INET, &resp.Saddr, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET, &resp.Daddr, dbuf, sizeof(dbuf));
	} else {
		inet_ntop(AF_INET6, resp.Saddr_v6, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET6, resp.Daddr_v6, dbuf, sizeof(dbuf));
	}

	printf("Flow: proto=%u %s:%u -> %s:%u\n",
	    resp.Protocol, sbuf, resp.Sport, dbuf, resp.Dport);
	printf("  Packets: %llu\n", (unsigned long long)resp.TotalPackets);
	printf("  Bytes:   %llu\n", (unsigned long long)resp.TotalBytes);
	return (0);
}

/* ------------------------------------------------------------------ */
/* route (IPR reassembly stats)                                       */
/* ------------------------------------------------------------------ */

/*
 * IPR stats response — mirrors struct ipr_statistics in CDX.
 * Defined locally to avoid pulling in fm_ehash.h.
 */
struct ipr_stats_resp {
	uint16_t	ackstatus;
	uint16_t	pad;		/* alignment */
	uint64_t	num_frag_pkts;
	uint64_t	num_reassemblies;
	uint64_t	num_completed_reassly;
	uint64_t	num_sess_matches;
	uint64_t	num_frags_too_small;
	uint64_t	num_reassm_timeouts;
	uint64_t	num_overlapping_frags;
	uint64_t	num_too_many_frags;
	uint64_t	num_failed_bufallocs;
	uint64_t	num_failed_ctxallocs;
} __attribute__((__packed__));

static void
print_ipr_stats(const char *label, const struct ipr_stats_resp *s)
{

	printf("%s reassembly statistics:\n", label);
	printf("  Fragment packets:       %llu\n",
	    (unsigned long long)s->num_frag_pkts);
	printf("  Reassemblies started:   %llu\n",
	    (unsigned long long)s->num_reassemblies);
	printf("  Reassemblies completed: %llu\n",
	    (unsigned long long)s->num_completed_reassly);
	printf("  Session matches:        %llu\n",
	    (unsigned long long)s->num_sess_matches);
	printf("  Fragments too small:    %llu\n",
	    (unsigned long long)s->num_frags_too_small);
	printf("  Reassembly timeouts:    %llu\n",
	    (unsigned long long)s->num_reassm_timeouts);
	printf("  Overlapping fragments:  %llu\n",
	    (unsigned long long)s->num_overlapping_frags);
	printf("  Too many fragments:     %llu\n",
	    (unsigned long long)s->num_too_many_frags);
	printf("  Failed buffer allocs:   %llu\n",
	    (unsigned long long)s->num_failed_bufallocs);
	printf("  Failed context allocs:  %llu\n",
	    (unsigned long long)s->num_failed_ctxallocs);
}

static int
stat_route(int argc, char **argv, int fd)
{
	struct ipr_stats_resp resp;
	uint16_t resp_len;
	int16_t rc;
	int do_v4 = 1, do_v6 = 1;

	if (argc >= 1) {
		if (strcmp(argv[0], "v4") == 0)
			do_v6 = 0;
		else if (strcmp(argv[0], "v6") == 0)
			do_v4 = 0;
		else {
			fprintf(stderr,
			    "usage: cmmctl stat route [v4|v6]\n");
			return (1);
		}
	}

	if (do_v4) {
		memset(&resp, 0, sizeof(resp));
		resp_len = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_IPR_V4_STATS, NULL, 0,
		    &rc, &resp, &resp_len) < 0)
			return (1);
		if (rc != 0) {
			fprintf(stderr, "stat route v4: error %d\n", rc);
			return (1);
		}
		print_ipr_stats("IPv4", &resp);
	}

	if (do_v6) {
		memset(&resp, 0, sizeof(resp));
		resp_len = sizeof(resp);
		if (ctrl_command(fd, FPP_CMD_IPR_V6_STATS, NULL, 0,
		    &rc, &resp, &resp_len) < 0)
			return (1);
		if (rc != 0) {
			fprintf(stderr, "stat route v6: error %d\n", rc);
			return (1);
		}
		print_ipr_stats("IPv6", &resp);
	}

	return (0);
}

/* ------------------------------------------------------------------ */
/* Top-level dispatcher                                               */
/* ------------------------------------------------------------------ */

static void
stat_usage(void)
{

	fprintf(stderr,
	    "usage: cmmctl stat <command> [args...]\n\n"
	    "Control:\n"
	    "  enable <feature>           Enable stat collection\n"
	    "  disable <feature>          Disable stat collection\n"
	    "    features: queue interface pppoe bridge ipsec "
	    "vlan tunnel flow\n\n"
	    "Query:\n"
	    "  conn [reset]               Connection counts\n"
	    "  iface <name> [reset]       Interface packet/byte counters\n"
	    "  queue <iface> <q> [reset]  Queue counters\n"
	    "  vlan [reset]               VLAN counters (all entries)\n"
	    "  tunnel [name] [reset]      Tunnel counters\n"
	    "  ipsec [reset]              IPsec SA counters\n"
	    "  flow <proto> <sip> <dip> <sport> <dport> [reset]\n"
	    "                             Per-flow counters\n"
	    "  route [v4|v6]              IP reassembly stats\n\n"
	    "Adding 'reset' performs atomic query-and-reset.\n");
}

int
cmmctl_stat_main(int argc, char **argv, int fd)
{

	if (argc < 1) {
		stat_usage();
		return (1);
	}

	if (strcasecmp(argv[0], "enable") == 0)
		return (stat_enable(argc - 1, argv + 1, fd,
		    FPP_CMM_STAT_ENABLE));
	if (strcasecmp(argv[0], "disable") == 0)
		return (stat_enable(argc - 1, argv + 1, fd,
		    FPP_CMM_STAT_DISABLE));
	if (strcasecmp(argv[0], "conn") == 0)
		return (stat_conn(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "iface") == 0)
		return (stat_iface(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "queue") == 0)
		return (stat_queue(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "vlan") == 0)
		return (stat_vlan(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "tunnel") == 0)
		return (stat_tunnel(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "ipsec") == 0)
		return (stat_ipsec(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "flow") == 0)
		return (stat_flow(argc - 1, argv + 1, fd));
	if (strcasecmp(argv[0], "route") == 0)
		return (stat_route(argc - 1, argv + 1, fd));

	fprintf(stderr, "cmmctl stat: unknown command '%s'\n", argv[0]);
	stat_usage();
	return (1);
}
