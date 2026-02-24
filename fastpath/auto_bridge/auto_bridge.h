/*
 * auto_bridge.h — L2 flow detection for bridge offload
 *
 * Public header shared between the auto_bridge kernel module and
 * userspace consumers (CMM).  Defines the message format for the
 * /dev/autobridge character device.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef AUTO_BRIDGE_H
#define AUTO_BRIDGE_H

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdint.h>
#endif

#include <net/ethernet.h>

#define ABM_DEV_PATH	"/dev/autobridge"
#define ABM_DEV_NAME	"autobridge"

/* Event types (kernel -> userspace via read()) */
#define ABM_EVENT_FLOW_NEW	1
#define ABM_EVENT_FLOW_UPDATE	2
#define ABM_EVENT_FLOW_DEL	3
#define ABM_EVENT_RESET		4

/* Response flags (userspace -> kernel via write()) */
#define ABM_FLAG_OFFLOADED	0x01
#define ABM_FLAG_DENIED		0x02
#define ABM_FLAG_ACK		0x04

/*
 * L2 flow identification tuple.
 * Matches on MAC pair + ethertype + optional VLAN/PPPoE/L3/L4.
 * Used as hash key in both kernel and CMM hash tables.
 */
struct abm_l2flow {
	uint8_t		saddr[ETHER_ADDR_LEN];	/* source MAC */
	uint8_t		daddr[ETHER_ADDR_LEN];	/* destination MAC */
	uint16_t	ethertype;		/* network byte order */
	uint16_t	svlan_tag;		/* S-VLAN TCI, 0xFFFF=none */
	uint16_t	cvlan_tag;		/* C-VLAN TCI, 0xFFFF=none */
	uint16_t	session_id;		/* PPPoE session, 0=none */
	/* L3/L4 fields — populated only when l3_filtering enabled */
	uint8_t		proto;			/* IPPROTO_*, 0=none */
	uint8_t		pad;
	uint16_t	sport;			/* source port, net order */
	uint16_t	dport;			/* dest port, net order */
	uint16_t	pad2;
	uint32_t	sip[4];			/* source IP (v4 in [0]) */
	uint32_t	dip[4];			/* dest IP (v4 in [0]) */
};

/*
 * Event message: kernel -> CMM (read from /dev/autobridge).
 * Fixed-size for simple ring buffer and framing.
 */
struct abm_event {
	uint8_t		type;		/* ABM_EVENT_* */
	uint8_t		pad[3];
	struct abm_l2flow flow;
	uint32_t	iif_index;	/* input member port ifindex */
	uint32_t	oif_index;	/* output member port ifindex */
	uint16_t	mark;		/* QoS mark */
	uint16_t	pad2;
};

/*
 * Response message: CMM -> kernel (write to /dev/autobridge).
 * Identifies the flow by its L2 tuple and sets flags.
 */
struct abm_response {
	struct abm_l2flow flow;		/* identifies the flow */
	uint32_t	flags;		/* ABM_FLAG_* */
};

#endif /* AUTO_BRIDGE_H */
