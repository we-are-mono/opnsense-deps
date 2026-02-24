/*
 * auto_bridge_private.h — Kernel-private structures
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef AUTO_BRIDGE_PRIVATE_H
#define AUTO_BRIDGE_PRIVATE_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/callout.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include "auto_bridge.h"

#define ABM_HASH_SIZE		1024
#define ABM_MAC_HASH_SIZE	128
#define ABM_RING_SIZE		1024	/* event ring buffer entries */
#define ABM_MAX_ENTRIES		5000

/* Timeouts (seconds) */
#define ABM_TIMEOUT_CONFIRMED	120
#define ABM_TIMEOUT_LINUX	10
#define ABM_TIMEOUT_DYING	120

/* L2 flow states */
enum abm_state {
	ABM_STATE_CONFIRMED,	/* detected, event sent to CMM */
	ABM_STATE_FF,		/* CMM offloaded to CDX */
	ABM_STATE_LINUX,	/* CMM denied offload */
	ABM_STATE_DYING,	/* cleanup / port down */
};

/* Internal flags */
#define ABM_FL_NEEDS_UPDATE	0x01
#define ABM_FL_DEAD		0x02
#define ABM_FL_WAIT_ACK		0x04
#define ABM_FL_PENDING_MSG	0x08

/*
 * L2 flow table entry.
 *
 * Three linked lists for different lookup patterns:
 *   - hash_entry:    primary hash by full L2 flow tuple
 *   - src_mac_entry: secondary hash by source MAC (FDB expiry checks)
 *   - dst_mac_entry: secondary hash by dest MAC (MAC movement detection)
 */
struct abm_entry {
	LIST_ENTRY(abm_entry)	hash_entry;
	LIST_ENTRY(abm_entry)	src_mac_entry;
	LIST_ENTRY(abm_entry)	dst_mac_entry;

	struct abm_l2flow	flow;		/* L2 flow tuple */
	uint32_t		iif_index;	/* input interface index */
	uint32_t		oif_index;	/* output interface index */
	uint16_t		mark;		/* QoS mark */
	uint8_t			state;		/* enum abm_state */
	uint8_t			flags;		/* ABM_FL_* */
	struct callout		timer;		/* timeout callout */
	time_t			time_sent;	/* last event send time */
};

LIST_HEAD(abm_hash_head, abm_entry);

/*
 * Ring buffer for kernel -> userspace events.
 * Single producer (hook context), single consumer (read()).
 */
struct abm_ring {
	struct abm_event	events[ABM_RING_SIZE];
	volatile uint32_t	head;	/* next write position */
	volatile uint32_t	tail;	/* next read position */
};

/*
 * Jenkins one-at-a-time hash (portable version).
 */
static inline uint32_t
abm_jenkins_hash(const void *key, size_t len, uint32_t initval)
{
	const uint8_t *p = (const uint8_t *)key;
	uint32_t hash = initval;
	size_t i;

	for (i = 0; i < len; i++) {
		hash += p[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return (hash);
}

static inline uint32_t
abm_flow_hash(const struct abm_l2flow *flow)
{

	return (abm_jenkins_hash(flow, sizeof(*flow), 0x12345678) &
	    (ABM_HASH_SIZE - 1));
}

static inline uint32_t
abm_mac_hash(const uint8_t *mac)
{

	return (abm_jenkins_hash(mac, ETHER_ADDR_LEN, 0x12345678) &
	    (ABM_MAC_HASH_SIZE - 1));
}

#endif /* AUTO_BRIDGE_PRIVATE_H */
