/*
 * pf_notify.h — PF state change notification for offload
 *
 * Public header shared between pf_notify.ko and userspace (CMM).
 * Defines the message format for /dev/pfnotify.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PF_NOTIFY_H
#define PF_NOTIFY_H

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdint.h>
#include <sys/types.h>
#endif

#define PFN_DEV_PATH	"/dev/pfnotify"
#define PFN_DEV_NAME	"pfnotify"

/* Event types (kernel -> userspace via read()) */
#define PFN_EVENT_INSERT	1	/* new PF state created */
#define PFN_EVENT_READY		2	/* state is offload-ready */
#define PFN_EVENT_DELETE	3	/* PF state removed */

/*
 * Compact state key — mirrors pf_state_key fields needed by CMM.
 * 40 bytes per key.
 */
struct pfn_state_key {
	uint8_t		addr[2][16];	/* pf_addr[0], pf_addr[1] */
	uint16_t	port[2];	/* network byte order */
	uint8_t		af;		/* sa_family_t */
	uint8_t		proto;		/* IPPROTO_* */
	uint8_t		pad[2];
};

/*
 * PF state notification event.
 *
 * Carries everything CMM needs to create a cmm_conn and determine
 * offload eligibility without any follow-up ioctl:
 *   - Both state keys (wire + stack) for NAT detection
 *   - Peer states for TCP ESTABLISHED / UDP bidirectional check
 *   - State ID for DELETE matching
 *   - Interface name for eligibility filtering
 *
 * Fixed 128 bytes for ring buffer alignment.
 */
struct pfn_event {
	uint8_t			type;		/* PFN_EVENT_* */
	uint8_t			direction;	/* PF_IN or PF_OUT */
	uint8_t			src_state;	/* pf_state_peer src.state */
	uint8_t			dst_state;	/* pf_state_peer dst.state */
	uint8_t			_pad0[4];	/* align id to 8 */
	uint64_t		id;		/* pf_kstate.id */
	uint32_t		creatorid;	/* pf_kstate.creatorid */
	uint16_t		state_flags;	/* pf_kstate.state_flags */
	uint16_t		_pad1;
	char			ifname[16];	/* IFNAMSIZ */
	struct pfn_state_key	key[2];		/* [0]=wire, [1]=stack */
	uint8_t			_pad2[8];	/* pad to 128 bytes */
};

#ifdef _KERNEL
_Static_assert(sizeof(struct pfn_event) == 128,
    "pfn_event must be exactly 128 bytes");
#endif

#endif /* PF_NOTIFY_H */
