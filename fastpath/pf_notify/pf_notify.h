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

/* pfn_event.flags */
#define PFN_EVF_NO_OFFLOAD	0x0001	/* PF must see every packet: TCP
					 * sequence rewriting (modulate
					 * state, synproxy) or a dummynet
					 * pipe, which CDX can't do */

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
	uint16_t		flags;		/* PFN_EVF_* (was padding) */
	char			ifname[16];	/* IFNAMSIZ */
	struct pfn_state_key	key[2];		/* [0]=wire, [1]=stack */
	uint32_t		rt_ifindex;	/* route-to/reply-to egress
						 * ifindex, 0 if pf didn't
						 * override the route for
						 * this state */
	uint8_t			_pad2[4];	/* pad to 128 bytes */
};

#ifdef _KERNEL
_Static_assert(sizeof(struct pfn_event) == 128,
    "pfn_event must be exactly 128 bytes");
#endif

/* --- Counter sync (userspace -> kernel via ioctl) --- */

#define PFN_COUNTER_BATCH_MAX	256

struct pfn_counter_entry {
	uint64_t	id;		/* PF state ID */
	uint32_t	creatorid;	/* PF state creator ID */
	uint32_t	pad;
	uint64_t	packets[2];	/* delta [0]=forward, [1]=reply */
	uint64_t	bytes[2];	/* delta [0]=forward, [1]=reply */
	uint8_t		missing;	/* out: 1 if PF had no matching state */
	uint8_t		pad2[7];
};

struct pfn_counter_update {
	uint32_t	count;		/* number of entries */
	uint32_t	pad;
	struct pfn_counter_entry *entries;	/* userspace pointer, in/out */
};

#ifdef _KERNEL
#include <sys/ioccom.h>
#endif

#define PFN_IOC_UPDATE_COUNTERS	_IOWR('N', 1, struct pfn_counter_update)

/* --- Offload pin (userspace -> kernel via ioctl) --- */

/*
 * A pinned PF state never times out while the hardware carries its flow;
 * CMM unpins it when CDX reports the flow idle or drops it.  Unpinning
 * restarts PF's normal timeout from now.
 */
#define PFN_PIN_BATCH_MAX	256

#define PFN_PIN_OK		0	/* done */
#define PFN_PIN_MISSING		1	/* PF had no matching state */
#define PFN_PIN_CLOSING		2	/* TCP already closing, not pinned */
#define PFN_PIN_OWN_TIMEOUT	3	/* rule sets its own timeout, not
					 * pinned (CDX only has global ones) */

struct pfn_pin_entry {
	uint64_t	id;		/* PF state ID */
	uint32_t	creatorid;	/* PF state creator ID */
	uint8_t		pin;		/* 1 = pin, 0 = unpin */
	uint8_t		result;		/* out: PFN_PIN_* */
	uint8_t		pad[2];
};

struct pfn_pin_update {
	uint32_t	count;		/* number of entries, 0 = support probe */
	uint32_t	pad;
	struct pfn_pin_entry *entries;	/* userspace pointer, in/out */
};

#define PFN_IOC_SET_PIN		_IOWR('N', 2, struct pfn_pin_update)

/* --- Route-to/reply-to lookup (userspace -> kernel via ioctl) --- */

/*
 * The interface and gateway pf's route-to/reply-to picked for a state,
 * so CMM can send the offloaded flow the same way.
 */
struct pfn_state_rt {
	uint64_t	id;		/* PF state ID */
	uint32_t	creatorid;	/* PF state creator ID */
	uint32_t	ifindex;	/* out: egress interface, 0 = none */
	uint8_t		rt;		/* out: PF_ROUTETO/PF_REPLYTO/PF_DUPTO,
					 * 0 = pf routes it normally */
	uint8_t		af;		/* out: gateway address family */
	uint8_t		pad[6];
	uint8_t		addr[16];	/* out: gateway address */
};

#define PFN_IOC_GET_STATE_RT	_IOWR('N', 3, struct pfn_state_rt)

#endif /* PF_NOTIFY_H */
