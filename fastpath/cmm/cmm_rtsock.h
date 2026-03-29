/*
 * cmm_rtsock.h — PF_ROUTE socket wrapper
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_RTSOCK_H
#define CMM_RTSOCK_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>

/* Open PF_ROUTE socket, returns fd or -1 */
int cmm_rtsock_open(void);

/* Dispatch pending route socket messages (call when kqueue fires) */
void cmm_rtsock_dispatch(struct cmm_global *g);

/*
 * Send RTM_GET and read reply.
 * dst: destination sockaddr (sockaddr_in or sockaddr_in6)
 * flags: RTF_LLINFO for ARP lookup, 0 for route lookup
 * reply: buffer for reply (caller provides, min 512 bytes)
 * replylen: in/out — buffer size / actual reply size
 * Returns 0 on success, -1 on error.
 */
int cmm_rtsock_get(int fd, struct sockaddr *dst, int flags,
    void *reply, size_t *replylen);

/*
 * Parse sockaddrs after a route message header.
 * Fills pointers into the message buffer (no copies).
 */
struct cmm_rtsock_addrs {
	struct sockaddr		*dst;
	struct sockaddr		*gateway;
	struct sockaddr		*netmask;
	struct sockaddr_dl	*ifp;	/* interface name */
	struct sockaddr		*ifa;	/* interface address */
};

void cmm_rtsock_parse_addrs(struct rt_msghdr *rtm, size_t msglen,
    struct cmm_rtsock_addrs *addrs);

/* Sequence number (module-internal, exposed for matching) */
extern int cmm_rtsock_seq;

#endif /* CMM_RTSOCK_H */
