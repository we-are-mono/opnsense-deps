/*
 * cmm_deny.h — Deny-rule filtering for offload eligibility
 *
 * Config-file-driven rules that prevent specific connections
 * from being offloaded to hardware.  Rules match on protocol,
 * source/destination address (with CIDR prefix), ports, and
 * interface name.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_DENY_H
#define CMM_DENY_H

#include <sys/types.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>

#define CMM_DENY_CONF	"/usr/local/etc/cmm_deny.conf"

struct cmm_deny_rule {
	STAILQ_ENTRY(cmm_deny_rule)	entry;
	uint8_t		proto;		/* IPPROTO_TCP/UDP, or 0 = any */
	sa_family_t	af;		/* AF_INET/AF_INET6, or 0 = any */
	struct {
		struct in6_addr	addr;
		uint8_t		prefixlen;	/* 0 = any */
	} src, dst;
	uint16_t	sport;		/* network byte order, 0 = any */
	uint16_t	dport;		/* network byte order, 0 = any */
	char		ifname[IFNAMSIZ]; /* empty = any */
};

STAILQ_HEAD(cmm_deny_list, cmm_deny_rule);

/*
 * Load deny rules from config file.
 * If the file doesn't exist, no rules are loaded (everything offloaded).
 * Returns 0 on success, -1 on fatal error (malloc failure).
 */
int	cmm_deny_init(const char *confpath);

/* Free all deny rules. */
void	cmm_deny_fini(void);

/*
 * Check if a connection should be denied offload by tuple fields.
 * All address/port arguments are in network byte order.
 * Returns 1 if denied (do not offload), 0 if allowed.
 */
int	cmm_deny_check_tuple(sa_family_t af, uint8_t proto,
	    const void *saddr, const void *daddr,
	    uint16_t sport, uint16_t dport, const char *ifname);

/* Return the number of loaded deny rules. */
int	cmm_deny_count(void);

#endif /* CMM_DENY_H */
