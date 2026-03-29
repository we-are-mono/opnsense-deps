/*
 * cmm.h — CMM global state and shared definitions
 *
 * Connection Management Module for FreeBSD.
 * Monitors PF state table and routes, programs FMan hash tables
 * via FCI/CDX for hardware flow offload.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_H
#define CMM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "libfci.h"
#include "fpp.h"
#include "fpp_private.h"
#include "list.h"
#include "jhash.h"

/*
 * Debug levels (set via -d flag).
 * 0 = errors only, 1 = warnings, 2 = info, 3 = debug, 4 = trace
 */
#define CMM_LOG_ERR	0
#define CMM_LOG_WARN	1
#define CMM_LOG_INFO	2
#define CMM_LOG_DEBUG	3
#define CMM_LOG_TRACE	4

#define CMM_STATS_SYNC_MS	5000	/* CDX flow counter sync interval */
#define CMM_MAINT_MS		30000	/* maintenance timer (retry + route GC) */
#define CMM_PID_FILE		"/var/run/cmm.pid"

struct cmm_global {
	/* FCI handles */
	FCI_CLIENT	*fci_handle;	/* synchronous command handle */
	FCI_CLIENT	*fci_catch;	/* async event handle */

	/* OS file descriptors */
	int		rtsock_fd;	/* PF_ROUTE socket (monitoring) */
	int		rtsock_query_fd;/* PF_ROUTE socket (RTM_GET queries) */
	int		kq;		/* kqueue fd */
	int		pfkey_fd;	/* PF_KEY socket */
	int		ctrl_listen_fd;	/* control socket (listen) */
	int		ctrl_clients[4];/* control socket clients */
	int		autobridge_fd;	/* /dev/autobridge (L2 bridge) */
	int		pfnotify_fd;	/* /dev/pfnotify (state events) */

	/* Configuration */
	int		debug_level;
	int		foreground;	/* don't daemonize */

	/* Runtime */
	volatile int	running;

	/* Route ID counter */
	uint32_t	next_route_id;

	/* Single-threaded: all processing in kqueue event loop */
};

extern struct cmm_global cmm_g;

/* Logging */
#define cmm_print(level, fmt, ...) do {					\
	if ((level) <= cmm_g.debug_level) {				\
		const char *_pfx[] = { "ERR", "WARN", "INFO",		\
		    "DBG", "TRC" };					\
		fprintf(stderr, "cmm[%s]: " fmt "\n",			\
		    _pfx[(level)], ##__VA_ARGS__);			\
	}								\
} while (0)

#endif /* CMM_H */
