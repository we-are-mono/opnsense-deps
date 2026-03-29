/*
 * cmm_bridge.h — L2 bridge offload module
 *
 * Consumes L2 flow events from auto_bridge.ko (/dev/autobridge)
 * and programs CDX via FPP_CMD_RX_L2FLOW_ENTRY.  Also handles
 * bridge port resolution for L3 routes (when the output interface
 * is a bridge, CDX needs the physical member port name).
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_BRIDGE_H
#define CMM_BRIDGE_H

#include "cmm.h"
#include "auto_bridge.h"

#define CMM_L2FLOW_HASH_SIZE	1024

/*
 * L2 flow table entry — tracks flows offloaded to CDX.
 * Keyed by abm_l2flow tuple (same as kernel hash key).
 */
struct cmm_l2flow {
	struct list_head	hash_entry;
	struct abm_l2flow	flow;		/* L2 flow tuple */
	char			input_name[IFNAMSIZ];
	char			output_name[IFNAMSIZ];
	uint16_t		mark;
	int			fpp_programmed;	/* registered in CDX */
};

/*
 * Bridge member port record — cached from BRDGGIFS ioctl.
 */
struct cmm_bridge_port {
	struct list_head	entry;
	char			ifname[IFNAMSIZ];
	int			ifindex;
};

/*
 * Per-bridge record — tracks detected bridges and their ports.
 */
struct cmm_bridge {
	struct list_head	entry;
	char			ifname[IFNAMSIZ];
	int			ifindex;
	uint8_t			macaddr[ETHER_ADDR_LEN];
	struct list_head	ports;		/* cmm_bridge_port list */
};

/* Module lifecycle */
int	cmm_bridge_init(struct cmm_global *g);
void	cmm_bridge_fini(struct cmm_global *g);

/* Called from kqueue event loop when /dev/autobridge is readable */
void	cmm_bridge_event(struct cmm_global *g);

/*
 * Bridge port resolution for L3 routes.
 * When a route's output interface is a bridge, this queries the
 * bridge FDB to find which physical member port can reach dst_mac,
 * writing the port's interface name into out_ifname.
 *
 * Returns 0 on success, -1 if MAC not found in FDB.
 */
int	cmm_bridge_resolve_port(int bridge_ifindex,
	    const uint8_t *dst_mac, char *out_ifname, size_t namelen);

/*
 * Rescan bridges after interface changes (RTM_IFINFO).
 * Detects new/removed bridges and updates member port lists.
 */
void	cmm_bridge_itf_update(struct cmm_global *g);

/*
 * Handle FCI async events (CDX L2 bridge flow timeout notifications).
 * Called from the top-level FCI event dispatcher in cmm.c.
 * Returns FCI_CB_CONTINUE for unrecognized events.
 */
int	cmm_bridge_fci_event(unsigned short fcode, unsigned short len,
	    unsigned short *payload);

#endif /* CMM_BRIDGE_H */
