/*
 * cmm_itf.h — Interface monitoring
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_ITF_H
#define CMM_ITF_H

#include "cmm.h"

#define ITF_HASH_SIZE	64

struct cmm_ifaddr {
	struct list_head	entry;
	sa_family_t		family;
	union {
		struct in_addr	v4;
		struct in6_addr	v6;
	} addr;
	uint8_t			prefixlen;
};

/* CMM-internal interface flags (itf_flags, distinct from IFF_* flags) */
#define ITF_F_VLAN		(1 << 0)	/* 802.1Q VLAN interface */
#define ITF_F_FPP_VLAN		(1 << 1)	/* VLAN registered in CDX */
#define ITF_F_TUNNEL		(1 << 2)	/* Tunnel interface (gif/gre) */
#define ITF_F_FPP_TNL		(1 << 3)	/* Tunnel registered in CDX */
#define ITF_F_BRIDGE		(1 << 4)	/* Bridge interface */
#define ITF_F_L2TP		(1 << 5)	/* L2TP tunnel interface */
#define ITF_F_FPP_L2TP		(1 << 6)	/* L2TP registered in CDX */
#define ITF_F_WIFI		(1 << 7)	/* WiFi VAP interface */
#define ITF_F_FPP_WIFI		(1 << 8)	/* WiFi VAP registered in CDX */
#define ITF_F_LAGG		(1 << 9)	/* LAGG (link aggregation) */
#define ITF_F_FPP_LAGG		(1 << 10)	/* LAGG registered in CDX */
#define ITF_F_PPPOE		(1 << 11)	/* PPPoE session interface */
#define ITF_F_FPP_PPPOE	(1 << 12)	/* PPPoE registered in CDX */

struct cmm_route;

struct cmm_interface {
	struct list_head	entry;		/* hash bucket chain */
	char			ifname[IFNAMSIZ];
	int			ifindex;
	int			parent_ifindex;	/* physical parent (VLAN) */
	uint8_t			macaddr[ETHER_ADDR_LEN];
	uint32_t		mtu;
	uint32_t		flags;		/* IFF_UP, IFF_RUNNING, ... */
	uint8_t			link_state;	/* LINK_STATE_UP/DOWN/UNKNOWN */
	uint32_t		itf_flags;	/* ITF_F_* */
	uint16_t		vlan_id;
	struct list_head	addrs;		/* cmm_ifaddr list */
	/* Tunnel state (valid when ITF_F_TUNNEL set) */
	uint8_t			tnl_mode;	/* TNL_6O4, TNL_4O6, ... */
	sa_family_t		tnl_family;	/* outer address family */
	uint8_t			tnl_local[16];	/* local endpoint */
	uint8_t			tnl_remote[16];	/* remote endpoint */
	struct cmm_route	*tnl_route;	/* route to remote */
	/* L2TP state (valid when ITF_F_L2TP set) */
	uint16_t		l2tp_local_tun_id;
	uint16_t		l2tp_peer_tun_id;
	uint16_t		l2tp_local_ses_id;
	uint16_t		l2tp_peer_ses_id;
	uint16_t		l2tp_options;
	uint16_t		l2tp_sock_id;	/* cmm_socket ID */
	/* LAGG state (valid when ITF_F_LAGG set) */
	char			lagg_active_port[IFNAMSIZ];
	char			lagg_members[8][IFNAMSIZ];
	int			lagg_num_members;
	/* PPPoE state (valid when ITF_F_PPPOE set) */
	uint16_t		pppoe_session_id;
	uint8_t			pppoe_peer_mac[ETHER_ADDR_LEN];
	int			pppoe_parent_ifindex;
};

/* Initialize interface table from getifaddrs */
int cmm_itf_init(void);

/* Clean up interface table */
void cmm_itf_fini(void);

/* Handle routing socket messages */
void cmm_itf_handle_ifinfo(struct cmm_global *g, void *msg, int msglen);
void cmm_itf_handle_newaddr(struct cmm_global *g, void *msg, int msglen);
void cmm_itf_handle_deladdr(struct cmm_global *g, void *msg, int msglen);

/* Lookups */
struct cmm_interface *cmm_itf_find_by_index(int ifindex);
struct cmm_interface *cmm_itf_find_by_name(const char *name);

/* Check if an address is local to this machine */
int cmm_itf_is_local_addr(sa_family_t af, const void *addr);

/* Iterate all VLAN interfaces, calling fn for each with ITF_F_VLAN set */
typedef int (*cmm_itf_vlan_fn)(struct cmm_global *, struct cmm_interface *);
void cmm_itf_foreach_vlan(struct cmm_global *g, cmm_itf_vlan_fn fn);

/* Iterate all tunnel interfaces, calling fn for each with ITF_F_TUNNEL set */
typedef int (*cmm_itf_tunnel_fn)(struct cmm_global *, struct cmm_interface *);
void cmm_itf_foreach_tunnel(struct cmm_global *g, cmm_itf_tunnel_fn fn);

/* Iterate all L2TP interfaces, calling fn for each with ITF_F_L2TP set */
typedef int (*cmm_itf_l2tp_fn)(struct cmm_global *, struct cmm_interface *);
void cmm_itf_foreach_l2tp(struct cmm_global *g, cmm_itf_l2tp_fn fn);

/* Iterate all WiFi interfaces, calling fn for each with ITF_F_WIFI set */
typedef int (*cmm_itf_wifi_fn)(struct cmm_global *, struct cmm_interface *);
void cmm_itf_foreach_wifi(struct cmm_global *g, cmm_itf_wifi_fn fn);

/* Iterate all LAGG interfaces, calling fn for each with ITF_F_LAGG set */
typedef int (*cmm_itf_lagg_fn)(struct cmm_global *, struct cmm_interface *);
void cmm_itf_foreach_lagg(struct cmm_global *g, cmm_itf_lagg_fn fn);

/* Iterate all PPPoE interfaces, calling fn for each with ITF_F_PPPOE set */
typedef int (*cmm_itf_pppoe_fn)(struct cmm_global *, struct cmm_interface *);
void cmm_itf_foreach_pppoe(struct cmm_global *g, cmm_itf_pppoe_fn fn);

/* Probe interface for tunnel endpoints (gif/gre) */
void itf_detect_tunnel(struct cmm_interface *itf, int sd);

/* Probe interface for PPPoE session (via netgraph) */
void itf_detect_pppoe(struct cmm_interface *itf);

#endif /* CMM_ITF_H */
