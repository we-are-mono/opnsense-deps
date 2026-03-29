/*
 * cmm_bridge.c — L2 bridge offload module
 *
 * Three logical sections:
 *   1. Bridge detection and port enumeration (FreeBSD ioctls)
 *   2. L2 flow offload (auto_bridge consumer → CDX programming)
 *   3. CDX timeout callback (hardware flow expiry)
 *
 * Combines the functionality of Linux module_rx.c (L2 flow offload)
 * and ffbridge.c (bridge port resolution).
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_bridgevar.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_bridge.h"
#include "cmm_itf.h"
#include "libfci.h"

/* L2 flow hash table */
static struct list_head l2flow_table[CMM_L2FLOW_HASH_SIZE];

/* Detected bridges */
static struct list_head bridge_list;

/* auto_bridge device fd */
static int autobridge_fd = -1;

/* Default flow timeout in CDX (seconds) */
#define CMM_L2FLOW_TIMEOUT_DEFAULT	30

/* ------------------------------------------------------------------ */
/* Section 1: Bridge detection and port enumeration                   */
/* ------------------------------------------------------------------ */

/*
 * Query bridge member ports via SIOCGDRVSPEC / BRDGGIFS ioctl.
 * Populates br->ports list.
 */
static int
bridge_get_ports(struct cmm_bridge *br, int sd)
{
	struct ifdrv ifd;
	struct ifbifconf bif;
	struct ifbreq *breqs;
	uint32_t len;
	int i, count;

	/* First call with len=0 to get required buffer size */
	memset(&ifd, 0, sizeof(ifd));
	strlcpy(ifd.ifd_name, br->ifname, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = BRDGGIFS;
	ifd.ifd_len = sizeof(bif);
	ifd.ifd_data = &bif;

	memset(&bif, 0, sizeof(bif));
	bif.ifbic_len = 0;
	bif.ifbic_buf = NULL;

	if (ioctl(sd, SIOCGDRVSPEC, &ifd) < 0) {
		cmm_print(CMM_LOG_DEBUG,
		    "bridge: BRDGGIFS size query failed for %s: %s",
		    br->ifname, strerror(errno));
		return (-1);
	}

	len = bif.ifbic_len;
	if (len == 0)
		return (0);	/* no member ports */

	breqs = calloc(1, len);
	if (breqs == NULL)
		return (-1);

	bif.ifbic_len = len;
	bif.ifbic_req = breqs;

	if (ioctl(sd, SIOCGDRVSPEC, &ifd) < 0) {
		cmm_print(CMM_LOG_WARN,
		    "bridge: BRDGGIFS failed for %s: %s",
		    br->ifname, strerror(errno));
		free(breqs);
		return (-1);
	}

	count = bif.ifbic_len / sizeof(struct ifbreq);

	for (i = 0; i < count; i++) {
		struct cmm_bridge_port *port;
		int idx;

		idx = if_nametoindex(breqs[i].ifbr_ifsname);
		if (idx == 0)
			continue;

		port = calloc(1, sizeof(*port));
		if (port == NULL)
			continue;

		strlcpy(port->ifname, breqs[i].ifbr_ifsname,
		    sizeof(port->ifname));
		port->ifindex = idx;
		list_add(&br->ports, &port->entry);

		cmm_print(CMM_LOG_DEBUG,
		    "bridge: %s member port: %s (ifindex %d)",
		    br->ifname, port->ifname, port->ifindex);
	}

	free(breqs);
	return (count);
}

/*
 * Free all port entries from a bridge.
 */
static void
bridge_free_ports(struct cmm_bridge *br)
{
	struct list_head *pos, *tmp;

	for (pos = list_first(&br->ports); pos != &br->ports;) {
		tmp = list_next(pos);
		list_del(pos);
		free(container_of(pos, struct cmm_bridge_port, entry));
		pos = tmp;
	}
}

/*
 * Free all bridges and their ports.
 */
static void
bridge_free_all(void)
{
	struct list_head *pos, *tmp;

	for (pos = list_first(&bridge_list); pos != &bridge_list;) {
		tmp = list_next(pos);
		struct cmm_bridge *br = container_of(pos,
		    struct cmm_bridge, entry);
		bridge_free_ports(br);
		list_del(pos);
		free(br);
		pos = tmp;
	}
}

/*
 * Find a bridge record by ifindex.
 */
static struct cmm_bridge *
bridge_find(int ifindex)
{
	struct list_head *pos;

	for (pos = list_first(&bridge_list); pos != &bridge_list;
	    pos = list_next(pos)) {
		struct cmm_bridge *br = container_of(pos,
		    struct cmm_bridge, entry);
		if (br->ifindex == ifindex)
			return (br);
	}
	return (NULL);
}

/*
 * Scan system for bridge interfaces using getifaddrs.
 * Detect bridges by IFT_BRIDGE type in the link-layer address.
 */
static void
bridge_scan(int sd)
{
	struct ifaddrs *ifap, *ifa;

	/* Clear old state */
	bridge_free_all();

	if (getifaddrs(&ifap) < 0) {
		cmm_print(CMM_LOG_ERR, "bridge: getifaddrs: %s",
		    strerror(errno));
		return;
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		struct sockaddr_dl *sdl;
		struct cmm_bridge *br;
		int idx;

		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_type != IFT_BRIDGE)
			continue;

		idx = if_nametoindex(ifa->ifa_name);
		if (idx == 0)
			continue;

		/* Already seen (multiple addrs per interface) */
		if (bridge_find(idx) != NULL)
			continue;

		br = calloc(1, sizeof(*br));
		if (br == NULL)
			continue;

		strlcpy(br->ifname, ifa->ifa_name, sizeof(br->ifname));
		br->ifindex = idx;
		if (sdl->sdl_alen == ETHER_ADDR_LEN)
			memcpy(br->macaddr, LLADDR(sdl), ETHER_ADDR_LEN);
		list_head_init(&br->ports);
		list_add(&bridge_list, &br->entry);

		bridge_get_ports(br, sd);

		cmm_print(CMM_LOG_INFO,
		    "bridge: detected %s (ifindex %d, "
		    "mac %02x:%02x:%02x:%02x:%02x:%02x)",
		    br->ifname, br->ifindex,
		    br->macaddr[0], br->macaddr[1], br->macaddr[2],
		    br->macaddr[3], br->macaddr[4], br->macaddr[5]);
	}

	freeifaddrs(ifap);
}

/*
 * Query bridge FDB to resolve a destination MAC to a physical
 * member port name.  Used by cmm_fe_route_register() when the
 * output interface is a bridge.
 */
int
cmm_bridge_resolve_port(int bridge_ifindex, const uint8_t *dst_mac,
    char *out_ifname, size_t namelen)
{
	struct ifdrv ifd;
	struct ifbaconf bac;
	struct ifbareq *bareqs;
	char brname[IFNAMSIZ];
	uint32_t len;
	int sd, found, i, count;

	if (if_indextoname(bridge_ifindex, brname) == NULL)
		return (-1);

	sd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sd < 0)
		return (-1);

	/* Query FDB size */
	memset(&ifd, 0, sizeof(ifd));
	strlcpy(ifd.ifd_name, brname, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = BRDGRTS;
	ifd.ifd_len = sizeof(bac);
	ifd.ifd_data = &bac;

	memset(&bac, 0, sizeof(bac));
	bac.ifbac_len = 0;
	bac.ifbac_buf = NULL;

	if (ioctl(sd, SIOCGDRVSPEC, &ifd) < 0) {
		close(sd);
		return (-1);
	}

	len = bac.ifbac_len;
	if (len == 0) {
		close(sd);
		return (-1);
	}

	bareqs = calloc(1, len);
	if (bareqs == NULL) {
		close(sd);
		return (-1);
	}

	bac.ifbac_len = len;
	bac.ifbac_req = bareqs;

	if (ioctl(sd, SIOCGDRVSPEC, &ifd) < 0) {
		free(bareqs);
		close(sd);
		return (-1);
	}
	close(sd);

	count = bac.ifbac_len / sizeof(struct ifbareq);
	found = 0;

	for (i = 0; i < count; i++) {
		if (memcmp(bareqs[i].ifba_dst, dst_mac,
		    ETHER_ADDR_LEN) == 0) {
			strlcpy(out_ifname, bareqs[i].ifba_ifsname, namelen);
			found = 1;
			cmm_print(CMM_LOG_DEBUG,
			    "bridge: resolved MAC "
			    "%02x:%02x:%02x:%02x:%02x:%02x → %s "
			    "on %s",
			    dst_mac[0], dst_mac[1], dst_mac[2],
			    dst_mac[3], dst_mac[4], dst_mac[5],
			    out_ifname, brname);
			break;
		}
	}

	free(bareqs);
	return (found ? 0 : -1);
}

/*
 * Rescan bridges after interface change events.
 * Re-enumerate bridges and send BRIDGED_ITF_UPDATE for each member port.
 */
void
cmm_bridge_itf_update(struct cmm_global *g)
{
	struct list_head *bpos, *ppos;
	fpp_bridged_itf_cmd_t cmd;
	int sd;

	sd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sd < 0)
		return;

	bridge_scan(sd);
	close(sd);

	/* Notify CDX about bridged interfaces */
	for (bpos = list_first(&bridge_list); bpos != &bridge_list;
	    bpos = list_next(bpos)) {
		struct cmm_bridge *br = container_of(bpos,
		    struct cmm_bridge, entry);

		for (ppos = list_first(&br->ports); ppos != &br->ports;
		    ppos = list_next(ppos)) {
			struct cmm_bridge_port *port = container_of(ppos,
			    struct cmm_bridge_port, entry);

			memset(&cmd, 0, sizeof(cmd));
			strlcpy(cmd.ifname, port->ifname,
			    sizeof(cmd.ifname));
			cmd.is_bridged = 1;
			memcpy(cmd.br_macaddr, br->macaddr,
			    ETHER_ADDR_LEN);

			if (fci_write(g->fci_handle,
			    FPP_CMD_BRIDGED_ITF_UPDATE,
			    sizeof(cmd), (unsigned short *)&cmd) != 0) {
				cmm_print(CMM_LOG_WARN,
				    "bridge: BRIDGED_ITF_UPDATE "
				    "failed for %s", port->ifname);
			} else {
				cmm_print(CMM_LOG_DEBUG,
				    "bridge: BRIDGED_ITF_UPDATE "
				    "sent for %s (bridge %s)",
				    port->ifname, br->ifname);
			}
		}
	}
}

/* ------------------------------------------------------------------ */
/* Section 2: L2 flow offload (auto_bridge consumer)                  */
/* ------------------------------------------------------------------ */

static inline unsigned int
l2flow_hash(const struct abm_l2flow *flow)
{
	return (jhash(flow, sizeof(*flow), 0x12345678) &
	    (CMM_L2FLOW_HASH_SIZE - 1));
}

static struct cmm_l2flow *
l2flow_find(const struct abm_l2flow *flow)
{
	struct list_head *bucket, *pos;
	unsigned int h;

	h = l2flow_hash(flow);
	bucket = &l2flow_table[h];

	for (pos = list_first(bucket); pos != bucket;
	    pos = list_next(pos)) {
		struct cmm_l2flow *entry = container_of(pos,
		    struct cmm_l2flow, hash_entry);
		if (memcmp(&entry->flow, flow, sizeof(*flow)) == 0)
			return (entry);
	}
	return (NULL);
}

static struct cmm_l2flow *
l2flow_add(const struct abm_l2flow *flow)
{
	struct cmm_l2flow *entry;
	unsigned int h;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return (NULL);

	memcpy(&entry->flow, flow, sizeof(*flow));
	h = l2flow_hash(flow);
	list_add(&l2flow_table[h], &entry->hash_entry);

	return (entry);
}

static void
l2flow_del(struct cmm_l2flow *entry)
{
	list_del(&entry->hash_entry);
	free(entry);
}

/*
 * Deregister a single L2 flow from CDX.
 */
static int
l2flow_fpp_deregister(struct cmm_global *g, struct cmm_l2flow *entry)
{
	fpp_l2_bridge_flow_entry_cmd_t cmd;
	int rc;

	if (!entry->fpp_programmed)
		return (0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_DEREGISTER;
	memcpy(cmd.srcaddr, entry->flow.saddr, ETHER_ADDR_LEN);
	memcpy(cmd.destaddr, entry->flow.daddr, ETHER_ADDR_LEN);
	cmd.ethertype = entry->flow.ethertype;
	cmd.svlan_tag = entry->flow.svlan_tag;
	cmd.cvlan_tag = entry->flow.cvlan_tag;
	cmd.session_id = entry->flow.session_id;
	strlcpy(cmd.input_name, entry->input_name,
	    sizeof(cmd.input_name));

	rc = fci_write(g->fci_handle, FPP_CMD_RX_L2FLOW_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "bridge: L2FLOW deregister failed: %d", rc);
	}

	entry->fpp_programmed = 0;
	return (rc == 0 ? 0 : -1);
}

/*
 * Register or update a L2 flow in CDX.
 */
static int
l2flow_fpp_register(struct cmm_global *g, struct cmm_l2flow *entry,
    int update)
{
	fpp_l2_bridge_flow_entry_cmd_t cmd;
	int rc;

	memset(&cmd, 0, sizeof(cmd));

	if (update && entry->fpp_programmed)
		cmd.action = FPP_ACTION_UPDATE;
	else
		cmd.action = FPP_ACTION_REGISTER;

	cmd.ethertype = entry->flow.ethertype;
	memcpy(cmd.destaddr, entry->flow.daddr, ETHER_ADDR_LEN);
	memcpy(cmd.srcaddr, entry->flow.saddr, ETHER_ADDR_LEN);
	cmd.svlan_tag = entry->flow.svlan_tag;
	cmd.cvlan_tag = entry->flow.cvlan_tag;
	cmd.session_id = entry->flow.session_id;
	cmd.mark = entry->mark;

	/* L3/L4 optional fields */
	cmd.proto = entry->flow.proto;
	memcpy(cmd.saddr, entry->flow.sip, sizeof(cmd.saddr));
	memcpy(cmd.daddr, entry->flow.dip, sizeof(cmd.daddr));
	cmd.sport = entry->flow.sport;
	cmd.dport = entry->flow.dport;

	strlcpy(cmd.input_name, entry->input_name,
	    sizeof(cmd.input_name));
	strlcpy(cmd.output_name, entry->output_name,
	    sizeof(cmd.output_name));

	rc = fci_write(g->fci_handle, FPP_CMD_RX_L2FLOW_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);

	if (rc == 0 || rc == FPP_ERR_BRIDGE_ENTRY_ALREADY_EXISTS) {
		entry->fpp_programmed = 1;
		cmm_print(CMM_LOG_DEBUG,
		    "bridge: L2FLOW %s "
		    "%02x:%02x:%02x:%02x:%02x:%02x -> "
		    "%02x:%02x:%02x:%02x:%02x:%02x "
		    "etype=0x%04x in=%s out=%s",
		    cmd.action == FPP_ACTION_REGISTER ?
		    "registered" : "updated",
		    entry->flow.saddr[0], entry->flow.saddr[1],
		    entry->flow.saddr[2], entry->flow.saddr[3],
		    entry->flow.saddr[4], entry->flow.saddr[5],
		    entry->flow.daddr[0], entry->flow.daddr[1],
		    entry->flow.daddr[2], entry->flow.daddr[3],
		    entry->flow.daddr[4], entry->flow.daddr[5],
		    ntohs(entry->flow.ethertype),
		    entry->input_name, entry->output_name);
		return (0);
	}

	cmm_print(CMM_LOG_WARN,
	    "bridge: L2FLOW register failed: %d", rc);
	return (-1);
}

/*
 * Send a response back to auto_bridge.ko via /dev/autobridge.
 */
static void
autobridge_respond(const struct abm_l2flow *flow, uint32_t flags)
{
	struct abm_response resp;

	if (autobridge_fd < 0)
		return;

	memset(&resp, 0, sizeof(resp));
	memcpy(&resp.flow, flow, sizeof(resp.flow));
	resp.flags = flags;

	if (write(autobridge_fd, &resp, sizeof(resp)) !=
	    (ssize_t)sizeof(resp)) {
		cmm_print(CMM_LOG_WARN,
		    "bridge: write to autobridge failed: %s",
		    strerror(errno));
	}
}

/*
 * Flush all L2 flows — deregister from CDX and free entries.
 */
static void
l2flow_flush_all(struct cmm_global *g)
{
	struct list_head *pos, *tmp;
	int i;

	for (i = 0; i < CMM_L2FLOW_HASH_SIZE; i++) {
		for (pos = list_first(&l2flow_table[i]);
		    pos != &l2flow_table[i];) {
			tmp = list_next(pos);
			struct cmm_l2flow *entry = container_of(pos,
			    struct cmm_l2flow, hash_entry);
			l2flow_fpp_deregister(g, entry);
			l2flow_del(entry);
			pos = tmp;
		}
	}
}

/*
 * Handle a FLOW_NEW event from auto_bridge.
 */
static void
handle_flow_new(struct cmm_global *g, const struct abm_event *ev)
{
	struct cmm_l2flow *entry;
	struct cmm_interface *iif, *oif;

	/* Resolve interface indexes to names */
	iif = cmm_itf_find_by_index(ev->iif_index);
	oif = cmm_itf_find_by_index(ev->oif_index);

	if (iif == NULL || oif == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "bridge: flow_new unknown iif=%u or oif=%u",
		    ev->iif_index, ev->oif_index);
		autobridge_respond(&ev->flow,
		    ABM_FLAG_DENIED | ABM_FLAG_ACK);
		return;
	}

	/* Check for existing entry */
	entry = l2flow_find(&ev->flow);
	if (entry != NULL) {
		/* Update if interfaces changed */
		if (strcmp(entry->input_name, iif->ifname) != 0 ||
		    strcmp(entry->output_name, oif->ifname) != 0) {
			strlcpy(entry->input_name, iif->ifname,
			    sizeof(entry->input_name));
			strlcpy(entry->output_name, oif->ifname,
			    sizeof(entry->output_name));
			entry->mark = ev->mark;
			l2flow_fpp_register(g, entry, 1);
		}
		autobridge_respond(&ev->flow,
		    ABM_FLAG_OFFLOADED | ABM_FLAG_ACK);
		return;
	}

	/* Create new entry */
	entry = l2flow_add(&ev->flow);
	if (entry == NULL) {
		autobridge_respond(&ev->flow,
		    ABM_FLAG_DENIED | ABM_FLAG_ACK);
		return;
	}

	strlcpy(entry->input_name, iif->ifname,
	    sizeof(entry->input_name));
	strlcpy(entry->output_name, oif->ifname,
	    sizeof(entry->output_name));
	entry->mark = ev->mark;

	/* Program CDX */
	if (l2flow_fpp_register(g, entry, 0) == 0) {
		autobridge_respond(&ev->flow,
		    ABM_FLAG_OFFLOADED | ABM_FLAG_ACK);
	} else {
		autobridge_respond(&ev->flow,
		    ABM_FLAG_DENIED | ABM_FLAG_ACK);
		l2flow_del(entry);
	}
}

/*
 * Handle a FLOW_UPDATE event from auto_bridge.
 */
static void
handle_flow_update(struct cmm_global *g, const struct abm_event *ev)
{
	struct cmm_l2flow *entry;
	struct cmm_interface *iif, *oif;

	entry = l2flow_find(&ev->flow);
	if (entry == NULL) {
		/* Treat as new */
		handle_flow_new(g, ev);
		return;
	}

	iif = cmm_itf_find_by_index(ev->iif_index);
	oif = cmm_itf_find_by_index(ev->oif_index);

	if (iif == NULL || oif == NULL) {
		cmm_print(CMM_LOG_WARN,
		    "bridge: flow_update unknown interfaces");
		return;
	}

	/* Update interfaces if changed */
	if (strcmp(entry->input_name, iif->ifname) != 0 ||
	    strcmp(entry->output_name, oif->ifname) != 0 ||
	    entry->mark != ev->mark) {
		strlcpy(entry->input_name, iif->ifname,
		    sizeof(entry->input_name));
		strlcpy(entry->output_name, oif->ifname,
		    sizeof(entry->output_name));
		entry->mark = ev->mark;
		l2flow_fpp_register(g, entry, 1);
	}

	autobridge_respond(&ev->flow,
	    ABM_FLAG_OFFLOADED | ABM_FLAG_ACK);
}

/*
 * Handle a FLOW_DEL event from auto_bridge.
 */
static void
handle_flow_del(struct cmm_global *g, const struct abm_event *ev)
{
	struct cmm_l2flow *entry;

	entry = l2flow_find(&ev->flow);
	if (entry == NULL) {
		cmm_print(CMM_LOG_DEBUG,
		    "bridge: flow_del for unknown flow");
		autobridge_respond(&ev->flow, ABM_FLAG_ACK);
		return;
	}

	l2flow_fpp_deregister(g, entry);
	l2flow_del(entry);

	autobridge_respond(&ev->flow, ABM_FLAG_ACK);

	cmm_print(CMM_LOG_DEBUG,
	    "bridge: flow deleted "
	    "%02x:%02x:%02x:%02x:%02x:%02x -> "
	    "%02x:%02x:%02x:%02x:%02x:%02x",
	    ev->flow.saddr[0], ev->flow.saddr[1],
	    ev->flow.saddr[2], ev->flow.saddr[3],
	    ev->flow.saddr[4], ev->flow.saddr[5],
	    ev->flow.daddr[0], ev->flow.daddr[1],
	    ev->flow.daddr[2], ev->flow.daddr[3],
	    ev->flow.daddr[4], ev->flow.daddr[5]);
}

/*
 * Handle a RESET event from auto_bridge.
 */
static void
handle_reset(struct cmm_global *g)
{
	int rc;

	cmm_print(CMM_LOG_INFO, "bridge: reset — flushing all flows");

	rc = fci_write(g->fci_handle, FPP_CMD_RX_L2BRIDGE_FLOW_RESET,
	    0, NULL);
	if (rc != 0)
		cmm_print(CMM_LOG_WARN,
		    "bridge: FLOW_RESET failed: %d", rc);

	l2flow_flush_all(g);
}

/*
 * Read and dispatch events from /dev/autobridge.
 * Called from the kqueue event loop when the fd is readable.
 */
void
cmm_bridge_event(struct cmm_global *g)
{
	struct abm_event ev;
	ssize_t n;

	for (;;) {
		n = read(autobridge_fd, &ev, sizeof(ev));
		if (n != (ssize_t)sizeof(ev)) {
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
				break;
			if (n == 0) {
				cmm_print(CMM_LOG_WARN,
				    "bridge: /dev/autobridge closed");
				break;
			}
			cmm_print(CMM_LOG_WARN,
			    "bridge: short read from autobridge: %zd", n);
			break;
		}

		switch (ev.type) {
		case ABM_EVENT_FLOW_NEW:
			handle_flow_new(g, &ev);
			break;
		case ABM_EVENT_FLOW_UPDATE:
			handle_flow_update(g, &ev);
			break;
		case ABM_EVENT_FLOW_DEL:
			handle_flow_del(g, &ev);
			break;
		case ABM_EVENT_RESET:
			handle_reset(g);
			break;
		default:
			cmm_print(CMM_LOG_WARN,
			    "bridge: unknown event type %u", ev.type);
			break;
		}
	}
}

/* ------------------------------------------------------------------ */
/* Section 3: CDX timeout callback                                    */
/* ------------------------------------------------------------------ */

/*
 * FCI event handler for FPP_CMD_RX_L2FLOW_ENTRY.
 * When CDX sends ACTION_REMOVED (flow timed out in hardware),
 * remove from our hash table and notify auto_bridge.
 *
 * Called from the top-level FCI event dispatcher in cmm.c.
 * Returns FCI_CB_CONTINUE for unrecognized events.
 */
int
cmm_bridge_fci_event(unsigned short fcode, unsigned short len,
    unsigned short *payload)
{
	fpp_l2_bridge_flow_entry_cmd_t *cmd;
	struct abm_l2flow flow;
	struct cmm_l2flow *entry;

	if (fcode != FPP_CMD_RX_L2FLOW_ENTRY)
		return (FCI_CB_CONTINUE);

	if (len < sizeof(*cmd))
		return (FCI_CB_CONTINUE);

	cmd = (fpp_l2_bridge_flow_entry_cmd_t *)payload;

	if (cmd->action != FPP_ACTION_REMOVED)
		return (FCI_CB_CONTINUE);

	cmm_print(CMM_LOG_DEBUG,
	    "bridge: CDX removed flow "
	    "%02x:%02x:%02x:%02x:%02x:%02x -> "
	    "%02x:%02x:%02x:%02x:%02x:%02x (timeout)",
	    cmd->srcaddr[0], cmd->srcaddr[1],
	    cmd->srcaddr[2], cmd->srcaddr[3],
	    cmd->srcaddr[4], cmd->srcaddr[5],
	    cmd->destaddr[0], cmd->destaddr[1],
	    cmd->destaddr[2], cmd->destaddr[3],
	    cmd->destaddr[4], cmd->destaddr[5]);

	/*
	 * Build the flow key to look up in our hash table.
	 * The CDX command contains the same fields we need.
	 */
	memset(&flow, 0, sizeof(flow));
	memcpy(flow.saddr, cmd->srcaddr, ETHER_ADDR_LEN);
	memcpy(flow.daddr, cmd->destaddr, ETHER_ADDR_LEN);
	flow.ethertype = cmd->ethertype;
	flow.svlan_tag = cmd->svlan_tag;
	flow.cvlan_tag = cmd->cvlan_tag;
	flow.session_id = cmd->session_id;
	flow.proto = cmd->proto;
	flow.sport = cmd->sport;
	flow.dport = cmd->dport;
	memcpy(flow.sip, cmd->saddr, sizeof(flow.sip));
	memcpy(flow.dip, cmd->daddr, sizeof(flow.dip));

	entry = l2flow_find(&flow);
	if (entry != NULL) {
		entry->fpp_programmed = 0;	/* already removed by CDX */
		l2flow_del(entry);
	}

	/* Notify auto_bridge so it can clean up kernel state */
	autobridge_respond(&flow, ABM_FLAG_ACK);

	return (FCI_CB_CONTINUE);
}

/* ------------------------------------------------------------------ */
/* Module lifecycle                                                    */
/* ------------------------------------------------------------------ */

/*
 * Enable L2 bridge on each detected bridge member port in CDX.
 */
static void
bridge_enable_ports(struct cmm_global *g)
{
	struct list_head *bpos, *ppos;

	for (bpos = list_first(&bridge_list); bpos != &bridge_list;
	    bpos = list_next(bpos)) {
		struct cmm_bridge *br = container_of(bpos,
		    struct cmm_bridge, entry);

		for (ppos = list_first(&br->ports); ppos != &br->ports;
		    ppos = list_next(ppos)) {
			struct cmm_bridge_port *port = container_of(ppos,
			    struct cmm_bridge_port, entry);
			fpp_l2_bridge_enable_cmd_t ecmd;

			memset(&ecmd, 0, sizeof(ecmd));
			ecmd.enable_flag = 1;
			strlcpy(ecmd.input_name, port->ifname,
			    sizeof(ecmd.input_name));

			if (fci_write(g->fci_handle,
			    FPP_CMD_RX_L2BRIDGE_ENABLE,
			    sizeof(ecmd),
			    (unsigned short *)&ecmd) != 0) {
				cmm_print(CMM_LOG_WARN,
				    "bridge: L2BRIDGE_ENABLE "
				    "failed for %s", port->ifname);
			} else {
				cmm_print(CMM_LOG_INFO,
				    "bridge: L2BRIDGE enabled "
				    "on %s", port->ifname);
			}
		}
	}
}

int
cmm_bridge_init(struct cmm_global *g)
{
	fpp_l2_bridge_control_cmd_t ctrl;
	int sd, i;

	/* Initialize hash table */
	for (i = 0; i < CMM_L2FLOW_HASH_SIZE; i++)
		list_head_init(&l2flow_table[i]);

	list_head_init(&bridge_list);

	/* Scan for bridges */
	sd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sd >= 0) {
		bridge_scan(sd);
		close(sd);
	}

	/* Open /dev/autobridge */
	autobridge_fd = open(ABM_DEV_PATH, O_RDWR | O_NONBLOCK);
	if (autobridge_fd < 0) {
		cmm_print(CMM_LOG_WARN,
		    "bridge: open %s: %s — running in manual mode",
		    ABM_DEV_PATH, strerror(errno));

		/* Manual mode: still enable bridge in CDX without
		 * auto flow detection */
		ctrl.mode_timeout = FPP_L2_BRIDGE_MODE_MANUAL;
		fci_write(g->fci_handle, FPP_CMD_RX_L2BRIDGE_MODE,
		    sizeof(ctrl), (unsigned short *)&ctrl);

		bridge_enable_ports(g);
		cmm_bridge_itf_update(g);

		cmm_print(CMM_LOG_INFO,
		    "bridge: initialized (manual mode)");
		return (0);
	}

	/* Store fd in global state for kqueue registration */
	g->autobridge_fd = autobridge_fd;

	/* Enable bridging on all detected member ports */
	bridge_enable_ports(g);

	/* Notify CDX about bridged interfaces */
	cmm_bridge_itf_update(g);

	/* Set auto mode */
	ctrl.mode_timeout = FPP_L2_BRIDGE_MODE_AUTO;
	if (fci_write(g->fci_handle, FPP_CMD_RX_L2BRIDGE_MODE,
	    sizeof(ctrl), (unsigned short *)&ctrl) != 0) {
		cmm_print(CMM_LOG_WARN,
		    "bridge: failed to set AUTO mode");
	} else {
		cmm_print(CMM_LOG_INFO,
		    "bridge: set AUTO mode in CDX");
	}

	/* Set default flow timeout */
	ctrl.mode_timeout = CMM_L2FLOW_TIMEOUT_DEFAULT;
	if (fci_write(g->fci_handle, FPP_CMD_RX_L2BRIDGE_FLOW_TIMEOUT,
	    sizeof(ctrl), (unsigned short *)&ctrl) != 0) {
		cmm_print(CMM_LOG_WARN,
		    "bridge: failed to set flow timeout");
	} else {
		cmm_print(CMM_LOG_INFO,
		    "bridge: set flow timeout to %ds",
		    CMM_L2FLOW_TIMEOUT_DEFAULT);
	}

	cmm_print(CMM_LOG_INFO,
	    "bridge: initialized (auto mode, fd=%d)", autobridge_fd);
	return (0);
}

void
cmm_bridge_fini(struct cmm_global *g)
{
	/* Deregister all flows from CDX */
	l2flow_flush_all(g);

	/* Free bridge records */
	bridge_free_all();

	/* Close autobridge device */
	if (autobridge_fd >= 0) {
		close(autobridge_fd);
		autobridge_fd = -1;
		g->autobridge_fd = -1;
	}

	cmm_print(CMM_LOG_INFO, "bridge: shut down");
}
