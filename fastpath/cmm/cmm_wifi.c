/*
 * cmm_wifi.c — WiFi VAP offload
 *
 * Detects WiFi VAP interfaces (uap0, uap1, ...) and registers them
 * with CDX via FPP_CMD_WIFI_VAP_ENTRY so the hardware flow offload
 * engine recognizes WiFi as a valid egress/ingress interface.
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/types.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>

#include "cmm.h"
#include "cmm_wifi.h"
#include "cmm_itf.h"

/*
 * Parse VAP ID from interface name: "uap0" → 0, "uap1" → 1, etc.
 * Returns -1 if the name doesn't match a WiFi VAP pattern.
 */
/*
 * Parse VAP ID from interface name.
 * uap interfaces use vapid 0..15, wlan interfaces use 16..31.
 * This avoids collisions since both "uap0" and "wlan0" would
 * otherwise both map to vapid 0.
 */
#define CMM_WLAN_VAPID_BASE	16

static int
cmm_wifi_parse_vapid(const char *ifname)
{
	const char *p;
	int base;

	if (strncmp(ifname, "uap", 3) == 0) {
		p = ifname + 3;
		base = 0;
	} else if (strncmp(ifname, "wlan", 4) == 0) {
		p = ifname + 4;
		base = CMM_WLAN_VAPID_BASE;
	} else {
		return (-1);
	}

	if (*p < '0' || *p > '9')
		return (-1);
	return (base + (int)strtol(p, NULL, 10));
}

static int
cmm_wifi_register(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_wifi_cmd_t cmd;
	int vap_id, rc;

	if (!(itf->itf_flags & ITF_F_WIFI))
		return (0);
	if (itf->itf_flags & ITF_F_FPP_WIFI)
		return (0);	/* already registered */

	vap_id = cmm_wifi_parse_vapid(itf->ifname);
	if (vap_id < 0) {
		cmm_print(CMM_LOG_WARN,
		    "wifi: %s: cannot parse VAP ID", itf->ifname);
		return (-1);
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_VWD_VAP_ADD;
	cmd.vap_id = vap_id;
	strlcpy(cmd.ifname, itf->ifname, sizeof(cmd.ifname));
	memcpy(cmd.mac_addr, itf->macaddr, 6);

	cmm_print(CMM_LOG_INFO,
	    "wifi: sending FPP_CMD_WIFI_VAP_ENTRY (0x%x) for %s "
	    "vapid=%d len=%zu",
	    FPP_CMD_WIFI_VAP_ENTRY, itf->ifname, vap_id,
	    sizeof(cmd));

	rc = fci_write(g->fci_handle, FPP_CMD_WIFI_VAP_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc != 0) {
		cmm_print(CMM_LOG_WARN,
		    "wifi: register %s failed: %d", itf->ifname, rc);
		return (-1);
	}

	itf->itf_flags |= ITF_F_FPP_WIFI;
	cmm_print(CMM_LOG_INFO,
	    "wifi: registered %s (vapid=%d mac=%02x:%02x:%02x:%02x:%02x:%02x)",
	    itf->ifname, vap_id,
	    itf->macaddr[0], itf->macaddr[1], itf->macaddr[2],
	    itf->macaddr[3], itf->macaddr[4], itf->macaddr[5]);

	return (0);
}

static int
cmm_wifi_deregister(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_wifi_cmd_t cmd;
	int vap_id;

	if (!(itf->itf_flags & ITF_F_FPP_WIFI))
		return (0);

	vap_id = cmm_wifi_parse_vapid(itf->ifname);
	if (vap_id < 0)
		return (-1);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_VWD_VAP_REMOVE;
	cmd.vap_id = vap_id;
	strlcpy(cmd.ifname, itf->ifname, sizeof(cmd.ifname));

	fci_write(g->fci_handle, FPP_CMD_WIFI_VAP_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);

	itf->itf_flags &= ~ITF_F_FPP_WIFI;
	cmm_print(CMM_LOG_INFO, "wifi: deregistered %s", itf->ifname);

	return (0);
}

int
cmm_wifi_init(struct cmm_global *g)
{
	int rc;

	/* Reset all WiFi VAP entries in CDX */
	rc = fci_write(g->fci_handle, FPP_CMD_WIFI_VAP_RESET, 0, NULL);
	if (rc != 0)
		cmm_print(CMM_LOG_WARN, "wifi: reset failed: %d", rc);

	/* Register all existing UP WiFi interfaces */
	cmm_itf_foreach_wifi(g, cmm_wifi_register);

	cmm_print(CMM_LOG_INFO, "wifi: initialized");
	return (0);
}

void
cmm_wifi_fini(struct cmm_global *g)
{

	cmm_itf_foreach_wifi(g, cmm_wifi_deregister);
}

void
cmm_wifi_notify(struct cmm_global *g, struct cmm_interface *itf)
{

	if (!(itf->itf_flags & ITF_F_WIFI))
		return;

	cmm_print(CMM_LOG_INFO,
	    "wifi: notify %s flags=0x%x itf_flags=0x%x%s%s",
	    itf->ifname, itf->flags, itf->itf_flags,
	    (itf->flags & IFF_UP) ? " UP" : " DOWN",
	    (itf->itf_flags & ITF_F_FPP_WIFI) ? " REGISTERED" : "");

	if ((itf->flags & IFF_UP) && !(itf->itf_flags & ITF_F_FPP_WIFI))
		cmm_wifi_register(g, itf);
	else if (!(itf->flags & IFF_UP) && (itf->itf_flags & ITF_F_FPP_WIFI))
		cmm_wifi_deregister(g, itf);
}
