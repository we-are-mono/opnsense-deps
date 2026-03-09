/*
 * cmm_lagg.c — LAGG interface offload
 *
 * Detects LAGG (link aggregation) interfaces and registers them with
 * CDX via FPP_CMD_LAGG_ENTRY so the hardware knows the LAGG-to-port
 * mapping for flow classification.  LAGG is transparent to header
 * manipulation — it only provides a traversable node so that
 * VLAN->LAGG->ETH resolution works.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <net/if.h>
#include <string.h>

#include "cmm.h"
#include "cmm_lagg.h"
#include "cmm_itf.h"

static int
cmm_lagg_register(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_lagg_cmd_t cmd;
	int rc;

	if (!(itf->itf_flags & ITF_F_LAGG))
		return (0);
	if (itf->itf_flags & ITF_F_FPP_LAGG)
		return (0);
	if (itf->lagg_active_port[0] == '\0')
		return (0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_REGISTER;
	strlcpy(cmd.lagg_ifname, itf->ifname, sizeof(cmd.lagg_ifname));
	strlcpy(cmd.lagg_phy_ifname, itf->lagg_active_port,
	    sizeof(cmd.lagg_phy_ifname));
	memcpy(cmd.macaddr, itf->macaddr, ETHER_ADDR_LEN);

	rc = fci_write(g->fci_handle, FPP_CMD_LAGG_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc == FPP_ERR_LAGG_ENTRY_ALREADY_REGISTERED) {
		cmm_print(CMM_LOG_DEBUG,
		    "lagg: %s already in CDX, reusing", itf->ifname);
	} else if (rc != 0) {
		cmm_print(CMM_LOG_WARN, "lagg: register %s failed: %d",
		    itf->ifname, rc);
		return (-1);
	}

	itf->itf_flags |= ITF_F_FPP_LAGG;
	cmm_print(CMM_LOG_INFO,
	    "lagg: registered %s (member=%s)",
	    itf->ifname, itf->lagg_active_port);

	return (0);
}

static int
cmm_lagg_deregister(struct cmm_global *g, struct cmm_interface *itf)
{
	fpp_lagg_cmd_t cmd;
	int rc;

	if (!(itf->itf_flags & ITF_F_FPP_LAGG))
		return (0);

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = FPP_ACTION_DEREGISTER;
	strlcpy(cmd.lagg_ifname, itf->ifname, sizeof(cmd.lagg_ifname));

	rc = fci_write(g->fci_handle, FPP_CMD_LAGG_ENTRY,
	    sizeof(cmd), (unsigned short *)&cmd);
	if (rc != 0 && rc != FPP_ERR_LAGG_ENTRY_NOT_FOUND)
		cmm_print(CMM_LOG_WARN, "lagg: deregister %s failed: %d",
		    itf->ifname, rc);

	itf->itf_flags &= ~ITF_F_FPP_LAGG;
	cmm_print(CMM_LOG_INFO, "lagg: deregistered %s", itf->ifname);

	return (0);
}

int
cmm_lagg_init(struct cmm_global *g)
{
	int rc;

	/* Reset all LAGG entries in CDX */
	rc = fci_write(g->fci_handle, FPP_CMD_LAGG_RESET, 0, NULL);
	if (rc != 0)
		cmm_print(CMM_LOG_WARN, "lagg: reset failed: %d", rc);

	/* Register all existing UP LAGG interfaces */
	cmm_itf_foreach_lagg(g, cmm_lagg_register);

	cmm_print(CMM_LOG_INFO, "lagg: initialized");
	return (0);
}

void
cmm_lagg_fini(struct cmm_global *g)
{
	cmm_itf_foreach_lagg(g, cmm_lagg_deregister);
}

void
cmm_lagg_notify(struct cmm_global *g, struct cmm_interface *itf)
{
	if (!(itf->itf_flags & ITF_F_LAGG))
		return;

	if ((itf->flags & IFF_UP) && !(itf->itf_flags & ITF_F_FPP_LAGG))
		cmm_lagg_register(g, itf);
	else if (!(itf->flags & IFF_UP) && (itf->itf_flags & ITF_F_FPP_LAGG))
		cmm_lagg_deregister(g, itf);
}
