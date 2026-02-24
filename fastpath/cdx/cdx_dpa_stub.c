/*
 * CDX DPAA hardware function stubs — FreeBSD port
 *
 * Residual stubs for DPAA functions that are either:
 *   - Dead code on FreeBSD (zero callers, different architecture)
 *   - Stubs even in the Linux reference (multicast ioctls use FCI path)
 *   - Features not in scope (WiFi offload, OH port NIA reconfiguration)
 *
 * Most original stubs have been replaced with real implementations in:
 *   - cdx_devman_freebsd.c  (interface management)
 *   - cdx_dpa_cfg.c         (FMan/PCD configuration)
 *   - cdx_ehash.c           (external hash table operations)
 *   - cdx_dpa_takeover.c    (DPA interface registration)
 *   - cdx_devoh_freebsd.c   (offline handler port management)
 *   - cdx_ifstats_freebsd.c (interface statistics)
 *   - cdx_qos_freebsd.c     (QoS / policer)
 *   - cdx_mc_freebsd.c      (multicast)
 *   - cdx_debug_freebsd.c   (debug display)
 *   - dpa_ipsec_freebsd.c   (IPsec SA management)
 *   - cdx_reassm_freebsd.c  (IP reassembly)
 *   - cdx_ceetm_freebsd.c   (CEETM QoS)
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021-2022 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "portdefs.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "fm_ehash.h"
#include "control_tunnel.h"
#include "control_socket.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "dpa_ipsec.h"

/*
 * Suppress -Wmissing-prototypes for this file. All stub functions have
 * prototypes in the CDX headers that their callers include. This stub
 * file intentionally doesn't include every CDX header to keep dependencies
 * minimal.
 */
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/* ================================================================
 * Globals referenced by Tier 1 code
 * ================================================================ */

/* devman.c globals */
struct dpa_iface_info *dpa_interface_info;
DEFINE_SPINLOCK(dpa_devlist_lock);

/* dpa_cfg.c globals */
struct cdx_fman_info *fman_info;

/* num_active_connections — defined in control_ipv4.c (Tier 1) */

/* Linux network namespace stub — used by dev_get_by_name() */
struct net init_net;

/* ================================================================
 * Dead-code stubs — zero callers on FreeBSD or permanently N/A
 * ================================================================ */

/* dpa_get_tx_chnl_info — zero callers.  FreeBSD devman gets the
 * TX QMan channel directly from sc->sc_port_tx_qman_chan. */
int
dpa_get_tx_chnl_info(uint32_t fqid, uint32_t *ch_id, uint32_t *wq_id)
{
	if (ch_id)
		*ch_id = 0;
	if (wq_id)
		*wq_id = 0;
	return (-1);
}

/* cdx_ioc_dpa_connadd — test-only ioctl (Linux dpa_test.c).
 * Production flow creation goes through FCI → control_ipv4.c. */
int
cdx_ioc_dpa_connadd(unsigned long args)
{
	DPA_INFO("stub: cdx_ioc_dpa_connadd\n");
	return (0);
}

/* Multicast ioctls — stubs even in the Linux reference (dpa_test.c).
 * Real multicast goes through FCI command handlers
 * (M_mc4_cmdproc/M_mc6_cmdproc) registered in cdx_mc_freebsd.c. */
int
cdx_ioc_create_mc_group(unsigned long args)
{
	DPA_INFO("stub: cdx_ioc_create_mc_group (use FCI path)\n");
	return (0);
}

int
cdx_ioc_add_member_to_group(unsigned long args)
{
	DPA_INFO("stub: cdx_ioc_add_member_to_group (use FCI path)\n");
	return (0);
}

int
cdx_ioc_add_mcast_table_entry(unsigned long args)
{
	DPA_INFO("stub: cdx_ioc_add_mcast_table_entry (use FCI path)\n");
	return (0);
}

/* dpa_classif_table_get_entry_stats_by_ref — only called under
 * #ifdef PRINT_CTENTRY_STATS (never defined).  Dead code. */
int
dpa_classif_table_get_entry_stats_by_ref(void *td, int dpa_handle,
    void *stats)
{
	return (-1);
}

/* get_ipsec_bp — only called from VWD (WiFi) RX path, not compiled. */
struct dpa_bp *
get_ipsec_bp(void)
{
	return (NULL);
}

/* dpa_register_ipsec_fq_handler — only called under
 * CONFIG_INET_IPSEC_OFFLOAD (Linux-only Kconfig symbol). */
int
dpa_register_ipsec_fq_handler(void *handler)
{
	return (0);
}

/* ================================================================
 * WiFi / VWD stubs — no WiFi offload on this platform
 * ================================================================ */
int
dpaa_vwd_init(void)
{
	return (0);
}

void
dpaa_vwd_exit(void)
{
	/* Stub */
}

/* ================================================================
 * OH port NIA/DMA reconfiguration — only called from WiFi path
 * (dpa_wifi.c:vwd_configure_port_pcd).  Stubbed because VWD is N/A.
 * When needed, implement via dpaa_oh.c kernel driver API.
 * ================================================================ */

int
ohport_set_ofne(uint32_t handle, uint32_t nia_val)
{
	return (-1);
}

int
ohport_set_dma(uint32_t handle, uint32_t val)
{
	return (-1);
}

/* ================================================================
 * Remaining devman helpers
 * ================================================================ */

/* fm_ehash_freebsd.c timestamp accessors */
extern void cdx_ehash_update_timestamp(uint32_t id, uint32_t value);

void
dpa_update_timestamp(uint32_t ts)
{

	cdx_ehash_update_timestamp(EXTERNAL_TIMESTAMP_TIMERID, ts);
}

/* cdx_check_rx_iface_type_vlan — real implementation in cdx_devman_freebsd.c */

/* cdx_debug.c stubs removed — real implementations in cdx_debug_freebsd.c */

/* mc4_init, mc6_init, mc4_exit, mc6_exit moved to cdx_mc_freebsd.c */

/* M_ipsec_sa_cache_lookup_by_h — real implementation in control_ipsec.c */
