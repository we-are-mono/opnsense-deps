/*
 * Shadow dpa_wifi.h for FreeBSD CDX port.
 *
 * The original is deeply Linux-coupled (linux/cdev.h, struct net_device,
 * struct qman_fq, etc.).  CDX uses it only for the is_wlan_iface check
 * in cdx_ehash.c.  Provide minimal stubs.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _DPAA_HOST_GENERIC_H_
#define _DPAA_HOST_GENERIC_H_

/* Stub: WiFi VAP forwarding — always fails (no WiFi offload on FreeBSD) */
static inline int
dpaa_get_vap_fwd_fq(uint16_t vap_id, uint32_t *fqid, uint32_t hash)
{

	return (-1);
}

#endif /* _DPAA_HOST_GENERIC_H_ */
