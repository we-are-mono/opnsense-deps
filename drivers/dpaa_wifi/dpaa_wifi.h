/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026 Mono Technologies Inc.
 *
 * dpaa_wifi — WiFi ↔ FMan OH port data plane bridge.
 *
 * Bridges mwifiex PCIe WiFi driver with DPAA1 FMan OH port so CDX
 * can hardware-offload WiFi traffic.
 */

#ifndef DPAA_WIFI_H_
#define DPAA_WIFI_H_

/*
 * RX bridge hook for mwifiex.
 *
 * When set in mwifiex_priv.wifi_bridge_fn, moal_recv_packet() calls
 * this instead of if_input().  The function injects the frame into
 * the FMan WiFi OH port for PCD classification / CDX offload.
 *
 * Returns 0 on success (mbuf consumed), errno on failure (caller frees).
 */
typedef int (*dpaa_wifi_bridge_fn_t)(if_t ifp, struct mbuf *m);

#endif /* DPAA_WIFI_H_ */
