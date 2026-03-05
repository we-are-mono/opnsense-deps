/*
 * cmm_wifi.h — WiFi VAP offload
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_WIFI_H
#define CMM_WIFI_H

#include "cmm.h"

struct cmm_interface;

/* Reset CDX WiFi state and register all existing UP WiFi VAPs */
int cmm_wifi_init(struct cmm_global *g);

/* Deregister all WiFi VAPs from CDX */
void cmm_wifi_fini(struct cmm_global *g);

/* Called when interface flags change — register/deregister as needed */
void cmm_wifi_notify(struct cmm_global *g, struct cmm_interface *itf);

#endif /* CMM_WIFI_H */
