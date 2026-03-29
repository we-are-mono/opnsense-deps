/*
 * cmm_wifi.h — WiFi VAP offload
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
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
