/*
 * cmm_lagg.h — LAGG interface offload
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_LAGG_H
#define CMM_LAGG_H

#include "cmm.h"

struct cmm_interface;

/* Reset CDX LAGG table and register all existing UP LAGGs */
int cmm_lagg_init(struct cmm_global *g);

/* Deregister all LAGGs from CDX */
void cmm_lagg_fini(struct cmm_global *g);

/* Called when interface flags change — register/deregister as needed */
void cmm_lagg_notify(struct cmm_global *g, struct cmm_interface *itf);

/* Check if a member port state change affects any LAGG — triggers failover */
void cmm_lagg_member_check(struct cmm_global *g, struct cmm_interface *itf);

#endif /* CMM_LAGG_H */
