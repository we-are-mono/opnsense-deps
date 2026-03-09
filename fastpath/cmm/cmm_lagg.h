/*
 * cmm_lagg.h — LAGG interface offload
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
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

#endif /* CMM_LAGG_H */
