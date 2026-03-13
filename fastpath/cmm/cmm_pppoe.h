/*
 * cmm_pppoe.h — PPPoE session offload
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_PPPOE_H
#define CMM_PPPOE_H

#include "cmm.h"

struct cmm_interface;

/* Register all existing UP PPPoE sessions with CDX */
int cmm_pppoe_init(struct cmm_global *g);

/* Deregister all PPPoE sessions from CDX */
void cmm_pppoe_fini(struct cmm_global *g);

/* Called when interface flags change — register/deregister as needed */
void cmm_pppoe_notify(struct cmm_global *g, struct cmm_interface *itf);

#endif /* CMM_PPPOE_H */
