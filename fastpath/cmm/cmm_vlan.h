/*
 * cmm_vlan.h — VLAN interface offload
 *
 * Copyright 2026 Mono Technologies Inc.
 * Copyright (C) 2007 Mindspeed Technologies, Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017, 2021 NXP
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_VLAN_H
#define CMM_VLAN_H

#include "cmm.h"

struct cmm_interface;

/* Reset CDX VLAN table and register all existing UP VLANs */
int cmm_vlan_init(struct cmm_global *g);

/* Deregister all VLANs from CDX */
void cmm_vlan_fini(struct cmm_global *g);

/* Called when interface flags change — register/deregister as needed */
void cmm_vlan_notify(struct cmm_global *g, struct cmm_interface *itf);

/* Deregister / re-register the VLANs on a parent that is going away or
 * coming back (a LAGG being deregistered or re-registered) */
void cmm_vlan_deregister_children(struct cmm_global *g, int parent_ifindex);
void cmm_vlan_register_children(struct cmm_global *g, int parent_ifindex);

#endif /* CMM_VLAN_H */
