/*
 * cmm_fe.h — Forward engine: programs CDX hash tables via FCI
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_FE_H
#define CMM_FE_H

#include "cmm.h"

struct cmm_conn;
struct cmm_route;

/* Reset all CDX conntrack and route tables */
int cmm_fe_reset(struct cmm_global *g);

/* Register/deregister IPv4 conntrack entry */
int cmm_fe_ct4_register(struct cmm_global *g, struct cmm_conn *conn);
int cmm_fe_ct4_deregister(struct cmm_global *g, struct cmm_conn *conn);

/* Register/deregister IPv6 conntrack entry */
int cmm_fe_ct6_register(struct cmm_global *g, struct cmm_conn *conn);
int cmm_fe_ct6_deregister(struct cmm_global *g, struct cmm_conn *conn);

/* Register/deregister route in CDX */
int cmm_fe_route_register(struct cmm_global *g, struct cmm_route *rt);
int cmm_fe_route_deregister(struct cmm_global *g, struct cmm_route *rt);

#endif /* CMM_FE_H */
