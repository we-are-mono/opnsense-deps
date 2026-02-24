/*
 * cmm_offload.h — Offload eligibility decisions
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_OFFLOAD_H
#define CMM_OFFLOAD_H

#include "cmm.h"

struct cmm_conn;
struct pf_state_export;

/*
 * Check if a PF state is eligible for hardware offload.
 * Returns 1 if eligible, 0 if not.
 */
int cmm_offload_eligible(const struct pf_state_export *pfs);

#endif /* CMM_OFFLOAD_H */
