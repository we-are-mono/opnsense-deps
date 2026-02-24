/*
 * Shadow header for <linux/module.h>
 *
 * Some Tier 1 CDX files (control_bridge.c, query_Rx.c) include this
 * directly. Route through our compat header which provides all the
 * module macros as no-ops.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_MODULE_H_COMPAT_
#define _LINUX_MODULE_H_COMPAT_

#include "linux_compat.h"

#endif
