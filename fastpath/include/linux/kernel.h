/*
 * Shadow header for <linux/kernel.h>
 *
 * Some Tier 1 CDX files (control_bridge.c, query_Rx.c) include this
 * directly. Route through our compat header which provides printk,
 * container_of, min/max, etc.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_KERNEL_H_COMPAT_
#define _LINUX_KERNEL_H_COMPAT_

#include "linux_compat.h"

#endif
