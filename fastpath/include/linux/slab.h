/*
 * Shadow linux/slab.h for FreeBSD CDX port.
 *
 * All slab allocator functions (kzalloc, kfree, kmalloc, GFP_KERNEL)
 * are already provided by linux_compat.h (included via cdx.h prelude).
 * This file exists solely to satisfy #include <linux/slab.h> directives.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_SLAB_H_SHADOW_
#define _LINUX_SLAB_H_SHADOW_

/* Nothing to add — see linux_compat.h */

#endif /* _LINUX_SLAB_H_SHADOW_ */
