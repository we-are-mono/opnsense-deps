/*
 * Shadow linux/netdevice.h for FreeBSD CDX port.
 *
 * struct net_device and helpers (dev_get_by_name, dev_put, netdev_priv)
 * are already provided by dpaa_eth.h (shadow).  This file exists solely
 * to satisfy #include "linux/netdevice.h" directives.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_NETDEVICE_H_SHADOW_
#define _LINUX_NETDEVICE_H_SHADOW_

#include "dpaa_eth.h"

#endif /* _LINUX_NETDEVICE_H_SHADOW_ */
