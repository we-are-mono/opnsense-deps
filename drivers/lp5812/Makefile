# TI LP5812 LED Controller kernel module for FreeBSD
#
# Build:
#   make -C /build/opnsense-deps/drivers/lp5812 \
#       KERNBUILDDIR=/usr/obj/build/opnsense-src/arm64.aarch64/sys/GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause


KMOD=	lp5812
SRCS=	lp5812.c

# Auto-generated headers required for OFW/FDT + I2C driver
SRCS+=	opt_platform.h device_if.h bus_if.h iicbus_if.h ofw_bus_if.h

.include <bsd.kmod.mk>
