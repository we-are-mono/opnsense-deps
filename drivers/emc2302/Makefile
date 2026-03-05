# Microchip EMC2301/2302/2303/2305 Fan Controller kernel module for FreeBSD
#
# Build:
#   make -C /build/opnsense-deps/drivers/emc2302 \
#       KERNBUILDDIR=/usr/obj/build/opnsense-src/arm64.aarch64/sys/MONO-GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause


KMOD=	emc2302
SRCS=	emc2302.c
SRCS+=	opt_platform.h device_if.h bus_if.h iicbus_if.h ofw_bus_if.h

.include <bsd.kmod.mk>
