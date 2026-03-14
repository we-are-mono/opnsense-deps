# NXP PCF2131 RTC kernel module for FreeBSD
#
# Build:
#   make -C /usr/deps/drivers/pcf2131 \
#       KERNBUILDDIR=/usr/obj/usr/src/arm64.aarch64/sys/GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause


KMOD=	pcf2131
SRCS=	pcf2131.c
SRCS+=	opt_platform.h device_if.h bus_if.h iicbus_if.h ofw_bus_if.h clock_if.h

.include <bsd.kmod.mk>
