# SFP LED Control kernel module for FreeBSD
#
# Build:
#   make -C /build/opnsense-deps/drivers/sfp-led \
#       KERNBUILDDIR=/usr/obj/build/opnsense-src/arm64.aarch64/sys/MONO-GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

SYSDIR?=	${.CURDIR}/../../../opnsense-src/sys

KMOD=	sfpled
SRCS=	sfp_led.c

# Auto-generated headers required for OFW/FDT + GPIO + I2C driver
SRCS+=	opt_platform.h device_if.h bus_if.h ofw_bus_if.h gpiobus_if.h iicbus_if.h

.include <bsd.kmod.mk>
