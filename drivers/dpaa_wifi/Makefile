# dpaa_wifi — WiFi ↔ FMan OH port data plane bridge
#
# Bridges mwifiex PCIe WiFi with DPAA1 FMan OH port for CDX offload.
#
# Build:
#   make -C /usr/deps/drivers/dpaa_wifi \
#       KERNBUILDDIR=/usr/obj/usr/src/arm64.aarch64/sys/GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause


KMOD=	dpaa_wifi
SRCS=	dpaa_wifi.c
SRCS+=	opt_platform.h device_if.h bus_if.h ofw_bus_if.h

# mwifiex driver headers + mlan for moal_freebsd.h → mlan_decl.h
VENDORDIR?=	${.CURDIR}/../../_vendor
MLANDIR=	${VENDORDIR}/mwifiex/mlan
CFLAGS+=	-I${.CURDIR}/../mwifiex -I${MLANDIR}
CFLAGS+=	-DPCIE -DSTA_SUPPORT -DUAP_SUPPORT -DMLAN_64BIT -DPCIE9098

# NCSW headers + required defines
CFLAGS+=	-DNCSW_FREEBSD -DNCSW_ARM_CORE -DENDIAN_LITTLE
CFLAGS+=	-DCORE_CACHELINE_SIZE=64
CFLAGS+=	-DDEBUG_ERRORS=1 -DREPORT_EVENTS=1
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/etc
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/flib
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/cores
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/Peripherals
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/integrations
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/Peripherals/FM/inc

.include <bsd.kmod.mk>
