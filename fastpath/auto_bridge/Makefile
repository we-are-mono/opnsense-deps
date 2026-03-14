# auto_bridge kernel module
#
# Build (cross-compile for arm64):
#   make -C /build/opnsense-deps/fastpath/auto_bridge \
#       KERNBUILDDIR=/usr/obj/build/opnsense-src/arm64.aarch64/sys/GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause


KMOD=	auto_bridge
SRCS=	auto_bridge.c

CFLAGS+= -I${.CURDIR}

.include <bsd.kmod.mk>
