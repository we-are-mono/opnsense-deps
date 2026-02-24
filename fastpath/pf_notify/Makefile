# pf_notify kernel module
#
# Build (cross-compile for arm64):
#   make -C /build/opnsense-deps/fastpath/pf_notify \
#       KERNBUILDDIR=/usr/obj/build/opnsense-src/arm64.aarch64/sys/MONO-GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

SYSDIR?=	${.CURDIR}/../../../opnsense-src/sys

KMOD=	pf_notify
SRCS=	pf_notify.c
SRCS+=	opt_pf.h opt_inet.h opt_inet6.h

CFLAGS+= -I${.CURDIR}

.include <bsd.kmod.mk>
