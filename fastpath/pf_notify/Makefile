# pf_notify kernel module
#
# Build (cross-compile for arm64):
#   make -C /usr/deps/fastpath/pf_notify \
#       KERNBUILDDIR=/usr/obj/usr/src/arm64.aarch64/sys/GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause


KMOD=	pf_notify
SRCS=	pf_notify.c
SRCS+=	opt_pf.h opt_inet.h opt_inet6.h

CFLAGS+= -I${.CURDIR}

.include <bsd.kmod.mk>
