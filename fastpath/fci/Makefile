# FCI (Fast Control Interface) kernel module for FreeBSD
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

.include "../Makefile.inc"

KMOD=	fci
SRCS=	fci_freebsd.c fci_sysctl.c
SRCS+=	opt_platform.h

.include <bsd.kmod.mk>
