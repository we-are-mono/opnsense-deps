# Common build settings for fastpath FreeBSD modules
# Cross-compile: env MAKEOBJDIRPREFIX=/tmp/obj make TARGET=arm64 TARGET_ARCH=aarch64
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

FASTPATH_ROOT=	${.CURDIR}/..
SYSDIR?=	${FASTPATH_ROOT}/../../opnsense-src/sys

CFLAGS+=	-I${FASTPATH_ROOT}/include
CFLAGS+=	-DENDIAN_LITTLE -DGCC_TOOLCHAIN
