# Fan control daemon for Mono Gateway
#
# Build:
#   mkdir -p /tmp/fand-build && cd /tmp/fand-build
#   make -f /build/opnsense-deps/drivers/fand/Makefile
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

SYSROOT?=	/usr/obj/build/opnsense-src/arm64.aarch64/tmp
CC?=		cc
TARGET?=	--target=aarch64-unknown-freebsd14.3

CFLAGS=		-O2 -pipe -Wall --sysroot=${SYSROOT} ${TARGET}
LDFLAGS=	${TARGET} --sysroot=${SYSROOT}

SRCDIR?=	${MAKEFILE:H}

PROG=	fand

all: ${PROG}

${PROG}: ${SRCDIR}/fand.c
	${CC} ${CFLAGS} ${LDFLAGS} -o ${PROG} ${SRCDIR}/fand.c

clean:
	rm -f ${PROG}

.PHONY: all clean
