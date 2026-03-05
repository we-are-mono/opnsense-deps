# CMM — Connection Management Module for FreeBSD
#
# Userspace daemon that monitors PF state table and routes,
# programs FMan hardware hash tables via FCI/CDX.
#
# Cross-compile for arm64:
#   make -f Makefile.cross
#
# Build natively on the target (simpler):
#   scp -r opnsense-deps/fastpath/{cmm,fci_lib,fci,include} target:/tmp/
#   ssh target "cd /tmp/cmm && make && make install"
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

PROG=		cmm
NO_MAN=		yes

SRCS=		cmm.c \
		cmm_conn.c \
		cmm_route.c \
		cmm_neigh.c \
		cmm_itf.c \
		cmm_rtsock.c \
		cmm_fe.c \
		cmm_offload.c \
		cmm_vlan.c \
		cmm_ipsec.c \
		cmm_tunnel.c \
		cmm_ctrl.c \
		cmm_wifi.c

CFLAGS+=	-I${.CURDIR}/../fci_lib
CFLAGS+=	-I${.CURDIR}/../fci
CFLAGS+=	-I${.CURDIR}/../include
CFLAGS+=	-DLS1043
CFLAGS+=	-DWIFI_ENABLE
CFLAGS+=	-Wall -Wextra -Wno-unused-parameter

# libfci
LDADD+=		-L${.CURDIR}/../fci_lib -lfci

.include <bsd.prog.mk>
