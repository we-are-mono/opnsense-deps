# NXP CAAM (SEC v4.0+) crypto accelerator kernel module for FreeBSD
#
# Includes JR (Job Ring) + QI (Queue Interface) paths in a single module.
# QI files require NCSW/DPAA include paths (DPAA must be patched into kernel).
#
# Build:
#   make -C /usr/deps/drivers/caam \
#       KERNBUILDDIR=/usr/obj/usr/src/arm64.aarch64/sys/GATEWAY \
#       MACHINE=arm64 MACHINE_ARCH=aarch64 CC=cc LD=ld.lld
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause


KMOD=	caam
SRCS=	caam.c caam_jr.c caam_crypto.c caam_alg.c caam_hash.c caam_rng.c
SRCS+=	caam_qi.c caam_qi_alg.c
SRCS+=	opt_platform.h device_if.h bus_if.h ofw_bus_if.h cryptodev_if.h

# NCSW/DPAA include paths needed by caam_qi.c and caam_qi_alg.c
# dflags_arm64.h includes <asm/byteorder.h> which lives in LinuxKPI
NCSW=	${SYSDIR}/contrib/ncsw
LINUXKPI=	-I${SYSDIR}/compat/linuxkpi/common/include \
		-I${SYSDIR}/compat/linuxkpi/dummy/include
NCSW_FLAGS=	${LINUXKPI} \
		-I${NCSW}/inc -I${NCSW}/inc/Peripherals -I${NCSW}/inc/integrations \
		-I${NCSW}/inc/cores -I${NCSW}/inc/etc -I${NCSW}/inc/flib \
		-I${NCSW}/etc \
		-I${NCSW}/build -include ${NCSW}/build/dflags_arm64.h
CFLAGS.caam_qi.c+=	${NCSW_FLAGS}
CFLAGS.caam_qi_alg.c+=	${NCSW_FLAGS}

.include <bsd.kmod.mk>
