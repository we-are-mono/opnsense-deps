# Top-level build Makefile for opnsense-deps
#
# Build everything:
#   make -C /build/opnsense-deps all
#
# Clean all build artifacts:
#   make -C /build/opnsense-deps clean
#
# Build subsets:
#   make -C /build/opnsense-deps modules    # kernel modules only
#   make -C /build/opnsense-deps userspace   # userspace only
#
# Parallel build (modules build concurrently):
#   make -C /build/opnsense-deps -j24 all
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

OPSDIR=		${.CURDIR}
FASTPATH=	${OPSDIR}/fastpath
DRIVERS=	${OPSDIR}/drivers

# Cross-compilation settings (all ?= for easy override)
SRCTOP?=	/build
SYSROOT?=	/usr/obj${SRCTOP}/opnsense-src/arm64.aarch64/tmp
KERNBUILDDIR?=	/usr/obj${SRCTOP}/opnsense-src/arm64.aarch64/sys/GATEWAY

# Common args for all kernel module builds
# Host clang cross-compiles with explicit --target (bsd.kmod.mk does NOT add it)
KMOD_ARGS=	KERNBUILDDIR=${KERNBUILDDIR} \
		MACHINE=arm64 MACHINE_ARCH=aarch64 \
		CC="cc --target=aarch64-unknown-freebsd14.3" LD=ld.lld

# Local build directory for userspace components
BUILDDIR?=	${OPSDIR}/_build

# Output directory for all final artifacts
DISTDIR?=	${OPSDIR}/dist

# ============================================================
# Top-level targets
# ============================================================

all: dist

# ============================================================
# Kernel modules (all independent — safe for -j)
# ============================================================

KMOD_CDX=	${FASTPATH}/cdx
KMOD_FCI=	${FASTPATH}/fci
KMOD_AB=	${FASTPATH}/auto_bridge
KMOD_PN=	${FASTPATH}/pf_notify
KMOD_EMC=	${DRIVERS}/emc2302
KMOD_INA=	${DRIVERS}/ina2xx
KMOD_LP=	${DRIVERS}/lp5812
KMOD_SFP=	${DRIVERS}/sfp-led

build-cdx:
	${MAKE} -C ${KMOD_CDX} ${KMOD_ARGS}

build-fci:
	${MAKE} -C ${KMOD_FCI} ${KMOD_ARGS}

build-auto_bridge:
	${MAKE} -C ${KMOD_AB} ${KMOD_ARGS}

build-pf_notify:
	${MAKE} -C ${KMOD_PN} ${KMOD_ARGS}

build-emc2302:
	${MAKE} -C ${KMOD_EMC} ${KMOD_ARGS}

build-ina2xx:
	${MAKE} -C ${KMOD_INA} ${KMOD_ARGS}

build-lp5812:
	${MAKE} -C ${KMOD_LP} ${KMOD_ARGS}

build-sfpled:
	${MAKE} -C ${KMOD_SFP} ${KMOD_ARGS}

modules: build-cdx build-fci build-auto_bridge build-pf_notify \
	 build-emc2302 build-ina2xx build-lp5812 build-sfpled

# ============================================================
# Userspace components (dependency order: fmlib -> fmc -> dpa_app)
# ============================================================

fmlib:
	@mkdir -p ${BUILDDIR}/fmlib
	cd ${BUILDDIR}/fmlib && ${MAKE} -f ${FASTPATH}/fmlib/Makefile.cross all

fmc: fmlib
	@mkdir -p ${BUILDDIR}/fmc
	cd ${BUILDDIR}/fmc && ${MAKE} -f ${FASTPATH}/fmc/Makefile.cross \
		FMLIB_LIB=${BUILDDIR}/fmlib all

dpa_app: fmc
	@mkdir -p ${BUILDDIR}/dpa_app
	cd ${BUILDDIR}/dpa_app && ${MAKE} -f ${FASTPATH}/dpa_app/Makefile.cross \
		FMLIB_LIB=${BUILDDIR}/fmlib FMC_LIB=${BUILDDIR}/fmc all

cmm:
	@mkdir -p ${BUILDDIR}/cmm
	cd ${BUILDDIR}/cmm && ${MAKE} -f ${FASTPATH}/cmm/Makefile.cross all

cmmctl:
	@mkdir -p ${BUILDDIR}/cmmctl
	cd ${BUILDDIR}/cmmctl && ${MAKE} -f ${FASTPATH}/cmmctl/Makefile.cross all

fand:
	@mkdir -p ${BUILDDIR}/fand
	cd ${BUILDDIR}/fand && ${MAKE} -f ${DRIVERS}/fand/Makefile all

userspace: fmlib fmc dpa_app cmm cmmctl fand

# ============================================================
# Collect outputs into dist/
# ============================================================

dist: modules userspace
	@mkdir -p ${DISTDIR}
	cp ${KMOD_CDX}/cdx.ko ${DISTDIR}/
	cp ${KMOD_FCI}/fci.ko ${DISTDIR}/
	cp ${KMOD_AB}/auto_bridge.ko ${DISTDIR}/
	cp ${KMOD_PN}/pf_notify.ko ${DISTDIR}/
	cp ${KMOD_EMC}/emc2302.ko ${DISTDIR}/
	cp ${KMOD_INA}/ina2xx.ko ${DISTDIR}/
	cp ${KMOD_LP}/lp5812.ko ${DISTDIR}/
	cp ${KMOD_SFP}/sfpled.ko ${DISTDIR}/
	cp ${BUILDDIR}/fmc/fmc ${DISTDIR}/
	cp ${BUILDDIR}/dpa_app/dpa_app ${DISTDIR}/
	cp ${BUILDDIR}/cmm/cmm ${DISTDIR}/
	cp ${BUILDDIR}/cmmctl/cmmctl ${DISTDIR}/
	cp ${BUILDDIR}/fand/fand ${DISTDIR}/

# ============================================================
# Clean
# ============================================================

clean:
	${MAKE} -C ${KMOD_CDX} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_FCI} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_AB} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_PN} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_EMC} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_INA} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_LP} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_SFP} ${KMOD_ARGS} clean
	rm -rf ${BUILDDIR}

.PHONY: all modules userspace dist clean \
	build-cdx build-fci build-auto_bridge build-pf_notify \
	build-emc2302 build-ina2xx build-lp5812 build-sfpled \
	fmlib fmc dpa_app cmm cmmctl fand
