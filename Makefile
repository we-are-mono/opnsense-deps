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

# Package version: derived from git tags (e.g., tag "26.1.2" + 3 commits = "26.1.2_3")
# Override: make package PKG_VERSION=26.1.2.1
_PKG_TAG!=	git -C ${OPSDIR} describe --abbrev=0 --always HEAD 2>/dev/null || echo 0.0.0
_PKG_REV!=	git -C ${OPSDIR} rev-list --count ${_PKG_TAG}..HEAD 2>/dev/null || echo 0
PKG_VERSION?=	${_PKG_TAG}${_PKG_REV:N0:S/^/_/}
PKG_STAGEDIR=	${BUILDDIR}/pkg-stage
PKG_CONFDIR=	${OPSDIR}/config
PKG_RCDDIR=	${OPSDIR}/rc.d
PKG_METADIR=	${OPSDIR}/pkg

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
KMOD_PCF=	${DRIVERS}/pcf2131
KMOD_CAAM=	${DRIVERS}/caam
KMOD_TMP=	${DRIVERS}/tmp431

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

build-pcf2131:
	${MAKE} -C ${KMOD_PCF} ${KMOD_ARGS}

build-caam:
	${MAKE} -C ${KMOD_CAAM} ${KMOD_ARGS}

build-tmp431:
	${MAKE} -C ${KMOD_TMP} ${KMOD_ARGS}

modules: build-cdx build-fci build-auto_bridge build-pf_notify \
	 build-emc2302 build-ina2xx build-lp5812 build-sfpled build-pcf2131 \
	 build-caam build-tmp431

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
	cp ${KMOD_PCF}/pcf2131.ko ${DISTDIR}/
	cp ${KMOD_CAAM}/caam.ko ${DISTDIR}/
	cp ${KMOD_TMP}/tmp431.ko ${DISTDIR}/
	cp ${BUILDDIR}/fmc/fmc ${DISTDIR}/
	cp ${BUILDDIR}/dpa_app/dpa_app ${DISTDIR}/
	cp ${BUILDDIR}/cmm/cmm ${DISTDIR}/
	cp ${BUILDDIR}/cmmctl/cmmctl ${DISTDIR}/
	cp ${BUILDDIR}/fand/fand ${DISTDIR}/

# ============================================================
# FreeBSD package (mono-gateway.pkg)
# ============================================================

package: clean dist
	@rm -f ${DISTDIR}/mono-gateway-*.pkg
	@rm -rf ${PKG_STAGEDIR}
	@mkdir -p ${PKG_STAGEDIR}/boot/modules
	@mkdir -p ${PKG_STAGEDIR}/usr/local/sbin
	@mkdir -p ${PKG_STAGEDIR}/etc/fmc/config
	@mkdir -p ${PKG_STAGEDIR}/usr/local/etc/rc.d
	@mkdir -p ${PKG_STAGEDIR}/usr/local/etc/rc.syshook.d/early
	# Kernel modules
	install -m 644 ${DISTDIR}/cdx.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/fci.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/auto_bridge.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/pf_notify.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/sfpled.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/lp5812.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/emc2302.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/ina2xx.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/pcf2131.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/caam.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/tmp431.ko ${PKG_STAGEDIR}/boot/modules/
	# Userspace binaries
	install -m 755 ${DISTDIR}/cmm ${PKG_STAGEDIR}/usr/local/sbin/
	install -m 755 ${DISTDIR}/cmmctl ${PKG_STAGEDIR}/usr/local/sbin/
	install -m 755 ${DISTDIR}/dpa_app ${PKG_STAGEDIR}/usr/local/sbin/
	install -m 755 ${DISTDIR}/fmc ${PKG_STAGEDIR}/usr/local/sbin/
	install -m 755 ${DISTDIR}/fand ${PKG_STAGEDIR}/usr/local/sbin/
	# Configuration files
	install -m 644 ${PKG_CONFDIR}/cdx_cfg.xml ${PKG_STAGEDIR}/etc/
	install -m 644 ${PKG_CONFDIR}/cdx_pcd.xml ${PKG_STAGEDIR}/etc/
	install -m 644 ${PKG_CONFDIR}/cdx_sp.xml ${PKG_STAGEDIR}/etc/
	install -m 644 ${PKG_CONFDIR}/hxs_pdl_v3.xml ${PKG_STAGEDIR}/etc/fmc/config/
	# rc.d service scripts
	install -m 755 ${PKG_RCDDIR}/cmm ${PKG_STAGEDIR}/usr/local/etc/rc.d/
	install -m 755 ${PKG_RCDDIR}/fand ${PKG_STAGEDIR}/usr/local/etc/rc.d/
	# rc.syshook early scripts
	install -m 755 ${PKG_RCDDIR}/01-growfs ${PKG_STAGEDIR}/usr/local/etc/rc.syshook.d/early/
	install -m 755 ${PKG_RCDDIR}/02-mono-modules ${PKG_STAGEDIR}/usr/local/etc/rc.syshook.d/early/
	# OPNsense plugin files (hwmon dashboard widget)
	cp -R ${OPSDIR}/plugins/hwmon/src/opnsense/ ${PKG_STAGEDIR}/usr/local/opnsense/
	chmod 755 ${PKG_STAGEDIR}/usr/local/opnsense/scripts/hwmon/sensors.py
	# Generate manifest with version
	sed 's/%%VERSION%%/${PKG_VERSION}/' ${PKG_METADIR}/+MANIFEST \
	    > ${PKG_STAGEDIR}/+MANIFEST
	# Build package (ABI override for cross-compilation on amd64 host)
	ABI=FreeBSD:14:aarch64 pkg create \
	    -M ${PKG_STAGEDIR}/+MANIFEST -p ${PKG_METADIR}/plist \
	    -r ${PKG_STAGEDIR} -o ${DISTDIR}/
	@echo "==> Package: ${DISTDIR}/mono-gateway-${PKG_VERSION}.pkg"

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
	${MAKE} -C ${KMOD_PCF} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_CAAM} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_TMP} ${KMOD_ARGS} clean
	rm -rf ${BUILDDIR}

.PHONY: all modules userspace dist package clean \
	build-cdx build-fci build-auto_bridge build-pf_notify \
	build-emc2302 build-ina2xx build-lp5812 build-sfpled build-pcf2131 \
	build-caam build-tmp431 \
	fmlib fmc dpa_app cmm cmmctl fand
