# Top-level build Makefile for opnsense-deps
#
# Build everything:
#   make -C /usr/deps all
#
# Clean all build artifacts:
#   make -C /usr/deps clean
#
# Build full image (kernel, modules, userspace, package, image):
#   make -C /usr/deps image
#
# Build subsets:
#   make -C /usr/deps modules    # kernel modules only
#   make -C /usr/deps userspace   # userspace only
#
# Parallel build (modules build concurrently):
#   make -C /usr/deps -j24 all
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

OPSDIR=		${.CURDIR}
FASTPATH=	${OPSDIR}/fastpath
DRIVERS=	${OPSDIR}/drivers
VENDORDIR?=	${OPSDIR}/_vendor

# Source and tooling paths (standard OPNsense layout)
SRCDIR?=	/usr/src
TOOLSDIR?=	/usr/tools
SYSROOT?=	/usr/obj${SRCDIR}/arm64.aarch64/tmp
KERNBUILDDIR?=	/usr/obj${SRCDIR}/arm64.aarch64/sys/GATEWAY

# OPNsense build settings
OPS_SETTINGS?=	26.1
OPS_BRANCH=	stable/${OPS_SETTINGS}
IMAGESDIR?=	/usr/local/opnsense/build/${OPS_SETTINGS}/aarch64/images
SETSDIR?=	/usr/local/opnsense/build/${OPS_SETTINGS}/aarch64/sets

# Common args for all kernel module builds
# Explicit --target ensures cross-compilation works from amd64; harmless on native aarch64
KMOD_ARGS=	SYSDIR=${SRCDIR}/sys \
		KERNBUILDDIR=${KERNBUILDDIR} \
		MACHINE=arm64 MACHINE_ARCH=aarch64 \
		CC="cc --target=aarch64-unknown-freebsd14.3" LD=ld.lld

# Local build directory for userspace components
BUILDDIR?=	${OPSDIR}/_build

# Output directory for all final artifacts
DISTDIR?=	${OPSDIR}/dist

# libxml2 aarch64 package for cross-compilation sysroot (fmc links against it).
# pkg.FreeBSD.org blocks directory listings, so we fetch by exact filename.
# Update this when the FreeBSD ports tree bumps libxml2.
LIBXML2_PKG?=	libxml2-2.15.2.pkg
LIBXML2_URL=	https://pkg.FreeBSD.org/FreeBSD:14:aarch64/latest/All/${LIBXML2_PKG}

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

all: modules userspace

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
KMOD_MWIFI=	${DRIVERS}/mwifiex
KMOD_DW=	${DRIVERS}/dpaa_wifi

# NXP vendor repositories (pinned commits for reproducible builds)
MWIFIEX_REPO=	https://github.com/nxp-imx/mwifiex.git
MWIFIEX_COMMIT=	84ca65c9ff935d7f2999af100a82531c22c65234
IMX_FW_REPO=	https://github.com/nxp-imx/imx-firmware.git
IMX_FW_COMMIT=	8c9b278016c97527b285f2fcbe53c2d428eb171d

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

fetch-vendor:
	@mkdir -p ${VENDORDIR}
	@if [ ! -d ${VENDORDIR}/mwifiex/.git ]; then \
		echo "==> Cloning nxp-imx/mwifiex"; \
		git clone --depth 1 ${MWIFIEX_REPO} ${VENDORDIR}/mwifiex; \
		cd ${VENDORDIR}/mwifiex && git fetch --depth 1 origin ${MWIFIEX_COMMIT} && git checkout ${MWIFIEX_COMMIT}; \
	fi
	@if [ ! -d ${VENDORDIR}/imx-firmware/.git ]; then \
		echo "==> Cloning nxp-imx/imx-firmware"; \
		git clone --depth 1 ${IMX_FW_REPO} ${VENDORDIR}/imx-firmware; \
		cd ${VENDORDIR}/imx-firmware && git fetch --depth 1 origin ${IMX_FW_COMMIT} && git checkout ${IMX_FW_COMMIT}; \
	fi

build-mwifiex: fetch-vendor
	${MAKE} -C ${KMOD_MWIFI} ${KMOD_ARGS} VENDORDIR=${VENDORDIR}

build-dpaa_wifi: fetch-vendor
	${MAKE} -C ${KMOD_DW} ${KMOD_ARGS} VENDORDIR=${VENDORDIR}

modules: build-cdx build-fci build-auto_bridge build-pf_notify \
	 build-emc2302 build-ina2xx build-lp5812 build-sfpled build-pcf2131 \
	 build-caam build-tmp431 build-mwifiex build-dpaa_wifi
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
	cp ${KMOD_MWIFI}/mwifiex.ko ${DISTDIR}/
	cp ${KMOD_DW}/dpaa_wifi.ko ${DISTDIR}/

# ============================================================
# Userspace components (dependency order: fmlib -> fmc -> dpa_app)
# ============================================================

fmlib:
	@mkdir -p ${BUILDDIR}/fmlib
	cd ${BUILDDIR}/fmlib && ${MAKE} -f ${FASTPATH}/fmlib/Makefile.cross \
		SYSROOT=${SYSROOT} KSRCDIR=${SRCDIR} all

fmc: fmlib
	@mkdir -p ${BUILDDIR}/fmc
	cd ${BUILDDIR}/fmc && ${MAKE} -f ${FASTPATH}/fmc/Makefile.cross \
		SYSROOT=${SYSROOT} KSRCDIR=${SRCDIR} FMLIB_LIB=${BUILDDIR}/fmlib all

dpa_app: fmc
	@mkdir -p ${BUILDDIR}/dpa_app
	cd ${BUILDDIR}/dpa_app && ${MAKE} -f ${FASTPATH}/dpa_app/Makefile.cross \
		SYSROOT=${SYSROOT} KSRCDIR=${SRCDIR} \
		FMLIB_LIB=${BUILDDIR}/fmlib FMC_LIB=${BUILDDIR}/fmc all

cmm:
	@mkdir -p ${BUILDDIR}/cmm
	cd ${BUILDDIR}/cmm && ${MAKE} -f ${FASTPATH}/cmm/Makefile.cross \
		SYSROOT=${SYSROOT} KSRCDIR=${SRCDIR} all

cmmctl:
	@mkdir -p ${BUILDDIR}/cmmctl
	cd ${BUILDDIR}/cmmctl && ${MAKE} -f ${FASTPATH}/cmmctl/Makefile.cross \
		SYSROOT=${SYSROOT} all

fand:
	@mkdir -p ${BUILDDIR}/fand
	cd ${BUILDDIR}/fand && ${MAKE} -f ${DRIVERS}/fand/Makefile \
		SYSROOT=${SYSROOT} all

userspace: fmlib fmc dpa_app cmm cmmctl fand
	@mkdir -p ${DISTDIR}
	cp ${BUILDDIR}/fmc/fmc ${DISTDIR}/
	cp ${BUILDDIR}/dpa_app/dpa_app ${DISTDIR}/
	cp ${BUILDDIR}/cmm/cmm ${DISTDIR}/
	cp ${BUILDDIR}/cmmctl/cmmctl ${DISTDIR}/
	cp ${BUILDDIR}/fand/fand ${DISTDIR}/

# ============================================================
# FreeBSD package (mono-gateway.pkg)
# ============================================================

package: all
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
	install -m 644 ${DISTDIR}/mwifiex.ko ${PKG_STAGEDIR}/boot/modules/
	install -m 644 ${DISTDIR}/dpaa_wifi.ko ${PKG_STAGEDIR}/boot/modules/
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
	install -m 755 ${PKG_RCDDIR}/mwifiex_uap ${PKG_STAGEDIR}/usr/local/etc/rc.d/
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
# Full image build (kernel, modules, userspace, package, image)
# ============================================================

_NCPU!=		sysctl -n hw.ncpu 2>/dev/null || echo 4

image:
	@echo "NOTE: run as root (sudo make image)"
	@rm -rf ${DISTDIR}/*
	@touch ${DISTDIR}/.keep
	@echo "==> Step 1: Checking repositories"
	@test -d ${SRCDIR}/.git || git clone https://github.com/we-are-mono/opnsense-src.git -b ${OPS_BRANCH} ${SRCDIR}
	@test -d ${TOOLSDIR}/.git || git clone https://github.com/opnsense/tools.git ${TOOLSDIR}
	@cp -n ${OPSDIR}/config/GATEWAY.conf ${TOOLSDIR}/device/ 2>/dev/null || true
	cd ${SRCDIR} && git checkout ${OPS_BRANCH} && git pull || echo "    git pull skipped (NFS or no remote)"
	@echo "==> Step 2: Building kernel (clean)"
	rm -f ${SETSDIR}/kernel-*-GATEWAY.txz
	chflags -R noschg /usr/obj${SRCDIR}/arm64.aarch64 2>/dev/null || true
	rm -rf /usr/obj${SRCDIR}/arm64.aarch64
	${MAKE} -C ${TOOLSDIR} kernel \
		DEVICE=GATEWAY SETTINGS=${OPS_SETTINGS} \
		TOOLSDIR=${TOOLSDIR} SRCDIR=${SRCDIR}
	@echo "==> Step 2a: Populating sysroot from base set"
	@_base=$$(ls ${SETSDIR}/base-*-aarch64-GATEWAY.txz 2>/dev/null | head -1); \
	if [ -z "$$_base" ]; then \
		echo "ERROR: no base set found in ${SETSDIR}"; exit 1; \
	fi; \
	echo "    extracting headers and libraries from $$(basename $$_base)"; \
	tar xf "$$_base" -C ${SYSROOT} --no-fflags \
		--include='./usr/include/*' \
		--include='./usr/lib/*.a' \
		--include='./usr/lib/*.so' \
		--include='./usr/lib/*.o' \
		--include='./lib/*.so*'
	@echo "==> Step 2b: Installing libxml2 into sysroot"
	@if [ ! -f ${SYSROOT}/usr/local/lib/libxml2.so ]; then \
		rm -f /tmp/libxml2.pkg; \
		fetch -qo /tmp/libxml2.pkg '${LIBXML2_URL}'; \
		rm -rf /tmp/libxml2-extract; \
		mkdir -p /tmp/libxml2-extract; \
		tar xf /tmp/libxml2.pkg -C /tmp/libxml2-extract; \
		mkdir -p ${SYSROOT}/usr/local/include ${SYSROOT}/usr/local/lib; \
		cp -r /tmp/libxml2-extract/usr/local/include/libxml2 \
			${SYSROOT}/usr/local/include/; \
		cp -a /tmp/libxml2-extract/usr/local/lib/libxml2* \
			${SYSROOT}/usr/local/lib/; \
		rm -rf /tmp/libxml2-extract /tmp/libxml2.pkg; \
		echo "    libxml2 installed into sysroot"; \
	else \
		echo "    libxml2 already in sysroot"; \
	fi
	@echo "==> Step 3: Building modules, userspace, and package"
	${MAKE} -C ${OPSDIR} -j${_NCPU} package
	@echo "==> Step 5: Assembling image"
	rm -f ${IMAGESDIR}/OPNsense-*-GATEWAY.img \
		${IMAGESDIR}/OPNsense-*-GATEWAY.img.gz
	${MAKE} -C ${TOOLSDIR} arm-5G \
		DEVICE=GATEWAY SETTINGS=${OPS_SETTINGS} \
		TOOLSDIR=${TOOLSDIR} SRCDIR=${SRCDIR}
	@echo "==> Step 6: Compressing and copying to dist/"
	@mkdir -p ${DISTDIR}
	gzip -k ${IMAGESDIR}/OPNsense-*-GATEWAY.img
	cp ${IMAGESDIR}/OPNsense-*-GATEWAY.img.gz ${DISTDIR}/
	@echo "==> Image ready:"
	@ls -lh ${DISTDIR}/OPNsense-*-GATEWAY.img.gz

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
	${MAKE} -C ${KMOD_MWIFI} ${KMOD_ARGS} clean
	${MAKE} -C ${KMOD_DW} ${KMOD_ARGS} clean
	rm -rf ${BUILDDIR}

# Ensure "make -j clean all" serializes clean before build
.ORDER: clean all
.ORDER: clean modules
.ORDER: clean userspace

.PHONY: all modules userspace package image clean fetch-vendor \
	build-cdx build-fci build-auto_bridge build-pf_notify \
	build-emc2302 build-ina2xx build-lp5812 build-sfpled build-pcf2131 \
	build-caam build-tmp431 build-mwifiex build-dpaa_wifi \
	fmlib fmc dpa_app cmm cmmctl fand
