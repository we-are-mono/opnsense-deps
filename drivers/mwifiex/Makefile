# NXP 88W9098 PCIe WiFi driver for FreeBSD
#
# Compiles the OS-independent mlan layer + FreeBSD OS abstraction (moal),
# and embeds the PCIe+UART combo firmware via firmware(9).
#
# Vendor source (mlan + firmware) is cloned at build time by the top-level
# Makefile's fetch-vendor target into _vendor/.
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

VENDORDIR?=	${.CURDIR}/../../_vendor
MLANDIR=	${VENDORDIR}/mwifiex/mlan
FWDIR=		${VENDORDIR}/imx-firmware/FwImage_9098_PCIE

KMOD=	mwifiex

# Embed PCIe+UART combo firmware via firmware(9)
FIRMWS=	pcieuart9098_combo_v1.bin:mwifiex_9098_pcie_fw:1

# FreeBSD driver (moal layer)
SRCS=	mwifiex_pci.c moal_shim_freebsd.c

# mlan core (OS-independent)
SRCS+=	mlan_shim.c mlan_init.c mlan_txrx.c mlan_cmdevt.c mlan_misc.c
SRCS+=	mlan_cfp.c mlan_wmm.c mlan_pcie.c
SRCS+=	mlan_11n.c mlan_11n_aggr.c mlan_11n_rxreorder.c
SRCS+=	mlan_11ac.c mlan_11ax.c mlan_11d.c mlan_11h.c
SRCS+=	mlan_scan.c mlan_join.c mlan_meas.c
SRCS+=	mlan_sta_ioctl.c mlan_sta_cmd.c mlan_sta_cmdresp.c mlan_sta_event.c
SRCS+=	mlan_sta_tx.c mlan_sta_rx.c
SRCS+=	mlan_uap_ioctl.c mlan_uap_cmdevent.c mlan_uap_txrx.c
# Skip: mlan_module.c (Linux EXPORT_SYMBOL), mlan_sdio.c, mlan_usb.c

# Required kernel interface headers
SRCS+=	device_if.h bus_if.h pci_if.h

# mlan include path + preprocessor defines
MLAN_CFLAGS=	-I${MLANDIR} \
		-DPCIE \
		-DSTA_SUPPORT \
		-DUAP_SUPPORT \
		-DMLAN_64BIT \
		-DPCIE9098 \
		-DDEBUG_LEVEL1

# mlan is NXP vendor code — suppress warnings that -Werror would reject
MLAN_NOWARN=	-Wno-error=unused-variable \
		-Wno-error=unused-label \
		-Wno-error=unused-but-set-variable \
		-Wno-error=missing-prototypes \
		-Wno-error=strict-prototypes \
		-Wno-error=cast-qual \
		-Wno-error=undef \
		-fgnu89-inline

# Apply mlan flags to all mlan source files
.for _f in mlan_shim.c mlan_init.c mlan_txrx.c mlan_cmdevt.c mlan_misc.c \
	mlan_cfp.c mlan_wmm.c mlan_pcie.c \
	mlan_11n.c mlan_11n_aggr.c mlan_11n_rxreorder.c \
	mlan_11ac.c mlan_11ax.c mlan_11d.c mlan_11h.c \
	mlan_scan.c mlan_join.c mlan_meas.c \
	mlan_sta_ioctl.c mlan_sta_cmd.c mlan_sta_cmdresp.c mlan_sta_event.c \
	mlan_sta_tx.c mlan_sta_rx.c \
	mlan_uap_ioctl.c mlan_uap_cmdevent.c mlan_uap_txrx.c
CFLAGS.${_f}+=	${MLAN_CFLAGS} ${MLAN_NOWARN}
.endfor

# FreeBSD moal files also need mlan include path + defines
CFLAGS.mwifiex_pci.c+=		${MLAN_CFLAGS}
CFLAGS.moal_shim_freebsd.c+=	${MLAN_CFLAGS}

# Create symlinks from mlan source directory so kmod.mk can find them
.for _f in mlan_shim.c mlan_init.c mlan_txrx.c mlan_cmdevt.c mlan_misc.c \
	mlan_cfp.c mlan_wmm.c mlan_pcie.c \
	mlan_11n.c mlan_11n_aggr.c mlan_11n_rxreorder.c \
	mlan_11ac.c mlan_11ax.c mlan_11d.c mlan_11h.c \
	mlan_scan.c mlan_join.c mlan_meas.c \
	mlan_sta_ioctl.c mlan_sta_cmd.c mlan_sta_cmdresp.c mlan_sta_event.c \
	mlan_sta_tx.c mlan_sta_rx.c \
	mlan_uap_ioctl.c mlan_uap_cmdevent.c mlan_uap_txrx.c
${_f}: ${MLANDIR}/${_f}
	ln -sf ${MLANDIR}/${_f} ${.TARGET}
CLEANFILES+=	${_f}
.endfor

# Firmware binary symlink (bsd.kmod.mk looks for it in .CURDIR)
pcieuart9098_combo_v1.bin: ${FWDIR}/pcieuart9098_combo_v1.bin
	ln -sf ${FWDIR}/pcieuart9098_combo_v1.bin ${.TARGET}
CLEANFILES+=	pcieuart9098_combo_v1.bin

.include <bsd.kmod.mk>
