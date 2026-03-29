# CDX (Conntrack Data-plane eXpress) kernel module for FreeBSD
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: GPL-2.0+

.include "../Makefile.inc"

KMOD=	cdx

# FreeBSD-specific files (in this directory)
SRCS=	cdx_main_freebsd.c cdx_timer_freebsd.c cdx_cmdhandler_freebsd.c \
	cdx_dev_freebsd.c cdx_sysctl.c cdx_dpa_stub.c cdx_dpa_takeover.c \
	cdx_dpa_bridge.c cdx_dpa_cfg.c cdx_dpa_init.c \
	cdx_usermodehelper.c \
	cdx_devman_freebsd.c cdx_ehash.c \
	cdx_ifstats_freebsd.c cdx_debug_freebsd.c \
	cdx_qos_freebsd.c cdx_mc_freebsd.c \
	cdx_devoh_freebsd.c cdx_reassm_freebsd.c \
	cdx_ceetm_freebsd.c \
	dpa_ipsec_freebsd.c cdx_dpa_ipsec_freebsd.c

# Tier 1 CDX sources (from original CDX tree, mostly unchanged)
SRCS+=	cdx_hal.c \
	layer2.c control_ipv4.c control_ipv6.c control_tx.c control_rx.c \
	control_vlan.c control_lagg.c control_pppoe.c control_bridge.c control_tunnel.c \
	control_socket.c control_stat.c control_natpt.c control_qm.c \
	control_wifi.c control_ipsec.c control_rtp_relay.c \
	control_pktcap.c \
	query_Rx.c query_ipsec.c

SRCS+=	opt_platform.h opt_dpaa.h device_if.h bus_if.h ofw_bus_if.h

# Search path for Tier 1 sources in vendor CDX tree
.PATH:	${FASTPATH_ROOT}/vendor/cdx

# Force-include our prelude before every source file. This pre-includes
# shadow headers (cdx.h, dpa_ipsec.h, misc.h) setting their include guards,
# so when Tier 1 files find originals in vendor/cdx/ they're skipped.
CFLAGS+=	-include ${FASTPATH_ROOT}/include/cdx_prelude.h
CFLAGS+=	-I${FASTPATH_ROOT}/vendor/cdx
CFLAGS+=	-DENABLE_EGRESS_QOS
CFLAGS+=	-DDPAA_FAST_PATH
CFLAGS+=	-DENABLE_FLOW_TIME_STAMPS
CFLAGS+=	-DDPA_IPSEC_OFFLOAD
CFLAGS+=	-DWIFI_ENABLE

# NCSW build environment defines (replicate dflags_arm64.h without its
# Linux-specific includes like <asm/byteorder.h> and <linux/delay.h>)
CFLAGS+=	-Wno-typedef-redefinition
CFLAGS+=	-DNCSW_ARM_CORE -DNCSW_FREEBSD -DCORE_CACHELINE_SIZE=64
CFLAGS+=	-DDEBUG_ERRORS=1 -DREPORT_EVENTS=1
CFLAGS+=	-DDEBUG_GLOBAL_LEVEL=REPORT_LEVEL_INFO
CFLAGS+=	-DEVENT_GLOBAL_LEVEL=REPORT_LEVEL_MINOR

# NCSW headers — the full set needed for cross-directory quoted includes
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/etc
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/flib
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/cores
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/integrations
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/inc/Peripherals
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/build
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/Peripherals/FM/Pcd
CFLAGS+=	-I${SYSDIR}/contrib/ncsw/Peripherals/FM/inc

# Relax warnings for Tier 1 vendor sources — original NXP code not written
# for FreeBSD's strict Clang warnings.  Shared relaxation flags:
VENDOR_WARN=	-Wno-missing-prototypes -Wno-gnu-pointer-arith \
		-Wno-pointer-arith -Wno-cast-qual

CFLAGS.cdx_hal.c+=		${VENDOR_WARN}
CFLAGS.layer2.c+=		${VENDOR_WARN}
CFLAGS.control_ipv4.c+=		${VENDOR_WARN}
CFLAGS.control_ipv6.c+=		${VENDOR_WARN}
CFLAGS.control_tx.c+=		${VENDOR_WARN}
CFLAGS.control_rx.c+=		${VENDOR_WARN}
CFLAGS.control_vlan.c+=		${VENDOR_WARN}
CFLAGS.control_lagg.c+=		${VENDOR_WARN}
CFLAGS.control_pppoe.c+=	${VENDOR_WARN}
CFLAGS.control_bridge.c+=	${VENDOR_WARN}
CFLAGS.control_tunnel.c+=	${VENDOR_WARN}
CFLAGS.control_socket.c+=	${VENDOR_WARN}
CFLAGS.control_stat.c+=		${VENDOR_WARN}
CFLAGS.control_natpt.c+=	${VENDOR_WARN}
CFLAGS.control_qm.c+=		${VENDOR_WARN}
CFLAGS.control_wifi.c+=		${VENDOR_WARN}
CFLAGS.control_ipsec.c+=	${VENDOR_WARN}
CFLAGS.control_rtp_relay.c+=	${VENDOR_WARN}
CFLAGS.control_pktcap.c+=	${VENDOR_WARN}
CFLAGS.query_Rx.c+=		${VENDOR_WARN}
CFLAGS.query_ipsec.c+=		${VENDOR_WARN}

# cdx_ehash.c is ported vendor code (originally cdx-5.03.1/cdx_ehash.c)
CFLAGS.cdx_ehash.c+=		${VENDOR_WARN}

# cdx_mc_freebsd.c is ported vendor code (originally dpa_control_mc.c + cdx_mc_query.c)
CFLAGS.cdx_mc_freebsd.c+=	${VENDOR_WARN}

# IPsec offload — ported from cdx-5.03.1/dpa_ipsec.c + cdx_dpa_ipsec.c
CFLAGS.dpa_ipsec_freebsd.c+=		${VENDOR_WARN}
CFLAGS.cdx_dpa_ipsec_freebsd.c+=	${VENDOR_WARN}

.include <bsd.kmod.mk>
