/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026 Mono Technologies Inc.
 *
 * NXP 88W9098 PCIe WiFi driver — FreeBSD OS abstraction header.
 * This replaces mlinux/moal_main.h for the FreeBSD port.
 */

#ifndef _MOAL_FREEBSD_H_
#define _MOAL_FREEBSD_H_

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/callout.h>
#include <sys/taskqueue.h>
#include <sys/firmware.h>
#include <sys/endian.h>
#include <sys/sysctl.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <machine/stdarg.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/ethernet.h>

/* mlan types and declarations */
#include "mlan_decl.h"
#include "mlan_ioctl.h"

#include "mwifiex_pci.h"

MALLOC_DECLARE(M_MWIFIEX);

/*
 * Lock wrapper — mlan stores a t_void* and passes it back to
 * moal_spin_lock/unlock. We wrap a FreeBSD mutex.
 */
struct mwifiex_lock {
	struct mtx	mtx;
};

/*
 * Timer wrapper — mlan stores a t_void* and passes it back to
 * moal_start_timer/stop_timer.
 */
struct mwifiex_timer {
	struct callout	callout;
	void		(*callback)(void *);
	void		*context;
	t_u8		periodic;
	t_u32		msec;
};

/*
 * DMA allocation tracker — we need to track bus_dma resources for
 * each consistent allocation so we can free them properly.
 */
struct mwifiex_dma_alloc {
	bus_dma_tag_t		tag;
	bus_dmamap_t		map;
	bus_addr_t		paddr;
	void			*vaddr;
	bus_size_t		size;
	SLIST_ENTRY(mwifiex_dma_alloc) link;
};

/*
 * Per-BSS private — one per interface (STA + UAP).
 * Analogous to Linux moal_private.
 */
struct mwifiex_priv {
	struct mwifiex_handle	*handle;
	if_t			ifp;
	uint8_t			bss_index;	/* 0=STA, 1=UAP */
	uint8_t			bss_type;	/* MLAN_BSS_TYPE_STA/UAP */
	uint8_t			bss_role;	/* MLAN_BSS_ROLE_STA/UAP */
	uint8_t			mac_addr[ETHER_ADDR_LEN];
	volatile int		running;	/* IFF_DRV_RUNNING set */

	/* TX pending count */
	volatile int		tx_pending;

	/* Statistics */
	uint64_t		tx_packets;
	uint64_t		tx_bytes;
	uint64_t		tx_errors;
	uint64_t		rx_packets;
	uint64_t		rx_bytes;
	uint64_t		rx_errors;

	/* dpaa_wifi bridge hook — set by dpaa_wifi.ko to divert RX
	 * frames to the FMan OH port for CDX offload.  NULL = disabled. */
	int			(*wifi_bridge_fn)(if_t ifp, struct mbuf *m);
};

/*
 * FreeBSD MOAL handle — our equivalent of Linux moal_handle.
 * This is passed as pmoal_handle to all moal_* callbacks.
 */
struct mwifiex_handle {
	struct mwifiex_softc	*sc;		/* back-pointer to softc */

	/* MLAN adapter — returned by mlan_register() */
	t_void			*pmlan_adapter;

	/* Firmware image (from firmware(9)) */
	const struct firmware	*fw_image;
	t_u32			fw_len;

	/* DMA tag for consistent allocations */
	bus_dma_tag_t		dma_tag;

	/* Track all DMA allocations for cleanup */
	SLIST_HEAD(, mwifiex_dma_alloc) dma_allocs;
	struct mtx		dma_list_mtx;

	/* Deferred processing tasks (scheduled from interrupt context) */
	struct task		main_task;	/* DEFER_HANDLING */
	struct task		cmdresp_task;	/* DEFER_CMDRESP */
	struct task		rx_task;	/* DEFER_RX_DATA */
	struct task		txcmpl_task;	/* DEFER_TX_COMPLTE */

	/* Per-BSS interfaces (STA=0, UAP=1) */
	struct mwifiex_priv	*priv[MLAN_MAX_BSS_NUM];
	int			priv_num;

	/* Synchronous IOCTL completion */
	volatile int		ioctl_wait_done;
	mlan_status		ioctl_status;

	/* Status */
	volatile int		fw_ready;
	volatile int		surprise_removed;

	/* Card type info */
	t_u16			card_type;

	/* UAP configuration (set via sysctl) */
	char			uap_ssid[33];		/* max 32 chars + NUL */
	char			uap_passphrase[65];	/* max 64 chars + NUL */
	int			uap_channel;		/* 0=auto, 1-14=2.4G */
	int			uap_max_sta;		/* max stations */
	int			uap_bandwidth;		/* 20, 40, or 80 MHz */
	char			uap_security[16];	/* open/wpa2/wpa3/wpa2wpa3 */
	int			uap_hidden;		/* 0=broadcast, 1=hidden */
	volatile int		uap_started;		/* BSS is running */
};

/* Callback table setup (moal_shim_freebsd.c) */
void	mwifiex_fill_callbacks(mlan_callbacks *cb);

#endif /* _MOAL_FREEBSD_H_ */
