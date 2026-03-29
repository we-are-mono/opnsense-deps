/*
 * cdx_dpa_bridge.c — Discover DPAA1 handles from FreeBSD newbus
 *
 * CDX is a loadable kernel module, not a newbus child of fman.  This
 * bridge uses devclass_find/devclass_get_device to locate the fman
 * driver and extract its PCD, MURAM, and FM handles.  It then calls
 * cdx_dpa_init() to create the classification hash tables and populate
 * fman_info for use by the CDX runtime.
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2022 NXP
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <vm/uma.h>
#include <machine/atomic.h>

#include <net/if.h>
#include <net/if_var.h>

#include "cdx_ioctl.h"
#include "cdx_dpa_init.h"
#include "cdx_dpa_bridge.h"

/* FreeBSD DPAA1 driver headers — accessor functions */
#include <contrib/ncsw/inc/integrations/dpaa_integration_ext.h>
#include <contrib/ncsw/inc/Peripherals/fm_ext.h>
#include <contrib/ncsw/inc/Peripherals/fm_port_ext.h>
#include <contrib/ncsw/inc/Peripherals/qm_ext.h>
#include <dev/dpaa/fman.h>
#include <dev/dpaa/bman.h>
#include <dev/dpaa/if_dtsec.h>
#include <dev/dpaa/dpaa_oh.h>

/* NCSW internal header — need t_FmPcd for physicalMuramBase */
#include "fm_pcd.h"

/*
 * t_FmMuram is a private struct in fm_muram.c.  We duplicate the layout
 * here to extract baseAddr (the virtual MURAM base address).  This is
 * safe because the struct layout is ABI-stable within the NCSW build.
 */
struct cdx_fm_muram {
	t_Handle	h_Mem;
	uintptr_t	baseAddr;
	uint32_t	size;
};
_Static_assert(offsetof(struct cdx_fm_muram, baseAddr) == sizeof(t_Handle),
    "cdx_fm_muram.baseAddr must follow h_Mem");
_Static_assert(offsetof(struct cdx_fm_muram, size) == sizeof(t_Handle) + sizeof(uintptr_t),
    "cdx_fm_muram.size must follow baseAddr");

/* ----------------------------------------------------------------
 * Module-private state
 * ---------------------------------------------------------------- */

static struct cdx_fman_info	cdx_fman_info_data;
static device_t			cdx_fman_dev;

/*
 * OH port state — device_t handles indexed by CDX port number (1-based).
 * CDX OH port number N maps to cell-index (N + 2), i.e.:
 *   number=1 → cell-index 3 ("dpa-fman0-oh@2", IPsec)
 *   number=2 → cell-index 4 ("dpa-fman0-oh@3", WiFi)
 * Cell-index 2 (port@82000) is skipped — reserved for Host Command.
 */
#define	CDX_MAX_OH_PORTS	2
static device_t	cdx_oh_devs[CDX_MAX_OH_PORTS];	/* index 0 = number 1 */

/*
 * Global fman_info pointer — declared in cdx_dpa_stub.c (or will be
 * moved here once stubs are fully replaced).  CDX runtime code reads
 * this via dpa_get_pcdhandle(), dpa_get_tdinfo(), etc.
 */
extern struct cdx_fman_info	*fman_info;

/* Number of FMan instances (LS1046A has one) */
uint32_t cdx_num_fmans;

/*
 * FmMurambaseAddr — virtual base address of MURAM.
 * Used by cdx_ehash.c MURAM_VIRT_TO_PHYS_ADDR macro to convert
 * virtual MURAM pointers to 24-bit physical offsets for Action
 * Descriptors.  On Linux SDK this is set in fm_muram.c; on FreeBSD
 * we extract it from the NCSW MURAM handle during bridge init.
 */
void *FmMurambaseAddr;

/* ----------------------------------------------------------------
 * Initialization
 * ---------------------------------------------------------------- */

int
cdx_dpa_bridge_init(void)
{
	devclass_t dc;
	device_t fmdev;
	t_Handle fm_handle, pcd_handle, muram_handle, netenv_handle;
	t_FmPcd *p_FmPcd;
	int rv;

	/* Find fman device via devclass */
	dc = devclass_find("fman");
	if (dc == NULL) {
		printf("cdx: bridge: fman devclass not found\n");
		return (ENXIO);
	}

	fmdev = devclass_get_device(dc, 0);
	if (fmdev == NULL) {
		printf("cdx: bridge: fman0 device not found\n");
		return (ENXIO);
	}

	cdx_fman_dev = fmdev;

	/* Get handles from fman driver */
	rv = fman_get_handle(fmdev, &fm_handle);
	if (rv != 0 || fm_handle == NULL) {
		printf("cdx: bridge: fman_get_handle failed\n");
		return (ENXIO);
	}

	rv = fman_get_pcd_handle(fmdev, &pcd_handle);
	if (rv != 0 || pcd_handle == NULL) {
		printf("cdx: bridge: fman_get_pcd_handle failed\n");
		return (ENXIO);
	}

	rv = fman_get_muram_handle(fmdev, &muram_handle);
	if (rv != 0 || muram_handle == NULL) {
		printf("cdx: bridge: fman_get_muram_handle failed\n");
		return (ENXIO);
	}

	rv = fman_get_netenv_handle(fmdev, &netenv_handle);
	if (rv != 0 || netenv_handle == NULL) {
		printf("cdx: bridge: fman_get_netenv_handle failed\n");
		return (ENXIO);
	}

	printf("cdx: bridge: found fman0 — fm=%p pcd=%p muram=%p netenv=%p\n",
	    fm_handle, pcd_handle, muram_handle, netenv_handle);

	/*
	 * Hot-add Host Command port to existing PCD.
	 * The PCD was created at boot with Parser + KeyGen + CC.  This
	 * adds the HC port needed for advanced offload (hash tables,
	 * header manipulation) without rebuilding PCD — existing dtsec
	 * KeyGen schemes and port bindings are preserved.
	 */
	rv = fman_reinit_pcd_with_hc(fmdev);
	if (rv != 0) {
		printf("cdx: bridge: fman_reinit_pcd_with_hc failed: %d\n",
		    rv);
		return (rv);
	}

	printf("cdx: bridge: PCD upgraded — pcd=%p netenv=%p\n",
	    pcd_handle, netenv_handle);

	/*
	 * Initialize fman_info with handles only.
	 *
	 * Hash tables and port/table metadata are NOT created here.
	 * dpa_app (userspace) will program FMan PCD via FMC and pass
	 * all table/port info to CDX via the CDX_CTRL_DPA_SET_PARAMS
	 * ioctl (handled in cdx_dpa_takeover.c).
	 */
	memset(&cdx_fman_info_data, 0, sizeof(cdx_fman_info_data));
	cdx_fman_info_data.index = 0;
	cdx_fman_info_data.pcd_handle = pcd_handle;
	cdx_fman_info_data.fm_handle = fm_handle;
	cdx_fman_info_data.muram_handle = muram_handle;

	/* Get physical MURAM base from PCD internal state */
	p_FmPcd = (t_FmPcd *)pcd_handle;
	cdx_fman_info_data.physicalMuramBase = p_FmPcd->physicalMuramBase;

	/*
	 * Set FmMurambaseAddr — the virtual base of the MURAM mapping.
	 * cdx_ehash.c uses MURAM_VIRT_TO_PHYS_ADDR(addr) which computes
	 * (addr - FmMurambaseAddr) to get the 24-bit MURAM offset for ADs.
	 */
	{
		struct cdx_fm_muram *p_muram;
		p_muram = (struct cdx_fm_muram *)muram_handle;
		FmMurambaseAddr = (void *)p_muram->baseAddr;
	}

	printf("cdx: bridge: MURAM virt=%p phys=0x%jx\n",
	    FmMurambaseAddr,
	    (uintmax_t)cdx_fman_info_data.physicalMuramBase);

	/* Set global pointers for CDX runtime */
	fman_info = &cdx_fman_info_data;
	cdx_num_fmans = 1;

	/* Initialize per-interface MURAM statistics */
	rv = cdxdrv_init_stats(muram_handle);
	if (rv != 0) {
		printf("cdx: bridge: cdxdrv_init_stats failed: %d\n", rv);
		return (ENXIO);
	}

	/* Print dtsec interface summary for diagnostics */
	cdx_dpa_bridge_print_dtsec();

	/* Discover OH ports */
	cdx_dpa_bridge_discover_oh_ports();

	printf("cdx: bridge: initialization complete\n");
	return (0);
}

/* SDK external hash table API (fm_ehash_freebsd.c) */
extern void ExternalHashTableDelete(t_Handle h_HashTbl);
extern void cdx_destroy_port_fqs(void);

void
cdx_dpa_bridge_destroy(void)
{
	struct cdx_fman_info *fi = &cdx_fman_info_data;
	uint32_t i;

	/*
	 * Step 1: Delete PCD on all ports FIRST.
	 * This stops FMan from classifying frames through CDX hash
	 * tables and KG schemes.  Without this, FMan continues to
	 * reference MURAM objects we're about to free → exceptions.
	 */
	{
		devclass_t dc;
		device_t dev;
		struct dtsec_softc *sc;
		int unit;

		dc = devclass_find("dtsec");
		if (dc != NULL) {
			for (unit = 0; unit < devclass_get_maxunit(dc);
			    unit++) {
				dev = devclass_get_device(dc, unit);
				if (dev == NULL)
					continue;
				sc = device_get_softc(dev);
				if (sc == NULL || sc->sc_rxph == NULL)
					continue;
				FM_PORT_DeletePCD(sc->sc_rxph);
				device_printf(dev, "PCD deleted for CDX "
				    "unload\n");
			}
		}

		/* OH ports */
		for (i = 0; i < CDX_MAX_OH_PORTS; i++) {
			t_Handle ohp;
			if (cdx_oh_devs[i] == NULL)
				continue;
			ohp = dpaa_oh_get_fm_port(cdx_oh_devs[i]);
			if (ohp != NULL) {
				FM_PORT_DeletePCD(ohp);
				printf("cdx: OH port %u PCD deleted\n",
				    i + 1);
			}
		}
	}

	/* Clear globals to prevent concurrent access */
	fman_info = NULL;
	cdx_num_fmans = 0;
	cdx_fman_dev = NULL;

	/*
	 * Step 2: Free distribution FQRs.
	 * PCD is already deleted, so no new frames will be enqueued.
	 * Retire existing FQs and quiesce portal poll tasks.
	 */
	cdx_destroy_port_fqs();

	/*
	 * Delete all hash tables tracked in tbl_info.
	 * Handles both standalone (from cdx_dpa_init) and bound
	 * (from cdx_ioc_set_dpa_params) hash tables.
	 */
	if (fi->tbl_info != NULL) {
		for (i = 0; i < fi->num_tables; i++) {
			if (fi->tbl_info[i].id != NULL) {
				ExternalHashTableDelete(fi->tbl_info[i].id);
				fi->tbl_info[i].id = NULL;
			}
		}
		free(fi->tbl_info, M_DEVBUF);
		fi->tbl_info = NULL;
		fi->num_tables = 0;
	}

	/* Free port info (includes trailing dist_info allocation) */
	if (fi->portinfo != NULL) {
		free(fi->portinfo, M_DEVBUF);
		fi->portinfo = NULL;
		fi->max_ports = 0;
	}

	/*
	 * Clear standalone htable_handles[] tracking array.
	 * In standalone mode these point to the same handles we just
	 * freed above.  In FMC mode they were already cleared by the
	 * ioctl handler.  Either way, NULL them to prevent stale access.
	 */
	cdx_dpa_clear_handles();
}

/*
 * Return the fman device_t for use by other CDX subsystems.
 * Needed by cdx_ioc_set_dpa_params() to resolve chardev handle IDs.
 */
device_t
cdx_dpa_bridge_get_fman_dev(void)
{

	return (cdx_fman_dev);
}

/* ----------------------------------------------------------------
 * dtsec interface registration
 *
 * Enumerates all dtsec devices via newbus and registers each with
 * CDX's onif table.  This is the FreeBSD equivalent of Linux's
 * dpa_cfg.c loop which calls cdx_add_eth_onif() during module init.
 *
 * Must be called after cdx_dpa_bridge_init() (so the bridge can
 * find dtsec devices) and after devman_init_linux_stats() (so the
 * devlist lock is initialized).
 * ---------------------------------------------------------------- */

/* Declared in cdx_devman_freebsd.c */
int cdx_add_eth_onif(char *name);

int
cdx_dpa_bridge_register_dtsec(void)
{
	devclass_t dc;
	device_t *devlist;
	int count, i, registered, rv;

	dc = devclass_find("dtsec");
	if (dc == NULL) {
		printf("cdx: bridge: dtsec devclass not found\n");
		return (ENXIO);
	}

	if (devclass_get_devices(dc, &devlist, &count) != 0) {
		printf("cdx: bridge: failed to enumerate dtsec devices\n");
		return (ENXIO);
	}

	registered = 0;
	for (i = 0; i < count; i++) {
		struct dtsec_softc *sc;
		const char *ifname;

		sc = device_get_softc(devlist[i]);
		if (sc == NULL || sc->sc_ifnet == NULL)
			continue;

		/* Skip hidden (internally-used) interfaces */
		if (sc->sc_hidden)
			continue;

		ifname = if_name(sc->sc_ifnet);
		rv = cdx_add_eth_onif(__DECONST(char *, ifname));
		if (rv != 0) {
			printf("cdx: bridge: failed to register %s: %d\n",
			    ifname, rv);
			continue;
		}
		registered++;
	}

	free(devlist, M_TEMP);
	printf("cdx: bridge: registered %d dtsec interface(s) with CDX\n",
	    registered);
	return (0);
}

/* ----------------------------------------------------------------
 * dtsec interface enumeration — diagnostic
 * ---------------------------------------------------------------- */

void
cdx_dpa_bridge_print_dtsec(void)
{
	devclass_t dc;
	device_t *devlist;
	int count, i;

	dc = devclass_find("dtsec");
	if (dc == NULL) {
		printf("cdx: bridge: dtsec devclass not found\n");
		return;
	}

	if (devclass_get_devices(dc, &devlist, &count) != 0) {
		printf("cdx: bridge: failed to enumerate dtsec devices\n");
		return;
	}

	printf("cdx: bridge: found %d dtsec interface(s)\n", count);
	for (i = 0; i < count; i++) {
		struct dtsec_softc *sc;

		sc = device_get_softc(devlist[i]);
		if (sc == NULL || sc->sc_ifnet == NULL)
			continue;

		printf("cdx: bridge:   %s — eth_id=%u type=%s "
		    "mac=%02x:%02x:%02x:%02x:%02x:%02x%s\n",
		    if_name(sc->sc_ifnet),
		    sc->sc_eth_id,
		    (sc->sc_eth_dev_type == ETH_10GSEC) ? "10G" : "1G",
		    sc->sc_mac_addr[0], sc->sc_mac_addr[1],
		    sc->sc_mac_addr[2], sc->sc_mac_addr[3],
		    sc->sc_mac_addr[4], sc->sc_mac_addr[5],
		    sc->sc_hidden ? " (hidden)" : "");
	}

	free(devlist, M_TEMP);
}

/*
 * Find a dtsec device by interface name.  Used by devman (Step 6)
 * when CMM registers an interface.
 *
 * Returns the dtsec_softc pointer, or NULL if not found.
 */
struct dtsec_softc *
cdx_dpa_bridge_find_dtsec(const char *ifname)
{
	devclass_t dc;
	device_t *devlist;
	int count, i;
	struct dtsec_softc *result = NULL;

	dc = devclass_find("dtsec");
	if (dc == NULL)
		return (NULL);

	if (devclass_get_devices(dc, &devlist, &count) != 0)
		return (NULL);

	for (i = 0; i < count; i++) {
		struct dtsec_softc *sc;

		sc = device_get_softc(devlist[i]);
		if (sc == NULL || sc->sc_ifnet == NULL)
			continue;

		if (strcmp(if_name(sc->sc_ifnet), ifname) == 0) {
			result = sc;
			break;
		}
	}

	free(devlist, M_TEMP);
	return (result);
}

/*
 * cdx_dpa_bridge_find_ifnet — Find the ifnet for a dtsec by name.
 *
 * Thin wrapper around cdx_dpa_bridge_find_dtsec that returns just
 * the ifnet pointer.  Used by cdx_dpa_takeover.c to avoid including
 * if_dtsec.h in the CDX module.
 */
if_t
cdx_dpa_bridge_find_ifnet(const char *ifname)
{
	struct dtsec_softc *sc;

	sc = cdx_dpa_bridge_find_dtsec(ifname);
	if (sc == NULL)
		return (NULL);

	return (sc->sc_ifnet);
}

/*
 * Find a dtsec device by FMan port index (eth_id).  Used by devman
 * to look up dtsec devices by port number rather than name.
 *
 * Returns the dtsec_softc pointer, or NULL if not found.
 */
struct dtsec_softc *
cdx_dpa_bridge_find_dtsec_by_ethid(uint8_t eth_id)
{
	devclass_t dc;
	device_t *devlist;
	int count, i;
	struct dtsec_softc *result = NULL;

	dc = devclass_find("dtsec");
	if (dc == NULL)
		return (NULL);

	if (devclass_get_devices(dc, &devlist, &count) != 0)
		return (NULL);

	for (i = 0; i < count; i++) {
		struct dtsec_softc *sc;

		sc = device_get_softc(devlist[i]);
		if (sc == NULL)
			continue;

		if (sc->sc_eth_id == eth_id) {
			result = sc;
			break;
		}
	}

	free(devlist, M_TEMP);
	return (result);
}

/*
 * cdx_dpa_bridge_find_ifname_by_fman_params — Find dtsec interface name
 * by FMan index, port index, and speed type.
 *
 * This is the FreeBSD equivalent of Linux's find_osdev_by_fman_params().
 * Used by cdx_dpa_takeover.c to replace dpa_app-generated portinfo names
 * (e.g., "dpa-fm0-10G-eth0") with actual FreeBSD kernel interface names
 * (e.g., "dtsec3").
 *
 * type: 1 = 1G (ETH_DTSEC), 10 = 10G (ETH_10GSEC), 0 = OH (skipped)
 *
 * Returns a pointer to the interface name string (owned by ifnet, valid
 * as long as the interface exists), or NULL if not found.
 */
const char *
cdx_dpa_bridge_find_ifname_by_fman_params(uint32_t fm_index, uint32_t port_idx,
    uint32_t type)
{
	devclass_t dc;
	device_t *devlist;
	int count, i;
	enum eth_dev_type want_type;
	const char *result = NULL;

	if (type == 0)
		return (NULL);	/* OH ports don't have dtsec interfaces */

	want_type = (type == 10) ? ETH_10GSEC : ETH_DTSEC;

	dc = devclass_find("dtsec");
	if (dc == NULL)
		return (NULL);

	if (devclass_get_devices(dc, &devlist, &count) != 0)
		return (NULL);

	for (i = 0; i < count; i++) {
		struct dtsec_softc *sc;

		sc = device_get_softc(devlist[i]);
		if (sc == NULL || sc->sc_ifnet == NULL)
			continue;

		if (sc->sc_eth_dev_type == want_type &&
		    sc->sc_eth_id == port_idx) {
			result = if_name(sc->sc_ifnet);
			break;
		}
	}

	free(devlist, M_TEMP);
	return (result);
}

/*
 * cdx_dpa_bridge_get_rx_pool — Return the BMan pool handle from a dtsec.
 *
 * All dtsec interfaces share the same BMan buffer pool (same bpid from FDT).
 * Returns NULL if no dtsec is found or the pool is not initialized.
 */
t_Handle
cdx_dpa_bridge_get_rx_pool(void)
{
	struct dtsec_softc *sc;

	sc = cdx_dpa_bridge_find_dtsec_by_ethid(0);
	if (sc != NULL)
		return (sc->sc_rx_pool);
	return (NULL);
}

/*
 * cdx_dpa_bridge_get_rx_sc — Return an opaque dtsec_softc pointer.
 *
 * Used by cdx_dpa_takeover.c to cache the softc pointer for passing
 * as ext_arg2 in m_extadd.  The CDX module doesn't include if_dtsec.h
 * directly, so the pointer is opaque (void *) from its perspective.
 */
void *
cdx_dpa_bridge_get_rx_sc(void)
{

	return (cdx_dpa_bridge_find_dtsec_by_ethid(0));
}

/*
 * cdx_dpa_bridge_rx_buf_free — Consumption model buffer free.
 *
 * Recovers the original KVA pointer stashed at offset 0 of the buffer
 * by the dtsec driver's BMan refill code, frees to UMA, and decrements
 * sc_rx_buf_total.  The dtsec refill mechanism will notice the BMan
 * pool count is low and replenish it with fresh allocations.
 *
 * This matches dtsec_rm_fqr_mext_free() in if_dtsec_rm.c.
 */
void
cdx_dpa_bridge_rx_buf_free(void *sc_opaque, void *buf)
{
	struct dtsec_softc *sc = sc_opaque;

	uma_zfree(sc->sc_rx_zone, (void *)(*(uintptr_t *)buf));
	atomic_subtract_32(&sc->sc_rx_buf_total, 1);
}

/*
 * cdx_dpa_bridge_rx_pool_refill — Refill BMan pool from UMA.
 *
 * Allocates buffers from the dtsec UMA zone, stashes the KVA pointer
 * at offset 0 (matching dtsec_rm_buf_stash_ptr), and puts them into
 * BMan.  Increments sc_rx_buf_total for each buffer added.
 *
 * Must be called when BMan pool count is low.  This is the CDX
 * equivalent of the refill at the top of dtsec_rm_fqr_rx_callback().
 * When CDX replaces the dtsec PCD, dtsec RX callbacks no longer fire,
 * so CDX must handle refill itself.
 *
 * Returns the number of buffers actually added to BMan.
 */
unsigned int
cdx_dpa_bridge_rx_pool_refill(void *sc_opaque, unsigned int count)
{
	struct dtsec_softc *sc = sc_opaque;
	unsigned int i;
	uint8_t *buf;

	for (i = 0; i < count; i++) {
		buf = uma_zalloc(sc->sc_rx_zone, M_NOWAIT);
		if (buf == NULL)
			break;
		/* Stash KVA pointer at offset 0 for recovery after
		 * BMan/FMan round-trip (matches dtsec_rm_buf_stash_ptr) */
		*(uintptr_t *)buf = (uintptr_t)buf;
		if (bman_put_buffer(sc->sc_rx_pool, buf) != 0) {
			uma_zfree(sc->sc_rx_zone, buf);
			break;
		}
		atomic_add_32(&sc->sc_rx_buf_total, 1);
	}
	return (i);
}

/* ----------------------------------------------------------------
 * QoS helpers — port handle and PCD accessors for cdx_qos_freebsd.c
 * ---------------------------------------------------------------- */

/*
 * Get the NCSW FM_PORT RX handle for a dtsec port by eth_id.
 * Used by cdx_qos_freebsd.c to call FM_PORT_PcdPlcrAllocProfiles.
 */
t_Handle
cdx_dpa_bridge_get_rx_port_handle(uint8_t eth_id)
{
	struct dtsec_softc *sc;

	sc = cdx_dpa_bridge_find_dtsec_by_ethid(eth_id);
	if (sc == NULL)
		return (NULL);
	return (sc->sc_rxph);
}

/*
 * Get the PCD handle (from fman_info).
 * All dtsec ports share the same PCD on LS1046A (single FMan).
 */
t_Handle
cdx_dpa_bridge_get_pcd_handle(void)
{

	if (fman_info == NULL)
		return (NULL);
	return (fman_info->pcd_handle);
}

/*
 * Check whether a dtsec port is 10G (TGEC) by eth_id.
 * Used to select appropriate default rate limits.
 */
bool
cdx_dpa_bridge_is_10g_port(uint8_t eth_id)
{
	struct dtsec_softc *sc;

	sc = cdx_dpa_bridge_find_dtsec_by_ethid(eth_id);
	if (sc == NULL)
		return (false);
	return (sc->sc_eth_dev_type == ETH_10GSEC);
}

/* ----------------------------------------------------------------
 * OH port discovery
 *
 * Discovers dpaa_oh devices via newbus and stores their device_t
 * handles for later use by CDX devoh code.  OH ports are identified
 * by cell-index, matching Linux SDK port assignment:
 *   cell-index 3 → CDX number 1 (portid 9, IPsec, "dpa-fman0-oh@2")
 *   cell-index 4 → CDX number 2 (portid 10, WiFi, "dpa-fman0-oh@3")
 * Cell-index 2 (port@82000) is reserved for Host Command.
 * ---------------------------------------------------------------- */

void
cdx_dpa_bridge_discover_oh_ports(void)
{
	int i;

	for (i = 0; i < CDX_MAX_OH_PORTS; i++) {
		int cell_index = i + 3;	/* number 1→cell 3, number 2→cell 4 */
		device_t dev;

		dev = dpaa_oh_find_port(cell_index);
		if (dev == NULL) {
			printf("cdx: bridge: OH port cell-index %d not found\n",
			    cell_index);
			cdx_oh_devs[i] = NULL;
			continue;
		}

		cdx_oh_devs[i] = dev;
		printf("cdx: bridge:   OH port %d: cell-index=%d "
		    "QMan chan=0x%x dflt FQID=%u data_off=%u\n",
		    i + 1, cell_index,
		    dpaa_oh_get_qman_channel(dev),
		    dpaa_oh_get_default_fqid(dev),
		    dpaa_oh_get_data_offset(dev));
	}
}

/*
 * Get the device_t for an OH port by CDX port number (1-based).
 * Returns NULL if the port was not discovered.
 */
device_t
cdx_dpa_bridge_get_oh_dev(int number)
{

	if (number < 1 || number > CDX_MAX_OH_PORTS)
		return (NULL);
	return (cdx_oh_devs[number - 1]);
}

/*
 * Get the FM_PORT handle for an OH port by CDX port number.
 * Used by CDX PCD initialization to call FM_PORT_SetPCD().
 */
t_Handle
cdx_dpa_bridge_get_oh_fm_port(int number)
{
	device_t dev;

	dev = cdx_dpa_bridge_get_oh_dev(number);
	if (dev == NULL)
		return (NULL);
	return (dpaa_oh_get_fm_port(dev));
}

/*
 * Get the QMan channel for an OH port by CDX port number.
 * Used by devoh to create FQs targeting the OH port.
 */
uint32_t
cdx_dpa_bridge_get_oh_channel(int number)
{
	device_t dev;

	dev = cdx_dpa_bridge_get_oh_dev(number);
	if (dev == NULL)
		return (0);
	return (dpaa_oh_get_qman_channel(dev));
}

/*
 * Get the default FQID for an OH port by CDX port number.
 */
uint32_t
cdx_dpa_bridge_get_oh_dflt_fqid(int number)
{
	device_t dev;

	dev = cdx_dpa_bridge_get_oh_dev(number);
	if (dev == NULL)
		return (0);
	return (dpaa_oh_get_default_fqid(dev));
}
