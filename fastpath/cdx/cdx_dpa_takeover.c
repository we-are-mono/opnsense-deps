/*
 * cdx_dpa_takeover.c — CDX_CTRL_DPA_SET_PARAMS ioctl handler
 *
 * Handles the CDX_CTRL_DPA_SET_PARAMS ioctl from dpa_app.  dpa_app
 * programs FMan PCD via FMC, creating NCSW hash tables and CC trees.
 * The ioctl passes hash table handles to CDX, which binds them to
 * CDX enhanced external hash format via ExternalHashTableBindNCSW:
 *   1. Reusing the MURAM Action Descriptor (same address, CC tree valid)
 *   2. Overwriting the AD with CDX enhanced external hash format
 *   3. Allocating new DDR buckets and per-bucket spinlocks
 *
 * After bind, CDX runtime (ExternalHashTableAddKey/DeleteKey) manages
 * flow entries in the DDR buckets.  FMan CC tree follows the same MURAM
 * address into CDX-format entries with hardware opcodes.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021-2022 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>

#include "cdx_ioctl.h"
#include "cdx_dpa_bridge.h"

/* FreeBSD DPAA1 driver — handle resolution */
#include <dev/dpaa/fman.h>
#include <dev/dpaa/fman_chardev.h>
#include <dev/dpaa/bman.h>
#include <dev/dpaa/dpaa_oh.h>

/* From if_dtsec.h — forward declare to avoid pulling in NCSW port types */
void	dtsec_rm_buf_free_external(uint8_t bpid, void *buf);
void	dtsec_rm_pool_rx_refill_bpid(uint8_t bpid);

/* NCSW types (t_Handle) */
#include <contrib/ncsw/inc/ncsw_ext.h>

/* NCSW PCD types (for t_FmPcdCcNextEngineParams) */
#include <contrib/ncsw/inc/Peripherals/fm_pcd_ext.h>

/* NCSW QMan types (for e_QmFQChannel, t_QmReceivedFrameCallback) */
#include <contrib/ncsw/inc/Peripherals/qm_ext.h>

/* ExternalHashTableModifyMissNextEngine — provided by kernel fm_ehash.c */
extern t_Error ExternalHashTableModifyMissNextEngine(t_Handle h_HashTbl,
    t_FmPcdCcNextEngineParams *p_FmPcdCcNextEngineParams);

/* Deferred RX delivery — kernel symbol from qman_portals.c */
extern void qman_rx_defer(struct mbuf *m);

/* DPAA FD accessors — from dpaa_ext.h */
#include <contrib/ncsw/inc/Peripherals/dpaa_ext.h>

/* FM_PORT_BUFFER_SIZE — from dtsec_rm.c */
#define	CDX_RX_BUFFER_SIZE	9600

/* FreeBSD QMan API — kernel symbol resolution */
extern t_Handle qman_fqr_create(uint32_t fqids_num,
    e_QmFQChannel channel, uint8_t wq, bool force_fqid,
    uint32_t fqid_or_align, bool init_parked, bool hold_active,
    bool prefer_in_cache, bool congst_avoid_ena, t_Handle congst_group,
    int8_t overhead_accounting_len, uint32_t tail_drop_threshold);
extern t_Error qman_fqr_register_cb(t_Handle fqr,
    t_QmReceivedFrameCallback *callback, t_Handle app);
extern t_Error qman_fqr_free(t_Handle fqr);
extern void qman_portal_quiesce(void);
extern void dtsec_release_rss_fqrs(void);

/* Global fman_info pointer (declared in cdx_dpa_stub.c) */
extern struct cdx_fman_info *fman_info;
extern uint32_t cdx_num_fmans;

/* devman list and OH port registration (cdx_devoh_freebsd.c) */
#include "portdefs.h"		/* struct dpa_iface_info */
#define	IF_TYPE_OFPORT	(1 << 8)	/* from layer2.h */
extern struct dpa_iface_info *dpa_interface_info;
extern int cdxdrv_create_of_fqs(struct dpa_iface_info *dpa_oh_iface_info);

/* IPR configuration (cdx_reassm_freebsd.c) */
extern struct cdx_ipr_info ipr_info;

/* QoS policer init (cdx_qos_freebsd.c) */
extern int cdx_qos_init_expt_profiles(void);
#ifdef ENABLE_INGRESS_QOS
extern int cdx_qos_init_ingress_profiles(void);
#endif

#define	PORTID_SHIFT_VAL	8
#define	CDX_NUM_RX_CPUS		4	/* LS1046A quad-core */

/*
 * Distribution FQR tracking for cleanup.
 */
#define	CDX_MAX_DIST_FQRS	64
static t_Handle cdx_dist_fqrs[CDX_MAX_DIST_FQRS];
static int cdx_num_dist_fqrs;

/* Global BMan pool handle for releasing buffers in dist FQ callback */
/* cdx_rx_pool removed — buffers now freed via dtsec_rm_buf_free_external */

/*
 * cdx_dist_mext_free — mbuf external storage free for dist FQ frames.
 *
 * Uses the dtsec driver's dtsec_rm_buf_free_external() to properly:
 *  1. Map BPID → dtsec_softc (correct per-port UMA zone)
 *  2. Recover stashed KVA pointer from buffer privData
 *  3. Free to UMA zone (driver's refill path replenishes BMan)
 *  4. Decrement sc_rx_buf_total (prevents refill stall)
 *
 * ext_arg1 = buffer DMAP address (from FD).
 * ext_arg2 = (void *)(uintptr_t)bpid.
 */
static void
cdx_dist_mext_free(struct mbuf *m)
{
	void *buf;
	uint8_t bpid;

	buf = m->m_ext.ext_arg1;
	bpid = (uint8_t)(uintptr_t)m->m_ext.ext_arg2;
	if (buf != NULL)
		dtsec_rm_buf_free_external(bpid, buf);
}

/*
 * cdx_dist_fq_rx_callback — Callback for CDX distribution FQs.
 *
 * Frames arriving here are miss frames from CDX enhanced hash tables:
 * they matched a KG distribution scheme but no CDX flow entry.
 *
 * For dtsec ports: build an mbuf and deliver to the FreeBSD network
 * stack via qman_rx_defer (deferred delivery avoids nested portal
 * locks).  This matches Linux where distribution FQs use the same
 * rx_default_dqrr callback as regular driver RX FQs.
 *
 * For OH ports (WiFi, IPsec): dispatch to registered handler via BPID.
 *
 * The app parameter carries the dtsec ifnet pointer (set during FQ
 * creation in cdx_create_port_fqs).  NULL means no dtsec mapping.
 */
static volatile uint64_t cdx_dist_fq_rx_count;

static e_RxStoreResponse
cdx_dist_fq_rx_callback(t_Handle app, t_Handle qm_fqr,
    t_Handle qm_portal __unused, uint32_t fqid_offset,
    t_DpaaFD *frame)
{
	dpaa_oh_dist_cb_t fn;
	t_Handle fn_app;
	void *frame_va;

	/* Check for registered OH port handler (WiFi, IPsec, etc.) */
	fn = dpaa_oh_lookup_dist_cb(frame->bpid, &fn_app);
	if (fn != NULL)
		return (fn(fn_app, qm_fqr, qm_portal, fqid_offset, frame));

	/*
	 * OH port frames (app==NULL): try fallback callback.
	 * dpaa_wifi registers this to handle CDX→WiFi download
	 * frames that carry dtsec BPIDs (not registered by BPID).
	 */
	if (app == NULL) {
		fn = dpaa_oh_lookup_dist_fallback(&fn_app);
		if (fn != NULL)
			return (fn(fn_app, qm_fqr, qm_portal,
			    fqid_offset, frame));
	}

	frame_va = DPAA_FD_GET_ADDR(frame);
	if (frame_va == NULL)
		return (e_RX_STORE_RESPONSE_CONTINUE);

	/*
	 * Dtsec miss frames: build mbuf and deliver to stack.
	 * app is the ifnet pointer set by cdx_create_port_fqs.
	 */
	if (app != NULL) {
		if_t ifp = (if_t)app;
		struct mbuf *m;

		m = m_gethdr(M_NOWAIT, MT_HEADER);
		if (m == NULL)
			goto drop;

		m_extadd(m, frame_va, CDX_RX_BUFFER_SIZE,
		    cdx_dist_mext_free, frame_va,
		    (void *)(uintptr_t)frame->bpid, 0,
		    EXT_NET_DRV);

		m->m_pkthdr.rcvif = ifp;
		m->m_data = (char *)frame_va + DPAA_FD_GET_OFFSET(frame);
		m->m_len = DPAA_FD_GET_LENGTH(frame);
		m->m_pkthdr.len = m->m_len;

		if_inc_counter(ifp, IFCOUNTER_IPACKETS, 1);
		if_inc_counter(ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);

		qman_rx_defer(m);
		dtsec_rm_pool_rx_refill_bpid(frame->bpid);

		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

drop:
	/* No dtsec mapping — log and return buffer via driver path */
	atomic_fetchadd_64(&cdx_dist_fq_rx_count, 1);
	if (cdx_dist_fq_rx_count <= 5 ||
	    (cdx_dist_fq_rx_count % 100000) == 0) {
		uint32_t base_fqid = QM_FQR_GetFqid(qm_fqr);
		printf("cdx: dist_fq_rx_callback: count=%ju "
		    "fqid=0x%x (base=0x%x+%u) DROPPED\n",
		    (uintmax_t)cdx_dist_fq_rx_count,
		    base_fqid + fqid_offset, base_fqid, fqid_offset);
	}

	if (frame_va != NULL)
		dtsec_rm_buf_free_external(frame->bpid, frame_va);

	return (e_RX_STORE_RESPONSE_CONTINUE);
}

/*
 * cdx_create_port_fqs — Create QMan FQs for CDX distribution FQIDs.
 *
 * CDX PCD uses KG distribution schemes that hash frames to FQIDs
 * computed as base_fqid + (portid << 8).  These FQIDs MUST exist as
 * initialized FQs in QMan — otherwise the CDX microcode's POST_BMI_ENQ
 * handler fails to release FMan tasks (TNUMs), stalling the pipeline.
 *
 * Called after fman_info is populated with port/distribution metadata
 * from the CDX_CTRL_DPA_SET_PARAMS ioctl.
 */
int
cdx_create_port_fqs(void)
{
	struct cdx_fman_info *fi = fman_info;
	uint32_t i, j;
	int nfqr = 0;

	if (fi == NULL || fi->portinfo == NULL) {
		printf("cdx: create_port_fqs: no port info\n");
		return (0);
	}

	/* Buffer free now uses dtsec_rm_buf_free_external(bpid, buf)
	 * which maps BPID → per-port UMA zone. No pool handle needed. */

	for (i = 0; i < fi->max_ports; i++) {
		struct cdx_port_info *pi = &fi->portinfo[i];
		struct cdx_dist_info *di = pi->dist_info;
		uint32_t portid = pi->portid;
		if_t ifp;

		if (di == NULL || pi->max_dist == 0)
			continue;

		/*
		 * Look up the dtsec ifnet for this port.
		 * pi->name was resolved to kernel name (e.g. "dtsec3")
		 * in Step 1 of set_dpa_params.  OH ports have type==0
		 * and won't match — ifp will be NULL, and the callback
		 * will fall through to the OH/drop path.
		 */
		ifp = (pi->type != 0) ?
		    cdx_dpa_bridge_find_ifnet(pi->name) : NULL;

		for (j = 0; j < pi->max_dist; j++) {
			uint32_t fqid;
			uint32_t count;
			t_Handle fqr;

			count = di[j].count;
			if (count == 0)
				continue;

			fqid = di[j].base_fqid +
			    (portid << PORTID_SHIFT_VAL);

			fqr = qman_fqr_create(count,
			    (e_QmFQChannel)(e_QM_FQ_CHANNEL_SWPORTAL0 +
			    (fqid % CDX_NUM_RX_CPUS)),
			    1,				/* wq */
			    true,			/* force_fqid */
			    fqid,			/* specific FQID */
			    false,			/* init_parked */
			    false,			/* hold_active */
			    true,			/* prefer_in_cache */
			    false,			/* congst_avoid */
			    NULL,			/* congst_group */
			    0,				/* overhead_len */
			    0);				/* tail_drop */
			if (fqr == NULL) {
				printf("cdx: create_port_fqs: FAILED "
				    "FQID 0x%x count %u port '%s'\n",
				    fqid, count, pi->name);
				continue;	/* non-fatal */
			}

			qman_fqr_register_cb(fqr,
			    cdx_dist_fq_rx_callback, ifp);

			if (nfqr < CDX_MAX_DIST_FQRS)
				cdx_dist_fqrs[nfqr] = fqr;
			nfqr++;

		}
	}

	cdx_num_dist_fqrs = nfqr;
	printf("cdx: create_port_fqs: %d FQRs created\n", nfqr);
	return (0);
}

/* Forward declaration for cdx_dpa_bridge.c */
void cdx_destroy_port_fqs(void);

/*
 * cdx_destroy_port_fqs — Free all CDX distribution FQRs.
 *
 * Called from cdx_dpa_bridge_destroy() during module unload, BEFORE
 * hash table deletion.  Retires each FQ via QMan hardware (RETIRE →
 * OOS → destroy), then quiesces all portal poll tasks to ensure no
 * in-flight QM_PORTAL_Poll() call references the about-to-be-freed
 * CDX callback function.
 */
void
cdx_destroy_port_fqs(void)
{
	int i, n;

	n = cdx_num_dist_fqrs;
	if (n > CDX_MAX_DIST_FQRS)
		n = CDX_MAX_DIST_FQRS;

	for (i = 0; i < n; i++) {
		if (cdx_dist_fqrs[i] != NULL) {
			qman_fqr_free(cdx_dist_fqrs[i]);
			cdx_dist_fqrs[i] = NULL;
		}
	}

	/*
	 * After retiring all FQs, drain all per-CPU portal taskqueues.
	 * A portal poll task on another CPU may be mid-iteration with a
	 * DQRR entry already fetched before the retire took effect.
	 * taskqueue_drain() waits for any in-flight poll to complete.
	 */
	qman_portal_quiesce();

	printf("cdx: destroy_port_fqs: %d FQRs freed\n", n);
	cdx_num_dist_fqrs = 0;
}

/*
 * Find the Ethernet distribution KG scheme handle from portinfo.
 * Scans all ports' dist_info for type == ETHERNET_DIST.
 * Returns the resolved NCSW scheme handle, or NULL if not found.
 *
 * Based on Linux vendor get_ethdist_info_by_fman_params()
 * (dpa_cfg.c:214) with the dist++ loop bug fixed.
 */
static t_Handle
get_ethdist_scheme_handle(struct cdx_port_info *pinfo, uint32_t nports)
{
	uint32_t i, j;

	for (i = 0; i < nports; i++) {
		struct cdx_dist_info *d = pinfo[i].dist_info;
		for (j = 0; j < pinfo[i].max_dist; j++, d++) {
			if (d->type == ETHERNET_DIST)
				return (d->handle);
		}
	}
	return (NULL);
}

/*
 * cdx_ioc_set_dpa_params — Handle CDX_CTRL_DPA_SET_PARAMS ioctl.
 *
 * Called from cdx_dev_freebsd.c.  The top-level struct is already
 * in kernel space (FreeBSD _IOWR copies it), but pointer members
 * inside still reference userspace and need copyin().
 *
 * Flow:
 *  1. copyin fman_info, table_info, port_info, dist_info from userspace
 *  2. Resolve chardev handle IDs (hash tables + KG scheme handles)
 *  3. Install new metadata into global fman_info
 *  4. Create policer profiles, then patch miss actions (KG + PLCR)
 *  5. Create distribution FQs, register OH ports
 */
int
cdx_ioc_set_dpa_params(unsigned long args)
{
	struct cdx_ctrl_set_dpa_params *params;
	struct cdx_fman_info u_finfo;
	struct table_info *k_tinfo;
	struct cdx_port_info *k_pinfo, *tmp_pinfo;
	struct cdx_dist_info *k_dinfo;
	struct cdx_ipr_info k_ipr;
	device_t fmdev;
	struct fmcd_softc *fmcd;
	t_Handle pcd_handle, fm_handle, muram_handle;
	uint32_t i, j, num_tables, max_ports, total_dists;
	int error;

	params = (struct cdx_ctrl_set_dpa_params *)args;

	if (params->num_fmans == 0 || params->num_fmans > 4) {
		printf("cdx: set_dpa_params: invalid num_fmans %u\n",
		    params->num_fmans);
		return (EINVAL);
	}

	/* LS1046A has exactly 1 FMan */
	if (params->num_fmans != 1) {
		printf("cdx: set_dpa_params: only 1 FMan supported, got %u\n",
		    params->num_fmans);
		return (EINVAL);
	}

	if (fman_info == NULL) {
		printf("cdx: set_dpa_params: bridge not initialized\n");
		return (ENXIO);
	}

	/* Get fman device and chardev for handle resolution */
	fmdev = cdx_dpa_bridge_get_fman_dev();
	if (fmdev == NULL) {
		printf("cdx: set_dpa_params: no fman device\n");
		return (ENXIO);
	}

	fmcd = fman_get_fmcd(fmdev);
	if (fmcd == NULL) {
		printf("cdx: set_dpa_params: no fmcd chardev\n");
		return (ENXIO);
	}

	fman_get_pcd_handle(fmdev, &pcd_handle);
	fman_get_handle(fmdev, &fm_handle);
	fman_get_muram_handle(fmdev, &muram_handle);

	/*
	 * Step 1: copyin fman_info from userspace.
	 * params->fman_info is a userspace pointer.
	 */
	error = copyin(params->fman_info, &u_finfo, sizeof(u_finfo));
	if (error != 0) {
		printf("cdx: set_dpa_params: copyin fman_info: %d\n", error);
		return (error);
	}

	num_tables = u_finfo.num_tables;
	max_ports = u_finfo.max_ports;

	if (num_tables > 256 || max_ports > 32) {
		printf("cdx: set_dpa_params: invalid num_tables=%u "
		    "max_ports=%u\n", num_tables, max_ports);
		return (EINVAL);
	}

	/*
	 * Step 2: copyin table_info array from userspace.
	 * u_finfo.tbl_info is a userspace pointer.
	 */
	k_tinfo = malloc(num_tables * sizeof(*k_tinfo),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	error = copyin(u_finfo.tbl_info, k_tinfo,
	    num_tables * sizeof(*k_tinfo));
	if (error != 0) {
		printf("cdx: set_dpa_params: copyin tbl_info: %d\n", error);
		goto fail_tinfo;
	}

	/*
	 * Step 2.5: Resolve chardev handle IDs to kernel pointers.
	 *
	 * dpa_app stores opaque handle IDs (from the chardev handle
	 * table) in tbl_info[].id.  Translate them to NCSW kernel
	 * pointers (en_exthash_info*) so the rest of the code can
	 * use them directly with ExternalHashTable* functions.
	 */
	for (i = 0; i < num_tables; i++) {
		if (k_tinfo[i].id != NULL) {
			t_Handle resolved = fmcd_handle_resolve(fmcd,
			    (uint64_t)(uintptr_t)k_tinfo[i].id,
			    FMCD_HDL_HASH_TABLE);
			if (resolved == NULL) {
				printf("cdx: set_dpa_params: table %u: "
				    "bad handle 0x%lx\n",
				    i, (unsigned long)(uintptr_t)
				    k_tinfo[i].id);
				k_tinfo[i].id = NULL;
			} else {
				k_tinfo[i].id = resolved;
			}
		}
	}

	/*
	 * Step 3: copyin port_info + dist_info from userspace.
	 *
	 * dpa_app allocates portinfo + trailing dist_info as one block.
	 * Each port->dist_info is a userspace pointer into that block.
	 * We copyin portinfo first to learn dist counts, then allocate
	 * a combined kernel buffer and copyin each port's dist_info.
	 */
	k_pinfo = NULL;
	if (max_ports > 0 && u_finfo.portinfo != NULL) {
		/* Temporary copyin of portinfo to learn dist counts */
		tmp_pinfo = malloc(max_ports * sizeof(*tmp_pinfo),
		    M_TEMP, M_WAITOK);
		error = copyin(u_finfo.portinfo, tmp_pinfo,
		    max_ports * sizeof(*tmp_pinfo));
		if (error != 0) {
			printf("cdx: set_dpa_params: copyin portinfo: %d\n",
			    error);
			free(tmp_pinfo, M_TEMP);
			goto fail_tinfo;
		}

		/* Calculate total distribution entries */
		total_dists = 0;
		for (i = 0; i < max_ports; i++) {
			if (tmp_pinfo[i].max_dist > 64) {
				printf("cdx: set_dpa_params: port %u: "
				    "invalid max_dist %u\n",
				    i, tmp_pinfo[i].max_dist);
				free(tmp_pinfo, M_TEMP);
				error = EINVAL;
				goto fail_tinfo;
			}
			total_dists += tmp_pinfo[i].max_dist;
		}

		/* Allocate combined portinfo + dist_info buffer */
		k_pinfo = malloc(
		    max_ports * sizeof(*k_pinfo) +
		    total_dists * sizeof(struct cdx_dist_info),
		    M_DEVBUF, M_WAITOK | M_ZERO);

		/* Copy portinfo from temp buffer */
		memcpy(k_pinfo, tmp_pinfo, max_ports * sizeof(*k_pinfo));
		free(tmp_pinfo, M_TEMP);

		/* copyin each port's dist_info and fix up pointers */
		k_dinfo = (struct cdx_dist_info *)(k_pinfo + max_ports);
		for (i = 0; i < max_ports; i++) {
			struct cdx_dist_info *u_dinfo;

			u_dinfo = k_pinfo[i].dist_info; /* userspace ptr */
			if (k_pinfo[i].max_dist > 0 && u_dinfo != NULL) {
				error = copyin(u_dinfo, k_dinfo,
				    k_pinfo[i].max_dist *
				    sizeof(struct cdx_dist_info));
				if (error != 0) {
					printf("cdx: set_dpa_params: "
					    "copyin dist_info port %u: %d\n",
					    i, error);
					goto fail_pinfo;
				}
			}
			k_pinfo[i].dist_info = k_dinfo;
			k_dinfo += k_pinfo[i].max_dist;
		}

		/*
		 * Replace dpa_app-generated port names with actual FreeBSD
		 * kernel interface names.  dpa_app creates names like
		 * "dpa-fm0-10G-eth0" but CDX commands use kernel names
		 * like "dtsec3".  This is the FreeBSD equivalent of Linux
		 * dpa_cfg.c:311-324 which calls find_osdev_by_fman_params().
		 */
		for (i = 0; i < max_ports; i++) {
			const char *ifname;

			if (k_pinfo[i].type == 0)
				continue;	/* OH port — no dtsec */

			ifname = cdx_dpa_bridge_find_ifname_by_fman_params(
			    k_pinfo[i].fm_index, k_pinfo[i].index,
			    k_pinfo[i].type);
			if (ifname != NULL) {
				printf("cdx: set_dpa_params: port %s -> %s\n",
				    k_pinfo[i].name, ifname);
				strlcpy(k_pinfo[i].name, ifname,
				    sizeof(k_pinfo[i].name));
			} else {
				printf("cdx: set_dpa_params: WARNING: "
				    "no dtsec for port %s "
				    "(fm%u idx%u type%u)\n",
				    k_pinfo[i].name, k_pinfo[i].fm_index,
				    k_pinfo[i].index, k_pinfo[i].type);
			}
		}
	}

	/*
	 * Step 3.5: Resolve dist_info scheme handles.
	 *
	 * dpa_app stores chardev device IDs in dist_info[].handle
	 * (from FM_PCD_Get_Sch_handle via fmlib).  Translate to
	 * kernel NCSW KG scheme pointers for use in miss fixup.
	 */
	if (k_pinfo != NULL) {
		for (i = 0; i < max_ports; i++) {
			struct cdx_dist_info *d = k_pinfo[i].dist_info;
			for (j = 0; j < k_pinfo[i].max_dist; j++, d++) {
				if (d->handle != NULL) {
					t_Handle resolved =
					    fmcd_handle_resolve(fmcd,
					    (uint64_t)(uintptr_t)d->handle,
					    FMCD_HDL_KG_SCHEME);
					if (resolved == NULL) {
						printf("cdx: set_dpa_params: "
						    "port %u dist %u: bad "
						    "scheme handle 0x%lx\n",
						    i, j,
						    (unsigned long)(uintptr_t)
						    d->handle);
					}
					d->handle = resolved;
				}
			}
		}
	}

	/*
	 * Step 4: copyin ipr_info (optional).
	 */
	memset(&k_ipr, 0, sizeof(k_ipr));
	if (params->ipr_info != NULL) {
		error = copyin(params->ipr_info, &k_ipr, sizeof(k_ipr));
		if (error != 0) {
			printf("cdx: set_dpa_params: copyin ipr_info: %d\n",
			    error);
			goto fail_pinfo;
		}
	}
	/* Store in global for cdx_init_ip_reassembly() */
	ipr_info = k_ipr;

	/*
	 * Step 7: Install new state into global fman_info.
	 *
	 * fman_info points to the static cdx_fman_info_data in bridge.c.
	 * We update it in-place with the new metadata from dpa_app.
	 *
	 * If dpa_app is restarted, old tbl_info/portinfo allocations
	 * must be freed to prevent memory leaks.  The hash table handles
	 * (tbl_info[].id) are NOT freed here — they are NCSW objects
	 * owned by the PCD CC tree and remain valid across dpa_app
	 * restarts (only freed on CDX module unload).
	 */
	if (fman_info->tbl_info != NULL && fman_info->tbl_info != k_tinfo) {
		free(fman_info->tbl_info, M_DEVBUF);
		printf("cdx: set_dpa_params: freed old tbl_info\n");
	}
	if (fman_info->portinfo != NULL && fman_info->portinfo != k_pinfo) {
		free(fman_info->portinfo, M_DEVBUF);
		printf("cdx: set_dpa_params: freed old portinfo\n");
	}
	fman_info->num_tables = num_tables;
	fman_info->tbl_info = k_tinfo;
	fman_info->max_ports = max_ports;
	fman_info->portinfo = k_pinfo;
	fman_info->index = u_finfo.index;

	/* Rate limiter config from userspace */
	memcpy(&fman_info->expt_rate_limit_info,
	    &u_finfo.expt_rate_limit_info,
	    sizeof(fman_info->expt_rate_limit_info));
	fman_info->expt_ratelim_mode = u_finfo.expt_ratelim_mode;
	fman_info->expt_ratelim_burst_size = u_finfo.expt_ratelim_burst_size;

	/* Use kernel-known NCSW handles (NOT userspace fmlib handles) */
	fman_info->fm_handle = fm_handle;
	fman_info->pcd_handle = pcd_handle;
	fman_info->muram_handle = muram_handle;
	/* physicalMuramBase + fmMuramMemSize already set by bridge_init */

	/*
	 * Step 7b: Create exception traffic policer profiles.
	 * These rate-limit miss/exception frames reaching the host CPU.
	 */
	if (cdx_qos_init_expt_profiles() != 0)
		printf("cdx: set_dpa_params: expt policer init failed\n");

	/*
	 * Step 7c: Patch miss actions on CDX enhanced hash tables.
	 *
	 * Match Linux vendor cdxdrv_set_miss_action() (dpa_cfg.c:416):
	 *   - ETHERNET / PPPOE tables → PLCR policer (rate-limits
	 *     exception traffic, breaks CC re-entry loop)
	 *   - All other tables → KG scheme with CC_EN (re-enters
	 *     CC tree, eventually hits Ethernet table's PLCR miss)
	 */
	{
		t_Handle eth_scheme;
		uint32_t patched = 0, skipped = 0;

		eth_scheme = get_ethdist_scheme_handle(k_pinfo,
		    max_ports);
		if (eth_scheme == NULL)
			printf("cdx: set_dpa_params: WARNING: no "
			    "Ethernet distribution scheme found\n");
		else
			printf("cdx: set_dpa_params: eth dist scheme "
			    "%p\n", eth_scheme);

		for (i = 0; i < num_tables; i++) {
			t_FmPcdCcNextEngineParams miss_params;

			if (k_tinfo[i].id == NULL ||
			    (uintptr_t)k_tinfo[i].id <
			    VM_MIN_KERNEL_ADDRESS ||
			    k_tinfo[i].dpa_type !=
			    DPA_CLS_TBL_EXTERNAL_HASH) {
				skipped++;
				continue;
			}

			memset(&miss_params, 0, sizeof(miss_params));

			if (k_tinfo[i].type != ETHERNET_TABLE &&
			    k_tinfo[i].type != PPPOE_RELAY_TABLE) {
				/*
				 * Non-Ethernet tables: KG scheme miss.
				 * KG re-enters CC tree (CC_EN), frame
				 * eventually reaches Ethernet table
				 * whose PLCR miss breaks the loop.
				 */
				if (eth_scheme == NULL) {
					skipped++;
					continue;
				}
				miss_params.nextEngine = e_FM_PCD_KG;
				miss_params.params.kgParams
				    .h_DirectScheme = eth_scheme;
			} else {
				/*
				 * Ethernet / PPPoE tables: PLCR miss.
				 * Rate-limits exception traffic and
				 * enqueues to default FQID (set by KG
				 * on initial classification).
				 */
				miss_params.nextEngine = e_FM_PCD_PLCR;
				miss_params.params.plcrParams
				    .sharedProfile = 1;
				miss_params.params.plcrParams
				    .newRelativeProfileId =
				    CDX_EXPT_ETH_RATELIMIT;
			}

			if (ExternalHashTableModifyMissNextEngine(
			    k_tinfo[i].id, &miss_params) != E_OK) {
				printf("cdx: set_dpa_params: "
				    "miss fixup FAILED table %u '%s'\n",
				    i, k_tinfo[i].name);
				skipped++;
				continue;
			}
			patched++;

			printf("cdx: set_dpa_params: table %u '%s' "
			    "type %u miss -> %s\n",
			    i, k_tinfo[i].name, k_tinfo[i].type,
			    (miss_params.nextEngine == e_FM_PCD_PLCR) ?
			    "PLCR" : "KG");
		}

		/*
		 * Sync FMan PCD Host Command channel after all
		 * miss action modifications.  Flushes any FMan
		 * internal caches so the microcode sees the
		 * updated MURAM AD values.
		 */
		if (patched > 0) {
			int sync_err = 0;
			for (i = 0; i < num_tables; i++) {
				if (k_tinfo[i].id == NULL ||
				    (uintptr_t)k_tinfo[i].id <
				    VM_MIN_KERNEL_ADDRESS ||
				    k_tinfo[i].dpa_type !=
				    DPA_CLS_TBL_EXTERNAL_HASH)
					continue;
				if (ExternalHashTableFmPcdHcSync(
				    k_tinfo[i].id) != 0) {
					printf("cdx: set_dpa_params: "
					    "HcSync failed table %u\n",
					    i);
					sync_err++;
				}
			}
			if (sync_err == 0)
				printf("cdx: set_dpa_params: "
				    "HcSync OK (%u tables)\n",
				    patched);
		}

		printf("cdx: set_dpa_params: miss fixup complete — "
		    "%u patched, %u skipped (of %u tables)\n",
		    patched, skipped, num_tables);
	}

	/*
	 * Step 7d: Create ingress QoS policer profiles.
	 * Per-queue rate limiting for offloaded flows.
	 */
#ifdef ENABLE_INGRESS_QOS
	if (cdx_qos_init_ingress_profiles() != 0)
		printf("cdx: set_dpa_params: ingress policer init failed\n");
#endif

	/*
	 * Step 7e: Register OH ports in devman interface list.
	 *
	 * The Linux dpa_cfg.c iterates portinfo and calls
	 * cdx_add_oh_iface() for each OH port (type==0).  We must
	 * do the same here — fman_info->portinfo is now set, so
	 * get_dpa_oh_iface_info() can resolve portids from the XML.
	 */
	for (i = 0; i < max_ports; i++) {
		if (k_pinfo[i].type == 0) {
			if (cdx_add_oh_iface(k_pinfo[i].name) != 0) {
				printf("cdx: set_dpa_params: "
				    "OH port %s add failed\n",
				    k_pinfo[i].name);
			}
		}
	}

	/*
	 * Step 8: Create QMan FQs for CDX distribution FQIDs.
	 *
	 * The CDX microcode's POST_BMI_ENQ handler references distribution
	 * FQIDs internally.  Without initialized FQs at these FQIDs, the
	 * microcode fails to release FMan tasks (TNUMs), stalling the
	 * pipeline after ~6 frames.
	 */

	/* Free driver RSS FQRs 1..127 — orphaned after CDX replaces PCD.
	 * Recovers ~1270 MallocSmart slices for CDX distribution FQRs. */
	dtsec_release_rss_fqrs();

	error = cdx_create_port_fqs();
	if (error != 0)
		printf("cdx: set_dpa_params: create_port_fqs failed: %d\n",
		    error);

	/*
	 * Step 9: Register OH ports in offline_port_info.
	 *
	 * Walk the devman interface list for OH ports and populate the
	 * offline port tracking array (cdx_devoh_freebsd.c).  This must
	 * run after dpa_add_oh_if() has registered all OH interfaces.
	 */
	{
		struct dpa_iface_info *p;

		for (p = dpa_interface_info; p != NULL; p = p->next) {
			if (p->if_flags & IF_TYPE_OFPORT)
				cdxdrv_create_of_fqs(p);
		}
	}

	/*
	 * Step 10: Mark PCD resources as transferred to CDX.
	 *
	 * All PCD objects (hash tables, CC trees, KG schemes, net envs)
	 * created by dpa_app are now owned by CDX.  Tell the chardev
	 * so its close handler won't attempt to delete them.
	 */
	fmcd_pcd_mark_transferred(fmcd);

	return (0);

fail_pinfo:
	if (k_pinfo != NULL)
		free(k_pinfo, M_DEVBUF);
fail_tinfo:
	free(k_tinfo, M_DEVBUF);
	return (error);
}
