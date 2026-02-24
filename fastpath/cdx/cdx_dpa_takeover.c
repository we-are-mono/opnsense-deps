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

#include "cdx_ioctl.h"
#include "cdx_dpa_bridge.h"

/* FreeBSD DPAA1 driver — handle resolution */
#include <dev/dpaa/fman.h>
#include <dev/dpaa/fman_chardev.h>
#include <dev/dpaa/bman.h>

/* NCSW types (t_Handle) */
#include <contrib/ncsw/inc/ncsw_ext.h>

/* NCSW PCD types (for t_FmPcdCcNextEngineParams) */
#include <contrib/ncsw/inc/Peripherals/fm_pcd_ext.h>

/* NCSW QMan types (for e_QmFQChannel, t_QmReceivedFrameCallback) */
#include <contrib/ncsw/inc/Peripherals/qm_ext.h>

/* ExternalHashTableModifyMissNextEngine — provided by kernel fm_ehash.c */
extern t_Error ExternalHashTableModifyMissNextEngine(t_Handle h_HashTbl,
    t_FmPcdCcNextEngineParams *p_FmPcdCcNextEngineParams);

/* FreeBSD QMan API — kernel symbol resolution */
extern t_Handle qman_fqr_create(uint32_t fqids_num,
    e_QmFQChannel channel, uint8_t wq, bool force_fqid,
    uint32_t fqid_or_align, bool init_parked, bool hold_active,
    bool prefer_in_cache, bool congst_avoid_ena, t_Handle congst_group,
    int8_t overhead_accounting_len, uint32_t tail_drop_threshold);
extern t_Error qman_fqr_register_cb(t_Handle fqr,
    t_QmReceivedFrameCallback *callback, t_Handle app);
extern t_Error qman_fqr_free(t_Handle fqr);
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

/*
 * Distribution FQR tracking for cleanup.
 */
#define	CDX_MAX_DIST_FQRS	64
static t_Handle cdx_dist_fqrs[CDX_MAX_DIST_FQRS];
static int cdx_num_dist_fqrs;

/* Global BMan pool handle for releasing buffers in CDX dist FQ callback */
static t_Handle cdx_rx_pool;

/*
 * cdx_dist_fq_rx_callback — Callback for CDX distribution FQs.
 *
 * Frames arriving here matched a KG distribution scheme but didn't
 * match any hash table entry (and weren't caught by the miss action).
 * This shouldn't normally happen with correct PCD config, but if it
 * does we must release the BMan buffer to avoid pool exhaustion.
 */
static volatile uint64_t cdx_dist_fq_rx_count;

static e_RxStoreResponse
cdx_dist_fq_rx_callback(t_Handle app __unused, t_Handle qm_fqr,
    t_Handle qm_portal __unused, uint32_t fqid_offset,
    t_DpaaFD *frame)
{
	void *frame_va;

	atomic_fetchadd_64(&cdx_dist_fq_rx_count, 1);
	if (cdx_dist_fq_rx_count <= 5 ||
	    (cdx_dist_fq_rx_count % 100000) == 0) {
		uint32_t base_fqid = QM_FQR_GetFqid(qm_fqr);
		printf("cdx: dist_fq_rx_callback: count=%ju "
		    "fqid=0x%x (base=0x%x+%u)\n",
		    (uintmax_t)cdx_dist_fq_rx_count,
		    base_fqid + fqid_offset, base_fqid, fqid_offset);
	}

	frame_va = DPAA_FD_GET_ADDR(frame);
	if (frame_va != NULL && cdx_rx_pool != NULL)
		bman_put_buffer(cdx_rx_pool, frame_va);

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

	/* Grab BMan pool handle from first dtsec for buffer release in
	 * dist FQ callback.  All dtsec interfaces share the same pool. */
	if (cdx_rx_pool == NULL)
		cdx_rx_pool = cdx_dpa_bridge_get_rx_pool();

	for (i = 0; i < fi->max_ports; i++) {
		struct cdx_port_info *pi = &fi->portinfo[i];
		struct cdx_dist_info *di = pi->dist_info;
		uint32_t portid = pi->portid;

		if (di == NULL || pi->max_dist == 0)
			continue;

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
			    e_QM_FQ_CHANNEL_POOL1,	/* pool channel */
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
			    cdx_dist_fq_rx_callback, NULL);

			if (nfqr < CDX_MAX_DIST_FQRS)
				cdx_dist_fqrs[nfqr] = fqr;
			nfqr++;

		}
	}

	cdx_num_dist_fqrs = nfqr;
	printf("cdx: create_port_fqs: %d FQRs created\n", nfqr);
	return (0);
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
 *  2. Resolve chardev handle IDs to NCSW hash table handles
 *  3. Bind each NCSW hash table to CDX (ExternalHashTableBindNCSW)
 *  4. Tear down old standalone hash tables
 *  5. Install new metadata into global fman_info
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
	uint32_t i, num_tables, max_ports, total_dists;
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
	 * Step 5: Patch miss actions on CDX enhanced hash tables.
	 *
	 * With USE_ENHANCED_EHASH, FM_PCD_HashTableSet creates CDX
	 * enhanced hash tables directly (via ExternalHashTableSet).
	 * k_tinfo[].id was resolved from chardev handle IDs to
	 * en_exthash_info* kernel pointers in step 2.5 above.
	 *
	 * Patch each table's miss action to enqueue unmatched frames
	 * to the dtsec driver's RX default FQID (so misses reach the
	 * FreeBSD network stack).
	 *
	 * port_idx is a bitmask: bit N set = table belongs to portid N.
	 * CDX portids 0-7 map to fmlib RX indexes (fmcd rx_port_fqids[]).
	 */
	{
		uint32_t patched = 0, skipped = 0;

		for (i = 0; i < num_tables; i++) {
			uint32_t port_bits, bit;
			uint32_t rx_fqid;

			if (k_tinfo[i].id == NULL ||
			    (uintptr_t)k_tinfo[i].id < VM_MIN_KERNEL_ADDRESS ||
			    k_tinfo[i].dpa_type != DPA_CLS_TBL_EXTERNAL_HASH) {
				skipped++;
				continue;
			}

			/* Find the first physical port and its RX FQID */
			port_bits = k_tinfo[i].port_idx;
			rx_fqid = 0;
			for (bit = 0; bit < 8; bit++) {
				if (port_bits & (1U << bit)) {
					rx_fqid = fmcd_get_rx_dflt_fqid(
					    fmcd, bit);
					if (rx_fqid != 0)
						break;
				}
			}

			if (rx_fqid != 0) {
				t_FmPcdCcNextEngineParams miss_params;

				memset(&miss_params, 0, sizeof(miss_params));
				miss_params.nextEngine = e_FM_PCD_DONE;
				miss_params.params.enqueueParams.action =
				    e_FM_PCD_ENQ_FRAME;
				miss_params.params.enqueueParams.overrideFqid =
				    TRUE;
				miss_params.params.enqueueParams.newFqid =
				    rx_fqid;

				ExternalHashTableModifyMissNextEngine(
				    k_tinfo[i].id, &miss_params);
			}
			patched++;
			if (patched <= 3 || (patched % 20) == 0) {
				printf("cdx: set_dpa_params: table %u '%s' "
				    "miss -> FQID %u\n",
				    i, k_tinfo[i].name, rx_fqid);
			}
		}

		printf("cdx: set_dpa_params: miss fixup complete — "
		    "%u patched, %u skipped (of %u tables)\n",
		    patched, skipped, num_tables);
	}

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
	 * Step 7c: Create ingress QoS policer profiles.
	 * Per-queue rate limiting for offloaded flows.
	 */
#ifdef ENABLE_INGRESS_QOS
	if (cdx_qos_init_ingress_profiles() != 0)
		printf("cdx: set_dpa_params: ingress policer init failed\n");
#endif

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
