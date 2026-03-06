/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026 Mono Technologies Inc.
 *
 * dpaa_wifi — WiFi ↔ FMan OH port data plane bridge.
 *
 * Bridges mwifiex PCIe WiFi driver with DPAA1 FMan Offline/Header
 * Manipulation port so CDX can hardware-offload WiFi traffic.
 *
 * Two data paths:
 *
 *   CDX→WiFi (download): CDX enqueues to OH port FQID → PCD miss →
 *     default FQ callback → mbuf → if_transmit(uapN) → mwifiex → air.
 *
 *   WiFi→CDX (upload): mwifiex RX → dpaa_wifi_inject() → BMan buffer →
 *     OH port → PCD hit → CDX offload → dtsec TX → wire.
 *     PCD miss → default FQ → if_input(uapN) → stack.
 *
 * Supports multiple VAPs (uap0, uap1, wlan0, etc.) via IFNET event-driven
 * lifecycle.  VAP interfaces are automatically hooked on arrival and
 * unhooked on departure.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/eventhandler.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/callout.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>

#include <machine/bus.h>
#include <machine/cpu.h>

#include <contrib/ncsw/inc/Peripherals/dpaa_ext.h>
#include <contrib/ncsw/inc/Peripherals/qm_ext.h>
#include <contrib/ncsw/inc/Peripherals/fm_ext.h>
#include <contrib/ncsw/inc/Peripherals/fm_port_ext.h>
#include <contrib/ncsw/inc/ncsw_ext.h>

#include <dev/dpaa/dpaa_oh.h>
#include <dev/dpaa/if_dtsec.h>
#include <dev/dpaa/bman.h>
#include <dev/dpaa/qman.h>

#include "moal_freebsd.h"
#include "dpaa_wifi.h"

/* WiFi OH port: cell-index 4 in DTS (dpa-fman0-oh@3, portid 9) */
#define WIFI_OH_CELL_INDEX	4

/* BMan pool for WiFi injection (WiFi→OH) */
#define WIFI_POOL_SIZE		512
#define WIFI_POOL_REFILL_THRESH	128
#define WIFI_POOL_REFILL_COUNT	64
#define WIFI_BUF_SIZE		(9600 + 64)	/* matches FM_PORT_BUFFER_SIZE */

/* Multi-VAP support: 88W9098 creates up to 2 BSS; 4 gives headroom */
#define DPAA_WIFI_MAX_VAPS	4

/* Per-VAP distribution FQs for CDX→WiFi download (matches Linux CDX_VWD_FWD_FQ_MAX) */
#define DPAA_WIFI_FWD_FQ_MAX	64	/* must be power of 2 */
#define DPAA_WIFI_FWD_FQ_WQ	5	/* matches Linux DEFA_VWD_WQ_ID */
#define DPAA_WIFI_NUM_CPUS	4	/* LS1046A quad-core */

/* Enqueue retry: EQCR has 8 entries, 64 yields is generous */
#define DPAA_WIFI_ENQUEUE_RETRIES	64

/*
 * TX backpressure: minimum free buffers in BMan pool.
 *
 * When pool_free drops below this threshold, new inject frames are
 * dropped to prevent pool exhaustion.  Uses bman_count() which
 * correctly reflects both software returns (miss callback) and
 * hardware returns (CDX offload → FMan TX release).
 *
 * Linux VWD uses a separate txconf pool + drain model; we use the
 * simpler pool-count approach since our single pool serves both paths.
 */
#define DPAA_WIFI_POOL_BP_THRESH_DEFAULT	64

/*
 * privData layout in WiFi injection buffers (16 bytes total):
 *   [0..7]  KVA stash (uintptr_t) — for UMA free after BMan/FMan round-trip
 *   [8]     VAP index (uint8_t) — for miss-path RX callback to identify VAP
 *   [9..15] reserved
 *
 * For SG table buffers, [8..15] holds a packed pointer:
 *   (uintptr_t)mbuf_ptr | vap_idx
 * mbufs are >=256-byte aligned, so the low 8 bits encode vap_idx.
 */
#define PRIVDATA_KVA_OFF	0
#define PRIVDATA_VAP_OFF	sizeof(uintptr_t)

struct dpaa_wifi_vap {
	if_t		ifp;
	uint8_t		mac[ETHER_ADDR_LEN];
	uint8_t		active;
	/* Per-VAP distribution FQs (CDX→WiFi download) */
	t_Handle	fwd_fqr[DPAA_WIFI_FWD_FQ_MAX];
	uint32_t	fwd_fqid_base;
	uint8_t		fwd_fqs_active;
	/* TX inject counters */
	volatile uint64_t inject_count;
	volatile uint64_t tx_backpressure;	/* backpressure drops */
	volatile uint64_t tx_nobuf;		/* BMan pool exhaustion */
	volatile uint64_t tx_enqueue_fail;	/* enqueue failure after retry */
	/* RX counters */
	volatile uint64_t rx_to_stack;
	volatile uint64_t rx_to_mwifiex;
	volatile uint64_t rx_fwd_to_mwifiex;	/* CDX→WiFi via per-VAP FQ */
	volatile uint64_t rx_err;		/* FMan error frames */
};

/* Callback context for per-VAP distribution FQs */
struct dpaa_wifi_fwd_ctx {
	struct dpaa_wifi_vap *vap;
	uint8_t		vap_idx;
};
static struct dpaa_wifi_fwd_ctx wifi_fwd_ctx[DPAA_WIFI_MAX_VAPS];

static device_t		wifi_oh_dev;
static uint32_t		wifi_data_offset;	/* buffer prefix size */
static uint8_t		wifi_bpid;		/* our BMan pool ID */
static t_Handle		wifi_pool;		/* BMan pool handle */
static uma_zone_t	wifi_zone;		/* UMA zone for pool buffers */
static uma_zone_t	wifi_sgt_zone;		/* UMA zone for SG tables */
static volatile uint32_t wifi_buf_total;	/* allocated buffer count */

/* VAP table */
static struct dpaa_wifi_vap wifi_vaps[DPAA_WIFI_MAX_VAPS];
static volatile int	wifi_nvaps;
static struct mtx	wifi_vap_mtx;

/* IFNET event handlers */
static eventhandler_tag	wifi_arrival_tag;
static eventhandler_tag	wifi_departure_tag;

/* Module-wide statistics */
static volatile uint64_t wifi_inject_nobuf;
static volatile uint64_t wifi_inject_enq_fail;
static volatile uint64_t wifi_rx_drop;
static volatile uint64_t wifi_rx_cdx_to_wifi;	/* CDX→WiFi (download) */
static volatile uint64_t wifi_tx_if_fail;	/* if_transmit errors */
static volatile uint64_t wifi_tx_oactive;	/* IFF_DRV_OACTIVE rejects */

/* TX backpressure */
static volatile uint64_t wifi_tx_sent;
static unsigned int wifi_pool_bp_thresh = DPAA_WIFI_POOL_BP_THRESH_DEFAULT;
static volatile uint64_t wifi_tx_backpressure;

/* Sysctl */
static struct sysctl_ctx_list wifi_sysctl_ctx;
static struct sysctl_oid *wifi_sysctl_tree;

/* Periodic diagnostic callout */
static struct callout wifi_diag_callout;
static struct mtx wifi_diag_mtx;

/*
 * Periodic diagnostic tick — enable by uncommenting the printf block
 * below for debugging WiFi offload counters on the serial console.
 */
static void
wifi_diag_tick(void *arg __unused)
{
#if 0	/* Enable for debugging: prints stats every 2s to console */
	uint32_t pool_free;

	pool_free = (wifi_pool != NULL) ? bman_count(wifi_pool) : 0;

	printf("dpaa_wifi: DIAG pool_free=%u/%u sent=%ju bp=%ju "
	    "nobuf=%ju enqfail=%ju rxdrop=%ju cdx2w=%ju txfail=%ju "
	    "oactive=%ju nvaps=%d",
	    pool_free, wifi_buf_total,
	    (uintmax_t)wifi_tx_sent,
	    (uintmax_t)wifi_tx_backpressure,
	    (uintmax_t)wifi_inject_nobuf,
	    (uintmax_t)wifi_inject_enq_fail,
	    (uintmax_t)wifi_rx_drop,
	    (uintmax_t)wifi_rx_cdx_to_wifi,
	    (uintmax_t)wifi_tx_if_fail,
	    (uintmax_t)wifi_tx_oactive,
	    wifi_nvaps);
	/* Per-VAP FWD FQ counters */
	for (int i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (wifi_vaps[i].active)
			printf(" v%d:fwd=%ju",
			    i, (uintmax_t)wifi_vaps[i].rx_fwd_to_mwifiex);
	}
	printf("\n");
#endif

	callout_reset(&wifi_diag_callout, 2 * hz, wifi_diag_tick, NULL);
}

/* Forward declarations */
static int	dpaa_wifi_inject(if_t ifp, struct mbuf *m);

/*
 * Return true if the interface name is a WiFi VAP we should hook.
 */
static bool
dpaa_wifi_is_wifi_ifname(const char *name)
{

	return (strncmp(name, "uap", 3) == 0 ||
	    strncmp(name, "wlan", 4) == 0);
}

/*
 * Find a VAP table index by interface pointer.
 * Returns -1 if not found.  Lock not required (read-only scan).
 */
static int
dpaa_wifi_find_vap_idx(if_t ifp)
{
	int i;

	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (wifi_vaps[i].active && wifi_vaps[i].ifp == ifp)
			return (i);
	}
	return (-1);
}

/*
 * Find target VAP for CDX→WiFi (download) frames.
 *
 * The Ethernet destination MAC is a WiFi client MAC, not the AP MAC.
 * Try to match against VAP MACs (handles AP-destined frames: ARP,
 * management).  Fall back to first active VAP for client-destined
 * unicast — with one radio, all clients are on the same UAP.
 */
static struct dpaa_wifi_vap *
dpaa_wifi_find_vap_for_rx(const void *frame_data)
{
	const struct ether_header *eh;
	int i;

	eh = (const struct ether_header *)frame_data;

	/* Try exact MAC match (AP-addressed frames) */
	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (wifi_vaps[i].active &&
		    memcmp(wifi_vaps[i].mac, eh->ether_dhost,
		    ETHER_ADDR_LEN) == 0)
			return (&wifi_vaps[i]);
	}

	/* Fallback: first active VAP (client-destined unicast) */
	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (wifi_vaps[i].active)
			return (&wifi_vaps[i]);
	}

	return (NULL);
}

/*
 * Per-VAP distribution FQ callback.
 *
 * CDX→WiFi frames arrive here via hash-distributed FQs.
 * The VAP is known from the callback context (no MAC lookup).
 * Same logic as the CDX→WiFi path in dpaa_wifi_rx_cb().
 */
static e_RxStoreResponse
dpaa_wifi_fwd_rx_cb(t_Handle app, t_Handle fqr, t_Handle portal,
    uint32_t fqid_off, t_DpaaFD *frame)
{
	struct dpaa_wifi_fwd_ctx *ctx = app;
	struct dpaa_wifi_vap *vap = ctx->vap;
	void *buf;
	struct mbuf *m;
	uint32_t fd_status, frame_len;
	uint8_t bpid;

	buf = DPAA_FD_GET_ADDR(frame);
	if (__predict_false(buf == NULL))
		return (e_RX_STORE_RESPONSE_CONTINUE);

	fd_status = DPAA_FD_GET_STATUS(frame);
	bpid = frame->bpid;

	if (__predict_false(fd_status & 0x07FE0000)) {
		atomic_add_64(&vap->rx_err, 1);
		dtsec_rm_buf_free_external(bpid, buf);
		dtsec_rm_pool_rx_refill_bpid(bpid);

		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

	if (__predict_false(!vap->active)) {
		dtsec_rm_buf_free_external(bpid, buf);
		dtsec_rm_pool_rx_refill_bpid(bpid);

		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

	frame_len = DPAA_FD_GET_LENGTH(frame);
	m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR,
	    frame_len > MCLBYTES ? MJUMPAGESIZE : MCLBYTES);
	if (__predict_false(m == NULL)) {
		atomic_add_64(&wifi_rx_drop, 1);
		dtsec_rm_buf_free_external(bpid, buf);
		dtsec_rm_pool_rx_refill_bpid(bpid);

		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

	memcpy(mtod(m, void *),
	    (char *)buf + DPAA_FD_GET_OFFSET(frame), frame_len);
	m->m_len = frame_len;
	m->m_pkthdr.len = frame_len;
	m->m_pkthdr.rcvif = vap->ifp;

	/* Release dtsec buffer and refill BMan pool */
	dtsec_rm_buf_free_external(bpid, buf);
	dtsec_rm_pool_rx_refill_bpid(bpid);

	/* Fast reject when WiFi TX is backed up */
	if (__predict_false(if_getdrvflags(vap->ifp) & IFF_DRV_OACTIVE)) {
		m_freem(m);
		atomic_add_64(&wifi_tx_oactive, 1);
	} else if (__predict_false(if_transmit(vap->ifp, m) != 0)) {
		atomic_add_64(&wifi_tx_if_fail, 1);
	}
	atomic_add_64(&vap->rx_fwd_to_mwifiex, 1);
	atomic_add_64(&wifi_rx_cdx_to_wifi, 1);
	return (e_RX_STORE_RESPONSE_CONTINUE);
}

static void
dpaa_wifi_destroy_fwd_fqs(int slot)
{
	struct dpaa_wifi_vap *vap = &wifi_vaps[slot];
	int i;

	vap->fwd_fqs_active = 0;
	atomic_thread_fence_rel();

	dpaa_oh_unregister_vap_fwd_fqs(slot);

	for (i = 0; i < DPAA_WIFI_FWD_FQ_MAX; i++) {
		if (vap->fwd_fqr[i] != NULL) {
			qman_fqr_free(vap->fwd_fqr[i]);
			vap->fwd_fqr[i] = NULL;
		}
	}
	vap->fwd_fqid_base = 0;
}

/*
 * Create 64 per-VAP distribution FQs for CDX→WiFi download.
 * Follows the dtsec RSS pattern: aligned base + force_fqid,
 * round-robin across CPU portals.
 */
static int
dpaa_wifi_create_fwd_fqs(int slot)
{
	struct dpaa_wifi_vap *vap = &wifi_vaps[slot];
	t_Handle fqr;
	uint32_t base_fqid;
	int i;

	/* FQ 0: allocate with alignment to get contiguous base */
	fqr = qman_fqr_create(1,
	    (e_QmFQChannel)(e_QM_FQ_CHANNEL_SWPORTAL0),
	    DPAA_WIFI_FWD_FQ_WQ, false,
	    DPAA_WIFI_FWD_FQ_MAX,	/* alignment */
	    false, false, true, false, 0, 0, 0);
	if (fqr == NULL) {
		printf("dpaa_wifi: vap %d: couldn't create aligned FWD FQR 0\n",
		    slot);
		return (EIO);
	}

	vap->fwd_fqr[0] = fqr;
	base_fqid = qman_fqr_get_base_fqid(fqr);
	vap->fwd_fqid_base = base_fqid;

	wifi_fwd_ctx[slot].vap = vap;
	wifi_fwd_ctx[slot].vap_idx = (uint8_t)slot;

	if (qman_fqr_register_cb(fqr, dpaa_wifi_fwd_rx_cb,
	    &wifi_fwd_ctx[slot]) != E_OK) {
		printf("dpaa_wifi: vap %d: couldn't register FWD FQ 0 cb\n",
		    slot);
		qman_fqr_free(fqr);
		vap->fwd_fqr[0] = NULL;
		return (EIO);
	}

	/* FQs 1..63: force-allocate, round-robin across CPUs */
	for (i = 1; i < DPAA_WIFI_FWD_FQ_MAX; i++) {
		e_QmFQChannel channel =
		    (e_QmFQChannel)(e_QM_FQ_CHANNEL_SWPORTAL0 +
		    (i % DPAA_WIFI_NUM_CPUS));

		fqr = qman_fqr_create(1, channel, DPAA_WIFI_FWD_FQ_WQ,
		    true, base_fqid + i,
		    false, false, true, false, 0, 0, 0);
		if (fqr == NULL) {
			printf("dpaa_wifi: vap %d: couldn't create FWD FQR %d "
			    "(FQID %u)\n", slot, i, base_fqid + i);
			goto fail;
		}

		vap->fwd_fqr[i] = fqr;

		if (qman_fqr_register_cb(fqr, dpaa_wifi_fwd_rx_cb,
		    &wifi_fwd_ctx[slot]) != E_OK) {
			printf("dpaa_wifi: vap %d: couldn't register "
			    "FWD FQ %d cb\n", slot, i);
			qman_fqr_free(fqr);
			vap->fwd_fqr[i] = NULL;
			goto fail;
		}
	}

	atomic_thread_fence_rel();
	vap->fwd_fqs_active = 1;

	if (dpaa_oh_register_vap_fwd_fqs(slot, base_fqid,
	    DPAA_WIFI_FWD_FQ_MAX) != 0)
		printf("dpaa_wifi: vap %d: OH registration failed\n", slot);

	printf("dpaa_wifi: vap %d: created %d FWD FQs, base FQID %u, "
	    "across %d CPUs\n",
	    slot, DPAA_WIFI_FWD_FQ_MAX, base_fqid, DPAA_WIFI_NUM_CPUS);
	return (0);

fail:
	dpaa_wifi_destroy_fwd_fqs(slot);
	return (EIO);
}

/*
 * Hook a WiFi VAP — set the RX bridge function pointer.
 * Caller must hold wifi_vap_mtx.
 */
static int
dpaa_wifi_add_vap(if_t ifp)
{
	struct mwifiex_priv *priv;
	int i, slot;

	/* Already hooked? */
	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (wifi_vaps[i].active && wifi_vaps[i].ifp == ifp)
			return (0);
	}

	/* Find a free slot */
	slot = -1;
	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (!wifi_vaps[i].active) {
			slot = i;
			break;
		}
	}
	if (slot < 0) {
		printf("dpaa_wifi: VAP table full (%d max)\n",
		    DPAA_WIFI_MAX_VAPS);
		return (ENOSPC);
	}

	priv = if_getsoftc(ifp);
	if (priv == NULL) {
		printf("dpaa_wifi: %s has no softc\n", if_name(ifp));
		return (ENXIO);
	}

	memcpy(wifi_vaps[slot].mac, priv->mac_addr, ETHER_ADDR_LEN);
	wifi_vaps[slot].inject_count = 0;
	wifi_vaps[slot].tx_backpressure = 0;
	wifi_vaps[slot].tx_nobuf = 0;
	wifi_vaps[slot].tx_enqueue_fail = 0;
	wifi_vaps[slot].rx_to_stack = 0;
	wifi_vaps[slot].rx_to_mwifiex = 0;
	wifi_vaps[slot].rx_fwd_to_mwifiex = 0;
	wifi_vaps[slot].rx_err = 0;
	wifi_vaps[slot].ifp = ifp;

	/* Create per-VAP distribution FQs for CDX→WiFi download */
	if (dpaa_wifi_create_fwd_fqs(slot) != 0)
		printf("dpaa_wifi: %s: FWD FQs failed, "
		    "CDX will use OH default FQ\n", if_name(ifp));

	/* Publish the hook — must be last (readers are lock-free) */
	atomic_thread_fence_rel();
	wifi_vaps[slot].active = 1;
	atomic_add_int(&wifi_nvaps, 1);

	priv->wifi_bridge_fn = dpaa_wifi_inject;

	printf("dpaa_wifi: hooked %s (slot %d, mac %02x:%02x:%02x:%02x:%02x:%02x)\n",
	    if_name(ifp), slot,
	    wifi_vaps[slot].mac[0], wifi_vaps[slot].mac[1],
	    wifi_vaps[slot].mac[2], wifi_vaps[slot].mac[3],
	    wifi_vaps[slot].mac[4], wifi_vaps[slot].mac[5]);
	return (0);
}

/*
 * Unhook a WiFi VAP — clear the RX bridge function pointer.
 * Caller must hold wifi_vap_mtx.
 */
static void
dpaa_wifi_remove_vap(if_t ifp)
{
	struct mwifiex_priv *priv;
	int i;

	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (wifi_vaps[i].active && wifi_vaps[i].ifp == ifp) {
			priv = if_getsoftc(ifp);
			if (priv != NULL)
				priv->wifi_bridge_fn = NULL;

			printf("dpaa_wifi: unhooked %s (slot %d, "
			    "inject=%ju bp=%ju nobuf=%ju enqfail=%ju "
			    "stack=%ju wifi=%ju fwd=%ju err=%ju)\n",
			    if_name(ifp), i,
			    (uintmax_t)wifi_vaps[i].inject_count,
			    (uintmax_t)wifi_vaps[i].tx_backpressure,
			    (uintmax_t)wifi_vaps[i].tx_nobuf,
			    (uintmax_t)wifi_vaps[i].tx_enqueue_fail,
			    (uintmax_t)wifi_vaps[i].rx_to_stack,
			    (uintmax_t)wifi_vaps[i].rx_to_mwifiex,
			    (uintmax_t)wifi_vaps[i].rx_fwd_to_mwifiex,
			    (uintmax_t)wifi_vaps[i].rx_err);

			wifi_vaps[i].active = 0;
			atomic_thread_fence_rel();
			dpaa_wifi_destroy_fwd_fqs(i);
			wifi_vaps[i].ifp = NULL;
			atomic_subtract_int(&wifi_nvaps, 1);
			return;
		}
	}
}

/*
 * IFNET arrival event — auto-hook WiFi VAPs as they appear.
 */
static void
dpaa_wifi_ifnet_arrival(void *arg __unused, if_t ifp)
{

	if (!dpaa_wifi_is_wifi_ifname(if_name(ifp)))
		return;

	mtx_lock(&wifi_vap_mtx);
	dpaa_wifi_add_vap(ifp);
	mtx_unlock(&wifi_vap_mtx);
}

/*
 * IFNET departure event — auto-unhook WiFi VAPs as they disappear.
 */
static void
dpaa_wifi_ifnet_departure(void *arg __unused, if_t ifp)
{
	int i;

	/* Quick check without lock */
	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (wifi_vaps[i].active && wifi_vaps[i].ifp == ifp)
			break;
	}
	if (i == DPAA_WIFI_MAX_VAPS)
		return;

	mtx_lock(&wifi_vap_mtx);
	dpaa_wifi_remove_vap(ifp);
	mtx_unlock(&wifi_vap_mtx);
}

/*
 * Scan for already-existing WiFi interfaces at module load time.
 * Handles the case where mwifiex loaded before dpaa_wifi.
 */
static void
dpaa_wifi_scan_existing(void)
{
	static const char *names[] = {
		"uap0", "uap1", "wlan0", "wlan1"
	};
	if_t ifp;
	int i;

	mtx_lock(&wifi_vap_mtx);
	for (i = 0; i < (int)nitems(names); i++) {
		ifp = ifunit(names[i]);
		if (ifp != NULL)
			dpaa_wifi_add_vap(ifp);
	}
	mtx_unlock(&wifi_vap_mtx);
}

/*
 * BMan pool callbacks for WiFi injection buffers.
 */
static uint8_t *
wifi_pool_get_buffer(t_Handle h_pool, t_Handle *context)
{
	uint8_t *buf;

	buf = uma_zalloc(wifi_zone, M_NOWAIT);
	if (buf != NULL)
		*(uintptr_t *)(buf + PRIVDATA_KVA_OFF) = (uintptr_t)buf;
	return (buf);
}

static t_Error
wifi_pool_put_buffer(t_Handle h_pool, uint8_t *buffer, t_Handle context)
{

	uma_zfree(wifi_zone,
	    (void *)(*(uintptr_t *)(buffer + PRIVDATA_KVA_OFF)));
	return (E_OK);
}

/*
 * Refill WiFi BMan pool if running low.
 */
static void
wifi_pool_refill(void)
{
	uint8_t *buf;
	unsigned int i;

	for (i = 0; i < WIFI_POOL_REFILL_COUNT; i++) {
		buf = uma_zalloc(wifi_zone, M_NOWAIT);
		if (buf == NULL)
			break;
		*(uintptr_t *)(buf + PRIVDATA_KVA_OFF) = (uintptr_t)buf;
		if (bman_put_buffer(wifi_pool, buf) != 0) {
			uma_zfree(wifi_zone, buf);
			break;
		}
	}
	if (i > 0)
		atomic_add_32(&wifi_buf_total, i);
}

/*
 * Return a WiFi pool buffer.
 * Called from all paths where a WiFi injection buffer returns after
 * FMan processing (miss callback, dist callback, drop paths).
 */
static inline void
wifi_buf_return(void *buf)
{

	bman_put_buffer(wifi_pool, buf);
}

/*
 * Free an SG table buffer and its stashed mbuf.
 * For SG inject frames returning from FMan.
 */
static inline void
wifi_sgt_free(void *sgt_buf)
{
	uintptr_t packed;
	struct mbuf *m;

	/* Recover and free the stashed mbuf */
	packed = *(uintptr_t *)((char *)sgt_buf + PRIVDATA_VAP_OFF);
	m = (struct mbuf *)(packed & ~(uintptr_t)0xFF);
	m_freem(m);

	/* Free SG table buffer via stashed KVA */
	uma_zfree(wifi_sgt_zone,
	    (void *)(*(uintptr_t *)((char *)sgt_buf + PRIVDATA_KVA_OFF)));
}

/*
 * Return a WiFi injection buffer (contiguous or SG) to its pool
 * and increment the TX done counter.  Detects SG by FD format.
 */
static inline void
wifi_buf_release(void *buf, t_DpaaFD *frame)
{

	if (__predict_false(DPAA_FD_GET_FORMAT(frame) ==
	    e_DPAA_FD_FORMAT_TYPE_SHORT_MBSF))
		wifi_sgt_free(buf);
	else
		wifi_buf_return(buf);
}

/*
 * Deliver a WiFi injection buffer to the stack (contiguous path).
 *
 * Shared helper for the OH default FQ callback (PCD miss) and the
 * CDX distribution FQ callback (PCD hit dispatched by BPID).
 * Both cases have a WiFi pool buffer with VAP index in privData.
 *
 * Copies frame data to a fresh mbuf and returns the BMan buffer to
 * the pool immediately.  Linux VWD does the same (process_rx_exception_pkt
 * copies to skb, then bman_release).  Without this, BMan buffers
 * accumulate in TCP receive buffers and the pool drains, stalling
 * all WiFi injection.
 *
 * Runs inside QM_PORTAL_Poll with NCSW_PLOCK held — delivers via
 * qman_rx_defer for deferred if_input after lock release.
 */
static e_RxStoreResponse
dpaa_wifi_deliver_to_stack(void *buf, t_DpaaFD *frame)
{
	struct mbuf *m;
	struct dpaa_wifi_vap *vap;
	uint8_t vap_idx;
	uint32_t frame_len;

	vap_idx = *(uint8_t *)((char *)buf + PRIVDATA_VAP_OFF);
	if (__predict_false(vap_idx >= DPAA_WIFI_MAX_VAPS ||
	    !wifi_vaps[vap_idx].active)) {
		atomic_add_64(&wifi_rx_drop, 1);
		wifi_buf_return(buf);
		return (e_RX_STORE_RESPONSE_CONTINUE);
	}
	vap = &wifi_vaps[vap_idx];

	frame_len = DPAA_FD_GET_LENGTH(frame);

	m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR,
	    frame_len > MCLBYTES ? MJUMPAGESIZE : MCLBYTES);
	if (__predict_false(m == NULL)) {
		atomic_add_64(&wifi_rx_drop, 1);
		wifi_buf_return(buf);
		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

	memcpy(mtod(m, void *),
	    (char *)buf + DPAA_FD_GET_OFFSET(frame), frame_len);
	m->m_len = frame_len;
	m->m_pkthdr.len = frame_len;
	m->m_pkthdr.rcvif = vap->ifp;

	/* Return BMan buffer to pool immediately */
	wifi_buf_return(buf);

	qman_rx_defer(m);
	atomic_add_64(&vap->rx_to_stack, 1);
	return (e_RX_STORE_RESPONSE_CONTINUE);
}

/*
 * Deliver an SG injection buffer to the stack.
 *
 * The original mbuf chain is stashed in the SG table buffer's privData.
 * We recover it, set the receive interface, free the SG table buffer,
 * and deliver the original mbuf to the stack.
 */
static e_RxStoreResponse
dpaa_wifi_deliver_to_stack_sg(void *sgt_buf, t_DpaaFD *frame)
{
	struct dpaa_wifi_vap *vap;
	uintptr_t packed;
	struct mbuf *m;
	uint8_t vap_idx;

	packed = *(uintptr_t *)((char *)sgt_buf + PRIVDATA_VAP_OFF);
	m = (struct mbuf *)(packed & ~(uintptr_t)0xFF);
	vap_idx = (uint8_t)(packed & 0xFF);

	if (__predict_false(vap_idx >= DPAA_WIFI_MAX_VAPS ||
	    !wifi_vaps[vap_idx].active)) {
		atomic_add_64(&wifi_rx_drop, 1);
		wifi_sgt_free(sgt_buf);
		return (e_RX_STORE_RESPONSE_CONTINUE);
	}
	vap = &wifi_vaps[vap_idx];

	m->m_pkthdr.rcvif = vap->ifp;

	/* Free SG table buffer */
	uma_zfree(wifi_sgt_zone,
	    (void *)(*(uintptr_t *)((char *)sgt_buf + PRIVDATA_KVA_OFF)));

	qman_rx_defer(m);
	atomic_add_64(&vap->rx_to_stack, 1);
	return (e_RX_STORE_RESPONSE_CONTINUE);
}

/*
 * Distribution FQ callback — WiFi frames that matched PCD KeyGen.
 *
 * Registered via dpaa_oh_register_dist_cb() so CDX can dispatch
 * WiFi frames from distribution FQs instead of dropping them.
 * Same delivery logic as the default FQ's WiFi→stack path.
 */
static e_RxStoreResponse
dpaa_wifi_dist_rx_cb(t_Handle app __unused, t_Handle qm_fqr,
    t_Handle qm_portal __unused, uint32_t fqid_offset,
    t_DpaaFD *frame)
{
	void *buf;
	uint32_t fd_status;

	buf = DPAA_FD_GET_ADDR(frame);
	if (__predict_false(buf == NULL))
		return (e_RX_STORE_RESPONSE_CONTINUE);

	fd_status = DPAA_FD_GET_STATUS(frame);
	if (__predict_false((fd_status & 0x07FE0000) || wifi_nvaps == 0)) {
		atomic_add_64(&wifi_rx_drop, 1);
		wifi_buf_release(buf, frame);
		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

	/* Dispatch by format: SG frames have stashed mbuf, contig use privData VAP index */
	if (__predict_false(DPAA_FD_GET_FORMAT(frame) ==
	    e_DPAA_FD_FORMAT_TYPE_SHORT_MBSF))
		return (dpaa_wifi_deliver_to_stack_sg(buf, frame));

	return (dpaa_wifi_deliver_to_stack(buf, frame));
}

/*
 * OH port default FQ callback — frames that PCD did not classify.
 *
 * Two cases, distinguished by BPID:
 *   1. BPID = wifi_bpid:  WiFi→CDX miss (our injection, PCD no match).
 *      Recover VAP index from privData, deliver to stack via if_input.
 *   2. BPID = other:  CDX→WiFi (CDX offloaded frame for WiFi client).
 *      Find target VAP by destination MAC, deliver via if_transmit.
 *
 * Runs inside QM_PORTAL_Poll with NCSW_PLOCK held — cannot call
 * if_input/if_transmit directly.  Use qman_rx_defer with M_PROTO1
 * tag to distinguish TX-bound frames in the drain loop.
 */
static e_RxStoreResponse
dpaa_wifi_rx_cb(t_Handle app, t_Handle fqr, t_Handle portal,
    uint32_t fqid_off, t_DpaaFD *frame)
{
	void *buf;
	struct mbuf *m;
	struct dpaa_wifi_vap *vap;
	uint8_t bpid;
	uint32_t fd_status, frame_len;

	buf = DPAA_FD_GET_ADDR(frame);
	if (__predict_false(buf == NULL))
		return (e_RX_STORE_RESPONSE_CONTINUE);

	bpid = frame->bpid;

	/* Check for FMan errors */
	fd_status = DPAA_FD_GET_STATUS(frame);
	if (__predict_false(fd_status & 0x07FE0000)) {	/* RX error mask */
		static volatile uint64_t rx_err_count;
		uint64_t n = atomic_fetchadd_64(
		    __DEVOLATILE(uint64_t *, &rx_err_count), 1);
		if (n < 5 || (n % 1000) == 0)
			printf("dpaa_wifi: rx_cb FMan error #%ju "
			    "fd_status=0x%08x bpid=%u len=%u\n",
			    (uintmax_t)(n + 1), fd_status, bpid,
			    DPAA_FD_GET_LENGTH(frame));
		atomic_add_64(&wifi_rx_drop, 1);
		goto drop;
	}

	if (__predict_false(wifi_nvaps == 0)) {
		atomic_add_64(&wifi_rx_drop, 1);
		goto drop;
	}

	if (bpid == wifi_bpid) {
		/*
		 * WiFi→CDX miss: frame from our injection that PCD
		 * didn't match.  Return to stack for normal processing.
		 * Handles both contiguous and SG formats.
		 */
		if (__predict_false(DPAA_FD_GET_FORMAT(frame) ==
		    e_DPAA_FD_FORMAT_TYPE_SHORT_MBSF))
			return (dpaa_wifi_deliver_to_stack_sg(buf, frame));
		return (dpaa_wifi_deliver_to_stack(buf, frame));
	}

	/*
	 * CDX→WiFi: frame from CDX offload destined for a
	 * WiFi client.  Find the target VAP by destination
	 * MAC match or first-active fallback, then deliver
	 * to mwifiex via if_transmit.
	 *
	 * Copy frame to a fresh mbuf and release the dtsec buffer
	 * immediately.  Without this, dtsec BMan pool drains when
	 * mwifiex TX can't keep up with wire RX rate — killing ALL
	 * wired traffic, not just WiFi.
	 *
	 * Call if_transmit DIRECTLY here — mwifiex TX uses PCIe DMA,
	 * not QMan, so there's no NCSW_PLOCK reentrancy risk.
	 * Using qman_rx_defer batches frames and overwhelms mwifiex
	 * TX ring, causing silent drops that kill TCP connections.
	 */
	vap = dpaa_wifi_find_vap_for_rx(
	    (char *)buf + DPAA_FD_GET_OFFSET(frame));
	if (__predict_false(vap == NULL)) {
		atomic_add_64(&wifi_rx_drop, 1);
		goto drop;
	}

	frame_len = DPAA_FD_GET_LENGTH(frame);
	m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR,
	    frame_len > MCLBYTES ? MJUMPAGESIZE : MCLBYTES);
	if (__predict_false(m == NULL)) {
		atomic_add_64(&wifi_rx_drop, 1);
		goto drop;
	}

	memcpy(mtod(m, void *),
	    (char *)buf + DPAA_FD_GET_OFFSET(frame), frame_len);
	m->m_len = frame_len;
	m->m_pkthdr.len = frame_len;
	m->m_pkthdr.rcvif = vap->ifp;

	/* Release dtsec buffer and refill BMan pool */
	dtsec_rm_buf_free_external(bpid, buf);
	dtsec_rm_pool_rx_refill_bpid(bpid);

	/*
	 * Fast reject when WiFi TX is backed up — avoids wasted
	 * M_PREPEND + m_defrag + malloc inside mwifiex just to
	 * get ENOBUFS at line rate.
	 */
	if (__predict_false(if_getdrvflags(vap->ifp) & IFF_DRV_OACTIVE)) {
		m_freem(m);
		atomic_add_64(&wifi_tx_oactive, 1);
	} else if (__predict_false(if_transmit(vap->ifp, m) != 0)) {
		atomic_add_64(&wifi_tx_if_fail, 1);
	}
	atomic_add_64(&vap->rx_to_mwifiex, 1);
	atomic_add_64(&wifi_rx_cdx_to_wifi, 1);
	return (e_RX_STORE_RESPONSE_CONTINUE);

drop:
	if (bpid == wifi_bpid)
		wifi_buf_release(buf, frame);
	else {
		dtsec_rm_buf_free_external(bpid, buf);
		dtsec_rm_pool_rx_refill_bpid(bpid);

	}
	return (e_RX_STORE_RESPONSE_CONTINUE);
}

/*
 * Inject a WiFi RX frame into the FMan OH port — contiguous path.
 *
 * Allocates a BMan buffer, copies frame data with proper prefix
 * headroom, builds a contiguous FD, and enqueues to the OH port.
 */
static int
dpaa_wifi_inject_contig(if_t ifp, struct mbuf *m, int vap_idx)
{
	void *buf;
	t_DpaaFD fd;
	int error, retry;

	buf = bman_get_buffer(wifi_pool);
	if (__predict_false(buf == NULL)) {
		/* Pool exhausted — try a quick refill */
		wifi_pool_refill();
		buf = bman_get_buffer(wifi_pool);
		if (buf == NULL) {
			atomic_add_64(&wifi_inject_nobuf, 1);
			atomic_add_64(&wifi_vaps[vap_idx].tx_nobuf, 1);
			m_freem(m);
			return (ENOBUFS);
		}
	}

	/* Stash KVA pointer and VAP index in privData */
	*(uintptr_t *)((char *)buf + PRIVDATA_KVA_OFF) = (uintptr_t)buf;
	*(uint8_t *)((char *)buf + PRIVDATA_VAP_OFF) = (uint8_t)vap_idx;

	/* Copy frame data after the prefix area */
	m_copydata(m, 0, m->m_pkthdr.len,
	    (char *)buf + wifi_data_offset);

	/*
	 * Build contiguous Frame Descriptor.
	 *
	 * No RPD/DTC flags needed — the OH port runs its own parser
	 * (PRS_AND_KG PCD) which populates the parse result in the
	 * buffer prefix automatically.  This matches Linux VWD behavior.
	 */
	memset(&fd, 0, sizeof(fd));
	DPAA_FD_SET_ADDR(&fd, buf);
	DPAA_FD_SET_FORMAT(&fd, e_DPAA_FD_FORMAT_TYPE_SHORT_SBSF);
	DPAA_FD_SET_OFFSET(&fd, wifi_data_offset);
	DPAA_FD_SET_LENGTH(&fd, m->m_pkthdr.len);
	fd.bpid = wifi_bpid;

	/* Enqueue with retry on portal-full (EBUSY) */
	for (retry = 0; retry < DPAA_WIFI_ENQUEUE_RETRIES; retry++) {
		error = dpaa_oh_enqueue(wifi_oh_dev, &fd);
		if (error != EBUSY)
			break;
		cpu_spinwait();
	}
	if (__predict_false(error != 0)) {
		atomic_add_64(&wifi_inject_enq_fail, 1);
		atomic_add_64(&wifi_vaps[vap_idx].tx_enqueue_fail, 1);
		bman_put_buffer(wifi_pool, buf);
		m_freem(m);
		return (error);
	}

	atomic_add_64(&wifi_tx_sent, 1);
	m_freem(m);
	atomic_add_64(&wifi_vaps[vap_idx].inject_count, 1);
	return (0);
}

/*
 * Inject a WiFi RX frame into the FMan OH port — scatter-gather path.
 *
 * For frames larger than WIFI_BUF_SIZE - wifi_data_offset (rare).
 * SG entries point directly at mbuf data segments (zero-copy).
 * The mbuf is held alive until FMan finishes and the frame returns
 * via the default/dist FQ callback.
 */
static int
dpaa_wifi_inject_sg(if_t ifp, struct mbuf *m, int vap_idx)
{
	void *sgt_buf;
	t_DpaaSGTE *sgt;
	t_DpaaFD fd;
	struct mbuf *seg;
	vm_offset_t vaddr;
	uintptr_t packed;
	uint32_t psize, dsize, ssize;
	int i, error, retry;

	sgt_buf = uma_zalloc(wifi_sgt_zone, M_NOWAIT);
	if (__predict_false(sgt_buf == NULL)) {
		atomic_add_64(&wifi_inject_nobuf, 1);
		atomic_add_64(&wifi_vaps[vap_idx].tx_nobuf, 1);
		m_freem(m);
		return (ENOBUFS);
	}

	/* Stash KVA for SG table buffer free */
	*(uintptr_t *)((char *)sgt_buf + PRIVDATA_KVA_OFF) =
	    (uintptr_t)sgt_buf;

	/* Pack mbuf pointer + VAP index (low 8 bits are free) */
	packed = (uintptr_t)m | (uint8_t)vap_idx;
	*(uintptr_t *)((char *)sgt_buf + PRIVDATA_VAP_OFF) = packed;

	/* Build SG entries from mbuf chain, splitting at page boundaries */
	sgt = (t_DpaaSGTE *)((char *)sgt_buf + wifi_data_offset);
	i = 0;
	psize = 0;
	for (seg = m; seg != NULL; seg = seg->m_next) {
		if (seg->m_len == 0)
			continue;
		dsize = seg->m_len;
		vaddr = (vm_offset_t)seg->m_data;
		while (dsize > 0 && i < DPAA_NUM_OF_SG_TABLE_ENTRY) {
			ssize = PAGE_SIZE - (vaddr & PAGE_MASK);
			if (ssize > dsize)
				ssize = dsize;

			DPAA_SGTE_SET_ADDR(&sgt[i], (void *)vaddr);
			DPAA_SGTE_SET_LENGTH(&sgt[i], ssize);
			DPAA_SGTE_SET_EXTENSION(&sgt[i], 0);
			DPAA_SGTE_SET_FINAL(&sgt[i], 0);
			DPAA_SGTE_SET_BPID(&sgt[i], 0);
			DPAA_SGTE_SET_OFFSET(&sgt[i], 0);

			dsize -= ssize;
			vaddr += ssize;
			psize += ssize;
			i++;
		}
		if (dsize > 0)
			break;	/* SG table overflow */
	}

	if (__predict_false(seg != NULL || i == 0)) {
		/* SG table overflow or empty */
		uma_zfree(wifi_sgt_zone, sgt_buf);
		m_freem(m);
		return (EMSGSIZE);
	}

	DPAA_SGTE_SET_FINAL(&sgt[i - 1], 1);

	/* Build SG Frame Descriptor */
	memset(&fd, 0, sizeof(fd));
	DPAA_FD_SET_ADDR(&fd, sgt_buf);
	DPAA_FD_SET_FORMAT(&fd, e_DPAA_FD_FORMAT_TYPE_SHORT_MBSF);
	DPAA_FD_SET_OFFSET(&fd, wifi_data_offset);
	DPAA_FD_SET_LENGTH(&fd, psize);
	fd.bpid = wifi_bpid;

	/* Enqueue with retry on portal-full (EBUSY) */
	for (retry = 0; retry < DPAA_WIFI_ENQUEUE_RETRIES; retry++) {
		error = dpaa_oh_enqueue(wifi_oh_dev, &fd);
		if (error != EBUSY)
			break;
		cpu_spinwait();
	}
	if (__predict_false(error != 0)) {
		atomic_add_64(&wifi_inject_enq_fail, 1);
		atomic_add_64(&wifi_vaps[vap_idx].tx_enqueue_fail, 1);
		uma_zfree(wifi_sgt_zone, sgt_buf);
		m_freem(m);
		return (error);
	}

	/* Do NOT free mbuf — held alive for FMan DMA until callback */
	atomic_add_64(&wifi_tx_sent, 1);
	atomic_add_64(&wifi_vaps[vap_idx].inject_count, 1);
	return (0);
}

/*
 * Inject a WiFi RX frame into the FMan OH port for PCD classification.
 *
 * Called from moal_recv_packet() instead of if_input() when the WiFi
 * bridge is active.  Routes to contiguous (common) or SG (rare) path.
 *
 * Returns 0 on success (mbuf consumed), errno on failure (caller frees).
 */
static int
dpaa_wifi_inject(if_t ifp, struct mbuf *m)
{
	int vap_idx;

	vap_idx = dpaa_wifi_find_vap_idx(ifp);
	if (__predict_false(vap_idx < 0)) {
		m_freem(m);
		return (ENXIO);
	}

	/* TX backpressure: drop if BMan pool is running low (0 = disabled) */
	if (__predict_false(wifi_pool_bp_thresh > 0 &&
	    bman_count(wifi_pool) < wifi_pool_bp_thresh)) {
		wifi_pool_refill();
		if (bman_count(wifi_pool) < wifi_pool_bp_thresh) {
			uint64_t bp = atomic_fetchadd_64(
			    __DEVOLATILE(uint64_t *, &wifi_tx_backpressure), 1);
			atomic_add_64(&wifi_vaps[vap_idx].tx_backpressure, 1);
			if (bp < 10 || (bp % 1000) == 0)
				printf("dpaa_wifi: BACKPRESSURE drop #%ju "
				    "pool_free=%u thresh=%u\n",
				    (uintmax_t)(bp + 1),
				    bman_count(wifi_pool),
				    wifi_pool_bp_thresh);
			m_freem(m);
			return (ENOBUFS);
		}
	}

	if (__predict_true(m->m_pkthdr.len <=
	    (int)(WIFI_BUF_SIZE - wifi_data_offset)))
		return (dpaa_wifi_inject_contig(ifp, m, vap_idx));

	if (wifi_sgt_zone != NULL)
		return (dpaa_wifi_inject_sg(ifp, m, vap_idx));

	/* SG not available and frame too large */
	m_freem(m);
	return (EMSGSIZE);
}

/*
 * Sysctl handler for BMan pool free count.
 */
static int
wifi_sysctl_pool_free(SYSCTL_HANDLER_ARGS)
{
	uint32_t val;

	val = (wifi_pool != NULL) ? bman_count(wifi_pool) : 0;
	return (sysctl_handle_int(oidp, &val, 0, req));
}

/*
 * Create sysctl tree: dev.dpaa_wifi.*
 */
static void
dpaa_wifi_sysctl_init(void)
{
	struct sysctl_oid *vap_tree, *vn;
	char vname[8];
	int i;

	sysctl_ctx_init(&wifi_sysctl_ctx);
	wifi_sysctl_tree = SYSCTL_ADD_NODE(&wifi_sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_dev), OID_AUTO,
	    "dpaa_wifi", CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
	    "WiFi DPAA bridge");

	SYSCTL_ADD_UINT(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "pool_bp_thresh", CTLFLAG_RW | CTLFLAG_MPSAFE,
	    &wifi_pool_bp_thresh, 0,
	    "TX backpressure: min free pool buffers");

	SYSCTL_ADD_U64(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "tx_sent", CTLFLAG_RD | CTLFLAG_MPSAFE,
	    __DEVOLATILE(uint64_t *, &wifi_tx_sent), 0,
	    "TX frames sent to OH port");

	SYSCTL_ADD_U64(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "tx_backpressure", CTLFLAG_RD | CTLFLAG_MPSAFE,
	    __DEVOLATILE(uint64_t *, &wifi_tx_backpressure), 0,
	    "TX frames dropped by backpressure");

	SYSCTL_ADD_U64(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "inject_nobuf", CTLFLAG_RD | CTLFLAG_MPSAFE,
	    __DEVOLATILE(uint64_t *, &wifi_inject_nobuf), 0,
	    "TX BMan pool exhaustion count");

	SYSCTL_ADD_U64(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "inject_enq_fail", CTLFLAG_RD | CTLFLAG_MPSAFE,
	    __DEVOLATILE(uint64_t *, &wifi_inject_enq_fail), 0,
	    "TX enqueue failures after retry");

	SYSCTL_ADD_U64(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "rx_drop", CTLFLAG_RD | CTLFLAG_MPSAFE,
	    __DEVOLATILE(uint64_t *, &wifi_rx_drop), 0,
	    "RX frames dropped");

	SYSCTL_ADD_U64(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "rx_cdx_to_wifi", CTLFLAG_RD | CTLFLAG_MPSAFE,
	    __DEVOLATILE(uint64_t *, &wifi_rx_cdx_to_wifi), 0,
	    "CDX to WiFi frame count");

	SYSCTL_ADD_PROC(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "pool_free", CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    NULL, 0, wifi_sysctl_pool_free, "IU",
	    "BMan pool free buffer count");

	SYSCTL_ADD_UINT(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "pool_total", CTLFLAG_RD | CTLFLAG_MPSAFE,
	    __DEVOLATILE(uint32_t *, &wifi_buf_total), 0,
	    "Total buffers allocated");

	/* Per-VAP subtree: dev.dpaa_wifi.vap.N.* */
	vap_tree = SYSCTL_ADD_NODE(&wifi_sysctl_ctx,
	    SYSCTL_CHILDREN(wifi_sysctl_tree), OID_AUTO,
	    "vap", CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
	    "Per-VAP statistics");

	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		snprintf(vname, sizeof(vname), "%d", i);
		vn = SYSCTL_ADD_NODE(&wifi_sysctl_ctx,
		    SYSCTL_CHILDREN(vap_tree), OID_AUTO,
		    vname, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
		    "VAP statistics");

		SYSCTL_ADD_U64(&wifi_sysctl_ctx,
		    SYSCTL_CHILDREN(vn), OID_AUTO,
		    "inject_count", CTLFLAG_RD | CTLFLAG_MPSAFE,
		    __DEVOLATILE(uint64_t *,
		    &wifi_vaps[i].inject_count), 0,
		    "TX frames injected to OH port");

		SYSCTL_ADD_U64(&wifi_sysctl_ctx,
		    SYSCTL_CHILDREN(vn), OID_AUTO,
		    "tx_backpressure", CTLFLAG_RD | CTLFLAG_MPSAFE,
		    __DEVOLATILE(uint64_t *,
		    &wifi_vaps[i].tx_backpressure), 0,
		    "TX backpressure drops");

		SYSCTL_ADD_U64(&wifi_sysctl_ctx,
		    SYSCTL_CHILDREN(vn), OID_AUTO,
		    "tx_nobuf", CTLFLAG_RD | CTLFLAG_MPSAFE,
		    __DEVOLATILE(uint64_t *,
		    &wifi_vaps[i].tx_nobuf), 0,
		    "TX BMan pool exhaustion");

		SYSCTL_ADD_U64(&wifi_sysctl_ctx,
		    SYSCTL_CHILDREN(vn), OID_AUTO,
		    "tx_enqueue_fail", CTLFLAG_RD | CTLFLAG_MPSAFE,
		    __DEVOLATILE(uint64_t *,
		    &wifi_vaps[i].tx_enqueue_fail), 0,
		    "TX enqueue failures");

		SYSCTL_ADD_U64(&wifi_sysctl_ctx,
		    SYSCTL_CHILDREN(vn), OID_AUTO,
		    "rx_to_stack", CTLFLAG_RD | CTLFLAG_MPSAFE,
		    __DEVOLATILE(uint64_t *,
		    &wifi_vaps[i].rx_to_stack), 0,
		    "RX frames to IP stack");

		SYSCTL_ADD_U64(&wifi_sysctl_ctx,
		    SYSCTL_CHILDREN(vn), OID_AUTO,
		    "rx_to_mwifiex", CTLFLAG_RD | CTLFLAG_MPSAFE,
		    __DEVOLATILE(uint64_t *,
		    &wifi_vaps[i].rx_to_mwifiex), 0,
		    "RX frames to mwifiex");

		SYSCTL_ADD_U64(&wifi_sysctl_ctx,
		    SYSCTL_CHILDREN(vn), OID_AUTO,
		    "rx_err", CTLFLAG_RD | CTLFLAG_MPSAFE,
		    __DEVOLATILE(uint64_t *,
		    &wifi_vaps[i].rx_err), 0,
		    "RX FMan error frames");
	}
}

static int
dpaa_wifi_load(void)
{
	int error;

	/* Find WiFi OH port */
	wifi_oh_dev = dpaa_oh_find_port(WIFI_OH_CELL_INDEX);
	if (wifi_oh_dev == NULL) {
		printf("dpaa_wifi: OH port cell-index %d not found\n",
		    WIFI_OH_CELL_INDEX);
		return (ENXIO);
	}

	wifi_data_offset = dpaa_oh_get_data_offset(wifi_oh_dev);
	printf("dpaa_wifi: OH port found, data_offset=%u, dflt_fqid=%u\n",
	    wifi_data_offset, dpaa_oh_get_default_fqid(wifi_oh_dev));

	/* Register callback on OH default FQ */
	error = dpaa_oh_register_cb(wifi_oh_dev, dpaa_wifi_rx_cb, NULL);
	if (error != 0) {
		printf("dpaa_wifi: failed to register OH callback: %d\n",
		    error);
		return (error);
	}

	/* Create BMan pool for WiFi injection buffers */
	wifi_zone = uma_zcreate("dpaa_wifi: Buffers", WIFI_BUF_SIZE,
	    NULL, NULL, NULL, NULL, 255, 0);
	if (wifi_zone == NULL) {
		printf("dpaa_wifi: failed to create UMA zone\n");
		goto fail_cb;
	}

	wifi_pool = bman_pool_create(&wifi_bpid, WIFI_BUF_SIZE,
	    0, 0, WIFI_POOL_SIZE,
	    wifi_pool_get_buffer, wifi_pool_put_buffer,
	    WIFI_POOL_REFILL_THRESH, WIFI_POOL_SIZE,
	    0, 0, NULL, (t_Handle)wifi_zone, NULL, NULL);
	if (wifi_pool == NULL) {
		printf("dpaa_wifi: failed to create BMan pool\n");
		goto fail_zone;
	}
	wifi_buf_total = WIFI_POOL_SIZE;

	printf("dpaa_wifi: BMan pool created, bpid=%u, %u buffers\n",
	    wifi_bpid, WIFI_POOL_SIZE);

	/* Create SG table UMA zone for oversized frames */
	wifi_sgt_zone = uma_zcreate("dpaa_wifi: SGT",
	    wifi_data_offset +
	    DPAA_NUM_OF_SG_TABLE_ENTRY * sizeof(t_DpaaSGTE),
	    NULL, NULL, NULL, NULL, 63, 0);
	if (wifi_sgt_zone == NULL)
		printf("dpaa_wifi: SG table zone failed (SG path disabled)\n");

	/* Register dist FQ callback so CDX dispatches WiFi frames */
	dpaa_oh_register_dist_cb(wifi_bpid, dpaa_wifi_dist_rx_cb, NULL);

	/*
	 * Register fallback for dist FQ frames with unrecognized BPIDs.
	 * CDX→WiFi download frames carry dtsec BPIDs, not wifi_bpid.
	 * Without this, they land on OH port dist FQs and get dropped.
	 */
	dpaa_oh_register_dist_fallback(dpaa_wifi_rx_cb, NULL);

	/* Initialize VAP table and IFNET event handlers */
	mtx_init(&wifi_vap_mtx, "dpaa_wifi_vap", NULL, MTX_DEF);

	wifi_arrival_tag = EVENTHANDLER_REGISTER(ifnet_arrival_event,
	    dpaa_wifi_ifnet_arrival, NULL, EVENTHANDLER_PRI_ANY);
	wifi_departure_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
	    dpaa_wifi_ifnet_departure, NULL, EVENTHANDLER_PRI_ANY);

	/* Scan for already-existing WiFi interfaces */
	dpaa_wifi_scan_existing();

	/* Create sysctl tree */
	dpaa_wifi_sysctl_init();

	/* Start periodic diagnostic */
	mtx_init(&wifi_diag_mtx, "dpaa_wifi_diag", NULL, MTX_DEF);
	callout_init_mtx(&wifi_diag_callout, &wifi_diag_mtx, 0);
	callout_reset(&wifi_diag_callout, 2 * hz, wifi_diag_tick, NULL);

	printf("dpaa_wifi: loaded (%d VAPs hooked, pool_bp_thresh=%u)\n",
	    wifi_nvaps, wifi_pool_bp_thresh);
	return (0);

fail_zone:
	uma_zdestroy(wifi_zone);
	wifi_zone = NULL;
fail_cb:
	dpaa_oh_register_cb(wifi_oh_dev, NULL, NULL);
	return (ENOMEM);
}

static void
dpaa_wifi_unload(void)
{
	int i;

	/* Stop diagnostic callout */
	callout_drain(&wifi_diag_callout);
	mtx_destroy(&wifi_diag_mtx);

	/* Deregister event handlers first (no new VAPs) */
	if (wifi_arrival_tag != NULL)
		EVENTHANDLER_DEREGISTER(ifnet_arrival_event,
		    wifi_arrival_tag);
	if (wifi_departure_tag != NULL)
		EVENTHANDLER_DEREGISTER(ifnet_departure_event,
		    wifi_departure_tag);

	/* Unhook all active VAPs */
	mtx_lock(&wifi_vap_mtx);
	for (i = 0; i < DPAA_WIFI_MAX_VAPS; i++) {
		if (wifi_vaps[i].active)
			dpaa_wifi_remove_vap(wifi_vaps[i].ifp);
	}
	mtx_unlock(&wifi_vap_mtx);
	mtx_destroy(&wifi_vap_mtx);

	/* Tear down sysctl tree */
	sysctl_ctx_free(&wifi_sysctl_ctx);

	/* Unregister dist FQ callback + default FQ callback */
	dpaa_oh_unregister_dist_cb(wifi_bpid);
	dpaa_oh_register_cb(wifi_oh_dev, NULL, NULL);

	/* Destroy BMan pool and UMA zones */
	if (wifi_pool != NULL) {
		bman_pool_destroy(wifi_pool);
		wifi_pool = NULL;
	}
	if (wifi_sgt_zone != NULL) {
		uma_zdestroy(wifi_sgt_zone);
		wifi_sgt_zone = NULL;
	}
	if (wifi_zone != NULL) {
		uma_zdestroy(wifi_zone);
		wifi_zone = NULL;
	}

	printf("dpaa_wifi: unloaded (nobuf=%ju enqfail=%ju drop=%ju "
	    "cdx2w=%ju txfail=%ju bp=%ju sent=%ju)\n",
	    (uintmax_t)wifi_inject_nobuf,
	    (uintmax_t)wifi_inject_enq_fail,
	    (uintmax_t)wifi_rx_drop,
	    (uintmax_t)wifi_rx_cdx_to_wifi,
	    (uintmax_t)wifi_tx_if_fail,
	    (uintmax_t)wifi_tx_backpressure,
	    (uintmax_t)wifi_tx_sent);
}

static int
dpaa_wifi_modevent(module_t mod, int type, void *unused)
{

	switch (type) {
	case MOD_LOAD:
		return (dpaa_wifi_load());
	case MOD_UNLOAD:
		dpaa_wifi_unload();
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t dpaa_wifi_mod = {
	"dpaa_wifi",
	dpaa_wifi_modevent,
	NULL,
};

DECLARE_MODULE(dpaa_wifi, dpaa_wifi_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
MODULE_DEPEND(dpaa_wifi, dpaa_oh, 1, 1, 1);
MODULE_DEPEND(dpaa_wifi, mwifiex, 1, 1, 1);
MODULE_VERSION(dpaa_wifi, 1);
