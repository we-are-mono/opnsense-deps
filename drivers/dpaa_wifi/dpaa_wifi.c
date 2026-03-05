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

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>

#include <machine/bus.h>

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

/*
 * privData layout in WiFi injection buffers (16 bytes total):
 *   [0..7]  KVA stash (uintptr_t) — for UMA free after BMan/FMan round-trip
 *   [8]     VAP index (uint8_t) — for miss-path RX callback to identify VAP
 *   [9..15] reserved
 */
#define PRIVDATA_KVA_OFF	0
#define PRIVDATA_VAP_OFF	sizeof(uintptr_t)

struct dpaa_wifi_vap {
	if_t		ifp;
	uint8_t		mac[ETHER_ADDR_LEN];
	uint8_t		active;
	volatile uint64_t inject_count;
	volatile uint64_t rx_to_stack;
	volatile uint64_t rx_to_mwifiex;
};

static device_t		wifi_oh_dev;
static uint32_t		wifi_data_offset;	/* buffer prefix size */
static uint8_t		wifi_bpid;		/* our BMan pool ID */
static t_Handle		wifi_pool;		/* BMan pool handle */
static uma_zone_t	wifi_zone;		/* UMA zone for pool buffers */
static volatile uint32_t wifi_buf_total;	/* in-flight buffer count */

/* VAP table */
static struct dpaa_wifi_vap wifi_vaps[DPAA_WIFI_MAX_VAPS];
static volatile int	wifi_nvaps;
static struct mtx	wifi_vap_mtx;

/* IFNET event handlers */
static eventhandler_tag	wifi_arrival_tag;
static eventhandler_tag	wifi_departure_tag;

/* Module-wide statistics */
static volatile uint64_t wifi_inject_nobuf;
static volatile uint64_t wifi_rx_drop;

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
	wifi_vaps[slot].rx_to_stack = 0;
	wifi_vaps[slot].rx_to_mwifiex = 0;
	wifi_vaps[slot].ifp = ifp;

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
			    "inject=%ju rx_stack=%ju rx_wifi=%ju)\n",
			    if_name(ifp), i,
			    (uintmax_t)wifi_vaps[i].inject_count,
			    (uintmax_t)wifi_vaps[i].rx_to_stack,
			    (uintmax_t)wifi_vaps[i].rx_to_mwifiex);

			wifi_vaps[i].active = 0;
			atomic_thread_fence_rel();
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
 * ext_free for mbufs backed by WiFi pool buffers (WiFi→CDX miss path).
 * The frame was injected by us, PCD didn't match, came back on default FQ.
 */
static void
dpaa_wifi_ext_free_wifi(struct mbuf *m)
{
	void *buf;

	buf = m->m_ext.ext_arg1;
	uma_zfree(wifi_zone,
	    (void *)(*(uintptr_t *)((char *)buf + PRIVDATA_KVA_OFF)));
	atomic_subtract_32(&wifi_buf_total, 1);
}

/*
 * ext_free for mbufs backed by dtsec pool buffers (CDX→WiFi path).
 * The frame came from a dtsec RX BMan pool via CDX offload.
 */
static void
dpaa_wifi_ext_free_dtsec(struct mbuf *m)
{
	void *buf;
	uint8_t bpid;

	buf = m->m_ext.ext_arg1;
	bpid = (uint8_t)(uintptr_t)m->m_ext.ext_arg2;
	dtsec_rm_buf_free_external(bpid, buf);
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
 * Deliver a WiFi injection buffer to the stack.
 *
 * Shared helper for the OH default FQ callback (PCD miss) and the
 * CDX distribution FQ callback (PCD hit dispatched by BPID).
 * Both cases have a WiFi pool buffer with VAP index in privData.
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

	vap_idx = *(uint8_t *)((char *)buf + PRIVDATA_VAP_OFF);
	if (__predict_false(vap_idx >= DPAA_WIFI_MAX_VAPS ||
	    !wifi_vaps[vap_idx].active)) {
		atomic_add_64(&wifi_rx_drop, 1);
		bman_put_buffer(wifi_pool, buf);
		return (e_RX_STORE_RESPONSE_CONTINUE);
	}
	vap = &wifi_vaps[vap_idx];

	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (__predict_false(m == NULL)) {
		atomic_add_64(&wifi_rx_drop, 1);
		bman_put_buffer(wifi_pool, buf);
		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

	m_extadd(m, buf, WIFI_BUF_SIZE,
	    dpaa_wifi_ext_free_wifi, buf, NULL, 0, EXT_NET_DRV);
	m->m_pkthdr.rcvif = vap->ifp;
	m->m_data = (char *)buf + DPAA_FD_GET_OFFSET(frame);
	m->m_len = DPAA_FD_GET_LENGTH(frame);
	m->m_pkthdr.len = m->m_len;

	if (__predict_false(bman_count(wifi_pool) < WIFI_POOL_REFILL_THRESH))
		wifi_pool_refill();

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
		bman_put_buffer(wifi_pool, buf);
		return (e_RX_STORE_RESPONSE_CONTINUE);
	}

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
	uint32_t fd_status;

	buf = DPAA_FD_GET_ADDR(frame);
	if (__predict_false(buf == NULL))
		return (e_RX_STORE_RESPONSE_CONTINUE);

	bpid = frame->bpid;

	/* Check for FMan errors */
	fd_status = DPAA_FD_GET_STATUS(frame);
	if (__predict_false(fd_status & 0x07FE0000)) {	/* RX error mask */
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
		 */
		return (dpaa_wifi_deliver_to_stack(buf, frame));
	}

	/*
	 * CDX→WiFi: frame from CDX offload destined for a
	 * WiFi client.  Find the target VAP by destination
	 * MAC match or first-active fallback, then deliver
	 * to mwifiex via if_transmit.
	 *
	 * Tag with M_PROTO1 so the drain loop uses if_transmit
	 * instead of if_input.
	 */
	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (__predict_false(m == NULL)) {
		atomic_add_64(&wifi_rx_drop, 1);
		goto drop;
	}

	vap = dpaa_wifi_find_vap_for_rx(
	    (char *)buf + DPAA_FD_GET_OFFSET(frame));
	if (__predict_false(vap == NULL)) {
		m_free(m);
		atomic_add_64(&wifi_rx_drop, 1);
		goto drop;
	}

	m_extadd(m, buf, WIFI_BUF_SIZE,
	    dpaa_wifi_ext_free_dtsec, buf,
	    (void *)(uintptr_t)bpid, 0, EXT_NET_DRV);
	m->m_pkthdr.rcvif = vap->ifp;
	m->m_data = (char *)buf + DPAA_FD_GET_OFFSET(frame);
	m->m_len = DPAA_FD_GET_LENGTH(frame);
	m->m_pkthdr.len = m->m_len;
	m->m_flags |= M_PROTO1;

	qman_rx_defer(m);
	atomic_add_64(&vap->rx_to_mwifiex, 1);
	return (e_RX_STORE_RESPONSE_CONTINUE);

drop:
	if (bpid == wifi_bpid)
		bman_put_buffer(wifi_pool, buf);
	else
		dtsec_rm_buf_free_external(bpid, buf);
	return (e_RX_STORE_RESPONSE_CONTINUE);
}

/*
 * Inject a WiFi RX frame into the FMan OH port for PCD classification.
 *
 * Called from moal_recv_packet() instead of if_input() when the WiFi
 * bridge is active.  Allocates a BMan buffer, copies frame data with
 * proper prefix headroom, builds an FD, and enqueues to the OH port.
 *
 * Returns 0 on success (mbuf consumed), ENOBUFS on pool exhaustion.
 */
static int
dpaa_wifi_inject(if_t ifp, struct mbuf *m)
{
	void *buf;
	t_DpaaFD fd;
	int vap_idx, error;

	vap_idx = dpaa_wifi_find_vap_idx(ifp);
	if (__predict_false(vap_idx < 0)) {
		m_freem(m);
		return (ENXIO);
	}

	buf = bman_get_buffer(wifi_pool);
	if (__predict_false(buf == NULL)) {
		/* Pool exhausted — try a quick refill */
		wifi_pool_refill();
		buf = bman_get_buffer(wifi_pool);
		if (buf == NULL) {
			atomic_add_64(&wifi_inject_nobuf, 1);
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

	/* Build contiguous Frame Descriptor */
	memset(&fd, 0, sizeof(fd));
	DPAA_FD_SET_ADDR(&fd, buf);
	DPAA_FD_SET_FORMAT(&fd, e_DPAA_FD_FORMAT_TYPE_SHORT_SBSF);
	DPAA_FD_SET_OFFSET(&fd, wifi_data_offset);
	DPAA_FD_SET_LENGTH(&fd, m->m_pkthdr.len);
	fd.bpid = wifi_bpid;

	error = dpaa_oh_enqueue(wifi_oh_dev, &fd);
	if (__predict_false(error != 0)) {
		/* Enqueue failed — return buffer to pool */
		bman_put_buffer(wifi_pool, buf);
		m_freem(m);
		return (error);
	}

	m_freem(m);
	atomic_add_64(&wifi_vaps[vap_idx].inject_count, 1);
	return (0);
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

	/* Register dist FQ callback so CDX dispatches WiFi frames */
	dpaa_oh_register_dist_cb(wifi_bpid, dpaa_wifi_dist_rx_cb, NULL);

	/* Initialize VAP table and IFNET event handlers */
	mtx_init(&wifi_vap_mtx, "dpaa_wifi_vap", NULL, MTX_DEF);

	wifi_arrival_tag = EVENTHANDLER_REGISTER(ifnet_arrival_event,
	    dpaa_wifi_ifnet_arrival, NULL, EVENTHANDLER_PRI_ANY);
	wifi_departure_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
	    dpaa_wifi_ifnet_departure, NULL, EVENTHANDLER_PRI_ANY);

	/* Scan for already-existing WiFi interfaces */
	dpaa_wifi_scan_existing();

	printf("dpaa_wifi: loaded (%d VAPs hooked, callback=active)\n",
	    wifi_nvaps);
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

	/* Unregister dist FQ callback + default FQ callback */
	dpaa_oh_unregister_dist_cb(wifi_bpid);
	dpaa_oh_register_cb(wifi_oh_dev, NULL, NULL);

	/* Destroy BMan pool and UMA zone */
	if (wifi_pool != NULL) {
		bman_pool_destroy(wifi_pool);
		wifi_pool = NULL;
	}
	if (wifi_zone != NULL) {
		uma_zdestroy(wifi_zone);
		wifi_zone = NULL;
	}

	printf("dpaa_wifi: unloaded (nobuf=%ju drop=%ju)\n",
	    (uintmax_t)wifi_inject_nobuf,
	    (uintmax_t)wifi_rx_drop);
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
