/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026 Mono Technologies Inc.
 *
 * NXP 88W9098 PCIe WiFi driver — FreeBSD OS abstraction (moal_shim).
 * Implements the moal_callbacks function pointer table that mlan calls.
 */

#include "moal_freebsd.h"
#include <sys/syslog.h>

MALLOC_DEFINE(M_MWIFIEX, "mwifiex", "NXP mwifiex WiFi driver");

/* ----------------------------------------------------------------
 * Memory allocation
 * ---------------------------------------------------------------- */

static mlan_status
moal_malloc(t_void *pmoal, t_u32 size, t_u32 flag, t_u8 **ppbuf)
{
	int mflag;

	mflag = (flag & MLAN_MEM_FLAG_ATOMIC) ? M_NOWAIT : M_WAITOK;
	if (!(flag & MLAN_MEM_FLAG_DIRTY))
		mflag |= M_ZERO;

	*ppbuf = malloc(size, M_MWIFIEX, mflag);
	if (*ppbuf == NULL)
		return MLAN_STATUS_FAILURE;
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_mfree(t_void *pmoal, t_u8 *pbuf)
{
	free(pbuf, M_MWIFIEX);
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_vmalloc(t_void *pmoal, t_u32 size, t_u8 **ppbuf)
{
	/* FreeBSD doesn't distinguish vmalloc/kmalloc */
	*ppbuf = malloc(size, M_MWIFIEX, M_WAITOK | M_ZERO);
	if (*ppbuf == NULL)
		return MLAN_STATUS_FAILURE;
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_vfree(t_void *pmoal, t_u8 *pbuf)
{
	free(pbuf, M_MWIFIEX);
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * DMA (consistent/coherent) memory
 * ---------------------------------------------------------------- */

static void
moal_dma_load_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	if (error == 0)
		*(bus_addr_t *)arg = segs[0].ds_addr;
}

static mlan_status
moal_malloc_consistent(t_void *pmoal, t_u32 size, t_u8 **ppbuf,
    t_u64 *pbuf_pa)
{
	struct mwifiex_handle *handle = pmoal;
	struct mwifiex_dma_alloc *da;
	int error;

	da = malloc(sizeof(*da), M_MWIFIEX, M_NOWAIT | M_ZERO);
	if (da == NULL)
		return MLAN_STATUS_FAILURE;

	da->size = size;

	error = bus_dma_tag_create(handle->dma_tag,
	    8, 0,			/* alignment, boundary */
	    BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter */
	    size, 1, size,		/* maxsize, nseg, maxsegsz */
	    BUS_DMA_ALLOCNOW, NULL, NULL,
	    &da->tag);
	if (error)
		goto fail;

	error = bus_dmamem_alloc(da->tag, &da->vaddr,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO | BUS_DMA_COHERENT, &da->map);
	if (error)
		goto fail_tag;

	error = bus_dmamap_load(da->tag, da->map, da->vaddr, size,
	    moal_dma_load_cb, &da->paddr, BUS_DMA_NOWAIT);
	if (error)
		goto fail_mem;

	*ppbuf = da->vaddr;
	*pbuf_pa = (t_u64)da->paddr;

	mtx_lock(&handle->dma_list_mtx);
	SLIST_INSERT_HEAD(&handle->dma_allocs, da, link);
	mtx_unlock(&handle->dma_list_mtx);

	return MLAN_STATUS_SUCCESS;

fail_mem:
	bus_dmamem_free(da->tag, da->vaddr, da->map);
fail_tag:
	bus_dma_tag_destroy(da->tag);
fail:
	free(da, M_MWIFIEX);
	return MLAN_STATUS_FAILURE;
}

static mlan_status
moal_mfree_consistent(t_void *pmoal, t_u32 size, t_u8 *pbuf,
    t_u64 buf_pa)
{
	struct mwifiex_handle *handle = pmoal;
	struct mwifiex_dma_alloc *da;

	mtx_lock(&handle->dma_list_mtx);
	SLIST_FOREACH(da, &handle->dma_allocs, link) {
		if (da->vaddr == pbuf) {
			SLIST_REMOVE(&handle->dma_allocs, da,
			    mwifiex_dma_alloc, link);
			mtx_unlock(&handle->dma_list_mtx);
			bus_dmamap_unload(da->tag, da->map);
			bus_dmamem_free(da->tag, da->vaddr, da->map);
			bus_dma_tag_destroy(da->tag);
			free(da, M_MWIFIEX);
			return MLAN_STATUS_SUCCESS;
		}
	}
	mtx_unlock(&handle->dma_list_mtx);

	printf("mwifiex: moal_mfree_consistent: unknown buf %p\n", pbuf);
	return MLAN_STATUS_FAILURE;
}

static mlan_status
moal_malloc_cached(t_void *pmoal, t_u32 size, t_u8 **ppbuf,
    t_u64 *pbuf_pa)
{
	/* For now, treat cached same as consistent */
	return moal_malloc_consistent(pmoal, size, ppbuf, pbuf_pa);
}

static mlan_status
moal_mfree_cached(t_void *pmoal, t_u32 size, t_u8 *pbuf,
    t_u64 buf_pa)
{
	return moal_mfree_consistent(pmoal, size, pbuf, buf_pa);
}

/* ----------------------------------------------------------------
 * DMA sync
 * ---------------------------------------------------------------- */

static mlan_status
moal_dma_sync_to_cpu(t_void *pmoal, t_u32 size, t_u64 buf_pa,
    moal_dma_sync_direction_t dir)
{
	/* On coherent ARM64, this is a no-op */
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_dma_sync_to_device(t_void *pmoal, t_u32 size, t_u64 buf_pa,
    moal_dma_sync_direction_t dir)
{
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_map_memory(t_void *pmoal, t_u8 *pbuf, t_u64 *pbuf_pa,
    t_u32 size, t_u32 flag)
{
	/* For simple streaming DMA, use vtophys */
	*pbuf_pa = (t_u64)vtophys(pbuf);
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_unmap_memory(t_void *pmoal, t_u8 *pbuf, t_u64 buf_pa,
    t_u32 size, t_u32 flag)
{
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Register I/O (BAR 0)
 * ---------------------------------------------------------------- */

static mlan_status
moal_write_reg(t_void *pmoal, t_u32 reg, t_u32 data)
{
	struct mwifiex_handle *handle = pmoal;
	struct mwifiex_softc *sc = handle->sc;

	MWIFIEX_WRITE_4(sc, reg, data);
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_read_reg(t_void *pmoal, t_u32 reg, t_u32 *data)
{
	struct mwifiex_handle *handle = pmoal;
	struct mwifiex_softc *sc = handle->sc;

	*data = MWIFIEX_READ_4(sc, reg);
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Synchronous data I/O — used for firmware download
 * ---------------------------------------------------------------- */

static mlan_status
moal_write_data_sync(t_void *pmoal, pmlan_buffer pmbuf,
    t_u32 port, t_u32 timeout)
{
	/*
	 * For PCIE, mlan_pcie.c handles ADMA ring writes directly via
	 * moal_read_reg/moal_write_reg. This callback is not used in
	 * the PCIE path (it's for SDIO block transfers).
	 */
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_read_data_sync(t_void *pmoal, pmlan_buffer pmbuf,
    t_u32 port, t_u32 timeout)
{
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Memory operations
 * ---------------------------------------------------------------- */

static t_void *
moal_memset(t_void *pmoal, t_void *pmem, t_u8 byte, t_u32 num)
{
	return memset(pmem, byte, num);
}

static t_void *
moal_memcpy(t_void *pmoal, t_void *pdest, const t_void *psrc, t_u32 num)
{
	return memcpy(pdest, psrc, num);
}

static t_void *
moal_memcpy_ext(t_void *pmoal, t_void *pdest, const t_void *psrc,
    t_u32 num, t_u32 dest_size)
{
	if (num > dest_size)
		num = dest_size;
	return memcpy(pdest, psrc, num);
}

static t_void *
moal_memmove(t_void *pmoal, t_void *pdest, const t_void *psrc, t_u32 num)
{
	return memmove(pdest, psrc, num);
}

static t_s32
moal_memcmp(t_void *pmoal, const t_void *pmem1, const t_void *pmem2,
    t_u32 num)
{
	return memcmp(pmem1, pmem2, num);
}

/* ----------------------------------------------------------------
 * Delay / sleep
 * ---------------------------------------------------------------- */

static t_void
moal_udelay(t_void *pmoal, t_u32 delay)
{
	DELAY(delay);
}

static t_void
moal_usleep_range(t_void *pmoal, t_u32 min_delay, t_u32 max_delay)
{
	/* Use DELAY for short waits, pause for longer */
	if (min_delay < 50)
		DELAY(min_delay);
	else
		pause("mwifiex", howmany(min_delay, 1000000 / hz));
}

/* ----------------------------------------------------------------
 * Time
 * ---------------------------------------------------------------- */

static mlan_status
moal_get_system_time(t_void *pmoal, t_u32 *psec, t_u32 *pusec)
{
	struct timeval tv;

	getmicrouptime(&tv);
	*psec = (t_u32)tv.tv_sec;
	*pusec = (t_u32)tv.tv_usec;
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_get_boot_ktime(t_void *pmoal, t_u64 *pnsec)
{
	struct timespec ts;

	nanouptime(&ts);
	*pnsec = (t_u64)ts.tv_sec * 1000000000ULL + (t_u64)ts.tv_nsec;
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Locks (spinlock wrapper)
 * ---------------------------------------------------------------- */

static mlan_status
moal_init_lock(t_void *pmoal, t_void **pplock)
{
	struct mwifiex_lock *lock;

	lock = malloc(sizeof(*lock), M_MWIFIEX, M_NOWAIT | M_ZERO);
	if (lock == NULL)
		return MLAN_STATUS_FAILURE;
	mtx_init(&lock->mtx, "mwifiex", NULL, MTX_DEF);
	*pplock = lock;
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_free_lock(t_void *pmoal, t_void *plock)
{
	struct mwifiex_lock *lock = plock;

	if (lock != NULL) {
		mtx_destroy(&lock->mtx);
		free(lock, M_MWIFIEX);
	}
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_spin_lock(t_void *pmoal, t_void *plock)
{
	struct mwifiex_lock *lock = plock;

	mtx_lock(&lock->mtx);
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_spin_unlock(t_void *pmoal, t_void *plock)
{
	struct mwifiex_lock *lock = plock;

	mtx_unlock(&lock->mtx);
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Timers
 * ---------------------------------------------------------------- */

static void
moal_timer_func(void *arg)
{
	struct mwifiex_timer *timer = arg;

	timer->callback(timer->context);
	if (timer->periodic)
		callout_reset(&timer->callout,
		    howmany(timer->msec * hz, 1000),
		    moal_timer_func, timer);
}

static mlan_status
moal_init_timer(t_void *pmoal, t_void **pptimer,
    void (*callback)(void *), t_void *pcontext)
{
	struct mwifiex_timer *timer;

	timer = malloc(sizeof(*timer), M_MWIFIEX, M_NOWAIT | M_ZERO);
	if (timer == NULL)
		return MLAN_STATUS_FAILURE;
	callout_init(&timer->callout, 1);
	timer->callback = callback;
	timer->context = pcontext;
	*pptimer = timer;
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_free_timer(t_void *pmoal, t_void *ptimer)
{
	struct mwifiex_timer *timer = ptimer;

	if (timer != NULL) {
		callout_drain(&timer->callout);
		free(timer, M_MWIFIEX);
	}
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_start_timer(t_void *pmoal, t_void *ptimer, t_u8 periodic,
    t_u32 msec)
{
	struct mwifiex_timer *timer = ptimer;

	timer->periodic = periodic;
	timer->msec = msec;
	callout_reset(&timer->callout, howmany(msec * hz, 1000),
	    moal_timer_func, timer);
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_stop_timer(t_void *pmoal, t_void *ptimer)
{
	struct mwifiex_timer *timer = ptimer;

	callout_stop(&timer->callout);
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Firmware data access
 * ---------------------------------------------------------------- */

static mlan_status
moal_get_fw_data(t_void *pmoal, t_u32 offset, t_u32 len, t_u8 *pbuf)
{
	struct mwifiex_handle *handle = pmoal;

	if (handle->fw_image == NULL)
		return MLAN_STATUS_FAILURE;

	if (offset + len > handle->fw_len)
		return MLAN_STATUS_FAILURE;

	memcpy(pbuf, (const t_u8 *)handle->fw_image->data + offset, len);
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_get_vdll_data(t_void *pmoal, t_u32 len, t_u8 *pbuf)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)pmoal;
	t_u32 offset;

	if (handle->fw_image == NULL)
		return MLAN_STATUS_FAILURE;

	if (len > handle->fw_len) {
		printf("mwifiex: Invalid VDLL length=%u fw_len=%u\n",
		    len, handle->fw_len);
		return MLAN_STATUS_FAILURE;
	}

	/* VDLL data is at the tail of the firmware image */
	offset = handle->fw_len - len;
	memcpy(pbuf, (const t_u8 *)handle->fw_image->data + offset, len);
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Buffer management (mlan_buffer alloc/free)
 * ---------------------------------------------------------------- */

static mlan_status
moal_alloc_mlan_buffer(t_void *pmoal, t_u32 size, ppmlan_buffer pmbuf)
{
	pmlan_buffer buf;

	buf = malloc(sizeof(*buf) + size, M_MWIFIEX, M_NOWAIT | M_ZERO);
	if (buf == NULL)
		return MLAN_STATUS_FAILURE;

	buf->pdesc = NULL;
	buf->pbuf = (t_u8 *)(buf + 1);
	buf->data_offset = 0;
	buf->data_len = size;
	buf->flags = 0;

	*pmbuf = buf;
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_free_mlan_buffer(t_void *pmoal, pmlan_buffer pmbuf)
{
	free(pmbuf, M_MWIFIEX);
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Completion callbacks
 * ---------------------------------------------------------------- */

static mlan_status
moal_init_fw_complete(t_void *pmoal, mlan_status status)
{
	struct mwifiex_handle *handle = pmoal;

	if (status == MLAN_STATUS_SUCCESS)
		handle->fw_ready = 1;
	else
		printf("mwifiex: firmware init failed (status=%d)\n", status);
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_shutdown_fw_complete(t_void *pmoal, mlan_status status)
{
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_get_hw_spec_complete(t_void *pmoal, mlan_status status,
    pmlan_hw_info phw, pmlan_bss_tbl ptbl)
{
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_ioctl_complete(t_void *pmoal, pmlan_ioctl_req pioctl_req,
    mlan_status status)
{
	struct mwifiex_handle *handle = pmoal;

	handle->ioctl_status = status;
	handle->ioctl_wait_done = 1;
	wakeup(__DEVOLATILE(void *, &handle->ioctl_wait_done));
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Packet TX/RX callbacks (stub — Phase 8)
 * ---------------------------------------------------------------- */

static mlan_status
moal_send_packet_complete(t_void *pmoal, pmlan_buffer pmbuf,
    mlan_status status)
{
	struct mwifiex_handle *handle = pmoal;
	struct mwifiex_priv *priv;
	struct mbuf *m;

	if (pmbuf == NULL)
		return MLAN_STATUS_SUCCESS;

	priv = handle->priv[pmbuf->bss_index];
	m = pmbuf->pdesc;

	if (status == MLAN_STATUS_SUCCESS) {
		if (priv != NULL) {
			priv->tx_packets++;
			priv->tx_bytes += pmbuf->data_len;
		}
	} else {
		if (priv != NULL)
			priv->tx_errors++;
	}

	/* Free mbuf and mlan_buffer */
	if (m != NULL)
		m_freem(m);
	free(pmbuf, M_MWIFIEX);

	if (priv != NULL) {
		atomic_subtract_int(&priv->tx_pending, 1);
		/* Resume TX when queue drains below low watermark */
		if (atomic_load_int(&priv->tx_pending) < MWIFIEX_TX_LOW_WATER &&
		    (if_getdrvflags(priv->ifp) & IFF_DRV_OACTIVE))
			if_setdrvflagbits(priv->ifp, 0, IFF_DRV_OACTIVE);
	}

	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_recv_packet(t_void *pmoal, pmlan_buffer pmbuf)
{
	struct mwifiex_handle *handle = pmoal;
	struct mwifiex_priv *priv;
	struct mbuf *m;

	if (pmbuf == NULL)
		return MLAN_STATUS_SUCCESS;

	priv = handle->priv[pmbuf->bss_index];
	if (priv == NULL || priv->ifp == NULL || !priv->running) {
		/* No interface for this BSS — tell mlan to free buffer */
		return MLAN_STATUS_FAILURE;
	}

	/* Allocate mbuf and copy RX data */
	m = m_get2(pmbuf->data_len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL) {
		priv->rx_errors++;
		return MLAN_STATUS_FAILURE;
	}

	m_copyback(m, 0, pmbuf->data_len,
	    pmbuf->pbuf + pmbuf->data_offset);
	m->m_pkthdr.len = m->m_len = pmbuf->data_len;
	m->m_pkthdr.rcvif = priv->ifp;

	priv->rx_packets++;
	priv->rx_bytes += pmbuf->data_len;

	if (priv->wifi_bridge_fn != NULL) {
		priv->wifi_bridge_fn(priv->ifp, m);
		return MLAN_STATUS_SUCCESS;
	}

	if_input(priv->ifp, m);

	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_recv_complete(t_void *pmoal, pmlan_buffer pmbuf,
    t_u32 port, mlan_status status)
{
	return MLAN_STATUS_SUCCESS;
}

static mlan_status
moal_recv_event(t_void *pmoal, pmlan_event pmevent)
{
	struct mwifiex_handle *handle = pmoal;
	t_u32 event_id = pmevent->event_id;

	/*
	 * Driver-internal defer events (bit 31 set) — mlan's interrupt
	 * handler fires these from wlan_process_pcie_int_status() which
	 * runs inside mlan_interrupt() in filter context.  We schedule
	 * taskqueue work for each type.
	 */
	switch (event_id) {
	case MLAN_EVENT_ID_DRV_DEFER_HANDLING:
		/* Re-run mlan main processing loop */
		taskqueue_enqueue(taskqueue_fast, &handle->main_task);
		return MLAN_STATUS_SUCCESS;

	case MLAN_EVENT_ID_DRV_DEFER_CMDRESP:
		/* Process command response */
		taskqueue_enqueue(taskqueue_fast, &handle->cmdresp_task);
		return MLAN_STATUS_SUCCESS;

	case MLAN_EVENT_ID_DRV_DEFER_RX_DATA:
		/* Process RX data */
		taskqueue_enqueue(taskqueue_fast, &handle->rx_task);
		return MLAN_STATUS_SUCCESS;

	case MLAN_EVENT_ID_DRV_DEFER_TX_COMPLTE:
		/* Process TX completion */
		taskqueue_enqueue(taskqueue_fast, &handle->txcmpl_task);
		return MLAN_STATUS_SUCCESS;

	case MLAN_EVENT_ID_DRV_DELAY_TX_COMPLETE:
		/* ADMA delayed TX completion — schedule TX complete task */
		taskqueue_enqueue(taskqueue_fast, &handle->txcmpl_task);
		return MLAN_STATUS_SUCCESS;

	case MLAN_EVENT_ID_DRV_DEFER_RX_WORK:
		/* Secondary RX work path */
		taskqueue_enqueue(taskqueue_fast, &handle->rx_task);
		return MLAN_STATUS_SUCCESS;

	case MLAN_EVENT_ID_DRV_FLUSH_RX_WORK:
	case MLAN_EVENT_ID_DRV_FLUSH_MAIN_WORK:
		/* Flush requests — drain pending work synchronously */
		taskqueue_drain(taskqueue_fast, &handle->main_task);
		taskqueue_drain(taskqueue_fast, &handle->rx_task);
		taskqueue_drain(taskqueue_fast, &handle->txcmpl_task);
		taskqueue_drain(taskqueue_fast, &handle->cmdresp_task);
		return MLAN_STATUS_SUCCESS;

	default:
		break;
	}

	/* Per-BSS events */
	{
		struct mwifiex_priv *priv;

		priv = handle->priv[pmevent->bss_index];

		switch (event_id) {
		case MLAN_EVENT_ID_DRV_CONNECTED:
		case MLAN_EVENT_ID_UAP_FW_STA_CONNECT:
			if (priv != NULL && priv->ifp != NULL)
				if_link_state_change(priv->ifp,
				    LINK_STATE_UP);
			break;

		case MLAN_EVENT_ID_FW_DISCONNECTED:
		case MLAN_EVENT_ID_UAP_FW_STA_DISCONNECT:
			if (priv != NULL && priv->ifp != NULL)
				if_link_state_change(priv->ifp,
				    LINK_STATE_DOWN);
			break;

		case MLAN_EVENT_ID_FW_STOP_TX:
			/* Firmware requests TX pause */
			if (priv != NULL && priv->ifp != NULL)
				if_setdrvflagbits(priv->ifp,
				    IFF_DRV_OACTIVE, 0);
			break;

		case MLAN_EVENT_ID_FW_START_TX:
			/* Firmware resumes TX */
			if (priv != NULL && priv->ifp != NULL)
				if_setdrvflagbits(priv->ifp,
				    0, IFF_DRV_OACTIVE);
			break;

		case MLAN_EVENT_ID_UAP_FW_BSS_START:
		case MLAN_EVENT_ID_UAP_FW_BSS_ACTIVE:
		case MLAN_EVENT_ID_UAP_FW_BSS_IDLE:
		case MLAN_EVENT_ID_DRV_UAP_CHAN_INFO:
		case MLAN_EVENT_ID_DRV_PASSTHRU:
		case MLAN_EVENT_ID_DRV_MGMT_FRAME:
		case MLAN_EVENT_ID_FW_TX_STATUS:
			/* Acknowledged but no host action needed */
			break;

		default:
			break;
		}
	}

	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Debug / print
 * ---------------------------------------------------------------- */

static t_void
moal_print(t_void *pmoal, t_u32 level, char *pformat, IN ...)
{
	struct mwifiex_handle *handle = pmoal;
	__va_list args;
	char buf[256];
	int pri;

	/*
	 * MFATAL (bit 1): always to console via printf().
	 * MERROR (bit 2): always to syslog via log() (not console).
	 * Everything else: only when debug sysctl is set.
	 */
	if (level == MFATAL) {
		va_start(args, pformat);
		printf("mwifiex: ");
		vprintf(pformat, args);
		va_end(args);
		return;
	}

	if (level == MERROR) {
		pri = LOG_WARNING;
	} else {
		if (handle == NULL || !handle->debug)
			return;
		pri = LOG_DEBUG;
	}

	va_start(args, pformat);
	vsnprintf(buf, sizeof(buf), pformat, args);
	va_end(args);
	log(pri, "mwifiex: %s", buf);
}

static t_void
moal_print_netintf(t_void *pmoal, t_u32 bss_index, t_u32 level)
{
}

static t_void
moal_assert(t_void *pmoal, t_u32 cond)
{
	KASSERT(cond, ("mwifiex: assertion failed"));
}

/* ----------------------------------------------------------------
 * Statistics / misc stubs
 * ---------------------------------------------------------------- */

static t_void
moal_hist_data_add(t_void *pmoal, t_u32 bss_index, t_u16 rx_rate,
    t_s8 snr, t_s8 nflr, t_u8 antenna)
{
}

static t_void
moal_updata_peer_signal(t_void *pmoal, t_u32 bss_index,
    t_u8 *peer_addr, t_s8 snr, t_s8 nflr)
{
}

static mlan_status
moal_get_host_time_ns(t_u64 *time)
{
	struct timespec ts;

	nanouptime(&ts);
	*time = (t_u64)ts.tv_sec * 1000000000ULL + (t_u64)ts.tv_nsec;
	return MLAN_STATUS_SUCCESS;
}

static t_u64
moal_do_div(t_u64 num, t_u32 base)
{
	return num / base;
}

static void
moal_tp_accounting(t_void *pmoal, t_void *buf, t_u32 drop_point)
{
}

static void
moal_tp_accounting_rx_param(t_void *pmoal, unsigned int type,
    unsigned int rsvd1)
{
}

static void
moal_amsdu_tp_accounting(t_void *pmoal, t_s32 delay, t_s32 copy_delay)
{
}

static mlan_status
moal_calc_short_ssid(t_u8 *pssid, t_u32 ssid_len, t_u32 *pshort_ssid)
{
	*pshort_ssid = 0;
	return MLAN_STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Unaligned access helpers
 * ---------------------------------------------------------------- */

static t_u16
moal_read_u16(const void *src)
{
	const uint8_t *p = src;
	return (t_u16)p[0] | ((t_u16)p[1] << 8);
}

static t_u32
moal_read_u32(const void *src)
{
	const uint8_t *p = src;
	return (t_u32)p[0] | ((t_u32)p[1] << 8) |
	    ((t_u32)p[2] << 16) | ((t_u32)p[3] << 24);
}

static void
moal_write_u16(void *dest, t_u16 val)
{
	uint8_t *p = dest;
	p[0] = val & 0xff;
	p[1] = (val >> 8) & 0xff;
}

static void
moal_write_u32(void *dest, t_u32 val)
{
	uint8_t *p = dest;
	p[0] = val & 0xff;
	p[1] = (val >> 8) & 0xff;
	p[2] = (val >> 16) & 0xff;
	p[3] = (val >> 24) & 0xff;
}

/* ----------------------------------------------------------------
 * CRC32
 * ---------------------------------------------------------------- */

static t_u32
moal_crc32_be(t_u32 initial_crc, t_u8 const *data, unsigned long len)
{
	/* Simple CRC32 — only used for 6GHz short SSID calculation */
	t_u32 crc = initial_crc;
	unsigned long i;

	for (i = 0; i < len; i++) {
		t_u32 j;
		crc ^= (t_u32)data[i] << 24;
		for (j = 0; j < 8; j++) {
			if (crc & 0x80000000)
				crc = (crc << 1) ^ 0x04C11DB7;
			else
				crc = crc << 1;
		}
	}
	return crc;
}

/* ----------------------------------------------------------------
 * Callback table population
 * ---------------------------------------------------------------- */

void
mwifiex_fill_callbacks(mlan_callbacks *cb)
{
	memset(cb, 0, sizeof(*cb));

	/* Memory */
	cb->moal_malloc = moal_malloc;
	cb->moal_mfree = moal_mfree;
	cb->moal_vmalloc = moal_vmalloc;
	cb->moal_vfree = moal_vfree;

	/* DMA memory (PCIE) */
	cb->moal_malloc_consistent = moal_malloc_consistent;
	cb->moal_mfree_consistent = moal_mfree_consistent;
	cb->moal_malloc_cached = moal_malloc_cached;
	cb->moal_mfree_cached = moal_mfree_cached;
	cb->moal_dma_sync_to_cpu = moal_dma_sync_to_cpu;
	cb->moal_dma_sync_to_device = moal_dma_sync_to_device;
	cb->moal_map_memory = moal_map_memory;
	cb->moal_unmap_memory = moal_unmap_memory;

	/* Register I/O */
	cb->moal_write_reg = moal_write_reg;
	cb->moal_read_reg = moal_read_reg;

	/* Data sync I/O */
	cb->moal_write_data_sync = moal_write_data_sync;
	cb->moal_read_data_sync = moal_read_data_sync;

	/* Memory operations */
	cb->moal_memset = moal_memset;
	cb->moal_memcpy = moal_memcpy;
	cb->moal_memcpy_ext = moal_memcpy_ext;
	cb->moal_memmove = moal_memmove;
	cb->moal_memcmp = moal_memcmp;

	/* Delays */
	cb->moal_udelay = moal_udelay;
	cb->moal_usleep_range = moal_usleep_range;

	/* Time */
	cb->moal_get_system_time = moal_get_system_time;
	cb->moal_get_boot_ktime = moal_get_boot_ktime;

	/* Locks */
	cb->moal_init_lock = moal_init_lock;
	cb->moal_free_lock = moal_free_lock;
	cb->moal_spin_lock = moal_spin_lock;
	cb->moal_spin_unlock = moal_spin_unlock;

	/* Timers */
	cb->moal_init_timer = moal_init_timer;
	cb->moal_free_timer = moal_free_timer;
	cb->moal_start_timer = moal_start_timer;
	cb->moal_stop_timer = moal_stop_timer;

	/* Firmware data */
	cb->moal_get_fw_data = moal_get_fw_data;
	cb->moal_get_vdll_data = moal_get_vdll_data;

	/* Buffer management */
	cb->moal_alloc_mlan_buffer = moal_alloc_mlan_buffer;
	cb->moal_free_mlan_buffer = moal_free_mlan_buffer;

	/* Completions */
	cb->moal_init_fw_complete = moal_init_fw_complete;
	cb->moal_shutdown_fw_complete = moal_shutdown_fw_complete;
	cb->moal_get_hw_spec_complete = moal_get_hw_spec_complete;
	cb->moal_ioctl_complete = moal_ioctl_complete;

	/* TX/RX */
	cb->moal_send_packet_complete = moal_send_packet_complete;
	cb->moal_recv_packet = moal_recv_packet;
	/*
	 * Do NOT set moal_recv_amsdu_packet — if set and it returns
	 * SUCCESS (not PENDING), mlan skips deaggregation and drops the
	 * entire AMSDU.  With NULL, mlan deaggregates internally and
	 * calls moal_recv_packet for each sub-frame.
	 */
	cb->moal_recv_complete = moal_recv_complete;
	cb->moal_recv_event = moal_recv_event;

	/* Debug */
	cb->moal_print = moal_print;
	cb->moal_print_netintf = moal_print_netintf;
	cb->moal_assert = moal_assert;

	/* Stats / misc */
	cb->moal_hist_data_add = moal_hist_data_add;
	cb->moal_updata_peer_signal = moal_updata_peer_signal;
	cb->moal_get_host_time_ns = moal_get_host_time_ns;
	cb->moal_do_div = moal_do_div;
	cb->moal_tp_accounting = moal_tp_accounting;
	cb->moal_tp_accounting_rx_param = moal_tp_accounting_rx_param;
	cb->moal_amsdu_tp_accounting = moal_amsdu_tp_accounting;
	cb->moal_calc_short_ssid = moal_calc_short_ssid;

	/* Unaligned access */
	cb->moal_unaligned_access.moal_read_u16 = moal_read_u16;
	cb->moal_unaligned_access.moal_read_u32 = moal_read_u32;
	cb->moal_unaligned_access.moal_write_u16 = moal_write_u16;
	cb->moal_unaligned_access.moal_write_u32 = moal_write_u32;

	/* CRC */
	cb->moal_crc32_be = moal_crc32_be;
}
