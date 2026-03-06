/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026 Mono Technologies Inc.
 *
 * NXP 88W9098 PCIe WiFi driver — PCI probe/attach with mlan integration.
 */

#include "moal_freebsd.h"

static int	mwifiex_detach(device_t dev);

/*
 * Interrupt handler — called by bus_setup_intr.
 * Calls mlan_interrupt() which reads HOST_INT_STATUS and records
 * which events need processing, then schedules the main task.
 */
static int
mwifiex_intr(void *arg)
{
	struct mwifiex_softc *sc = arg;
	struct mwifiex_handle *handle = sc->sc_handle;

	if (handle == NULL || handle->pmlan_adapter == NULL)
		return (FILTER_STRAY);

	if (handle->surprise_removed)
		return (FILTER_STRAY);

	mlan_interrupt(0, handle->pmlan_adapter);
	taskqueue_enqueue(taskqueue_fast, &handle->main_task);

	return (FILTER_HANDLED);
}

/*
 * Deferred processing tasks — scheduled from interrupt context.
 * mlan fires DRV_DEFER_* events from wlan_process_pcie_int_status()
 * (which runs inside mlan_interrupt() in filter context).  We must
 * process them asynchronously via taskqueue.
 */
static void
mwifiex_main_task(void *arg, int pending)
{
	struct mwifiex_handle *handle = arg;

	if (handle->pmlan_adapter == NULL)
		return;
	/*
	 * MLAN_STATUS_PENDING means mlan_main_process hit its restart
	 * limit and yielded.  Reschedule so remaining WMM queue entries
	 * get processed after completion tasks have had a chance to run.
	 */
	if (mlan_main_process(handle->pmlan_adapter) == MLAN_STATUS_PENDING)
		taskqueue_enqueue(taskqueue_fast, &handle->main_task);
}

static void
mwifiex_cmdresp_task(void *arg, int pending)
{
	struct mwifiex_handle *handle = arg;

	if (handle->pmlan_adapter != NULL)
		mlan_process_pcie_interrupt_cb(handle->pmlan_adapter,
		    RX_CMD_RESP);
}

static void
mwifiex_rx_task(void *arg, int pending)
{
	struct mwifiex_handle *handle = arg;

	if (handle->pmlan_adapter != NULL)
		mlan_process_pcie_interrupt_cb(handle->pmlan_adapter,
		    RX_DATA);
}

static void
mwifiex_txcmpl_task(void *arg, int pending)
{
	struct mwifiex_handle *handle = arg;

	if (handle->pmlan_adapter != NULL)
		mlan_process_pcie_interrupt_cb(handle->pmlan_adapter,
		    TX_COMPLETE);
}

/* ----------------------------------------------------------------
 * Synchronous IOCTL helper
 * ---------------------------------------------------------------- */

static mlan_status
mwifiex_do_ioctl(struct mwifiex_handle *handle, mlan_ioctl_req *req)
{
	mlan_status status;
	int loops = 0;

	handle->ioctl_wait_done = 0;

	status = mlan_ioctl(handle->pmlan_adapter, req);

	if (status == MLAN_STATUS_PENDING) {
		/* Drive processing and wait for completion (10s timeout) */
		taskqueue_enqueue(taskqueue_fast, &handle->main_task);
		while (!handle->ioctl_wait_done && loops < 100) {
			tsleep(__DEVOLATILE(void *,
			    &handle->ioctl_wait_done), 0, "mwioctl",
			    hz / 10);
			mlan_main_process(handle->pmlan_adapter);
			loops++;
		}
		if (!handle->ioctl_wait_done) {
			device_printf(handle->sc->sc_dev,
			    "IOCTL timeout (req_id=0x%x)\n", req->req_id);
			mlan_ioctl(handle->pmlan_adapter, NULL);
			return (MLAN_STATUS_FAILURE);
		}
		status = handle->ioctl_status;
	}
	return (status);
}

/* ----------------------------------------------------------------
 * Get MAC address from firmware via MLAN_OID_GET_FW_INFO
 * ---------------------------------------------------------------- */

static int
mwifiex_get_fw_info(struct mwifiex_handle *handle, int bss_index,
    uint8_t *mac_out)
{
	mlan_ioctl_req req;
	mlan_ds_get_info info;

	memset(&req, 0, sizeof(req));
	memset(&info, 0, sizeof(info));

	req.req_id = MLAN_IOCTL_GET_INFO;
	req.action = MLAN_ACT_GET;
	req.bss_index = bss_index;
	req.pbuf = (t_u8 *)&info;
	req.buf_len = sizeof(info);
	info.sub_command = MLAN_OID_GET_FW_INFO;

	if (mwifiex_do_ioctl(handle, &req) != MLAN_STATUS_SUCCESS)
		return (EIO);

	memcpy(mac_out, info.param.fw_info.mac_addr, ETHER_ADDR_LEN);
	return (0);
}

/* ----------------------------------------------------------------
 * Interface callbacks
 * ---------------------------------------------------------------- */

static void
mwifiex_if_init(void *arg)
{
	struct mwifiex_priv *priv = arg;
	if_t ifp = priv->ifp;

	priv->running = 1;
	if_setdrvflagbits(ifp, IFF_DRV_RUNNING, 0);
	if_setdrvflagbits(ifp, 0, IFF_DRV_OACTIVE);
}

static int
mwifiex_if_ioctl(if_t ifp, u_long cmd, caddr_t data)
{
	struct mwifiex_priv *priv = if_getsoftc(ifp);

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (if_getflags(ifp) & IFF_UP) {
			if (!(if_getdrvflags(ifp) & IFF_DRV_RUNNING))
				mwifiex_if_init(priv);
		} else {
			if (if_getdrvflags(ifp) & IFF_DRV_RUNNING) {
				priv->running = 0;
				if_setdrvflagbits(ifp, 0, IFF_DRV_RUNNING);
			}
		}
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;	/* firmware handles multicast filtering */
	default:
		return (ether_ioctl(ifp, cmd, data));
	}
	return (0);
}

static int
mwifiex_if_transmit(if_t ifp, struct mbuf *m)
{
	struct mwifiex_priv *priv = if_getsoftc(ifp);
	struct mwifiex_handle *handle = priv->handle;
	mlan_buffer *pmbuf;
	int len;

	if (!priv->running || handle->surprise_removed) {
		m_freem(m);
		return (ENETDOWN);
	}

	/* Backpressure: reject when TX queue is deep */
	if (__predict_false(atomic_load_int(&priv->tx_pending) >=
	    priv->tx_pending_limit)) {
		if_setdrvflagbits(ifp, IFF_DRV_OACTIVE, 0);
		m_freem(m);
		return (ENOBUFS);
	}

	/*
	 * mlan needs MLAN_MIN_DATA_HEADER_LEN (64) bytes of headroom
	 * before packet data for the TxPD descriptor.  Prepend space.
	 */
	M_PREPEND(m, MLAN_MIN_DATA_HEADER_LEN, M_NOWAIT);
	if (m == NULL)
		return (ENOBUFS);

	/*
	 * Ensure the entire buffer (TxPD headroom + Ethernet frame) is
	 * contiguous.  mlan writes TxPD at pmbuf->pbuf, reads the
	 * Ethernet DA at pmbuf->pbuf + data_offset, and DMA-maps the
	 * whole thing as a single buffer.  M_PREPEND may have created
	 * a chain if the original mbuf had no leading space.
	 */
	if (m->m_next != NULL) {
		m = m_defrag(m, M_NOWAIT);
		if (m == NULL)
			return (ENOBUFS);
	}

	len = m->m_pkthdr.len - MLAN_MIN_DATA_HEADER_LEN;

	/* Allocate mlan_buffer wrapping the mbuf data */
	pmbuf = malloc(sizeof(*pmbuf), M_MWIFIEX, M_NOWAIT | M_ZERO);
	if (pmbuf == NULL) {
		m_freem(m);
		return (ENOBUFS);
	}

	pmbuf->bss_index = priv->bss_index;
	pmbuf->pdesc = m;		/* store mbuf for completion */
	pmbuf->pbuf = mtod(m, t_u8 *);
	pmbuf->data_offset = MLAN_MIN_DATA_HEADER_LEN;
	pmbuf->data_len = len;
	pmbuf->priority = 1;		/* Best effort */
	pmbuf->buf_type = MLAN_BUF_TYPE_DATA;

	atomic_add_int(&priv->tx_pending, 1);
	mlan_send_packet(handle->pmlan_adapter, pmbuf);

	/* Schedule main processing to drive TX */
	taskqueue_enqueue(taskqueue_fast, &handle->main_task);

	return (0);
}

static void
mwifiex_if_qflush(if_t ifp)
{
	/* Nothing to flush — we don't maintain a local send queue */
}

static uint64_t
mwifiex_get_counter(if_t ifp, ift_counter cnt)
{
	struct mwifiex_priv *priv = if_getsoftc(ifp);

	switch (cnt) {
	case IFCOUNTER_IPACKETS:	return (priv->rx_packets);
	case IFCOUNTER_OPACKETS:	return (priv->tx_packets);
	case IFCOUNTER_IBYTES:		return (priv->rx_bytes);
	case IFCOUNTER_OBYTES:		return (priv->tx_bytes);
	case IFCOUNTER_IERRORS:		return (priv->rx_errors);
	case IFCOUNTER_OERRORS:		return (priv->tx_errors);
	default:			return (if_get_counter_default(ifp, cnt));
	}
}

/* ----------------------------------------------------------------
 * Interface creation / destruction
 * ---------------------------------------------------------------- */

static int
mwifiex_create_iface(struct mwifiex_softc *sc, int bss_index, int bss_type)
{
	struct mwifiex_handle *handle = sc->sc_handle;
	struct mwifiex_priv *priv;
	if_t ifp;

	priv = malloc(sizeof(*priv), M_MWIFIEX, M_WAITOK | M_ZERO);
	priv->handle = handle;
	priv->bss_index = bss_index;
	priv->bss_type = bss_type;
	priv->bss_role = (bss_type == MLAN_BSS_TYPE_UAP) ?
	    MLAN_BSS_ROLE_UAP : MLAN_BSS_ROLE_STA;
	priv->tx_pending_limit = MWIFIEX_TX_HIGH_WATER;

	/* Get MAC address from firmware */
	if (mwifiex_get_fw_info(handle, bss_index, priv->mac_addr) != 0) {
		device_printf(sc->sc_dev,
		    "failed to get MAC addr for bss %d\n", bss_index);
		free(priv, M_MWIFIEX);
		return (EIO);
	}

	ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		free(priv, M_MWIFIEX);
		return (ENOMEM);
	}

	priv->ifp = ifp;
	if_setsoftc(ifp, priv);
	if_setflags(ifp, IFF_SIMPLEX | IFF_BROADCAST | IFF_MULTICAST);
	if_setinitfn(ifp, mwifiex_if_init);
	if_setioctlfn(ifp, mwifiex_if_ioctl);
	if_settransmitfn(ifp, mwifiex_if_transmit);
	if_setqflushfn(ifp, mwifiex_if_qflush);
	if_setgetcounterfn(ifp, mwifiex_get_counter);

	/* Name: wlan0 for STA, uap0 for UAP */
	if (bss_type == MLAN_BSS_TYPE_UAP)
		if_initname(ifp, "uap", device_get_unit(sc->sc_dev));
	else
		if_initname(ifp, "wlan", device_get_unit(sc->sc_dev));

	ether_ifattach(ifp, priv->mac_addr);

	handle->priv[bss_index] = priv;
	handle->priv_num++;

	device_printf(sc->sc_dev, "%s: MAC %6D\n",
	    if_name(ifp), priv->mac_addr, ":");

	return (0);
}

static void
mwifiex_destroy_ifaces(struct mwifiex_handle *handle)
{
	int i;

	for (i = 0; i < MLAN_MAX_BSS_NUM; i++) {
		if (handle->priv[i] != NULL) {
			if (handle->priv[i]->ifp != NULL) {
				ether_ifdetach(handle->priv[i]->ifp);
				if_free(handle->priv[i]->ifp);
			}
			free(handle->priv[i], M_MWIFIEX);
			handle->priv[i] = NULL;
		}
	}
	handle->priv_num = 0;
}

/* ----------------------------------------------------------------
 * UAP (Access Point) configuration via firmware IOCTLs
 * ---------------------------------------------------------------- */

/*
 * Get extended firmware info for HT/VHT/HE capability detection.
 */
static int
mwifiex_get_fw_caps(struct mwifiex_handle *handle, mlan_fw_info *out)
{
	mlan_ioctl_req req;
	mlan_ds_get_info *info;
	int error;

	info = malloc(sizeof(*info), M_MWIFIEX, M_WAITOK | M_ZERO);

	memset(&req, 0, sizeof(req));
	req.req_id = MLAN_IOCTL_GET_INFO;
	req.action = MLAN_ACT_GET;
	req.bss_index = 1;
	req.pbuf = (t_u8 *)info;
	req.buf_len = sizeof(*info);
	info->sub_command = MLAN_OID_GET_FW_INFO;

	error = 0;
	if (mwifiex_do_ioctl(handle, &req) != MLAN_STATUS_SUCCESS)
		error = EIO;
	else
		memcpy(out, &info->param.fw_info, sizeof(*out));

	free(info, M_MWIFIEX);
	return (error);
}

/*
 * Determine secondary channel offset for 40MHz+ bandwidth.
 * Returns: 0=none, 1=above, 3=below (Band_Config_t chan2Offset encoding).
 */
static int
mwifiex_chan2_offset(int ch, int bandwidth)
{
	if (bandwidth < 40)
		return (0);

	if (ch <= 14) {
		/* 2.4 GHz: channels 1-7 → above, 8-13 → below */
		return (ch <= 7) ? 1 : 3;
	}

	/* 5 GHz: lower channel of pair → above, upper → below */
	switch (ch) {
	case 36: case 44: case 52: case 60:
	case 100: case 108: case 116: case 124:
	case 132: case 149: case 157:
		return (1);	/* secondary above */
	default:
		return (3);	/* secondary below */
	}
}

/*
 * Enable 11ac VHT for 5GHz UAP (MLAN_OID_11AC_VHT_CFG).
 * Must be called after BSS_CONFIG SET, before BSS_START.
 */
static int
mwifiex_uap_set_11ac(struct mwifiex_handle *handle, mlan_fw_info *fwi,
    int bandwidth)
{
	mlan_ioctl_req req;
	mlan_ds_11ac_cfg *ac;
	int ret;

	if (!(fwi->fw_bands & BAND_AAC))
		return (0);	/* FW doesn't support 11ac on 5GHz */

	ac = malloc(sizeof(*ac), M_MWIFIEX, M_WAITOK | M_ZERO);

	memset(&req, 0, sizeof(req));
	req.req_id = MLAN_IOCTL_11AC_CFG;
	req.action = MLAN_ACT_SET;
	req.bss_index = 1;
	req.pbuf = (t_u8 *)ac;
	req.buf_len = sizeof(*ac);
	ac->sub_command = MLAN_OID_11AC_VHT_CFG;

	ac->param.vht_cfg.band = BAND_SELECT_A;
	ac->param.vht_cfg.txrx = MLAN_RADIO_TXRX;
	ac->param.vht_cfg.vht_cap_info = fwi->usr_dot_11ac_dev_cap_a;
	ac->param.vht_cfg.vht_cap_info &=
	    ~DEFALUT_11AC_CAP_BEAMFORMING_RESET_MASK;
	ac->param.vht_cfg.vht_tx_mcs =
	    fwi->usr_dot_11ac_mcs_support >> 16;
	ac->param.vht_cfg.vht_rx_mcs =
	    fwi->usr_dot_11ac_mcs_support & 0xffff;
	ac->param.vht_cfg.skip_usr_11ac_mcs_cfg = MTRUE;
	/* bwcfg: FALSE=80MHz capable, TRUE=follow 11n 20/40MHz */
	ac->param.vht_cfg.bwcfg = (bandwidth <= 40) ? MTRUE : MFALSE;

	ret = 0;
	if (mwifiex_do_ioctl(handle, &req) != MLAN_STATUS_SUCCESS)
		ret = EIO;

	free(ac, M_MWIFIEX);
	return (ret);
}

/*
 * Enable 11ax HE for UAP (MLAN_OID_11AX_HE_CFG).
 * Works for both 2.4G and 5G.  GET current FW defaults, then SET back.
 */
static int
mwifiex_uap_set_11ax(struct mwifiex_handle *handle, mlan_fw_info *fwi,
    int is_5ghz)
{
	mlan_ioctl_req req;
	mlan_ds_11ax_cfg *ax;
	int ret;

	if (is_5ghz && !(fwi->fw_bands & BAND_AAX))
		return (0);
	if (!is_5ghz && !(fwi->fw_bands & BAND_GAX))
		return (0);

	ax = malloc(sizeof(*ax), M_MWIFIEX, M_WAITOK | M_ZERO);

	memset(&req, 0, sizeof(req));
	req.req_id = MLAN_IOCTL_11AX_CFG;
	req.action = MLAN_ACT_GET;
	req.bss_index = 1;
	req.pbuf = (t_u8 *)ax;
	req.buf_len = sizeof(*ax);
	ax->sub_command = MLAN_OID_11AX_HE_CFG;
	ax->param.he_cfg.band = is_5ghz ? MBIT(1) : MBIT(0);

	ret = 0;
	if (mwifiex_do_ioctl(handle, &req) != MLAN_STATUS_SUCCESS) {
		ret = EIO;
		goto out;
	}

	/* SET back to enable HE with firmware defaults */
	req.action = MLAN_ACT_SET;
	if (mwifiex_do_ioctl(handle, &req) != MLAN_STATUS_SUCCESS)
		ret = EIO;
out:
	free(ax, M_MWIFIEX);
	return (ret);
}

static int
mwifiex_uap_start(struct mwifiex_handle *handle)
{
	mlan_ioctl_req req;
	mlan_ds_bss *bss;
	mlan_uap_bss_param *cfg;
	mlan_fw_info fwi;
	int ch, bw, is_5ghz, is_open, error;
	const char *sec;

	if (handle->uap_ssid[0] == '\0')
		return (EINVAL);

	sec = handle->uap_security;
	is_open = (strcmp(sec, "open") == 0);

	/* Passphrase required for all security modes except open */
	if (!is_open && strlen(handle->uap_passphrase) < 8)
		return (EINVAL);

	/* Get firmware capabilities for 11ac/11ax */
	if (mwifiex_get_fw_caps(handle, &fwi) != 0)
		memset(&fwi, 0, sizeof(fwi));

	bss = malloc(sizeof(*bss), M_MWIFIEX, M_WAITOK | M_ZERO);

	/* Step 1: GET current BSS config from firmware */
	memset(&req, 0, sizeof(req));
	req.req_id = MLAN_IOCTL_BSS;
	req.action = MLAN_ACT_GET;
	req.bss_index = 1;
	req.pbuf = (t_u8 *)bss;
	req.buf_len = sizeof(*bss);
	bss->sub_command = MLAN_OID_UAP_BSS_CONFIG;

	if (mwifiex_do_ioctl(handle, &req) != MLAN_STATUS_SUCCESS) {
		device_printf(handle->sc->sc_dev,
		    "UAP BSS config GET failed\n");
		free(bss, M_MWIFIEX);
		return (EIO);
	}

	cfg = &bss->param.bss_config;

	/* Step 2: SSID and hidden */
	cfg->ssid.ssid_len = strlen(handle->uap_ssid);
	memcpy(cfg->ssid.ssid, handle->uap_ssid, cfg->ssid.ssid_len);
	cfg->bcast_ssid_ctl = handle->uap_hidden ? 0 : 1;

	/* Step 3: Channel, band, bandwidth */
	ch = handle->uap_channel;
	if (ch == 0)
		ch = 6;
	cfg->channel = ch;
	is_5ghz = (ch > 14);

	if (is_5ghz)
		cfg->bandcfg.chanBand = 1;	/* 5 GHz */
	else
		cfg->bandcfg.chanBand = 0;	/* 2.4 GHz */

	bw = handle->uap_bandwidth;
	if (bw >= 80 && is_5ghz)
		cfg->bandcfg.chanWidth = 3;	/* 80 MHz */
	else if (bw >= 40)
		cfg->bandcfg.chanWidth = 2;	/* 40 MHz */
	else
		cfg->bandcfg.chanWidth = 0;	/* 20 MHz */

	cfg->bandcfg.chan2Offset = mwifiex_chan2_offset(ch, bw);
	cfg->bandcfg.scanMode = 0;		/* manual channel */

	/*
	 * Rates must match the band.  The GET above returned defaults
	 * for the previously-configured band (2.4 GHz CCK+OFDM).
	 * 5 GHz requires OFDM-only rates; sending CCK rates on 5 GHz
	 * causes firmware to reject BSS_START.
	 */
	memset(cfg->rates, 0, sizeof(cfg->rates));
	if (is_5ghz) {
		static const t_u8 rates_a[] = {
			0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c
		};
		memcpy(cfg->rates, rates_a, sizeof(rates_a));
	} else {
		static const t_u8 rates_bg[] = {
			0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18,
			0x24, 0x30, 0x48, 0x60, 0x6c
		};
		memcpy(cfg->rates, rates_bg, sizeof(rates_bg));
	}

	/* Step 4: Security */
	if (is_open) {
		cfg->protocol = PROTOCOL_NO_SECURITY;
		cfg->key_mgmt = KEY_MGMT_NONE;
		cfg->auth_mode = MLAN_AUTH_MODE_OPEN;
		memset(&cfg->wpa_cfg, 0, sizeof(cfg->wpa_cfg));
	} else if (strcmp(sec, "wpa3") == 0) {
		cfg->protocol = PROTOCOL_WPA3_SAE;
		cfg->key_mgmt = KEY_MGMT_SAE;
		cfg->auth_mode = MLAN_AUTH_MODE_SAE;
		cfg->pwe_derivation = SAE_PWE_BOTH;
		cfg->wpa_cfg.pairwise_cipher_wpa2 = CIPHER_AES_CCMP;
		cfg->wpa_cfg.group_cipher = CIPHER_AES_CCMP;
		cfg->wpa_cfg.rsn_protection = 1;
		cfg->wpa_cfg.length = strlen(handle->uap_passphrase);
		memcpy(cfg->wpa_cfg.passphrase, handle->uap_passphrase,
		    cfg->wpa_cfg.length);
	} else if (strcmp(sec, "wpa2wpa3") == 0) {
		cfg->protocol = PROTOCOL_WPA2 | PROTOCOL_WPA3_SAE;
		cfg->key_mgmt = KEY_MGMT_PSK | KEY_MGMT_SAE;
		cfg->auth_mode = MLAN_AUTH_MODE_OPEN;
		cfg->pwe_derivation = SAE_PWE_BOTH;
		cfg->wpa_cfg.pairwise_cipher_wpa2 = CIPHER_AES_CCMP;
		cfg->wpa_cfg.group_cipher = CIPHER_AES_CCMP;
		cfg->wpa_cfg.rsn_protection = 1;
		cfg->wpa_cfg.length = strlen(handle->uap_passphrase);
		memcpy(cfg->wpa_cfg.passphrase, handle->uap_passphrase,
		    cfg->wpa_cfg.length);
	} else {
		/* Default: WPA2-PSK */
		cfg->protocol = PROTOCOL_WPA2;
		cfg->key_mgmt = KEY_MGMT_PSK;
		cfg->auth_mode = MLAN_AUTH_MODE_OPEN;
		cfg->wpa_cfg.pairwise_cipher_wpa2 = CIPHER_AES_CCMP;
		cfg->wpa_cfg.group_cipher = CIPHER_AES_CCMP;
		cfg->wpa_cfg.rsn_protection = 1;
		cfg->wpa_cfg.length = strlen(handle->uap_passphrase);
		memcpy(cfg->wpa_cfg.passphrase, handle->uap_passphrase,
		    cfg->wpa_cfg.length);
	}

	/* Step 5: 11n HT capabilities (match Linux moal_uap_cfg80211.c) */
	cfg->ht_cap_info = 0x10c;	/* SM Power Save disabled + Rx STBC */
	cfg->ht_cap_info |= 0x20;	/* Short GI for 20 MHz */
	if (bw >= 40) {
		cfg->ht_cap_info |= 0x1042; /* 40 MHz + Short GI 40 + DSSS/CCK */
		cfg->ampdu_param = 3;	/* max A-MPDU 65535 bytes */
	}
	cfg->supported_mcs_set[0] = 0xFF;	/* MCS 0-7 */
	if (fwi.usr_dev_mcs_support == HT_STREAM_MODE_2X2)
		cfg->supported_mcs_set[1] = 0xFF; /* MCS 8-15 (2x2) */
	if (bw >= 40)
		cfg->supported_mcs_set[4] = 0x01; /* 40MHz MCS32 */

	cfg->beacon_period = 100;
	cfg->dtim_period = 1;
	cfg->max_sta_count = handle->uap_max_sta > 0 ?
	    handle->uap_max_sta : 10;

	/* Step 6: SET BSS config */
	memset(&req, 0, sizeof(req));
	req.req_id = MLAN_IOCTL_BSS;
	req.action = MLAN_ACT_SET;
	req.bss_index = 1;
	req.pbuf = (t_u8 *)bss;
	req.buf_len = sizeof(*bss);
	bss->sub_command = MLAN_OID_UAP_BSS_CONFIG;

	if (mwifiex_do_ioctl(handle, &req) != MLAN_STATUS_SUCCESS) {
		device_printf(handle->sc->sc_dev,
		    "UAP BSS config SET failed\n");
		free(bss, M_MWIFIEX);
		return (EIO);
	}

	/* Step 7: Enable 11ac VHT for 5GHz */
	if (is_5ghz)
		mwifiex_uap_set_11ac(handle, &fwi, bw);

	/* Step 8: Enable 11ax HE */
	mwifiex_uap_set_11ax(handle, &fwi, is_5ghz);

	/* Step 9: Start BSS */
	memset(bss, 0, sizeof(*bss));
	memset(&req, 0, sizeof(req));

	req.req_id = MLAN_IOCTL_BSS;
	req.action = MLAN_ACT_SET;
	req.bss_index = 1;
	req.pbuf = (t_u8 *)bss;
	req.buf_len = sizeof(*bss);
	bss->sub_command = MLAN_OID_BSS_START;
	bss->param.host_based = 0;

	error = 0;
	if (mwifiex_do_ioctl(handle, &req) != MLAN_STATUS_SUCCESS) {
		device_printf(handle->sc->sc_dev,
		    "UAP BSS start failed\n");
		error = EIO;
	}

	free(bss, M_MWIFIEX);

	if (error)
		return (error);

	handle->uap_started = 1;

	/* Bring UAP interface up so RX packets are accepted */
	if (handle->priv[1] != NULL && handle->priv[1]->ifp != NULL) {
		struct mwifiex_priv *priv = handle->priv[1];
		priv->running = 1;
		if_setdrvflagbits(priv->ifp, IFF_DRV_RUNNING, 0);
		if_setdrvflagbits(priv->ifp, 0, IFF_DRV_OACTIVE);
	}

	device_printf(handle->sc->sc_dev,
	    "UAP started: SSID=\"%s\" ch=%d bw=%dMHz sec=%s\n",
	    handle->uap_ssid, ch, bw, sec);
	return (0);
}

static int
mwifiex_uap_stop(struct mwifiex_handle *handle)
{
	mlan_ioctl_req req;
	mlan_ds_bss *bss;

	if (!handle->uap_started)
		return (0);

	bss = malloc(sizeof(*bss), M_MWIFIEX, M_WAITOK | M_ZERO);

	memset(&req, 0, sizeof(req));
	req.req_id = MLAN_IOCTL_BSS;
	req.action = MLAN_ACT_SET;
	req.bss_index = 1;
	req.pbuf = (t_u8 *)bss;
	req.buf_len = sizeof(*bss);
	bss->sub_command = MLAN_OID_BSS_STOP;

	mwifiex_do_ioctl(handle, &req);
	handle->uap_started = 0;

	/* Mark UAP interface down */
	if (handle->priv[1] != NULL && handle->priv[1]->ifp != NULL) {
		handle->priv[1]->running = 0;
		if_setdrvflagbits(handle->priv[1]->ifp, 0, IFF_DRV_RUNNING);
	}

	free(bss, M_MWIFIEX);
	device_printf(handle->sc->sc_dev, "UAP stopped\n");
	return (0);
}

/* ----------------------------------------------------------------
 * UAP sysctl handlers
 * ---------------------------------------------------------------- */

static int
mwifiex_sysctl_uap_ssid(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	char buf[33];
	int error;

	strlcpy(buf, handle->uap_ssid, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error || req->newptr == NULL)
		return (error);
	strlcpy(handle->uap_ssid, buf, sizeof(handle->uap_ssid));
	return (0);
}

static int
mwifiex_sysctl_uap_passphrase(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	char buf[65];
	int error;

	strlcpy(buf, handle->uap_passphrase, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error || req->newptr == NULL)
		return (error);
	strlcpy(handle->uap_passphrase, buf,
	    sizeof(handle->uap_passphrase));
	return (0);
}

static int
mwifiex_sysctl_uap_channel(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	int val = handle->uap_channel;
	int error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	handle->uap_channel = val;
	return (0);
}

static int
mwifiex_sysctl_uap_max_sta(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	int val = handle->uap_max_sta;
	int error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	if (val < 1 || val > 32)
		return (EINVAL);
	handle->uap_max_sta = val;
	return (0);
}

static int
mwifiex_sysctl_uap_start(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	int val = handle->uap_started;
	int error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);

	if (val && !handle->uap_started)
		return (mwifiex_uap_start(handle));
	else if (!val && handle->uap_started)
		return (mwifiex_uap_stop(handle));

	return (0);
}

static int
mwifiex_sysctl_uap_bandwidth(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	int val = handle->uap_bandwidth;
	int error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	if (val != 20 && val != 40 && val != 80)
		return (EINVAL);
	handle->uap_bandwidth = val;
	return (0);
}

static int
mwifiex_sysctl_uap_security(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	char buf[16];
	int error;

	strlcpy(buf, handle->uap_security, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error || req->newptr == NULL)
		return (error);
	if (strcmp(buf, "open") != 0 && strcmp(buf, "wpa2") != 0 &&
	    strcmp(buf, "wpa3") != 0 && strcmp(buf, "wpa2wpa3") != 0)
		return (EINVAL);
	strlcpy(handle->uap_security, buf, sizeof(handle->uap_security));
	return (0);
}

static int
mwifiex_sysctl_uap_hidden(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	int val = handle->uap_hidden;
	int error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	if (val != 0 && val != 1)
		return (EINVAL);
	handle->uap_hidden = val;
	return (0);
}

static int
mwifiex_sysctl_uap_sta_list(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	mlan_ioctl_req req_ioctl;
	mlan_ds_get_info *info;
	mlan_ds_sta_list *sl;
	struct sbuf *sb;
	int error, i;

	if (!handle->uap_started)
		return (sysctl_handle_string(oidp, __DECONST(char *,
		    "(not started)"), 14, req));

	info = malloc(sizeof(*info), M_MWIFIEX, M_WAITOK | M_ZERO);

	memset(&req_ioctl, 0, sizeof(req_ioctl));
	req_ioctl.req_id = MLAN_IOCTL_GET_INFO;
	req_ioctl.action = MLAN_ACT_GET;
	req_ioctl.bss_index = 1;
	req_ioctl.pbuf = (t_u8 *)info;
	req_ioctl.buf_len = sizeof(*info);
	info->sub_command = MLAN_OID_UAP_STA_LIST;

	if (mwifiex_do_ioctl(handle, &req_ioctl) != MLAN_STATUS_SUCCESS) {
		free(info, M_MWIFIEX);
		return (sysctl_handle_string(oidp, __DECONST(char *,
		    "(query failed)"), 15, req));
	}

	sl = &info->param.sta_list;

	sb = sbuf_new_auto();
	for (i = 0; i < sl->sta_count; i++) {
		sbuf_printf(sb, "%02x:%02x:%02x:%02x:%02x:%02x rssi=%d\n",
		    sl->info[i].mac_address[0],
		    sl->info[i].mac_address[1],
		    sl->info[i].mac_address[2],
		    sl->info[i].mac_address[3],
		    sl->info[i].mac_address[4],
		    sl->info[i].mac_address[5],
		    (int)sl->info[i].rssi);
	}
	if (sl->sta_count == 0)
		sbuf_printf(sb, "(none)");
	sbuf_finish(sb);

	error = sysctl_handle_string(oidp, sbuf_data(sb),
	    sbuf_len(sb) + 1, req);
	sbuf_delete(sb);
	free(info, M_MWIFIEX);
	return (error);
}

static int
mwifiex_sysctl_uap_deauth(SYSCTL_HANDLER_ARGS)
{
	struct mwifiex_handle *handle = (struct mwifiex_handle *)arg1;
	mlan_ioctl_req req_ioctl;
	mlan_ds_bss *bss;
	char buf[18];	/* "xx:xx:xx:xx:xx:xx" + NUL */
	unsigned int mac[6];
	int error, i;

	buf[0] = '\0';
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error || req->newptr == NULL)
		return (error);

	if (!handle->uap_started)
		return (ENXIO);

	if (sscanf(buf, "%x:%x:%x:%x:%x:%x",
	    &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
		return (EINVAL);

	bss = malloc(sizeof(*bss), M_MWIFIEX, M_WAITOK | M_ZERO);

	memset(&req_ioctl, 0, sizeof(req_ioctl));
	req_ioctl.req_id = MLAN_IOCTL_BSS;
	req_ioctl.action = MLAN_ACT_SET;
	req_ioctl.bss_index = 1;
	req_ioctl.pbuf = (t_u8 *)bss;
	req_ioctl.buf_len = sizeof(*bss);
	bss->sub_command = MLAN_OID_UAP_DEAUTH_STA;

	for (i = 0; i < 6; i++)
		bss->param.deauth_param.mac_addr[i] = (t_u8)mac[i];
	bss->param.deauth_param.reason_code = 3;	/* LEAVING */

	error = 0;
	if (mwifiex_do_ioctl(handle, &req_ioctl) != MLAN_STATUS_SUCCESS)
		error = EIO;

	free(bss, M_MWIFIEX);

	if (error == 0)
		device_printf(handle->sc->sc_dev,
		    "deauthed station %s\n", buf);
	return (error);
}

static const char *
mwifiex_rev_string(uint8_t rev)
{
	switch (rev) {
	case MWIFIEX_REV_Z1Z2:	return "Z1/Z2";
	case MWIFIEX_REV_A0:	return "A0";
	case MWIFIEX_REV_A1:	return "A1";
	case MWIFIEX_REV_A2:	return "A2";
	default:		return "unknown";
	}
}

static int
mwifiex_probe(device_t dev)
{
	uint16_t vendor, device;

	vendor = pci_get_vendor(dev);
	device = pci_get_device(dev);

	if (vendor != MWIFIEX_VENDOR_ID)
		return (ENXIO);

	switch (device) {
	case MWIFIEX_9098_FN0:
		device_set_desc(dev, "NXP 88W9098 PCIe WiFi");
		return (BUS_PROBE_DEFAULT);
	case MWIFIEX_9098_FN1:
		device_set_desc(dev, "NXP 88W9098 PCIe Bluetooth");
		return (BUS_PROBE_DEFAULT);
	default:
		return (ENXIO);
	}
}

/*
 * Initialize mlan: register adapter, load firmware, download to chip.
 * Returns 0 on success, error code on failure.
 */
static int
mwifiex_init_mlan(struct mwifiex_softc *sc)
{
	struct mwifiex_handle *handle = sc->sc_handle;
	mlan_device mdev;
	mlan_fw_image fw;
	mlan_status status;

	memset(&mdev, 0, sizeof(mdev));
	mdev.pmoal_handle = handle;
	mdev.card_type = CARD_TYPE_PCIE9098;

	/* BSS attributes: one STA + one UAP */
	mdev.bss_attr[0].bss_type = MLAN_BSS_TYPE_STA;
	mdev.bss_attr[0].frame_type = MLAN_DATA_FRAME_TYPE_ETH_II;
	mdev.bss_attr[0].active = MTRUE;
	mdev.bss_attr[0].bss_priority = 0;
	mdev.bss_attr[0].bss_num = 0;

	mdev.bss_attr[1].bss_type = MLAN_BSS_TYPE_UAP;
	mdev.bss_attr[1].frame_type = MLAN_DATA_FRAME_TYPE_ETH_II;
	mdev.bss_attr[1].active = MTRUE;
	mdev.bss_attr[1].bss_priority = 0;
	mdev.bss_attr[1].bss_num = 0;

	/* Fill the callback table */
	mwifiex_fill_callbacks(&mdev.callbacks);

	/* Feature control */
	mdev.feature_control = FEATURE_CTRL_DEFAULT;

	/* Enable PRINTM debug output: MMSG|MFATAL|MERROR|MCMND|MEVENT */
	mdev.drvdbg = MMSG | MFATAL | MERROR | MCMND | MEVENT;

	/* Register with mlan */
	device_printf(sc->sc_dev, "registering with mlan...\n");
	status = mlan_register(&mdev, &handle->pmlan_adapter);
	if (status != MLAN_STATUS_SUCCESS) {
		device_printf(sc->sc_dev,
		    "mlan_register failed (status=%d)\n", status);
		return (ENXIO);
	}

	/* Tell mlan our interrupt mode */
	mlan_set_int_mode(handle->pmlan_adapter,
	    sc->sc_irq_rid == 1 ? PCIE_INT_MODE_MSI :
	    PCIE_INT_MODE_LEGACY, 0);

	/* Load firmware image via firmware(9) */
	handle->fw_image = firmware_get("mwifiex_9098_pcie_fw");
	if (handle->fw_image == NULL) {
		device_printf(sc->sc_dev,
		    "firmware_get(mwifiex_9098_pcie_fw) failed — "
		    "is mwifiex_9098_pcie_fw.ko loaded?\n");
		mlan_unregister(handle->pmlan_adapter);
		handle->pmlan_adapter = NULL;
		return (ENOENT);
	}
	handle->fw_len = handle->fw_image->datasize;
	device_printf(sc->sc_dev, "firmware loaded: %u bytes\n",
	    handle->fw_len);

	/* Download firmware to chip */
	memset(&fw, 0, sizeof(fw));
	fw.pfw_buf = __DECONST(t_u8 *, handle->fw_image->data);
	fw.fw_len = handle->fw_len;

	device_printf(sc->sc_dev, "downloading firmware to chip...\n");
	status = mlan_dnld_fw(handle->pmlan_adapter, &fw);
	if (status != MLAN_STATUS_SUCCESS &&
	    status != MLAN_STATUS_PENDING) {
		device_printf(sc->sc_dev,
		    "mlan_dnld_fw failed (status=%d)\n", status);
		firmware_put(handle->fw_image, FIRMWARE_UNLOAD);
		handle->fw_image = NULL;
		mlan_unregister(handle->pmlan_adapter);
		handle->pmlan_adapter = NULL;
		return (EIO);
	}

	/* Initialize firmware (sends GET_HW_SPEC, waits for FW ready) */
	device_printf(sc->sc_dev, "initializing firmware...\n");
	status = mlan_init_fw(handle->pmlan_adapter);
	if (status == MLAN_STATUS_PENDING) {
		/*
		 * FW init is async — driven by interrupts calling
		 * mlan_main_process().  Poll here with a timeout
		 * to wait for completion during attach.
		 */
		int tries;
		for (tries = 0; tries < 100; tries++) {
			mlan_main_process(handle->pmlan_adapter);
			if (handle->fw_ready)
				break;
			DELAY(50000);	/* 50ms */
		}
		if (!handle->fw_ready) {
			device_printf(sc->sc_dev,
			    "firmware init timed out\n");
			return (EIO);
		}
	} else if (status != MLAN_STATUS_SUCCESS) {
		device_printf(sc->sc_dev,
		    "mlan_init_fw failed (status=%d)\n", status);
		firmware_put(handle->fw_image, FIRMWARE_UNLOAD);
		handle->fw_image = NULL;
		mlan_unregister(handle->pmlan_adapter);
		handle->pmlan_adapter = NULL;
		return (EIO);
	}

	return (0);
}

static int
mwifiex_attach(device_t dev)
{
	struct mwifiex_softc *sc;
	struct mwifiex_handle *handle;
	uint32_t reg;
	int msi_count, error;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	sc->sc_device_id = pci_get_device(dev);
	sc->sc_is_fn0 = (sc->sc_device_id == MWIFIEX_9098_FN0);

	/* Enable bus mastering for DMA */
	pci_enable_busmaster(dev);

	/* Map BAR 0 */
	sc->sc_bar0_rid = PCIR_BAR(0);
	sc->sc_bar0 = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &sc->sc_bar0_rid, RF_ACTIVE);
	if (sc->sc_bar0 == NULL) {
		device_printf(dev, "failed to map BAR 0\n");
		error = ENXIO;
		goto fail;
	}
	sc->sc_bar0_bt = rman_get_bustag(sc->sc_bar0);
	sc->sc_bar0_bh = rman_get_bushandle(sc->sc_bar0);

	/* Map BAR 2 */
	sc->sc_bar2_rid = PCIR_BAR(2);
	sc->sc_bar2 = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &sc->sc_bar2_rid, RF_ACTIVE);
	if (sc->sc_bar2 == NULL) {
		device_printf(dev, "failed to map BAR 2\n");
		error = ENXIO;
		goto fail;
	}
	sc->sc_bar2_bt = rman_get_bustag(sc->sc_bar2);
	sc->sc_bar2_bh = rman_get_bushandle(sc->sc_bar2);

	/* Allocate MSI interrupt */
	msi_count = 1;
	if (pci_alloc_msi(dev, &msi_count) != 0) {
		device_printf(dev, "MSI allocation failed, using legacy IRQ\n");
		sc->sc_irq_rid = 0;
	} else {
		sc->sc_irq_rid = 1;
	}
	sc->sc_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ,
	    &sc->sc_irq_rid, RF_ACTIVE | RF_SHAREABLE);
	if (sc->sc_irq == NULL) {
		device_printf(dev, "failed to allocate IRQ\n");
		error = ENXIO;
		goto fail;
	}

	/* Read chip info (FN0 only — FN1/BT has no scratch registers) */
	if (sc->sc_is_fn0) {
		reg = MWIFIEX_READ_4(sc, PCIE9098_REV_ID_REG);
		sc->sc_revision = reg & 0xff;

		reg = MWIFIEX_READ_4(sc, PCIE9098_HOST_STRAP_REG);
		sc->sc_strap = reg & 0x7;

		reg = MWIFIEX_READ_4(sc, PCIE9098_MAGIC_REG);
		sc->sc_magic = reg & 0xff;

		device_printf(dev,
		    "88W9098 rev %s (0x%02x), strap=0x%x, magic=0x%02x\n",
		    mwifiex_rev_string(sc->sc_revision), sc->sc_revision,
		    sc->sc_strap, sc->sc_magic);

		/* Allocate and initialize MOAL handle */
		handle = malloc(sizeof(*handle), M_MWIFIEX,
		    M_WAITOK | M_ZERO);
		handle->sc = sc;
		handle->card_type = CARD_TYPE_PCIE9098;
		SLIST_INIT(&handle->dma_allocs);
		mtx_init(&handle->dma_list_mtx, "mwifiex_dma", NULL, MTX_DEF);

		/* Create parent DMA tag */
		error = bus_dma_tag_create(
		    bus_get_dma_tag(dev),	/* parent */
		    1, 0,			/* alignment, boundary */
		    BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
		    BUS_SPACE_MAXADDR,		/* highaddr */
		    NULL, NULL,			/* filter */
		    BUS_SPACE_MAXSIZE_32BIT,	/* maxsize */
		    1,				/* nsegments */
		    BUS_SPACE_MAXSIZE_32BIT,	/* maxsegsz */
		    0, NULL, NULL,		/* flags */
		    &handle->dma_tag);
		if (error) {
			device_printf(dev, "failed to create DMA tag: %d\n",
			    error);
			mtx_destroy(&handle->dma_list_mtx);
			free(handle, M_MWIFIEX);
			goto fail;
		}

		sc->sc_handle = handle;

		/* Set up deferred processing tasks */
		TASK_INIT(&handle->main_task, 0, mwifiex_main_task,
		    handle);
		TASK_INIT(&handle->cmdresp_task, 0, mwifiex_cmdresp_task,
		    handle);
		TASK_INIT(&handle->rx_task, 0, mwifiex_rx_task,
		    handle);
		TASK_INIT(&handle->txcmpl_task, 0, mwifiex_txcmpl_task,
		    handle);
		error = bus_setup_intr(dev, sc->sc_irq,
		    INTR_TYPE_NET | INTR_MPSAFE, mwifiex_intr, NULL,
		    sc, &sc->sc_irq_cookie);
		if (error) {
			device_printf(dev,
			    "failed to setup interrupt: %d\n", error);
			goto fail;
		}

		/* Initialize mlan + download firmware */
		error = mwifiex_init_mlan(sc);
		if (error) {
			device_printf(dev,
			    "mlan initialization failed: %d\n", error);
			/* Non-fatal — let driver attach for debugging */
		} else {
			/* Create network interfaces */
			mwifiex_create_iface(sc, 0, MLAN_BSS_TYPE_STA);
			mwifiex_create_iface(sc, 1, MLAN_BSS_TYPE_UAP);

			/* Register UAP sysctls */
			{
				struct sysctl_ctx_list *ctx;
				struct sysctl_oid *tree;

				ctx = device_get_sysctl_ctx(dev);
				tree = device_get_sysctl_tree(dev);

				handle->uap_channel = 36;
				handle->uap_max_sta = 10;
				handle->uap_bandwidth = 80;
				strlcpy(handle->uap_security, "wpa2",
				    sizeof(handle->uap_security));

				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_ssid",
				    CTLTYPE_STRING | CTLFLAG_RW |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_ssid, "A",
				    "UAP SSID");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_passphrase",
				    CTLTYPE_STRING | CTLFLAG_RW |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_passphrase, "A",
				    "UAP WPA2 passphrase");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_channel",
				    CTLTYPE_INT | CTLFLAG_RW |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_channel, "I",
				    "UAP channel (0=default 6)");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_max_sta",
				    CTLTYPE_INT | CTLFLAG_RW |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_max_sta, "I",
				    "UAP max stations (1-32)");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_bandwidth",
				    CTLTYPE_INT | CTLFLAG_RW |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_bandwidth, "I",
				    "UAP channel width (20, 40, 80 MHz)");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_security",
				    CTLTYPE_STRING | CTLFLAG_RW |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_security, "A",
				    "UAP security (open/wpa2/wpa3/wpa2wpa3)");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_hidden",
				    CTLTYPE_INT | CTLFLAG_RW |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_hidden, "I",
				    "UAP hidden SSID (0=broadcast, 1=hidden)");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_sta_list",
				    CTLTYPE_STRING | CTLFLAG_RD |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_sta_list, "A",
				    "UAP connected station list");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_deauth",
				    CTLTYPE_STRING | CTLFLAG_WR |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_deauth, "A",
				    "Deauth station (write MAC address)");
				SYSCTL_ADD_PROC(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "uap_start",
				    CTLTYPE_INT | CTLFLAG_RW |
				    CTLFLAG_MPSAFE,
				    handle, 0,
				    mwifiex_sysctl_uap_start, "I",
				    "Write 1 to start UAP, 0 to stop");
				SYSCTL_ADD_INT(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "tx_pending_limit", CTLFLAG_RW,
				    &handle->priv[1]->tx_pending_limit,
				    0,
				    "TX pending high watermark");
				SYSCTL_ADD_INT(ctx,
				    SYSCTL_CHILDREN(tree), OID_AUTO,
				    "debug", CTLFLAG_RW,
				    &handle->debug, 0,
				    "Debug print level (0=errors only, 1=all)");
			}
		}
	} else {
		device_printf(dev, "88W9098 BT function (skipping)\n");
	}

	return (0);

fail:
	mwifiex_detach(dev);
	return (error);
}

static int
mwifiex_detach(device_t dev)
{
	struct mwifiex_softc *sc;
	struct mwifiex_handle *handle;
	struct mwifiex_dma_alloc *da;

	sc = device_get_softc(dev);
	handle = sc->sc_handle;

	if (handle != NULL) {
		/* Stop UAP while interrupts still work */
		if (handle->uap_started)
			mwifiex_uap_stop(handle);

		handle->surprise_removed = 1;

		/* Destroy network interfaces */
		mwifiex_destroy_ifaces(handle);

		if (handle->pmlan_adapter != NULL) {
			mlan_shutdown_fw(handle->pmlan_adapter);
			mlan_unregister(handle->pmlan_adapter);
			handle->pmlan_adapter = NULL;
		}

		if (handle->fw_image != NULL) {
			firmware_put(handle->fw_image, FIRMWARE_UNLOAD);
			handle->fw_image = NULL;
		}

		/* Free any remaining DMA allocations */
		while (!SLIST_EMPTY(&handle->dma_allocs)) {
			da = SLIST_FIRST(&handle->dma_allocs);
			SLIST_REMOVE_HEAD(&handle->dma_allocs, link);
			bus_dmamap_unload(da->tag, da->map);
			bus_dmamem_free(da->tag, da->vaddr, da->map);
			bus_dma_tag_destroy(da->tag);
			free(da, M_MWIFIEX);
		}

		if (handle->dma_tag != NULL)
			bus_dma_tag_destroy(handle->dma_tag);

		mtx_destroy(&handle->dma_list_mtx);
		free(handle, M_MWIFIEX);
		sc->sc_handle = NULL;
	}

	if (sc->sc_irq_cookie != NULL)
		bus_teardown_intr(dev, sc->sc_irq, sc->sc_irq_cookie);
	if (sc->sc_irq != NULL)
		bus_release_resource(dev, SYS_RES_IRQ, sc->sc_irq_rid,
		    sc->sc_irq);
	if (sc->sc_irq_rid == 1)
		pci_release_msi(dev);
	if (sc->sc_bar2 != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->sc_bar2_rid,
		    sc->sc_bar2);
	if (sc->sc_bar0 != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->sc_bar0_rid,
		    sc->sc_bar0);

	return (0);
}

static device_method_t mwifiex_methods[] = {
	DEVMETHOD(device_probe,		mwifiex_probe),
	DEVMETHOD(device_attach,	mwifiex_attach),
	DEVMETHOD(device_detach,	mwifiex_detach),
	DEVMETHOD_END
};

DEFINE_CLASS_0(mwifiex, mwifiex_driver, mwifiex_methods,
    sizeof(struct mwifiex_softc));

DRIVER_MODULE(mwifiex, pci, mwifiex_driver, NULL, NULL);
MODULE_DEPEND(mwifiex, pci, 1, 1, 1);
MODULE_DEPEND(mwifiex, firmware, 1, 1, 1);
MODULE_VERSION(mwifiex, 1);
