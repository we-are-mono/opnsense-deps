/*
 * cdx_qos_freebsd.c — CDX QoS policer profile management for FreeBSD
 *
 * Ports QoS policer profiles from Linux cdx_qos.c + dpa_cfg.c:
 *
 * 1. Fast-forward policer: PORT_PRIVATE profiles per-dtsec port that
 *    rate-limit traffic routed through the FMan policer engine by the
 *    CDX soft parser ($nia = NIA_ENG_PLCR for TCP/UDP/ESP/PPPoE).
 *
 * 2. Exception traffic policer: SHARED profiles for miss/exception
 *    traffic to the control plane (frames that miss the EHASH table).
 *
 * 3. Ingress QoS policer: SHARED profiles for per-queue rate limiting
 *    of offloaded flows.  Profile IDs are embedded into EHASH entries.
 *
 * All use NCSW FM_PCD_PlcrProfileSet() / FM_PCD_PlcrProfileGetCounter().
 *
 * Copyright 2020-2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>

#include "portdefs.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "module_qm.h"
#include "cdx_dpa_bridge.h"

#include <contrib/ncsw/inc/Peripherals/fm_pcd_ext.h>
#include <contrib/ncsw/inc/Peripherals/fm_port_ext.h>
#include <contrib/ncsw/Peripherals/FM/inc/fm_common.h>
#include <dev/dpaa/if_dtsec.h>

/* Declared in cdx_devman_freebsd.c */
extern struct dpa_iface_info *dpa_get_iface_by_name(char *name);

/* Declared in cdx_dpa_bridge.c */
extern struct cdx_fman_info *fman_info;
extern uint32_t cdx_num_fmans;

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/* Per-port fast-forward policer profile state */
struct port_ff_rate_lim_info {
	void		*handle;	/* FM_PCD_PlcrProfileSet result */
	t_Handle	h_FmPcd;	/* PCD handle used for modify */
	uint32_t	cir_value;	/* committed info rate (pps) */
	uint32_t	pir_value;	/* peak info rate (pps) */
};

#define	MAX_PHYS_PORTS			64
/* Default rate limits — packet mode (packets per second) */
#define	DEFAULT_PORT_FF_CIR_VALUE_1G	4000000
#define	DEFAULT_PORT_FF_PIR_VALUE_1G	4000000
#define	DEFAULT_PORT_FF_CIR_VALUE_10G	2000000
#define	DEFAULT_PORT_FF_PIR_VALUE_10G	12000000
#define	DEFAULT_1G_PORT_FF_CBS		1
#define	DEFAULT_1G_PORT_FF_PBS		1
#define	DEFAULT_10G_PORT_FF_CBS		3
#define	DEFAULT_10G_PORT_FF_PBS		3

static struct port_ff_rate_lim_info port_rate_lim_mode[MAX_PHYS_PORTS];

/*
 * cdx_qos_add_ff_profile — Create a port-private policer profile.
 *
 * This is the core function ported from Linux dpa_add_port_ff_policier_profile().
 * Creates a PORT_PRIVATE profile with relativeProfileId=0 for the given
 * RX port.  On green/yellow: re-enter PCD via PRS (NIA -> KG -> CC).
 * On red: drop.
 */
static int
cdx_qos_add_ff_profile(uint8_t eth_id, t_Handle rx_port_handle,
    t_Handle h_FmPcd, bool is_10g)
{
	t_FmPcdPlcrProfileParams params;
	void *handle;
	uint32_t cir, pir, cbs, pbs;

	if (eth_id >= MAX_PHYS_PORTS) {
		printf("cdx: qos: eth_id %u out of range\n", eth_id);
		return (-1);
	}

	/* Select defaults based on port speed */
	if (is_10g) {
		cir = DEFAULT_PORT_FF_CIR_VALUE_10G;
		pir = DEFAULT_PORT_FF_PIR_VALUE_10G;
		cbs = DEFAULT_10G_PORT_FF_CBS;
		pbs = DEFAULT_10G_PORT_FF_PBS;
	} else {
		cir = DEFAULT_PORT_FF_CIR_VALUE_1G;
		pir = DEFAULT_PORT_FF_PIR_VALUE_1G;
		cbs = DEFAULT_1G_PORT_FF_CBS;
		pbs = DEFAULT_1G_PORT_FF_PBS;
	}

	memset(&params, 0, sizeof(params));
	params.id.newParams.profileType = e_FM_PCD_PLCR_PORT_PRIVATE;
	params.id.newParams.h_FmPort = rx_port_handle;
	params.id.newParams.relativeProfileId = 0;
	params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	params.color.dfltColor = e_FM_PCD_PLCR_RED;
	params.color.override = e_FM_PCD_PLCR_RED;

	/* Packet mode rate limiting */
	params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
	params.nonPassthroughAlgParams.committedInfoRate = cir;
	params.nonPassthroughAlgParams.peakOrExcessInfoRate = pir;
	params.nonPassthroughAlgParams.committedBurstSize = cbs;
	params.nonPassthroughAlgParams.peakOrExcessBurstSize = pbs;

	/*
	 * Green/Yellow: re-enter PCD from KG engine.
	 * e_FM_PCD_PRS sets NIA to 0x00480200 (KG engine entry point).
	 * This chains: PLCR -> KG -> CC (hash table lookup) -> offload/host.
	 *
	 * Red: drop the frame.
	 */
	params.nextEngineOnGreen = e_FM_PCD_PRS;
	params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
	params.nextEngineOnYellow = e_FM_PCD_PRS;
	params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
	params.nextEngineOnRed = e_FM_PCD_DONE;
	params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;

	handle = FM_PCD_PlcrProfileSet(h_FmPcd, &params);
	if (handle == NULL) {
		printf("cdx: qos: FM_PCD_PlcrProfileSet failed for eth_id %u\n",
		    eth_id);
		return (-1);
	}

	port_rate_lim_mode[eth_id].handle = handle;
	port_rate_lim_mode[eth_id].h_FmPcd = h_FmPcd;
	port_rate_lim_mode[eth_id].cir_value = cir;
	port_rate_lim_mode[eth_id].pir_value = pir;

	printf("cdx: qos: plcr profile for eth_id %u — handle=%p %s "
	    "cir=%u pir=%u\n",
	    eth_id, handle, is_10g ? "10G" : "1G", cir, pir);

	return (0);
}

/*
 * cdx_qos_init_ff_profiles — Create fast-forward policer profiles
 * for all dtsec interfaces.
 *
 * Called during CDX module init, after cdx_dpa_bridge_init() has
 * populated fman_info and before dpa_app calls FM_PORT_SetPCD().
 * The kernel's dtsec_rm_fm_port_rx_init() already called
 * FM_PORT_PcdPlcrAllocProfiles(rxph, 1) at boot time.
 */
int
cdx_qos_init_ff_profiles(void)
{
	devclass_t dc;
	device_t *devlist;
	int count, i, configured;

	dc = devclass_find("dtsec");
	if (dc == NULL) {
		printf("cdx: qos: dtsec devclass not found\n");
		return (-1);
	}

	if (devclass_get_devices(dc, &devlist, &count) != 0) {
		printf("cdx: qos: failed to enumerate dtsec devices\n");
		return (-1);
	}

	configured = 0;
	for (i = 0; i < count; i++) {
		struct dtsec_softc *sc;
		t_Handle pcd_handle;
		bool is_10g;

		sc = device_get_softc(devlist[i]);
		if (sc == NULL || sc->sc_rxph == NULL)
			continue;

		/* Skip hidden (internally-used) interfaces */
		if (sc->sc_hidden)
			continue;

		pcd_handle = cdx_dpa_bridge_get_pcd_handle();
		if (pcd_handle == NULL) {
			printf("cdx: qos: no PCD handle available\n");
			break;
		}

		is_10g = (sc->sc_eth_dev_type == ETH_10GSEC);

		if (cdx_qos_add_ff_profile(sc->sc_eth_id,
		    sc->sc_rxph, pcd_handle, is_10g) == 0)
			configured++;
	}

	free(devlist, M_TEMP);
	printf("cdx: qos: configured %d fast-forward policer profile(s)\n",
	    configured);
	return (0);
}

/*
 * cdx_qos_cleanup_ff_profiles — Delete all fast-forward profiles.
 * Called during CDX module unload.
 */
void
cdx_qos_cleanup_ff_profiles(void)
{
	int i;

	for (i = 0; i < MAX_PHYS_PORTS; i++) {
		if (port_rate_lim_mode[i].handle != NULL) {
			FM_PCD_PlcrProfileDelete(
			    port_rate_lim_mode[i].handle);
			port_rate_lim_mode[i].handle = NULL;
		}
	}
}

/*
 * cdx_set_ff_rate — Modify per-port fast-forward rate limits.
 *
 * Called from control_qm.c QM_QOS_SET_FF_RATE handler.
 * Replaces the stub in cdx_dpa_stub.c.
 */
int
cdx_set_ff_rate(char *ifname, uint32_t cir, uint32_t pir)
{
	struct dpa_iface_info *iface_info;
	int hardwarePortId;
	t_FmPcdPlcrProfileParams params;
	void *handle;
	uint32_t cbs, pbs;

	iface_info = dpa_get_iface_by_name(ifname);
	if (iface_info == NULL) {
		DPA_ERROR("%s: invalid interface <%s>\n", __func__, ifname);
		return (-1);
	}
	if (!(iface_info->if_flags & IF_TYPE_ETHERNET)) {
		DPA_ERROR("%s: %s is not ethernet (0x%x)\n",
		    __func__, ifname, iface_info->if_flags);
		return (-1);
	}

	hardwarePortId = iface_info->eth_info.hardwarePortId;
	if (hardwarePortId < 0 || hardwarePortId >= MAX_PHYS_PORTS)
		return (-1);
	if (port_rate_lim_mode[hardwarePortId].handle == NULL)
		return (-1);

	/* Select burst sizes based on port speed */
	if (iface_info->eth_info.speed == PORT_10G_SPEED) {
		cbs = DEFAULT_10G_PORT_FF_CBS;
		pbs = DEFAULT_10G_PORT_FF_PBS;
	} else {
		cbs = DEFAULT_1G_PORT_FF_CBS;
		pbs = DEFAULT_1G_PORT_FF_PBS;
	}

	memset(&params, 0, sizeof(params));
	params.modify = 1;
	params.id.h_Profile = port_rate_lim_mode[hardwarePortId].handle;
	params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	params.color.dfltColor = e_FM_PCD_PLCR_RED;
	params.color.override = e_FM_PCD_PLCR_RED;
	params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
	params.nonPassthroughAlgParams.committedInfoRate = cir;
	params.nonPassthroughAlgParams.peakOrExcessInfoRate = pir;
	params.nonPassthroughAlgParams.committedBurstSize = cbs;
	params.nonPassthroughAlgParams.peakOrExcessBurstSize = pbs;
	params.nextEngineOnGreen = e_FM_PCD_PRS;
	params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
	params.nextEngineOnYellow = e_FM_PCD_PRS;
	params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
	params.nextEngineOnRed = e_FM_PCD_DONE;
	params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;

	handle = FM_PCD_PlcrProfileSet(
	    port_rate_lim_mode[hardwarePortId].h_FmPcd, &params);
	if (handle == NULL) {
		DPA_ERROR("%s: unable to modify profile for port %d\n",
		    __func__, hardwarePortId);
		return (-1);
	}

	port_rate_lim_mode[hardwarePortId].cir_value = cir;
	port_rate_lim_mode[hardwarePortId].pir_value = pir;
	return (0);
}

/*
 * cdx_get_ff_rate — Query per-port fast-forward rate limits and counters.
 *
 * Called from control_qm.c QM_QOS_GET_FF_RATE handler.
 * Replaces the stub in cdx_dpa_stub.c.
 */
int
cdx_get_ff_rate(void *pcmd)
{
	PQosFFRateCommand cmd;
	struct dpa_iface_info *iface_info;
	int hardwarePortId;
	void *handle;

	cmd = (PQosFFRateCommand)pcmd;

	iface_info = dpa_get_iface_by_name(cmd->interface);
	if (iface_info == NULL)
		return (-1);
	if (!(iface_info->if_flags & IF_TYPE_ETHERNET))
		return (-1);

	hardwarePortId = iface_info->eth_info.hardwarePortId;
	if (hardwarePortId < 0 || hardwarePortId >= MAX_PHYS_PORTS)
		return (-1);

	handle = port_rate_lim_mode[hardwarePortId].handle;
	if (handle == NULL)
		return (-1);

	cmd->cir = port_rate_lim_mode[hardwarePortId].cir_value;
	cmd->pir = port_rate_lim_mode[hardwarePortId].pir_value;
	get_plcr_counter(handle, &cmd->counterval[0], cmd->clear);

	return (0);
}

/*
 * get_plcr_counter — Read policer profile counters.
 *
 * Reads red/yellow/green/recolored packet counters from the PLCR HW.
 * Replaces the stub in cdx_dpa_stub.c.
 */
void
get_plcr_counter(void *handle, uint32_t *counterval, uint32_t clear)
{
	uint32_t ii;
	uint32_t counter_id;

	for (ii = 0; ii < MAX_RATLIM_CNTR; ii++) {
		switch (ii) {
		case RED_TOTAL:
			counter_id =
			    e_FM_PCD_PLCR_PROFILE_RED_PACKET_TOTAL_COUNTER;
			break;
		case YELLOW_TOTAL:
			counter_id =
			    e_FM_PCD_PLCR_PROFILE_YELLOW_PACKET_TOTAL_COUNTER;
			break;
		case GREEN_TOTAL:
			counter_id =
			    e_FM_PCD_PLCR_PROFILE_GREEN_PACKET_TOTAL_COUNTER;
			break;
		case RED_RECOLORED:
			counter_id =
			    e_FM_PCD_PLCR_PROFILE_RECOLOURED_RED_PACKET_TOTAL_COUNTER;
			break;
		case YELLOW_RECOLORED:
			counter_id =
			    e_FM_PCD_PLCR_PROFILE_RECOLOURED_YELLOW_PACKET_TOTAL_COUNTER;
			break;
		default:
			return;
		}
		*(counterval + ii) =
		    FM_PCD_PlcrProfileGetCounter(handle, counter_id);
		if (clear)
			FM_PCD_PlcrProfileSetCounter(handle, counter_id, 0);
	}
}

/* ================================================================
 * Exception traffic rate limiting — SHARED policer profiles
 *
 * Controls the rate at which miss/exception traffic reaches the
 * host CPU.  One profile per CDX_EXPT_MAX_EXPT_LIMIT_TYPES type.
 * Called from control_qm.c CMD_QM_EXPT_RATE / CMD_QM_QUERY_EXPT_RATE.
 *
 * Ported from cdx_qos.c:106-223 + dpa_cfg.c:374-394.
 * ================================================================ */

/*
 * cdxdrv_modify_missaction_policer_profile — Modify an existing
 * shared policer profile for exception traffic.
 */
int
cdxdrv_modify_missaction_policer_profile(struct cdx_fman_info *finfo,
    uint32_t type)
{
	t_FmPcdPlcrProfileParams params;
	void *handle;

	if (type >= CDX_EXPT_MAX_EXPT_LIMIT_TYPES)
		return (-1);
	if (finfo->expt_rate_limit_info[type].limit == DISABLE_EXPT_PROFILE)
		return (-1);

	memset(&params, 0, sizeof(params));
	params.modify = 1;
	params.id.h_Profile = finfo->expt_rate_limit_info[type].handle;
	params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	params.color.dfltColor = e_FM_PCD_PLCR_RED;
	params.color.override = e_FM_PCD_PLCR_RED;

	if (finfo->expt_ratelim_mode == EXPT_PKT_LIM_PLCR_MODE_BYTE) {
		params.nonPassthroughAlgParams.rateMode =
		    e_FM_PCD_PLCR_BYTE_MODE;
		params.nonPassthroughAlgParams.committedInfoRate =
		    finfo->expt_rate_limit_info[type].limit;
		params.nonPassthroughAlgParams.committedBurstSize =
		    finfo->expt_ratelim_burst_size;
		params.nonPassthroughAlgParams.peakOrExcessInfoRate =
		    finfo->expt_rate_limit_info[type].limit;
		params.nonPassthroughAlgParams.peakOrExcessBurstSize =
		    finfo->expt_ratelim_burst_size;
		params.nonPassthroughAlgParams.byteModeParams
		    .frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
		params.nonPassthroughAlgParams.byteModeParams
		    .rollBackFrameSelection =
		    e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
	} else {
		params.nonPassthroughAlgParams.rateMode =
		    e_FM_PCD_PLCR_PACKET_MODE;
		params.nonPassthroughAlgParams.committedInfoRate =
		    finfo->expt_rate_limit_info[type].limit;
		params.nonPassthroughAlgParams.committedBurstSize =
		    finfo->expt_ratelim_burst_size;
		params.nonPassthroughAlgParams.peakOrExcessInfoRate =
		    finfo->expt_rate_limit_info[type].limit;
		params.nonPassthroughAlgParams.peakOrExcessBurstSize =
		    finfo->expt_ratelim_burst_size;
	}

	/* Green/Yellow: enqueue to host, Red: drop */
	params.nextEngineOnGreen = e_FM_PCD_DONE;
	params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
	params.nextEngineOnYellow = e_FM_PCD_DONE;
	params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
	params.nextEngineOnRed = e_FM_PCD_DONE;
	params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;

	handle = FM_PCD_PlcrProfileSet(finfo->pcd_handle, &params);
	if (handle == NULL) {
		DPA_ERROR("%s: unable to modify profile for type %u\n",
		    __func__, type);
		return (-1);
	}

	return (0);
}

/*
 * cdxdrv_create_missaction_policer_profiles — Create shared policer
 * profiles for all exception traffic types during init.
 *
 * Called from cdx_qos_init_expt_profiles() after fman_info is populated.
 */
int
cdxdrv_create_missaction_policer_profiles(struct cdx_fman_info *finfo)
{
	t_Handle h_FmPcd;
	t_FmPcdPlcrProfileParams params;
	void *handle;
	uint32_t ii, created = 0;

	h_FmPcd = finfo->pcd_handle;

	for (ii = 0; ii < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; ii++) {
		if (finfo->expt_rate_limit_info[ii].limit ==
		    DISABLE_EXPT_PROFILE) {
			finfo->expt_rate_limit_info[ii].handle = NULL;
			continue;
		}

		memset(&params, 0, sizeof(params));
		params.id.newParams.profileType = e_FM_PCD_PLCR_SHARED;
		params.id.newParams.relativeProfileId = ii;
		params.algSelection = e_FM_PCD_PLCR_RFC_2698;
		params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
		params.color.dfltColor = e_FM_PCD_PLCR_RED;
		params.color.override = e_FM_PCD_PLCR_RED;

		if (finfo->expt_ratelim_mode ==
		    EXPT_PKT_LIM_PLCR_MODE_BYTE) {
			params.nonPassthroughAlgParams.rateMode =
			    e_FM_PCD_PLCR_BYTE_MODE;
			params.nonPassthroughAlgParams.committedInfoRate =
			    finfo->expt_rate_limit_info[ii].limit;
			params.nonPassthroughAlgParams.committedBurstSize =
			    finfo->expt_ratelim_burst_size;
			params.nonPassthroughAlgParams.peakOrExcessInfoRate =
			    finfo->expt_rate_limit_info[ii].limit;
			params.nonPassthroughAlgParams
			    .peakOrExcessBurstSize =
			    finfo->expt_ratelim_burst_size;
			params.nonPassthroughAlgParams.byteModeParams
			    .frameLengthSelection =
			    e_FM_PCD_PLCR_FULL_FRM_LEN;
			params.nonPassthroughAlgParams.byteModeParams
			    .rollBackFrameSelection =
			    e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
		} else {
			params.nonPassthroughAlgParams.rateMode =
			    e_FM_PCD_PLCR_PACKET_MODE;
			params.nonPassthroughAlgParams.committedInfoRate =
			    finfo->expt_rate_limit_info[ii].limit;
			params.nonPassthroughAlgParams.committedBurstSize =
			    finfo->expt_ratelim_burst_size;
			params.nonPassthroughAlgParams.peakOrExcessInfoRate =
			    finfo->expt_rate_limit_info[ii].limit;
			params.nonPassthroughAlgParams
			    .peakOrExcessBurstSize =
			    finfo->expt_ratelim_burst_size;
		}

		params.nextEngineOnGreen = e_FM_PCD_DONE;
		params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
		params.nextEngineOnYellow = e_FM_PCD_DONE;
		params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
		params.nextEngineOnRed = e_FM_PCD_DONE;
		params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;

		handle = FM_PCD_PlcrProfileSet(h_FmPcd, &params);
		if (handle == NULL) {
			DPA_ERROR("%s: unable to set profile for type %u\n",
			    __func__, ii);
			return (-1);
		}

		finfo->expt_rate_limit_info[ii].handle = handle;
		created++;
	}

	printf("cdx: qos: %u expt policer profiles created "
	    "(mode=%u burst=%u)\n",
	    created, finfo->expt_ratelim_mode,
	    finfo->expt_ratelim_burst_size);
	return (0);
}

/*
 * cdx_qos_init_expt_profiles — Create exception traffic policer profiles.
 *
 * Called from cdx_dpa_takeover.c after fman_info is populated with
 * rate limit config from dpa_app.
 */
int
cdx_qos_init_expt_profiles(void)
{

	if (fman_info == NULL || fman_info->pcd_handle == NULL)
		return (-1);

	return (cdxdrv_create_missaction_policer_profiles(fman_info));
}

/*
 * cdx_set_expt_rate — Modify exception traffic rate limit.
 *
 * Called from control_qm.c CMD_QM_EXPT_RATE handler.
 */
int
cdx_set_expt_rate(uint32_t fm_index, uint32_t type, uint32_t limit,
    uint32_t burst_size)
{
	struct cdx_fman_info *finfo;
	uint32_t old_limit;

	if (fm_index >= cdx_num_fmans)
		return (-1);
	if (type >= CDX_EXPT_MAX_EXPT_LIMIT_TYPES)
		return (-1);

	finfo = fman_info + fm_index;
	if (finfo->expt_rate_limit_info[type].handle == NULL)
		return (-1);

	old_limit = finfo->expt_rate_limit_info[type].limit;
	finfo->expt_rate_limit_info[type].limit = limit;
	finfo->expt_ratelim_burst_size = burst_size;

	if (cdxdrv_modify_missaction_policer_profile(finfo, type) != 0) {
		finfo->expt_rate_limit_info[type].limit = old_limit;
		return (-1);
	}

	return (0);
}

/*
 * cdx_get_expt_rate — Query exception traffic rate limit and counters.
 *
 * Called from control_qm.c CMD_QM_QUERY_EXPT_RATE handler.
 */
int
cdx_get_expt_rate(void *pcmd)
{
	PQosExptRateCommand cmd;
	struct cdx_fman_info *finfo;
	void *handle;

	cmd = (PQosExptRateCommand)pcmd;

	if (cmd->expt_iftype != CDX_EXPT_ETH_RATELIMIT) {
		DPA_ERROR("%s: type %u not supported\n",
		    __func__, cmd->expt_iftype);
		return (-1);
	}

	finfo = fman_info + FMAN_INDEX;
	handle = finfo->expt_rate_limit_info[cmd->expt_iftype].handle;
	if (handle == NULL)
		return (-1);

	cmd->pkts_per_sec =
	    finfo->expt_rate_limit_info[cmd->expt_iftype].limit;
	cmd->burst_size = finfo->expt_ratelim_burst_size;
	get_plcr_counter(handle, &cmd->counterval[0], cmd->clear);

	return (0);
}

/* ================================================================
 * Ingress QoS policer — SHARED profiles for per-queue rate limiting
 *
 * 8 flow queues each get their own PLCR profile.  Profile IDs are
 * embedded into EHASH entries by cdx_ehash.c.  Guarded by
 * ENABLE_INGRESS_QOS in control_qm.c and cdx_ehash.c.
 *
 * Ported from cdx_qos.c:544-898 + dpa_cfg.c:989-1075.
 * ================================================================ */

#ifdef ENABLE_INGRESS_QOS

/*
 * FMan NIA value for post-policer processing — tells the policer
 * to return the frame to the CC engine after rate-checking.
 * Not in NCSW headers; defined in Linux cdx_qos.c.
 */
#define	e_FM_PCD_POST_POLICER_PROCES_FRAME	0x26

/* Default ingress QoS rate limits */
#define	DEFAULT_INGRESS_CIR_VALUE	0xffffffff
#define	DEFAULT_INGRESS_PIR_VALUE	0xffffffff

/*
 * cdxdrv_create_ingress_qos_policer_profiles — Create shared policer
 * profiles for each ingress flow queue.
 */
int
cdxdrv_create_ingress_qos_policer_profiles(struct cdx_fman_info *finfo)
{
	t_Handle h_FmPcd;
	t_FmPcdPlcrProfileParams params;
	void *handle;
	uint32_t ii, queue_no;

	h_FmPcd = finfo->pcd_handle;
	queue_no = 0;

	for (ii = CDX_INGRESS_QUEUE0_PROFILE_NO;
	    ii <= CDX_INGRESS_ALL_PROFILES; ii++) {

		memset(&params, 0, sizeof(params));
		params.id.newParams.profileType = e_FM_PCD_PLCR_SHARED;
		params.id.newParams.relativeProfileId = ii;
		params.algSelection = e_FM_PCD_PLCR_RFC_2698;
		params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
		params.color.dfltColor = e_FM_PCD_PLCR_RED;
		params.color.override = e_FM_PCD_PLCR_RED;

		/* Defaults: unlimited rate, byte mode */
		finfo->ingress_policer_info[queue_no].cir_value =
		    DEFAULT_INGRESS_CIR_VALUE;
		finfo->ingress_policer_info[queue_no].pir_value =
		    DEFAULT_INGRESS_PIR_VALUE;
		finfo->ingress_policer_info[queue_no].cbs =
		    DEFAULT_INGRESS_BYTE_MODE_CBS;
		finfo->ingress_policer_info[queue_no].pbs =
		    DEFAULT_INGRESS_BYTE_MODE_PBS;

		params.nonPassthroughAlgParams.rateMode =
		    e_FM_PCD_PLCR_BYTE_MODE;
		params.nonPassthroughAlgParams.committedInfoRate =
		    DEFAULT_INGRESS_CIR_VALUE;
		params.nonPassthroughAlgParams.committedBurstSize =
		    DEFAULT_INGRESS_BYTE_MODE_CBS;
		params.nonPassthroughAlgParams.peakOrExcessInfoRate =
		    DEFAULT_INGRESS_PIR_VALUE;
		params.nonPassthroughAlgParams.peakOrExcessBurstSize =
		    DEFAULT_INGRESS_BYTE_MODE_PBS;
		params.nonPassthroughAlgParams.byteModeParams
		    .frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
		params.nonPassthroughAlgParams.byteModeParams
		    .rollBackFrameSelection =
		    e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;

		/* Green/Yellow: return to CC, Red: drop */
		params.nextEngineOnGreen = e_FM_PCD_CC;
		params.paramsOnGreen.action =
		    e_FM_PCD_POST_POLICER_PROCES_FRAME;
		params.nextEngineOnYellow = e_FM_PCD_CC;
		params.paramsOnYellow.action =
		    e_FM_PCD_POST_POLICER_PROCES_FRAME;
		params.nextEngineOnRed = e_FM_PCD_DONE;
		params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;

		handle = FM_PCD_PlcrProfileSet(h_FmPcd, &params);
		if (handle == NULL) {
			DPA_ERROR("%s: unable to set profile for queue %u\n",
			    __func__, queue_no);
			return (-1);
		}

		finfo->ingress_policer_info[queue_no].handle = handle;
		finfo->ingress_policer_info[queue_no].profile_id =
		    FmPcdPlcrProfileGetAbsoluteId(handle);
		finfo->ingress_policer_info[queue_no].policer_on =
		    DISABLE_INGRESS_POLICER;

		queue_no++;
	}

	printf("cdx: qos: %u ingress policer profiles created\n", queue_no);
	return (0);
}

/*
 * cdxdrv_modify_ingress_qos_policer_profile — Modify rate limits
 * on a specific ingress queue's policer profile.
 */
int
cdxdrv_modify_ingress_qos_policer_profile(struct cdx_fman_info *finfo,
    uint32_t queue_no, uint32_t cir, uint32_t pir,
    uint32_t cbs, uint32_t pbs)
{
	t_FmPcdPlcrProfileParams params;
	void *handle;

	if (queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return (-1);
	if (finfo->ingress_policer_info[queue_no].policer_on ==
	    DISABLE_INGRESS_POLICER) {
		DPA_ERROR("%s: policer disabled on queue %u\n",
		    __func__, queue_no);
		return (-1);
	}

	memset(&params, 0, sizeof(params));
	params.modify = 1;
	params.id.h_Profile =
	    finfo->ingress_policer_info[queue_no].handle;
	params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	params.color.dfltColor = e_FM_PCD_PLCR_RED;
	params.color.override = e_FM_PCD_PLCR_RED;

	/* Byte mode for ingress flow queues */
	params.nonPassthroughAlgParams.rateMode =
	    e_FM_PCD_PLCR_BYTE_MODE;
	params.nonPassthroughAlgParams.committedInfoRate = cir;
	params.nonPassthroughAlgParams.committedBurstSize =
	    DEFAULT_INGRESS_BYTE_MODE_CBS;
	cbs = DEFAULT_INGRESS_BYTE_MODE_CBS;
	params.nonPassthroughAlgParams.peakOrExcessInfoRate = pir;
	params.nonPassthroughAlgParams.peakOrExcessBurstSize =
	    DEFAULT_INGRESS_BYTE_MODE_PBS;
	pbs = DEFAULT_INGRESS_BYTE_MODE_PBS;
	params.nonPassthroughAlgParams.byteModeParams
	    .frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
	params.nonPassthroughAlgParams.byteModeParams
	    .rollBackFrameSelection =
	    e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;

	params.nextEngineOnGreen = e_FM_PCD_CC;
	params.paramsOnGreen.action =
	    e_FM_PCD_POST_POLICER_PROCES_FRAME;
	params.nextEngineOnYellow = e_FM_PCD_CC;
	params.paramsOnYellow.action =
	    e_FM_PCD_POST_POLICER_PROCES_FRAME;
	params.nextEngineOnRed = e_FM_PCD_DONE;
	params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;

	handle = FM_PCD_PlcrProfileSet(finfo->pcd_handle, &params);
	if (handle == NULL) {
		DPA_ERROR("%s: unable to modify profile for queue %u\n",
		    __func__, queue_no);
		return (ERR_QM_INGRESS_SET_PROFILE_FAILED);
	}

	finfo->ingress_policer_info[queue_no].cir_value = cir;
	finfo->ingress_policer_info[queue_no].pir_value = pir;
	finfo->ingress_policer_info[queue_no].cbs = cbs;
	finfo->ingress_policer_info[queue_no].pbs = pbs;

	return (0);
}

/*
 * cdxdrv_set_default_qos_policer_profile — Reset a queue's policer
 * profile to default (unlimited) values.
 */
int
cdxdrv_set_default_qos_policer_profile(struct cdx_fman_info *finfo,
    uint32_t queue_no)
{
	t_FmPcdPlcrProfileParams params;
	void *handle;

	if (queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return (-1);

	memset(&params, 0, sizeof(params));
	params.modify = 1;
	params.id.h_Profile =
	    finfo->ingress_policer_info[queue_no].handle;
	params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	params.color.dfltColor = e_FM_PCD_PLCR_RED;
	params.color.override = e_FM_PCD_PLCR_RED;

	/* Reset to byte mode with unlimited rate */
	params.nonPassthroughAlgParams.rateMode =
	    e_FM_PCD_PLCR_BYTE_MODE;
	params.nonPassthroughAlgParams.committedInfoRate =
	    DEFAULT_INGRESS_CIR_VALUE;
	params.nonPassthroughAlgParams.committedBurstSize =
	    DEFAULT_INGRESS_BYTE_MODE_CBS;
	params.nonPassthroughAlgParams.peakOrExcessInfoRate =
	    DEFAULT_INGRESS_PIR_VALUE;
	params.nonPassthroughAlgParams.peakOrExcessBurstSize =
	    DEFAULT_INGRESS_BYTE_MODE_PBS;
	params.nonPassthroughAlgParams.byteModeParams
	    .frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
	params.nonPassthroughAlgParams.byteModeParams
	    .rollBackFrameSelection =
	    e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;

	params.nextEngineOnGreen = e_FM_PCD_CC;
	params.paramsOnGreen.action =
	    e_FM_PCD_POST_POLICER_PROCES_FRAME;
	params.nextEngineOnYellow = e_FM_PCD_CC;
	params.paramsOnYellow.action =
	    e_FM_PCD_POST_POLICER_PROCES_FRAME;
	params.nextEngineOnRed = e_FM_PCD_DONE;
	params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;

	handle = FM_PCD_PlcrProfileSet(finfo->pcd_handle, &params);
	if (handle == NULL) {
		DPA_ERROR("%s: unable to set defaults for queue %u\n",
		    __func__, queue_no);
		return (ERR_QM_INGRESS_SET_PROFILE_FAILED);
	}

	finfo->ingress_policer_info[queue_no].cir_value =
	    DEFAULT_INGRESS_CIR_VALUE;
	finfo->ingress_policer_info[queue_no].pir_value =
	    DEFAULT_INGRESS_PIR_VALUE;
	finfo->ingress_policer_info[queue_no].cbs =
	    DEFAULT_INGRESS_BYTE_MODE_CBS;
	finfo->ingress_policer_info[queue_no].pbs =
	    DEFAULT_INGRESS_BYTE_MODE_PBS;

	return (0);
}

/*
 * cdx_qos_init_ingress_profiles — Create ingress QoS policer profiles.
 *
 * Called from cdx_dpa_takeover.c after fman_info is populated.
 */
int
cdx_qos_init_ingress_profiles(void)
{

	if (fman_info == NULL || fman_info->pcd_handle == NULL)
		return (-1);

	return (cdxdrv_create_ingress_qos_policer_profiles(fman_info));
}

/*
 * cdx_get_policer_profile_id — Return absolute PLCR profile ID for
 * a given ingress queue, if policing is enabled on it.
 *
 * Called from cdx_ehash.c during flow entry insertion.
 */
int
cdx_get_policer_profile_id(uint32_t fm_index, uint32_t queue_no)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;

	finfo = fman_info;
	for (ii = 0; ii < cdx_num_fmans; ii++) {
		if (finfo->index == fm_index) {
			if (finfo->ingress_policer_info[queue_no].policer_on
			    == ENABLE_INGRESS_POLICER)
				return (finfo->ingress_policer_info[queue_no]
				    .profile_id);
			else
				break;
		}
		finfo++;
	}

	return (0);
}

/*
 * cdx_ingress_enable_or_disable_qos — Enable or disable ingress
 * policer on a specific flow queue.
 */
int
cdx_ingress_enable_or_disable_qos(uint32_t fm_index, uint32_t queue_no,
    uint32_t oper)
{
	struct cdx_fman_info *finfo;

	if (fm_index >= cdx_num_fmans)
		return (-1);

	finfo = fman_info + fm_index;

	if (finfo->ingress_policer_info[queue_no].handle == NULL)
		return (ERR_QM_INGRESS_POLICER_HANDLE_NULL);

	if (oper) {
		if (finfo->ingress_policer_info[queue_no].policer_on ==
		    ENABLE_INGRESS_POLICER) {
			DPA_INFO("cdx: qos: policer already enabled on "
			    "queue %u\n", queue_no);
			return (0);
		}
		finfo->ingress_policer_info[queue_no].policer_on =
		    ENABLE_INGRESS_POLICER;
		return (cdxdrv_modify_ingress_qos_policer_profile(finfo,
		    queue_no,
		    finfo->ingress_policer_info[queue_no].cir_value,
		    finfo->ingress_policer_info[queue_no].pir_value,
		    finfo->ingress_policer_info[queue_no].cbs,
		    finfo->ingress_policer_info[queue_no].pbs));
	} else {
		if (cdxdrv_set_default_qos_policer_profile(finfo,
		    queue_no) == 0) {
			finfo->ingress_policer_info[queue_no].policer_on =
			    DISABLE_INGRESS_POLICER;
			return (0);
		}
		return (ERR_QM_INGRESS_SET_PROFILE_FAILED);
	}
}

/*
 * cdx_ingress_policer_modify_config — Change rate limits on a queue.
 */
int
cdx_ingress_policer_modify_config(uint32_t fm_index, uint32_t queue_no,
    uint32_t cir, uint32_t pir, uint32_t cbs, uint32_t pbs)
{
	struct cdx_fman_info *finfo;

	if (fm_index >= cdx_num_fmans)
		return (-1);

	finfo = fman_info + fm_index;

	if (finfo->ingress_policer_info[queue_no].handle == NULL)
		return (ERR_QM_INGRESS_POLICER_HANDLE_NULL);

	return (cdxdrv_modify_ingress_qos_policer_profile(finfo, queue_no,
	    cir, pir, cbs, pbs));
}

/*
 * cdx_ingress_policer_reset — Reset all ingress flow queues to defaults.
 */
int
cdx_ingress_policer_reset(uint32_t fm_index)
{
	struct cdx_fman_info *finfo;
	uint32_t ii;

	if (fm_index >= cdx_num_fmans)
		return (-1);

	finfo = fman_info + fm_index;

	for (ii = 0; ii < INGRESS_FLOW_POLICER_QUEUES; ii++) {
		if (finfo->ingress_policer_info[ii].handle != NULL) {
			if (cdxdrv_set_default_qos_policer_profile(finfo,
			    ii) == 0)
				finfo->ingress_policer_info[ii].policer_on =
				    DISABLE_INGRESS_POLICER;
			else
				DPA_ERROR("%s: reset failed for queue %u\n",
				    __func__, ii);
		}
	}

	return (0);
}

/*
 * cdx_ingress_policer_stats — Read policer counters for a queue.
 */
int
cdx_ingress_policer_stats(uint32_t fm_index, uint32_t queue_no,
    void *stats, uint32_t clear)
{
	struct cdx_fman_info *finfo;
	pIngressQosStat plcr_stats;

	if (fm_index >= cdx_num_fmans)
		return (-1);

	finfo = fman_info + fm_index;

	if (finfo->ingress_policer_info[queue_no].handle == NULL) {
		DPA_ERROR("%s: policer handle NULL for queue %u\n",
		    __func__, queue_no);
		return (-1);
	}

	plcr_stats = (pIngressQosStat)stats;

	if (finfo->ingress_policer_info[queue_no].policer_on ==
	    ENABLE_INGRESS_POLICER)
		get_plcr_counter(
		    finfo->ingress_policer_info[queue_no].handle,
		    &plcr_stats->counterval[0], clear);

	plcr_stats->policer_on =
	    finfo->ingress_policer_info[queue_no].policer_on;
	plcr_stats->cir =
	    finfo->ingress_policer_info[queue_no].cir_value;
	plcr_stats->pir =
	    finfo->ingress_policer_info[queue_no].pir_value;
	plcr_stats->cbs = finfo->ingress_policer_info[queue_no].cbs;
	plcr_stats->pbs = finfo->ingress_policer_info[queue_no].pbs;

	return (0);
}

/*
 * cdx_sec_policer_reset — Reset SEC policer profile to defaults.
 * SEC_PROFILE_SUPPORT is not defined on FreeBSD, so this is a no-op.
 */
int
cdx_sec_policer_reset(uint32_t fm_index __unused)
{

	return (0);
}

#endif /* ENABLE_INGRESS_QOS */
