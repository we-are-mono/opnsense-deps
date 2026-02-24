/*
 *  Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**     
 * @file                cdx_qos.c     
 * @description         device management routines for Qos
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>
#include <uapi/linux/in6.h> 
#include <linux/spinlock.h>
#include <linux/if_arp.h>
#include "lnxwrp_fm.h"
#include <linux/fsl_oh_port.h>
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "fm_ehash.h"
#include "portdefs.h"
#include "layer2.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "mac.h"
#include "cdx.h"
#include "cdx_common.h"
#include "module_qm.h"
#include "fe.h"
#include "control_pppoe.h"
#include "control_tunnel.h"
#include "control_ipv6.h"
#include "endian_ext.h" 
#include "dpa_control_mc.h"
#include "dpa_wifi.h"
#include "cdx_ceetm_gdef.h" 
#include "cdx_defs.h"

//#define QOS_DEBUG	1

//per port fast forward policer information and defaults
struct port_ff_rate_lim_info {
	void *handle;
	t_Handle h_FmPcd;
	uint32_t cir_value;
	uint32_t pir_value;
};

#define MAX_PHYS_PORTS			64              /*dpaa limit*/
/* PORT PIR/CIR PBS/CBS values are for packet mode*/
#define DEFAULT_PORT_FF_CIR_VALUE_10G	2000000
#define DEFAULT_PORT_FF_PIR_VALUE_10G	12000000
#define DEFAULT_PORT_FF_CIR_VALUE_1G	4000000 /* This value is higher than the 64 byte 100% load, but with this value only it is giving 100% on 1046 RDB.*/
#define DEFAULT_PORT_FF_PIR_VALUE_1G	4000000
#define DEFAULT_10G_PORT_FF_CBS		3
#define DEFAULT_1G_PORT_FF_CBS		1
#define DEFAULT_10G_PORT_FF_PBS		3
#define DEFAULT_1G_PORT_FF_PBS		1
#define DEFAULT_PORT_FF_MODE		e_FM_PCD_PLCR_PACKET_MODE

//enable rate limiting on exception traffic
#define ENABLE_EXTP_RATE_LIMIT  1
//enable rate limiting on fast forward traffic
#define ENABLE_FF_RATE_LIMIT    1
#define DEFAULT_INGRESS_CIR_VALUE 0xffffffff
#define DEFAULT_INGRESS_PIR_VALUE 0xffffffff
/* For packet mode expected no of packets
	 for FMAN clock speed ( 3.9ns) */
#define DEFAULT_INGRESS_PKT_MODE_CBS 3
#define DEFAULT_INGRESS_PKT_MODE_PBS 3
#define e_FM_PCD_POST_POLICER_PROCES_FRAME 0x26

/* 
 * DEFAULT_SEC_PROFILE_PKT_MODE_CIR: Secure profile packet mode default CIR value.
 * This value is packet per second. 
 * For SIB ASK limited to around 500Mbps (for 66 byte packet)
 */
#define DEFAULT_SEC_PROFILE_PKT_MODE_CIR 740000
/* 
 * DEFAULT_SEC_PROFILE_PKT_MODE_PIR: Secure profile packet mode default PIR value.
 * This value is packet per second. 
 * For SIB ASK limited to around 730Mbps (for 66 byte packet)
 */
#define DEFAULT_SEC_PROFILE_PKT_MODE_PIR 1060000

/* TO SEC max burst is allowed, as the bursts are expected from 5G/DPDK interface */
/* Bursts are confiured in pkts/usec */
#define DEFAULT_SEC_PKT_MODE_CBS 32
#define DEFAULT_SEC_PKT_MODE_PBS 64

uint32_t port_ff_lim_mode = e_FM_PCD_PLCR_PACKET_MODE;
struct port_ff_rate_lim_info port_rate_lim_mode[MAX_PHYS_PORTS];

/* api to modify shared policer parameters for exception traffic to control plane */
int cdxdrv_modify_missaction_policer_profile(struct cdx_fman_info *finfo, uint32_t type)
{
	void *handle;
	t_FmPcdPlcrProfileParams Params;

	if (type >= CDX_EXPT_MAX_EXPT_LIMIT_TYPES)
		return FAILURE;
	if (finfo->expt_rate_limit_info[type].limit == DISABLE_EXPT_PROFILE) 
		return FAILURE;
	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = finfo->expt_rate_limit_info[type].handle;
	Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	//color as red by default
	Params.color.dfltColor = e_FM_PCD_PLCR_RED;
	//override color is RED
	Params.color.override = e_FM_PCD_PLCR_RED;
	//set algorithm mode as bytes/sec
	if (finfo->expt_ratelim_mode == EXPT_PKT_LIM_PLCR_MODE_BYTE) {
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
		Params.nonPassthroughAlgParams.committedInfoRate = finfo->expt_rate_limit_info[type].limit;
		Params.nonPassthroughAlgParams.committedBurstSize = finfo->expt_ratelim_burst_size;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = finfo->expt_rate_limit_info[type].limit;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = finfo->expt_ratelim_burst_size;
		Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
		Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
	} else {
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
		Params.nonPassthroughAlgParams.committedInfoRate = finfo->expt_rate_limit_info[type].limit;
		Params.nonPassthroughAlgParams.committedBurstSize = finfo->expt_ratelim_burst_size;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = finfo->expt_rate_limit_info[type].limit;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = finfo->expt_ratelim_burst_size;
	} 
	Params.nextEngineOnGreen = e_FM_PCD_DONE;
	Params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
	Params.nextEngineOnYellow = e_FM_PCD_DONE;
	Params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
	Params.nextEngineOnRed = e_FM_PCD_DONE;
	Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
	handle = FM_PCD_PlcrProfileSet(finfo->pcd_handle, &Params);
	if (!handle) {
		printk("%s::unable to modify profile for type %d\n",
				__FUNCTION__, type);
		return FAILURE;
	}	
#ifdef QOS_DEBUG
	printk("%s::plcr profile modified for type %d, mode %d, handle %p\n",
			__FUNCTION__, type, finfo->expt_ratelim_mode, handle);
#endif
	return SUCCESS;
}

/* api to add shared policer profile for exception traffic to control plane */
int cdxdrv_create_missaction_policer_profiles(struct cdx_fman_info *finfo)
{
	t_Handle h_FmPcd;
	t_FmPcdPlcrProfileParams Params;
	void *handle;
	uint32_t ii;

	h_FmPcd = finfo->pcd_handle;
	for (ii = 0 ; ii < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; ii++) {

		if (finfo->expt_rate_limit_info[ii].limit == DISABLE_EXPT_PROFILE)  {
			finfo->expt_rate_limit_info[ii].handle = NULL;
			continue;
		}
		memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
		Params.id.newParams.profileType = e_FM_PCD_PLCR_SHARED;
		Params.id.newParams.relativeProfileId = ii;
		Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
		Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
		//color as red by default
		Params.color.dfltColor = e_FM_PCD_PLCR_RED;
		//override color is RED
		Params.color.override = e_FM_PCD_PLCR_RED;
		//set algorithm mode as bytes/sec
		if (finfo->expt_ratelim_mode == EXPT_PKT_LIM_PLCR_MODE_BYTE) {
			Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
			Params.nonPassthroughAlgParams.committedInfoRate = finfo->expt_rate_limit_info[ii].limit;
			Params.nonPassthroughAlgParams.committedBurstSize = finfo->expt_ratelim_burst_size;
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate = finfo->expt_rate_limit_info[ii].limit;
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize = finfo->expt_ratelim_burst_size;
			Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
			Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
		} else {
			Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
			Params.nonPassthroughAlgParams.committedInfoRate = finfo->expt_rate_limit_info[ii].limit;
			Params.nonPassthroughAlgParams.committedBurstSize = finfo->expt_ratelim_burst_size;
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate = finfo->expt_rate_limit_info[ii].limit;
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize = finfo->expt_ratelim_burst_size;
		} 
		Params.nextEngineOnGreen = e_FM_PCD_DONE;
		Params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
		Params.nextEngineOnYellow = e_FM_PCD_DONE;
		Params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
		Params.nextEngineOnRed = e_FM_PCD_DONE;
		Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
		handle = FM_PCD_PlcrProfileSet(h_FmPcd, &Params);
		if (!handle) {
			printk("%s::unable to set profile for type %d\n",
					__FUNCTION__, ii);
			return FAILURE;
		}	
#ifdef QOS_DEBUG
		printk("%s::plcr profile modified for type %d, mode %d, handle %p\n",
				__FUNCTION__, ii, finfo->expt_ratelim_mode, handle);
		printk("cir %d, pir %d, cbs %d, pbs %d\n",
				Params.nonPassthroughAlgParams.committedInfoRate,
				Params.nonPassthroughAlgParams.peakOrExcessInfoRate,
				Params.nonPassthroughAlgParams.committedBurstSize,
				Params.nonPassthroughAlgParams.peakOrExcessBurstSize);
#endif
		finfo->expt_rate_limit_info[ii].handle = handle;
	}
	return 0;
}

static int dpa_add_port_ff_policier_profile(struct dpa_iface_info *iface_info,
		uint8_t hardwarePortId, void *port_handle, t_Handle h_FmPcd)
{
	void *handle;
	void *profhandle;
	t_FmPcdPlcrProfileParams Params;
	uint32_t uiPeakBurstSize, uiCommitedBurstSize;

	//init default cir and pir values for port
	if (!(iface_info->if_flags & IF_TYPE_ETHERNET)) {
		DPA_ERROR("%s::%d interface %s is not ethernet interface. Cannot configure it other than ethernet interfaces(flag 0x%x). \n",
				__FUNCTION__, __LINE__, iface_info->name, iface_info->if_flags);
		return FAILURE;
	}

	if (iface_info->eth_info.speed == PORT_1G_SPEED ) {
		port_rate_lim_mode[hardwarePortId].cir_value = DEFAULT_PORT_FF_CIR_VALUE_1G;
		port_rate_lim_mode[hardwarePortId].pir_value = DEFAULT_PORT_FF_PIR_VALUE_1G;
		uiPeakBurstSize = DEFAULT_1G_PORT_FF_PBS;
		uiCommitedBurstSize = DEFAULT_1G_PORT_FF_CBS;
	}
	else if (iface_info->eth_info.speed == PORT_10G_SPEED ) {
		port_rate_lim_mode[hardwarePortId].cir_value = DEFAULT_PORT_FF_CIR_VALUE_10G;
		port_rate_lim_mode[hardwarePortId].pir_value = DEFAULT_PORT_FF_PIR_VALUE_10G;
		uiPeakBurstSize = DEFAULT_10G_PORT_FF_PBS;
		uiCommitedBurstSize = DEFAULT_10G_PORT_FF_CBS;
	}
	else
	{
		DPA_ERROR("%s::%d interface %s speed(%u) is not 1G or 10G. Configure proper value. \n",
				__FUNCTION__, __LINE__, iface_info->name, iface_info->eth_info.speed);
		return FAILURE;
	}

	profhandle = fm_port_get_handle(port_handle);
#ifdef QOS_DEBUG
	printk("%s::creating profile for port %s, hwportid %d\n", __FUNCTION__,
			iface_info->name, hardwarePortId);
#endif
	if (FM_PORT_PcdPlcrAllocProfiles(profhandle, 1)) {
		DPA_ERROR("%s::unable to alloc plcr profile for dev %s\n",
				__FUNCTION__, iface_info->name);
		return FAILURE;
	}
	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.id.newParams.profileType = e_FM_PCD_PLCR_PORT_PRIVATE;
	Params.id.newParams.h_FmPort = profhandle;
	Params.id.newParams.relativeProfileId = 0;
	Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	//color as red by default
	Params.color.dfltColor = e_FM_PCD_PLCR_RED;
	//override color is RED
	Params.color.override = e_FM_PCD_PLCR_RED;
	//set algorithma mode 
	Params.nonPassthroughAlgParams.rateMode = port_ff_lim_mode;

#if 0 /* port, byte mode is not supporting */
	if (port_ff_lim_mode == e_FM_PCD_PLCR_BYTE_MODE) {
		Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
		Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
	}
#endif

	Params.nonPassthroughAlgParams.committedInfoRate = port_rate_lim_mode[hardwarePortId].cir_value;
	Params.nonPassthroughAlgParams.peakOrExcessInfoRate = port_rate_lim_mode[hardwarePortId].pir_value;
	Params.nonPassthroughAlgParams.committedBurstSize = uiCommitedBurstSize;
	Params.nonPassthroughAlgParams.peakOrExcessBurstSize = uiPeakBurstSize;
	Params.nextEngineOnGreen = e_FM_PCD_PRS;
	Params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
	Params.nextEngineOnYellow = e_FM_PCD_PRS;
	Params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
	Params.nextEngineOnRed = e_FM_PCD_DONE;
	Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
	handle = FM_PCD_PlcrProfileSet(h_FmPcd, &Params);
	if (!handle) {
		DPA_ERROR("%s::unable to profile set for port %s\n",
				__FUNCTION__, iface_info->name);
		return FAILURE;
	}
	port_rate_lim_mode[hardwarePortId].handle = handle;
	port_rate_lim_mode[hardwarePortId].h_FmPcd = h_FmPcd;
#ifdef QOS_DEBUG
	printk("%s::plcr profile for dev %s handle %p\n",
			__FUNCTION__, iface_info->name, handle);
#endif
	//change fmbm_rfne value to policer
	//FM_PORT_SetBmiNia(profhandle, 0x4c0000);
	return SUCCESS;
}

//api to add port specific policer profile on offline ports to reserve bandwidth for incoming control packets
int dpa_add_ethport_ff_policier_profile(struct dpa_iface_info *iface_info)
{
	struct eth_iface_info *eth_info;
	struct dpa_priv_s *priv;
	struct mac_device *mac_dev;
	uint8_t hardwarePortId;
	struct fm_port *port_handle;
	t_Handle h_FmPcd;

	eth_info = &iface_info->eth_info;
	priv = netdev_priv(eth_info->net_dev);
	mac_dev = priv->mac_dev;
	//hardwarePortId = fm_port_get_hwid(mac_dev->port_dev[RX]);
	hardwarePortId = eth_info->hardwarePortId;
	port_handle = mac_dev->port_dev[RX];
	h_FmPcd = dpa_get_pcdhandle(eth_info->fman_idx);
	if (h_FmPcd == NULL) {
		DPA_ERROR("%s::no pcd handle for eth dev %s\n",
				__FUNCTION__, iface_info->name);
		return FAILURE;
	}
	return(dpa_add_port_ff_policier_profile(iface_info,
				hardwarePortId, port_handle, h_FmPcd));

}

/* api to modify port specific policer profile to reserver bandwidth for incoming control packets */
int cdx_set_ff_rate(char *ifname, uint32_t cir, uint32_t pir)
{
	void *handle;
	int hardwarePortId;
	t_FmPcdPlcrProfileParams Params;
	struct dpa_iface_info *iface_info;


	iface_info = dpa_get_iface_by_name(ifname);
	if (!iface_info)
	{
		printk("%s()::%d Invalid interface name <%s>\n", 
				__func__, __LINE__, ifname);
		return FAILURE;	
	}
	if (!(iface_info->if_flags & IF_TYPE_ETHERNET)) {
		printk("%s()::%d Interface <%s> is not ethernet(0x%x).\n", 
				__func__, __LINE__, ifname, iface_info->if_flags);
		return FAILURE;	
	}
	hardwarePortId = iface_info->eth_info.hardwarePortId;
	if (hardwarePortId == -1) {
		return FAILURE;	
	}
	if (!port_rate_lim_mode[hardwarePortId].handle) 
		return FAILURE;	

#ifdef QOS_DEBUG
	printk("%s::modifying profile for %s::%d cir %d, pir %d\n", __FUNCTION__,
			ifname, hardwarePortId, cir, pir);
#endif
	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = port_rate_lim_mode[hardwarePortId].handle;
	Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	//color as red by default
	Params.color.dfltColor = e_FM_PCD_PLCR_RED;
	//override color is RED
	Params.color.override = e_FM_PCD_PLCR_RED;
	Params.nonPassthroughAlgParams.rateMode = port_ff_lim_mode;
	if (iface_info->eth_info.speed == PORT_1G_SPEED ) {
		Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_1G_PORT_FF_CBS;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_1G_PORT_FF_PBS;
	}
	else if (iface_info->eth_info.speed == PORT_10G_SPEED ) {
		Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_10G_PORT_FF_CBS;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_10G_PORT_FF_PBS;
	}
	else
	{
		DPA_ERROR("%s::%d interface %s speed(%u) is not 1G or 10G. Configure proper value. \n",
				__FUNCTION__, __LINE__, iface_info->name, iface_info->eth_info.speed);
		return FAILURE;
	}

#if 0 /* port byte mode is not supporting. */
	if (port_ff_lim_mode == e_FM_PCD_PLCR_BYTE_MODE) {
		Params.nonPassthroughAlgParams.committedInfoRate = cir;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = pir;
		Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
		Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
	} else 
#endif
	{
		Params.nonPassthroughAlgParams.committedInfoRate = cir;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = pir;
	}
	Params.nextEngineOnGreen = e_FM_PCD_PRS;
	Params.paramsOnGreen.action = e_FM_PCD_ENQ_FRAME;
	Params.nextEngineOnYellow = e_FM_PCD_PRS;
	Params.paramsOnYellow.action = e_FM_PCD_ENQ_FRAME;
	Params.nextEngineOnRed = e_FM_PCD_DONE;
	Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
	handle = FM_PCD_PlcrProfileSet(port_rate_lim_mode[hardwarePortId].h_FmPcd, &Params);
	if (!handle) {
		printk("%s::unable to modify profile for port %d\n",
				__FUNCTION__, hardwarePortId);
		return FAILURE;
	}
	port_rate_lim_mode[hardwarePortId].cir_value = cir;
	port_rate_lim_mode[hardwarePortId].pir_value = pir;
#ifdef QOS_DEBUG
	printk("%s::port %d cir value %d, pir value %d\n",
			__FUNCTION__, hardwarePortId, cir, pir);
#endif
	return SUCCESS;
}

void get_plcr_counter(void *handle, uint32_t *counterval, uint32_t clear)
{
	uint32_t ii;
	uint32_t counter_id;

	for (ii = 0; ii < MAX_RATLIM_CNTR; ii++) {
		switch(ii) {
			case RED_TOTAL:
				counter_id = e_FM_PCD_PLCR_PROFILE_RED_PACKET_TOTAL_COUNTER;
				break;
			case YELLOW_TOTAL:
				counter_id = e_FM_PCD_PLCR_PROFILE_YELLOW_PACKET_TOTAL_COUNTER;
				break;
			case GREEN_TOTAL:
				counter_id = e_FM_PCD_PLCR_PROFILE_GREEN_PACKET_TOTAL_COUNTER;
				break;
			case RED_RECOLORED:
				counter_id = e_FM_PCD_PLCR_PROFILE_RECOLOURED_RED_PACKET_TOTAL_COUNTER;
				break;
			case YELLOW_RECOLORED:
				counter_id = e_FM_PCD_PLCR_PROFILE_RECOLOURED_YELLOW_PACKET_TOTAL_COUNTER;
				break;
			default:
				return;
		}
		*(counterval + ii) = 
			FM_PCD_PlcrProfileGetCounter(handle, counter_id);
		if (clear) {
			FM_PCD_PlcrProfileSetCounter(handle, counter_id, 0);
		}
	}
}

int cdx_get_expt_rate(void *pcmd)
{
	PQosExptRateCommand cmd;
	struct cdx_fman_info *finfo;
	void *handle;

	cmd = (PQosExptRateCommand)pcmd;

	if (cmd->expt_iftype != CDX_EXPT_ETH_RATELIMIT) {
		DPA_ERROR("%s::type %d not supported\n", __FUNCTION__, cmd->expt_iftype);
		return -1;
	}
	finfo = (fman_info + FMAN_INDEX);
	handle = finfo->expt_rate_limit_info[cmd->expt_iftype].handle;
	if (!handle)	
		return -1;
	cmd->pkts_per_sec = finfo->expt_rate_limit_info[cmd->expt_iftype].limit;
	cmd->burst_size =  finfo->expt_ratelim_burst_size;
	get_plcr_counter(handle, &cmd->counterval[0], cmd->clear);
#ifdef QOS_DEBUG
	printk("%s::type %d rate %d pps\n", __FUNCTION__, cmd->expt_iftype, cmd->pkts_per_sec);
	printk("red %d yellow %d, green %d red recolored %d, yellow recolored %d\n",
			cmd->counterval[RED_TOTAL], cmd->counterval[YELLOW_TOTAL],
			cmd->counterval[GREEN_TOTAL], cmd->counterval[RED_RECOLORED],
			cmd->counterval[YELLOW_RECOLORED]);
#endif
	return 0;
}

int cdx_get_ff_rate(void *pcmd)
{
	int hardwarePortId;
	void *handle;
	PQosFFRateCommand cmd;

	cmd = (PQosFFRateCommand)pcmd;
	hardwarePortId = dpa_get_iface_hwid_by_name_and_type(cmd->interface, IF_TYPE_ETHERNET);
	if (hardwarePortId == -1) {
		return FAILURE;	
	}
	handle = port_rate_lim_mode[hardwarePortId].handle;
	if (!handle)  {
		printk("%s::invalid handle\n", __FUNCTION__);
		return FAILURE;	
	}
	cmd->cir = port_rate_lim_mode[hardwarePortId].cir_value;
	cmd->pir = port_rate_lim_mode[hardwarePortId].pir_value;
	get_plcr_counter(handle, &cmd->counterval[0], cmd->clear);
#ifdef QOS_DEBUG
	printk("%s::port %s::%d cir value %d, pir value %d\n",
			__FUNCTION__, cmd->interface, hardwarePortId, cmd->cir, cmd->pir);
	printk("red %d yellow %d, green %d red recolored %d, yellow recolored %d\n",
			cmd->counterval[RED_TOTAL], cmd->counterval[YELLOW_TOTAL],
			cmd->counterval[GREEN_TOTAL], cmd->counterval[RED_RECOLORED],
			cmd->counterval[YELLOW_RECOLORED]);
#endif
	return SUCCESS;
}

void *create_ddr_and_copy_from_muram(void *muramptr, void **ddrptr, U32 size)
{
	if ((*ddrptr = kmalloc(size, GFP_KERNEL)) == NULL)
	{
		DPA_ERROR("%s(%d) Memory allocation failure:\n", __FUNCTION__, __LINE__);
		return NULL;
	}
	memcpy(*ddrptr, muramptr, size);

	return *ddrptr;
}

void copy_ddr_to_muram_and_free_ddr(void *muramptr, void **ddrptr, U32 size)
{
	memcpy(muramptr, *ddrptr, size);
	kfree(*ddrptr);
	*ddrptr = NULL;
}

#ifdef ENABLE_INGRESS_QOS
/* api to add shared policer profiles for ingress Qos */
int cdxdrv_create_ingress_qos_policer_profiles(struct cdx_fman_info *finfo)
{
	t_Handle h_FmPcd;
	t_FmPcdPlcrProfileParams Params;
	void *handle;
	uint32_t ii,queue_no=0;

	h_FmPcd = finfo->pcd_handle;
	for (ii = CDX_INGRESS_QUEUE0_PROFILE_NO; ii <= CDX_INGRESS_ALL_PROFILES; ii++) {

		memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
		Params.id.newParams.profileType = e_FM_PCD_PLCR_SHARED;
		Params.id.newParams.relativeProfileId = ii;
		Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
		Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
		/*color as red by default*/
		Params.color.dfltColor = e_FM_PCD_PLCR_RED;
		/*override color is RED */
		Params.color.override = e_FM_PCD_PLCR_RED;

#ifdef SEC_PROFILE_SUPPORT
		if (ii != CDX_INGRESS_SEC_QUEUE_PROFILE_NO)
#endif /* endif for SEC_PROFILE_SUPPORT */
		{
			/* init default cir and pir values */
			finfo->ingress_policer_info[queue_no].cir_value = DEFAULT_INGRESS_CIR_VALUE;
			finfo->ingress_policer_info[queue_no].pir_value = DEFAULT_INGRESS_PIR_VALUE;
			finfo->ingress_policer_info[queue_no].cbs = DEFAULT_INGRESS_BYTE_MODE_CBS;
			finfo->ingress_policer_info[queue_no].pbs = DEFAULT_INGRESS_BYTE_MODE_PBS;

			/*set algorithm mode as Bytes/sec */
			Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
			/*Params.nonPassthroughAlgParams.committedInfoRate = finfo->ingress_policer_info[queue_no].cir_value; */
			Params.nonPassthroughAlgParams.committedInfoRate = DEFAULT_INGRESS_CIR_VALUE;
			Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_INGRESS_BYTE_MODE_CBS;
			/*Params.nonPassthroughAlgParams.peakOrExcessInfoRate = finfo->ingress_policer_info[queue_no].pir_value; */
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate = DEFAULT_INGRESS_PIR_VALUE;
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_INGRESS_BYTE_MODE_PBS;
			Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
			Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
		}
#ifdef SEC_PROFILE_SUPPORT
		else
		{
			/* init default sec profile cir and pir values */
			finfo->ingress_policer_info[queue_no].cir_value = DEFAULT_SEC_PROFILE_PKT_MODE_CIR;
			finfo->ingress_policer_info[queue_no].pir_value = DEFAULT_SEC_PROFILE_PKT_MODE_PIR;
			finfo->ingress_policer_info[queue_no].cbs = DEFAULT_SEC_PKT_MODE_CBS;
			finfo->ingress_policer_info[queue_no].pbs = DEFAULT_SEC_PKT_MODE_PBS;

			/*For sec profile set algorithm mode as Packets/sec */
			Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
			Params.nonPassthroughAlgParams.committedInfoRate = DEFAULT_SEC_PROFILE_PKT_MODE_CIR;
			Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_SEC_PKT_MODE_CBS;
			Params.nonPassthroughAlgParams.peakOrExcessInfoRate = DEFAULT_SEC_PROFILE_PKT_MODE_PIR;
			Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_SEC_PKT_MODE_PBS;
		}
#endif /* endif for SEC_PROFILE_SUPPORT */

		Params.nextEngineOnGreen = e_FM_PCD_CC;
		Params.paramsOnGreen.action = e_FM_PCD_POST_POLICER_PROCES_FRAME;
		Params.nextEngineOnYellow = e_FM_PCD_CC;
		Params.paramsOnYellow.action = e_FM_PCD_POST_POLICER_PROCES_FRAME;
		Params.nextEngineOnRed =e_FM_PCD_DONE;
		Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
		handle = FM_PCD_PlcrProfileSet(h_FmPcd, &Params);
		if (!handle) {
			printk("%s::unable to set profile for queue %d\n",
					__FUNCTION__, queue_no);
			return FAILURE;
		}
		finfo->ingress_policer_info[queue_no].handle = handle;
		finfo->ingress_policer_info[queue_no].profile_id = FmPcdPlcrProfileGetAbsoluteId(finfo->ingress_policer_info[queue_no].handle);
#ifdef QOS_DEBUG
		printk("%s::Ingress plcr profile created for  queue_no %d, handle %p,profile_id %d\n",
				__FUNCTION__, queue_no,handle,finfo->ingress_policer_info[queue_no].profile_id);
		printk("cir %u, pir %u, cbs %d, pbs %d\n",
				Params.nonPassthroughAlgParams.committedInfoRate,
				Params.nonPassthroughAlgParams.peakOrExcessInfoRate,
				Params.nonPassthroughAlgParams.committedBurstSize,
				Params.nonPassthroughAlgParams.peakOrExcessBurstSize);
#endif
#ifdef SEC_PROFILE_SUPPORT
		if (ii != CDX_INGRESS_SEC_QUEUE_PROFILE_NO)
#endif /* endif for SEC_PROFILE_SUPPORT */
			finfo->ingress_policer_info[queue_no].policer_on = DISABLE_INGRESS_POLICER;
#ifdef SEC_PROFILE_SUPPORT
		else
			finfo->ingress_policer_info[queue_no].policer_on = ENABLE_INGRESS_POLICER;
#endif /* endif for SEC_PROFILE_SUPPORT */

		queue_no++;
	}
	return 0;
}

/* api to modify ingress qos policer parameters */
int cdxdrv_modify_ingress_qos_policer_profile(struct cdx_fman_info *finfo, uint32_t queue_no,uint32_t cir, uint32_t pir, uint32_t cbs, uint32_t pbs)
{
	void *handle;
	t_FmPcdPlcrProfileParams Params;

	if (queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return FAILURE;


	if (finfo->ingress_policer_info[queue_no].policer_on == DISABLE_INGRESS_POLICER) {
		printk("%s::plcr profile is disabled on queue %d\n",__FUNCTION__, queue_no);
		return FAILURE;
	}

	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = finfo->ingress_policer_info[queue_no].handle;
	Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	/*color as red by default */
	Params.color.dfltColor = e_FM_PCD_PLCR_RED;
	/*override color is RED */
	Params.color.override = e_FM_PCD_PLCR_RED;
#ifdef SEC_PROFILE_SUPPORT
	if (queue_no != INGRESS_SEC_POLICER_QUEUE_NUM)
#endif /* endif for SEC_PROFILE_SUPPORT */
	{
		/*set algorithm mode as bytes/sec */
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
		Params.nonPassthroughAlgParams.committedInfoRate = cir;
		Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_INGRESS_BYTE_MODE_CBS;
		cbs = DEFAULT_INGRESS_BYTE_MODE_CBS;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = pir;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_INGRESS_BYTE_MODE_PBS;
		pbs = DEFAULT_INGRESS_BYTE_MODE_PBS;
		Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
		Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
	}
#ifdef SEC_PROFILE_SUPPORT
	else
	{
		/*set algorithm mode as Packets/sec */
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
		Params.nonPassthroughAlgParams.committedInfoRate = cir;
		Params.nonPassthroughAlgParams.committedBurstSize = cbs;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = pir;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = pbs;
	}
#endif /* endif for SEC_PROFILE_SUPPORT */

	Params.nextEngineOnGreen = e_FM_PCD_CC;
	Params.paramsOnGreen.action = e_FM_PCD_POST_POLICER_PROCES_FRAME;
	Params.nextEngineOnYellow = e_FM_PCD_CC;
	Params.paramsOnYellow.action = e_FM_PCD_POST_POLICER_PROCES_FRAME;
	Params.nextEngineOnRed = e_FM_PCD_DONE;
	Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
	handle = FM_PCD_PlcrProfileSet(finfo->pcd_handle, &Params);
	if (!handle) {
		printk("%s::unable to modify profile for queue %d\n",
				__FUNCTION__, queue_no);
		return ERR_QM_INGRESS_SET_PROFILE_FAILED;
	}
	finfo->ingress_policer_info[queue_no].cir_value = cir;
	finfo->ingress_policer_info[queue_no].pir_value = pir;
	finfo->ingress_policer_info[queue_no].cbs = cbs;
	finfo->ingress_policer_info[queue_no].pbs = pbs;
#ifdef QOS_DEBUG
	printk("%s::plcr profile modified for queue %d, handle %p\n",
			__FUNCTION__, queue_no, handle);
#endif
	return SUCCESS;
}
int cdxdrv_set_default_qos_policer_profile(struct cdx_fman_info *finfo, uint32_t queue_no)
{
	void *handle;
	t_FmPcdPlcrProfileParams Params;

	if (queue_no >= INGRESS_ALL_POLICER_QUEUES)
		return FAILURE;


	memset(&Params, 0, sizeof(t_FmPcdPlcrProfileParams));
	Params.modify = 1;
	Params.id.h_Profile = finfo->ingress_policer_info[queue_no].handle;
	Params.algSelection = e_FM_PCD_PLCR_RFC_2698;
	Params.colorMode = e_FM_PCD_PLCR_COLOR_BLIND;
	/*color as red by default */
	Params.color.dfltColor = e_FM_PCD_PLCR_RED;
	/*override color is RED */
	Params.color.override = e_FM_PCD_PLCR_RED;
#ifdef SEC_PROFILE_SUPPORT
	if (queue_no != INGRESS_SEC_POLICER_QUEUE_NUM)
#endif /* endif for SEC_PROFILE_SUPPORT */
	{
		/*set algorithm mode as bytes/sec (kilobits/sec)*/
		/*init default cir and pir values */
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_BYTE_MODE;
		Params.nonPassthroughAlgParams.committedInfoRate = DEFAULT_INGRESS_CIR_VALUE;
		Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_INGRESS_BYTE_MODE_CBS;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = DEFAULT_INGRESS_PIR_VALUE;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_INGRESS_BYTE_MODE_PBS;
		Params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_FULL_FRM_LEN;
		Params.nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN;
	}
#ifdef SEC_PROFILE_SUPPORT
	else /* PACKET_MODE */
	{
		/*set algorithm mode as Packets/sec */
		Params.nonPassthroughAlgParams.rateMode = e_FM_PCD_PLCR_PACKET_MODE;
		Params.nonPassthroughAlgParams.committedInfoRate = DEFAULT_SEC_PROFILE_PKT_MODE_CIR;
		Params.nonPassthroughAlgParams.committedBurstSize = DEFAULT_SEC_PKT_MODE_CBS;
		Params.nonPassthroughAlgParams.peakOrExcessInfoRate = DEFAULT_SEC_PROFILE_PKT_MODE_PIR;
		Params.nonPassthroughAlgParams.peakOrExcessBurstSize = DEFAULT_SEC_PKT_MODE_PBS;
	}
#endif /* endif for SEC_PROFILE_SUPPORT */

	Params.nextEngineOnGreen = e_FM_PCD_CC;
	Params.paramsOnGreen.action = e_FM_PCD_POST_POLICER_PROCES_FRAME;
	Params.nextEngineOnYellow = e_FM_PCD_CC;
	Params.paramsOnYellow.action = e_FM_PCD_POST_POLICER_PROCES_FRAME;
	Params.nextEngineOnRed = e_FM_PCD_DONE;
	Params.paramsOnRed.action = e_FM_PCD_DROP_FRAME;
	handle = FM_PCD_PlcrProfileSet(finfo->pcd_handle, &Params);
	if (!handle) {
		printk("%s::unable to set default values for queue %d\n",
				__FUNCTION__, queue_no);
		return ERR_QM_INGRESS_SET_PROFILE_FAILED;
	}

#ifdef SEC_PROFILE_SUPPORT
	if (queue_no != INGRESS_SEC_POLICER_QUEUE_NUM)
#endif /* endif for SEC_PROFILE_SUPPORT */
	{
		/* init default cir and pir values */
		finfo->ingress_policer_info[queue_no].cir_value = DEFAULT_INGRESS_CIR_VALUE;
		finfo->ingress_policer_info[queue_no].pir_value = DEFAULT_INGRESS_PIR_VALUE;
		finfo->ingress_policer_info[queue_no].cbs = DEFAULT_INGRESS_BYTE_MODE_CBS ;
		finfo->ingress_policer_info[queue_no].pbs = DEFAULT_INGRESS_BYTE_MODE_PBS;
	}
#ifdef SEC_PROFILE_SUPPORT
	else
	{
		/* init default sec profile  cir and pir values */
		finfo->ingress_policer_info[queue_no].cir_value = DEFAULT_SEC_PROFILE_PKT_MODE_CIR;
		finfo->ingress_policer_info[queue_no].pir_value = DEFAULT_SEC_PROFILE_PKT_MODE_PIR;
		finfo->ingress_policer_info[queue_no].cbs = DEFAULT_SEC_PKT_MODE_CBS ;
		finfo->ingress_policer_info[queue_no].pbs = DEFAULT_SEC_PKT_MODE_PBS;
	}
#endif /* endif for SEC_PROFILE_SUPPORT */
#ifdef QOS_DEBUG
	printk("%s::plcr profile set to default for queue %d, handle %p\n",
			__FUNCTION__, queue_no, handle);
#endif
	return SUCCESS;
}

int cdxdrv_enable_or_disable_ingress_policer(struct cdx_fman_info *finfo, uint32_t queue_no,uint32_t oper)
{
	if(oper) {
		if(finfo->ingress_policer_info[queue_no].policer_on == ENABLE_INGRESS_POLICER)
			printk("%s:: Policer already enabled on queue no %d\n",__FUNCTION__,queue_no);
		else {
			finfo->ingress_policer_info[queue_no].policer_on = ENABLE_INGRESS_POLICER;
			return cdxdrv_modify_ingress_qos_policer_profile(finfo,
					queue_no,finfo->ingress_policer_info[queue_no].cir_value,
					finfo->ingress_policer_info[queue_no].pir_value,
					finfo->ingress_policer_info[queue_no].cbs,
					finfo->ingress_policer_info[queue_no].pbs);
		}
	}
	else {
		if (cdxdrv_set_default_qos_policer_profile(finfo,queue_no) == SUCCESS) {
			finfo->ingress_policer_info[queue_no].policer_on = DISABLE_INGRESS_POLICER;
			return SUCCESS;
		}
		return ERR_QM_INGRESS_SET_PROFILE_FAILED;
	}
	return SUCCESS;
}

int cdxdrv_ingress_policer_reset(struct cdx_fman_info *finfo)
{
	uint32_t ii;
	for(ii = 0; ii< INGRESS_FLOW_POLICER_QUEUES; ii++) {
		if(finfo->ingress_policer_info[ii].handle) {
			if (cdxdrv_set_default_qos_policer_profile(finfo,ii)!= SUCCESS)
				printk("%s::plcr reset failed for queue %d, handle %p\n",
						__FUNCTION__, ii, finfo->ingress_policer_info[ii].handle);
			else
				finfo->ingress_policer_info[ii].policer_on = DISABLE_INGRESS_POLICER;
		}
		else
			printk("%s::plcr reset failed as handle is NULL for queue %d\n",
					__FUNCTION__, ii);
	}
	return SUCCESS;
}

#ifdef SEC_PROFILE_SUPPORT
int cdxdrv_sec_policer_reset(struct cdx_fman_info *finfo)
{
	uint32_t queue_no = INGRESS_SEC_POLICER_QUEUE_NUM;

	if(finfo->ingress_policer_info[queue_no].handle) {
		if (cdxdrv_set_default_qos_policer_profile(finfo, queue_no)!= SUCCESS)
			printk("%s::plcr reset failed for sec profile, handle %p\n",
					__FUNCTION__, finfo->ingress_policer_info[queue_no].handle);
		else
			finfo->ingress_policer_info[queue_no].policer_on = DISABLE_INGRESS_POLICER;
	}
	else
		printk("%s::plcr reset failed as handle is NULL for sec profile queue\n",
				__FUNCTION__);
	return SUCCESS;
}
#endif /* endif for SEC_PROFILE_SUPPORT */

int cdxdrv_ingress_policer_query(struct cdx_fman_info *finfo,uint32_t queue_no,void *cfg)
{
	PIngressQosCfgCommand plcr_cfg = (PIngressQosCfgCommand)cfg;

	plcr_cfg->status = finfo->ingress_policer_info[queue_no].policer_on;
	plcr_cfg->cir = finfo->ingress_policer_info[queue_no].cir_value;
	plcr_cfg->pir = finfo->ingress_policer_info[queue_no].pir_value;

#ifdef QOS_DEBUG
	printk("%s::queue %d,status %d cir %d pir %d \n",
			__FUNCTION__, queue_no,plcr_cfg->status,plcr_cfg->cir,plcr_cfg->pir);
#endif
	return SUCCESS;
}

int cdxdrv_ingress_policer_stats(struct cdx_fman_info *finfo,uint32_t queue_no,void *stats,uint32_t clear)
{

	pIngressQosStat plcr_stats = (pIngressQosStat)stats;

	if(finfo->ingress_policer_info[queue_no].policer_on == ENABLE_INGRESS_POLICER)
		get_plcr_counter(finfo->ingress_policer_info[queue_no].handle, &plcr_stats->counterval[0],clear);

	plcr_stats->policer_on = finfo->ingress_policer_info[queue_no].policer_on;
	plcr_stats->cir = finfo->ingress_policer_info[queue_no].cir_value;
	plcr_stats->pir = finfo->ingress_policer_info[queue_no].pir_value;
	plcr_stats->cbs = finfo->ingress_policer_info[queue_no].cbs;
	plcr_stats->pbs = finfo->ingress_policer_info[queue_no].pbs;

#ifdef QOS_DEBUG
	printk("%s:: queue %d policer_on %d red %d yellow %d, green %d red recolored %d, yellow recolored %d\n",
			__FUNCTION__,queue_no,plcr_stats->policer_on,plcr_stats->counterval[RED_TOTAL],
			plcr_stats->counterval[YELLOW_TOTAL],plcr_stats->counterval[GREEN_TOTAL],
			plcr_stats->counterval[RED_RECOLORED],plcr_stats->counterval[YELLOW_RECOLORED]);
#endif

	return SUCCESS;
}
#endif
