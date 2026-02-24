/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "portdefs.h"
#include "cdx.h"
#include "control_stat.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_socket.h"
#include "control_bridge.h"
#include "control_tunnel.h"
#include "control_ipsec.h"
#include "control_pppoe.h"
#include "control_vlan.h"
#include "misc.h"

#define MAX_QUERY_TIMER_VAL 900
extern spinlock_t dpa_devlist_lock;
int stat_Get_Next_SAEntry(PStatIpsecEntryResponse pSACmd, int reset_action);
void reset_stats_of_sa(PSAEntry pEntry);
extern int fmdev_get_port_base_addr(struct device *dev, uint32_t *base);
int gStatIpsecQueryStatus;
int gIPSecStatQueryTimer;

U16 dpa_iface_stats_get( struct dpa_iface_info *iface_info, struct iface_stats *ifstats)
{
	if (!(iface_info->if_flags & IF_STATS_ENABLED))
	{
		DPA_ERROR("%s:: iface stats not enabled if_flags 0x%x\n", __FUNCTION__, iface_info->if_flags);
		return ERR_STAT_FEATURE_NOT_ENABLED;
	}

	if(iface_info->if_flags & IF_TYPE_PPPOE) {
		struct en_ehash_ifstats_with_ts *stats;

		stats = (struct en_ehash_ifstats_with_ts *)iface_info->stats;
		ifstats->rx_packets = cpu_to_be32(stats->rxstats.pkts);
		ifstats->tx_packets = cpu_to_be32(stats->txstats.pkts);
		ifstats->rx_bytes = cpu_to_be64(stats->rxstats.bytes);
		ifstats->tx_bytes = cpu_to_be64(stats->txstats.bytes);
	} 
	else if(iface_info->if_flags & (IF_TYPE_TUNNEL | IF_TYPE_VLAN | IF_TYPE_ETHERNET)) {
		struct en_ehash_ifstats *stats;

		stats = (struct en_ehash_ifstats *)iface_info->stats;
		ifstats->rx_packets = cpu_to_be32(stats->rxstats.pkts);
		ifstats->tx_packets = cpu_to_be32(stats->txstats.pkts);
		ifstats->rx_bytes = cpu_to_be64(stats->rxstats.bytes);
		ifstats->tx_bytes = cpu_to_be64(stats->txstats.bytes);
	}
	else
	{
		DPA_ERROR("%s:: Invalid interface type 0x%x\n", __FUNCTION__, iface_info->if_flags);
		return ERR_INVALID_INTERFACE_TYPE;
	}

	return NO_ERR;
}

void  dpa_iface_stats_reset(struct dpa_iface_info *iface_info, struct iface_stats *stats)
{
	struct iface_stats *last_stats;

	last_stats = iface_info->last_stats;
	last_stats->rx_packets = stats->rx_packets;
	last_stats->tx_packets = stats->tx_packets;
	last_stats->rx_bytes = stats->rx_bytes;
	last_stats->tx_bytes = stats->tx_bytes;

	return;
}

U16 interface_stats_reset(uint32_t interface)
{
	struct dpa_iface_info *iface_info;
	struct iface_stats ifstats;
	U16 ret = 0;

	spin_lock(&dpa_devlist_lock);
	if ((iface_info = dpa_get_ifinfo_by_itfid(interface)) == NULL)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to find the interface index 0x%x\n", __FUNCTION__, interface);
		return ERR_UNKNOWN_INTERFACE;
	}
	spin_unlock(&dpa_devlist_lock);
	if ((ret = dpa_iface_stats_get(iface_info, &ifstats)) != NO_ERR)
	{
		DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __FUNCTION__, ret);
		return ret;
	}
	dpa_iface_stats_reset(iface_info, &ifstats);

	return NO_ERR;
}

static U16 phyif_stats_get(U16 interface, PStatInterfacePktResponse rsp, U8 do_reset)
{
	struct iface_stats ifstats;
	struct dpa_iface_info *iface_info = NULL;
	struct iface_stats *last_stats;
	U16 ret = 0;

	spin_lock(&dpa_devlist_lock);
	if ((iface_info = dpa_get_ifinfo_by_itfid((uint32_t)interface)) == NULL)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to find the interface index 0x%x\n", __FUNCTION__, interface);
		return ERR_UNKNOWN_INTERFACE;
	}
	spin_unlock(&dpa_devlist_lock);
	if ((ret = dpa_iface_stats_get(iface_info, &ifstats)) != NO_ERR)
	{
		DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __FUNCTION__, ret);
		return ret;
	}
	
	last_stats = iface_info->last_stats;
	rsp->total_bytes_received[0] = statistics_get_lsb(ifstats.rx_bytes - last_stats->rx_bytes);
	rsp->total_bytes_received[1] = statistics_get_msb(ifstats.rx_bytes - last_stats->rx_bytes);
	rsp->total_pkts_received = ifstats.rx_packets - last_stats->rx_packets;

	rsp->total_bytes_transmitted[0] = statistics_get_lsb(ifstats.tx_bytes - last_stats->tx_bytes);
	rsp->total_bytes_transmitted[1] = statistics_get_msb(ifstats.tx_bytes - last_stats->tx_bytes);
	rsp->total_pkts_transmitted = ifstats.tx_packets - last_stats->tx_packets;

	if (do_reset)
		dpa_iface_stats_reset(iface_info, &ifstats);
	return NO_ERR;
}


static U16 stats_interface_pkt(U8 action, U16 interface, PStatInterfacePktResponse statInterfacePktRsp, U16 *acklen)
{
	U16 ackstatus = CMD_OK;

	if(action & FPP_STAT_QUERY)
	{
		if ((ackstatus = phyif_stats_get(interface, statInterfacePktRsp,
							action & FPP_STAT_RESET)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to get interface(%d) stats, return value %d\n", __FUNCTION__, interface, ackstatus);
			return ackstatus;
		}

		statInterfacePktRsp->rsvd1 = 0;
		*acklen = sizeof(StatInterfacePktResponse);
	}
	else if(action & FPP_STAT_RESET)
	{
		if ((ackstatus = interface_stats_reset((uint32_t)interface)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to reset interface(%d) stats, return value %d\n", __FUNCTION__, interface, ackstatus);
			return ackstatus;
		}
	}
	else
		ackstatus = ERR_WRONG_COMMAND_PARAM;

	return ackstatus;
}



static U16 stats_connection(U16 action, PStatConnResponse statConnRsp, U16 *acklen)
{
	U16 ackstatus = CMD_OK;

	if(action & FPP_STAT_QUERY)
	{
		statConnRsp->num_active_connections = atomic_read(&num_active_connections);
		*acklen = sizeof(StatConnResponse);
	}
	else
		ackstatus = ERR_WRONG_COMMAND_PARAM;

	return ackstatus;
}


U32 stats_bitmask_enable_g = STAT_IPSEC_BITMASK;

void stat_ct_flow_get(struct hw_ct *ct, U64 *pkts, U64 *bytes, int do_reset)
{
	if (!ct)
	{
		*pkts = 0;
		*bytes = 0;
		return;
	}
	hw_ct_get_active(ct);
	*pkts = ct->pkts - ct->reset_pkts;
	*bytes = ct->bytes - ct->reset_bytes;
	if (do_reset)
	{
		ct->reset_pkts = ct->pkts;
		ct->reset_bytes = ct->bytes;
	}
}

void stat_ct_flow_reset(struct hw_ct *ct)
{
	U64 pkts;
	U64 bytes;

	stat_ct_flow_get(ct, &pkts, &bytes, TRUE);

	return;
}

/**
 * This function resets all IPv4 and IPv6 connections statistics counters
 */
static void ResetAllFlowStats(void)
{
	PCtEntry pCtEntry;
	struct slist_entry *entry;
	int ct_hash_index;

	for (ct_hash_index = 0; ct_hash_index < NUM_CT_ENTRIES; ct_hash_index++)
	{
		slist_for_each(pCtEntry, entry, &ct_cache[ct_hash_index], list)
		{
			stat_ct_flow_reset(pCtEntry->ct);
		}
	}
}

static U16 Get_Flow_stats(PStatFlowEntryResp flowStats, int do_reset)
{
	PCtEntry pEntry;

	if (flowStats->ip_family == 4)
	{
		pEntry = IPv4_find_ctentry(flowStats->Saddr, flowStats->Daddr, flowStats->Sport, flowStats->Dport, flowStats->Protocol);
		if (!pEntry)
		{
			printk("No connection for flow: saddr=%pI4 daddr=%pI4 sport=%u dport=%u proto=%u\n",
					&flowStats->Saddr, &flowStats->Daddr, htons(flowStats->Sport), htons(flowStats->Dport), flowStats->Protocol);
			return ERR_FLOW_ENTRY_NOT_FOUND;
		}
		stat_ct_flow_get(pEntry->ct, &flowStats->TotalPackets, &flowStats->TotalBytes, do_reset);
	}
	else if (flowStats->ip_family == 6)
	{
		pEntry = IPv6_find_ctentry(flowStats->Saddr_v6, flowStats->Daddr_v6, flowStats->Sport, flowStats->Dport, flowStats->Protocol);
		if (!pEntry)
		{
			printk("No connection for flow: saddr=%pI6c daddr=%pI6c sport=%u dport=%u proto=%u\n",
					flowStats->Saddr_v6, flowStats->Daddr_v6, htons(flowStats->Sport), htons(flowStats->Dport), flowStats->Protocol);
			return ERR_FLOW_ENTRY_NOT_FOUND;
		}
		stat_ct_flow_get(pEntry->ct, &flowStats->TotalPackets, &flowStats->TotalBytes, do_reset);
	}
	else
	{
		printk("ERROR: Invalid IP address family <0x%x>\n", flowStats->ip_family);
		return ERR_INVALID_IP_FAMILY;
	}

	return NO_ERR;
}

/**
 * M_stat_cmdproc
 *
 *
 *
 */
static U16 M_stat_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 acklen;
	U16 ackstatus;
	U16 action;

	acklen = 2;
	ackstatus = CMD_OK;

	switch (cmd_code)
	{

	case CMD_STAT_ENABLE:
	{
		StatEnableCmd statcmd;

		memcpy((U8*)&statcmd, (U8*)pcmd, sizeof(StatEnableCmd));

		if (statcmd.action == 1) /* ENABLE */
		{
			stats_bitmask_enable_g |= statcmd.bitmask;
		}
		else /*DISABLE */
		{
			if (statcmd.bitmask & STAT_IPSEC_BITMASK)
			{
				printk("ERROR: Disable IPSec stats not allowed. Because it disables ESP Sequence overfow rekeying.\n");
				ackstatus = ERR_STAT_FEATURE_NOT_ALLOWED_TO_DISABLE;
				goto end;
			}
			stats_bitmask_enable_g &= ~(statcmd.bitmask);
		}

		break;
	}

	case CMD_STAT_INTERFACE_PKT:
	{
		U16 interface;
		StatInterfaceCmd intPktCmd;
		PStatInterfacePktResponse statInterfacePktRsp;

		if (!(stats_bitmask_enable_g & STAT_INTERFACE_BITMASK))
		{
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
			goto end;
		}

		/* Ensure alignment */
		memcpy((U8*)&intPktCmd, (U8*)pcmd, sizeof(StatInterfaceCmd));
		interface = intPktCmd.interface;
		action = intPktCmd.action;
		statInterfacePktRsp = (PStatInterfacePktResponse)pcmd;
		ackstatus = stats_interface_pkt(action, interface, statInterfacePktRsp, &acklen);
		break;
	}

	case CMD_STAT_CONN:
	{
		StatConnectionCmd connCmd;
		PStatConnResponse statConnRsp;
		
		// Ensure alignment
		memcpy((U8*)&connCmd, (U8*)pcmd, sizeof(StatConnectionCmd));
		action = connCmd.action;
		statConnRsp = (PStatConnResponse)pcmd;
		ackstatus = stats_connection(action, statConnRsp, &acklen);
		break;
	}
	
	case CMD_STAT_PPPOE_STATUS:
	{
		int x;
		struct slist_entry *entry;
		pPPPoE_Info pEntry;
		StatPPPoEStatusCmd pppoeStatusCmd;

		if (!(stats_bitmask_enable_g & STAT_PPPOE_BITMASK))
		{
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
			goto end;
		}

		/* Ensure alignment */
		memcpy((U8*)&pppoeStatusCmd, (U8*)pcmd, sizeof(StatPPPoEStatusCmd));

		action = pppoeStatusCmd.action;

		if (action == FPP_STAT_RESET)
		{
			/* Reset the packet counters for all PPPoE Entries */
			for (x = 0; x < NUM_PPPOE_ENTRIES; x++)
			{
				slist_for_each(pEntry, entry, &pppoe_cache[x], list)
					if ((ackstatus = interface_stats_reset((uint32_t)pEntry->itf.index)) != NO_ERR)
					{
						DPA_ERROR("%s:: Failed to reset the pppoe stats.\n", __FUNCTION__);
						goto end;
					}
			}
		}
		else if ((action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			gStatPPPoEQueryStatus = 0;
			if (action == FPP_STAT_QUERY_RESET)
				gStatPPPoEQueryStatus |= STAT_PPPOE_QUERY_RESET;

			ackstatus = stat_PPPoE_Get_Next_SessionEntry((PStatPPPoEEntryResponse)pcmd, 1);
		}
		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;
		break;
	}


	case CMD_STAT_PPPOE_ENTRY:{
		int result;

		PStatPPPoEEntryResponse prsp = (PStatPPPoEEntryResponse)pcmd;

		if (stats_bitmask_enable_g & STAT_PPPOE_BITMASK)
		{
			result = stat_PPPoE_Get_Next_SessionEntry(prsp, 0);
			if (result != NO_ERR)
			{
				prsp->eof = 1;
			}

			acklen = sizeof(StatPPPoEEntryResponse);
		}
		else
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
		break;
	}


	case CMD_STAT_BRIDGE_STATUS:
	{
		ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
		break;
	}


	case CMD_STAT_BRIDGE_ENTRY:
	{
		
		ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
		break;
	}

	case CMD_STAT_VLAN_STATUS:
	{
		int x;
		PVlanEntry pEntry;
		struct slist_entry *entry;
		StatVlanStatusCmd vlanStatusCmd;	

		if (!(stats_bitmask_enable_g & STAT_VLAN_BITMASK))
		{
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
			goto end;
		}

		/* Ensure alignment */
		memcpy((U8*)&vlanStatusCmd, (U8*)pcmd, sizeof(StatVlanStatusCmd));

		action = vlanStatusCmd.action;

		if (action == FPP_STAT_RESET)
		{
			/* Reset the packet counters for all VLAN Entries */
			for (x = 0; x < NUM_VLAN_ENTRIES; x++)
			{
				slist_for_each(pEntry, entry, &vlan_cache[x], list)
					if ((ackstatus = interface_stats_reset((uint32_t)pEntry->itf.index)) != NO_ERR)
					{
						DPA_ERROR("%s:: Failed to reset the vlan stats.\n", __FUNCTION__);
						goto end;
					}
			}
		}
		else if ((action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			gStatVlanQueryStatus = 0;
			if (action == FPP_STAT_QUERY_RESET)
				gStatVlanQueryStatus |= STAT_VLAN_QUERY_RESET;

			ackstatus = stat_VLAN_Get_Next_SessionEntry((PStatVlanEntryResponse)pcmd, 1);
		}
		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;

		break;
	}


	case CMD_STAT_VLAN_ENTRY:
	{
		int result;
		
		PStatVlanEntryResponse prsp = (PStatVlanEntryResponse)pcmd;

		if (stats_bitmask_enable_g & STAT_VLAN_BITMASK)
		{
			result = stat_VLAN_Get_Next_SessionEntry(prsp, 0);
			if (result != NO_ERR)
			{
				prsp->eof = 1;
			}

			acklen = sizeof(StatVlanEntryResponse);
		}
		else
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
		break;
	}

	case CMD_STAT_TUNNEL_STATUS:
	{
		int x;
		PTnlEntry pEntry;
		struct slist_entry *entry;
		StatTunnelStatusCmd tunnelStatusCmd;

		if (!(stats_bitmask_enable_g & STAT_TUNNEL_BITMASK))
		{
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
			goto end;
		}

		/* Ensure alignment */
		memcpy((U8*)&tunnelStatusCmd, (U8*)pcmd, sizeof(StatTunnelStatusCmd));

		action = tunnelStatusCmd.action;
		if (action == FPP_STAT_RESET)
		{
			/* Reset the packet counters for all Tunnel Entries */
			for (x = 0; x < NUM_TUNNEL_ENTRIES; x++)
			{
				slist_for_each(pEntry, entry, &tunnel_name_cache[x], list)
					if ((ackstatus = interface_stats_reset((uint32_t)pEntry->itf.index)) != NO_ERR)
					{
						DPA_ERROR("%s:: Failed to reset the tunnel stats.\n", __FUNCTION__);
						goto end;
					}
			}
		}
		else if ((action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			gStatTunnelQueryStatus = 0;
			if (action == FPP_STAT_QUERY_RESET)
				gStatTunnelQueryStatus |= STAT_TUNNEL_QUERY_RESET;

			ackstatus = stat_tunnel_Get_Next_SessionEntry((PStatTunnelEntryResponse)pcmd, 1);
		}
		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;
		break;
	}


	case CMD_STAT_TUNNEL_ENTRY:
	{
		int result;

		PStatTunnelEntryResponse prsp = (PStatTunnelEntryResponse)pcmd;

		if (stats_bitmask_enable_g & STAT_TUNNEL_BITMASK)
		{
			result = stat_tunnel_Get_Next_SessionEntry(prsp, 0);
			if (result != NO_ERR)
			{
				prsp->eof = 1;
			}
			acklen = sizeof(StatTunnelEntryResponse);
		}
		else
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
		break;
	}

#ifdef DPA_IPSEC_OFFLOAD 
	case CMD_STAT_IPSEC_STATUS:
	{
		int x;
		PSAEntry pEntry;
		struct slist_entry *entry;
		StatIpsecStatusCmd ipsecStatusCmd;

		if (!(stats_bitmask_enable_g & STAT_IPSEC_BITMASK))
		{
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
			goto end;
		}

		/* Ensure alignment */
		memcpy((U8*)&ipsecStatusCmd, (U8*)pcmd, sizeof(StatIpsecStatusCmd));

		action = ipsecStatusCmd.action;
		/* Setting sequence number overflow query check interval time. */
		if (ipsecStatusCmd.iQueryTimerVal > MAX_QUERY_TIMER_VAL)
		{
			ackstatus = ERR_WRONG_COMMAND_PARAM;
			goto end;
		}
		gIPSecStatQueryTimer = ipsecStatusCmd.iQueryTimerVal;

		if(action == FPP_STAT_RESET)
		{
			/* Reset the packet counter for all SA Entries */
			for(x=0; x<NUM_SA_ENTRIES;x++) {

				slist_for_each(pEntry, entry, &sa_cache_by_h[x], list_h)
				{
					reset_stats_of_sa(pEntry);
				}
			}

		}
		else if( (action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			gStatIpsecQueryStatus = 0;

			if(action == FPP_STAT_QUERY_RESET)
			{
				gStatIpsecQueryStatus |= STAT_IPSEC_QUERY_RESET;
			}

			/* This function just initializes the static variables and returns */
			stat_Get_Next_SAEntry((PStatIpsecEntryResponse)pcmd, 1);

		}

		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;
		break;
	}
	case CMD_STAT_IPSEC_ENTRY:
	{
		int  result;
		/*PSAEntry pEntry;*/
		PStatIpsecEntryResponse prsp = (PStatIpsecEntryResponse)pcmd;

		if (stats_bitmask_enable_g & STAT_IPSEC_BITMASK)
		{
			result = stat_Get_Next_SAEntry(prsp, 0);
			if (result != NO_ERR)
			{
				prsp->eof = 1;
			}

			acklen = sizeof(StatIpsecEntryResponse);
		}
		else
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;


                break;
        }
#endif

	case CMD_STAT_FLOW:
	{
		StatFlowStatusCmd flowEntryCmd;
		PStatFlowEntryResp pflowEntryResp;
		int i;

		if (!(stats_bitmask_enable_g & STAT_FLOW_BITMASK))
		{
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
			goto end;
		}
		memcpy((U8*)&flowEntryCmd, (U8*)pcmd, sizeof(StatFlowStatusCmd));
		pflowEntryResp = (PStatFlowEntryResp)pcmd;

		action = flowEntryCmd.action;
		if (action == FPP_STAT_RESET)
		{
			ResetAllFlowStats();	/* Reset the statistics for all IPv4/IPv6 Entries */	
		}
		else if ((action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			pflowEntryResp->ip_family = flowEntryCmd.ip_family;
			if (pflowEntryResp->ip_family == 4)
			{
				pflowEntryResp->Saddr = flowEntryCmd.Saddr;
				pflowEntryResp->Daddr = flowEntryCmd.Daddr;
			}
			else
			{
				for (i = 0; i < 4; i++)
				{
					pflowEntryResp->Saddr_v6[i] = flowEntryCmd.Saddr_v6[i];
					pflowEntryResp->Daddr_v6[i] = flowEntryCmd.Daddr_v6[i];
				}
			}
			pflowEntryResp->Sport = flowEntryCmd.Sport;
			pflowEntryResp->Dport = flowEntryCmd.Dport;
			pflowEntryResp->Protocol = flowEntryCmd.Protocol;
			if ((ackstatus = Get_Flow_stats(pflowEntryResp, action == FPP_STAT_QUERY_RESET)) == NO_ERR)
				acklen = sizeof(StatFlowEntryResp);
		}
		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;
		break;
	}
	
	case FPP_CMD_IPR_V4_STATS:
		{
			int rc;
			rc = cdx_get_ipr_v4_stats((void *)pcmd);
			if (rc  == -1)
				ackstatus = ERR_WRONG_COMMAND_PARAM;		
			else
				acklen = (U16)rc;

		}
		break;

	case FPP_CMD_IPR_V6_STATS:
		{
			int rc;
			rc = cdx_get_ipr_v6_stats((void *)pcmd);
			if (rc  == -1)
				ackstatus = ERR_WRONG_COMMAND_PARAM;		
			else
				acklen = (U16)rc;
		}
		break;
	default:
		ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
		break;
	}

end:
	*pcmd = ackstatus;
	return acklen;
}


int statistics_init(void)
{
	set_cmd_handler(EVENT_STAT, M_stat_cmdproc);

	return 0;
}

void statistics_exit(void)
{

}


