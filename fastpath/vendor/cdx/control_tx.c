/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include "cdx.h"
#include "control_tx.h"
#include "misc.h"


char IF0_NAME[16] = TOSTR(DEFAULT_NAME_0);
char IF1_NAME[16] = TOSTR(DEFAULT_NAME_1);
char IF2_NAME[16] = TOSTR(DEFAULT_NAME_2);

DSCP_Vlan_PCP_Map_context gDscpVlanPcpMapCtx;

bool cdx_get_tx_dscp_vlanpcp_map_enable(uint32_t portid)
{
	return gDscpVlanPcpMapCtx.portid == portid ? 1 : 0;
}

static U16 update_port_dscp_vlan_pcp_map_cfg(uint8_t *ifname, uint8_t dscp, uint8_t vlan_pcp)
{
	struct cdx_port_info *port_info;

	port_info = get_dpa_port_info(ifname);
	if (!port_info)
	{
		DPA_ERROR("%s()::%d invalid interface name <%s>\n", __func__, __LINE__, ifname);
		return CMD_ERR;
	}

	if (gDscpVlanPcpMapCtx.portid == NO_TX_PORT)
	{
		DPA_ERROR("DSCP VLANPCP map is disabled on %s, first enable to configure it\n" , ifname);
		return CMD_OK;
	}
	if (gDscpVlanPcpMapCtx.portid != port_info->portid)
	{
		DPA_ERROR("To configure DSCP VLAN PCP mapping on %s, first disable on %s\n",
				 	ifname, get_dpa_port_name(gDscpVlanPcpMapCtx.portid));
		return CMD_OK;
	}
	if (set_dscp_vlan_pcp_map_cfg(dscp, vlan_pcp) != SUCCESS)
	{
		DPA_ERROR("%s (%d) failed to set DSCP VLAN PCP map cfg in muram memory\n", __func__,__LINE__);
		return CMD_ERR;
	}

	return CMD_OK;
}

static U16 update_port_dscp_vlan_pcp_map_status(uint8_t *ifname, uint8_t status)
{
	struct cdx_port_info *port_info;

	port_info = get_dpa_port_info(ifname);
	if (!port_info)
	{
		DPA_ERROR("%s()::%d invalid interface name <%s>\n", __func__, __LINE__, ifname);
		return CMD_ERR;
	}

	if (gDscpVlanPcpMapCtx.portid == NO_TX_PORT)
	{ 
		if (status == DSCP_VLAN_PCP_MAP_ENABLE)
		{
			if (reset_dscp_vlan_pcp_map_cfg() != SUCCESS)
			{
				DPA_ERROR("%s (%d) unable to enable DSCP VLAN PCP mapping on %s.\n",
									__func__,__LINE__, ifname);
				return CMD_ERR;
			}
			gDscpVlanPcpMapCtx.portid = (int32_t)port_info->portid;
		}
		else
		{
			DPA_ERROR("DSCP VLAN PCP mapping is already disabled on %s.\n", ifname);
			return CMD_OK;
		}
	}
	else if (gDscpVlanPcpMapCtx.portid == port_info->portid)
	{
		if (status == DSCP_VLAN_PCP_MAP_DISABLE)
		{
			if (reset_dscp_vlan_pcp_map_cfg() != SUCCESS)
			{
				DPA_ERROR("%s (%d) unable to disable DSCP VLAN PCP mapping on %s.\n",
									__func__,__LINE__, ifname);
				return CMD_ERR;
			}
			gDscpVlanPcpMapCtx.portid = NO_TX_PORT;
		}
		else
		{
			DPA_ERROR("DSCP VLAN PCP mapping on %s already enabled\n", ifname);
			return CMD_OK;
		}
	
	}
	else
	{
		DPA_ERROR("To configure DSCP VLAN PCP mapping on %s, first disable on %s\n",
				 	ifname, get_dpa_port_name(gDscpVlanPcpMapCtx.portid));
		return CMD_OK;
	}
	return CMD_OK;
}

static U16 get_port_dscp_vlan_pcp_map_cfg(PQueryDSCPVlanPCPMapCmd pCmd)
{
	struct cdx_port_info *port_info;

	port_info = get_dpa_port_info(pCmd->ifname);
	if (!port_info)
	{
		DPA_ERROR("%s()::%d invalid interface name <%s>\n", __func__, __LINE__, pCmd->ifname);
		return CMD_ERR;
	}

	pCmd->enable = DSCP_VLAN_PCP_MAP_DISABLE;
	if (gDscpVlanPcpMapCtx.portid == NO_TX_PORT)
	{
		DPA_INFO("DSCP VLAN PCP map is disabled on all ports.\n");
		return CMD_OK;
	}
	if (gDscpVlanPcpMapCtx.portid != port_info->portid)
	{
		DPA_INFO("DSCP VLAN PCP map is disabled on %s port and enabled on %s port.\n",
					pCmd->ifname, get_dpa_port_name(gDscpVlanPcpMapCtx.portid ));
		return CMD_OK;
	}
	pCmd->enable = DSCP_VLAN_PCP_MAP_ENABLE;

	if (get_dscp_vlan_pcp_map_cfg(pCmd) != SUCCESS)
	{
		DPA_ERROR("%s (%d) Failed to get DSCP VLAN PCP map configuration on port %s.\n",
					__func__,__LINE__, pCmd->ifname);
		return CMD_ERR;
	}

	return CMD_OK;
}

static void M_tx_port_update(PPortUpdateCommand cmd)
{
	char *if_name = get_onif_name(phy_port[cmd->portid].itf.index);

	strncpy(if_name, cmd->ifname, INTERFACE_NAME_LENGTH);
	if_name[INTERFACE_NAME_LENGTH - 1] = '\0';
}

static U16 M_tx_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U32 portid;
	U16 rc;
	U16 retlen = 2;

	portid = *pcmd;

	if (cmd_code < CMD_TX_DSCP_VLANPCP_MAP_STATUS) {
		if (portid >= GEM_PORTS) {
			rc = CMD_ERR;
			goto out;
		}
	}

	switch (cmd_code)
	{
	case CMD_TX_ENABLE:
		if (cmd_len > 2) {
			if (cmd_len > 14) {
				memcpy(phy_port[portid].mac_addr, &(((U8*)pcmd)[14]), 6);
				phy_port[portid].flags |= TX_ENABLED;
			}
		}

		rc = CMD_OK;
		break;

	case CMD_TX_DISABLE:
		phy_port[portid].flags &= ~TX_ENABLED;
#ifdef CDX_TODO_TX
		/*Reset tx enable flag in class and Util for this physical port*/
		for (id = CLASS0_ID; id <= CLASS_MAX_ID; id++)
			pe_dmem_writeb(id, phy_port[portid].flags, virt_to_class_dmem(&phy_port[portid].flags));
		pe_dmem_writeb(UTIL_ID, phy_port[portid].flags, virt_to_util_dmem(&util_phy_port[portid].flags));
#endif

		rc = CMD_OK;
		break;

	case CMD_PORT_UPDATE:

		/* Update the port info in the onif */
		M_tx_port_update((PPortUpdateCommand)pcmd);
		rc = CMD_OK;
		break;

	case CMD_TX_DSCP_VLANPCP_MAP_STATUS:
		{
			PDSCPVlanPCPMapCmd  pMapCmd = (PDSCPVlanPCPMapCmd)pcmd;

			rc = update_port_dscp_vlan_pcp_map_status(pMapCmd->ifname, 
							pMapCmd->status);
		}
		break;

	case CMD_TX_DSCP_VLANPCP_MAP_CFG:
		{
			PDSCPVlanPCPMapCmd  pMapCmd = (PDSCPVlanPCPMapCmd)pcmd;

			rc = update_port_dscp_vlan_pcp_map_cfg(pMapCmd->ifname, 
							pMapCmd->dscp, pMapCmd->vlan_pcp);
		}
		break;

	case CMD_TX_QUERY_IFACE_DSCP_VLANPCP_MAP:
		{
			PQueryDSCPVlanPCPMapCmd  pQueryCmd = (PQueryDSCPVlanPCPMapCmd)pcmd;

			if ((rc = get_port_dscp_vlan_pcp_map_cfg(pQueryCmd)) == CMD_OK)
				retlen = sizeof(QueryDSCPVlanPCPMapCmd);
		}
		break;

	default:
		rc = CMD_ERR;
		break;
	}

out:
	*pcmd = rc;
	return retlen;
}


int tx_init(void)
{
	int i;

	set_cmd_handler(EVENT_PKT_TX, M_tx_cmdproc);

	for (i = 0; i < MAX_PHY_PORTS; i++) {
		phy_port[i].id = i;
	}

#ifdef CDX_TODO
	add_onif((U8 *)IF0_NAME, &phy_port[0].itf, NULL, IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
	add_onif((U8 *)IF1_NAME, &phy_port[1].itf, NULL, IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
	add_onif((U8 *)IF2_NAME, &phy_port[2].itf, NULL, IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
#endif

#ifdef CDX_TODO_BRIDGE
	/* Register interfaces with bridge */
	bridge_interface_register((U8 *) IF0_NAME, 0);
	bridge_interface_register((U8 *) IF1_NAME, 1);
	bridge_interface_register((U8 *) IF2_NAME, 2);
#endif

	gDscpVlanPcpMapCtx.portid = NO_TX_PORT;

	return 0;
}

void tx_exit(void)
{
	int i;

	for (i = 0; i < GEM_PORTS; i++)
		remove_onif_by_index(phy_port[i].itf.index);
}
