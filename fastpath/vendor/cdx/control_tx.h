/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_TX_H_
#define _CONTROL_TX_H_

#define DEFAULT_NAME_0		eth0
#define DEFAULT_NAME_1		eth2
#define DEFAULT_NAME_2		eth3

#define NO_TX_PORT			-1
#define MAX_VLAN_PCP			7
#define DSCP_VLAN_PCP_MAP_ENABLE	1
#define DSCP_VLAN_PCP_MAP_DISABLE	0

typedef struct _tPortUpdateCommand {
	U16 portid;
	char ifname[IF_NAME_SIZE];
} PortUpdateCommand, *PPortUpdateCommand;

/*
 * This structure to map the dscp with vlan p bit on an interface.
*/
typedef struct _tDSCPVlanPCPMapCmd {
	uint8_t vlan_pcp;		/* VLAN P bit value(VLAN priority code point (PCP)) */
	uint8_t dscp;			/* DSCP 3 most significant bits value */
	uint8_t status;			/* Status of DSCP to VLAN PCP mapping. Enable/Disable. */
	uint8_t unused;			/* unused byte */
	uint8_t ifname[IF_NAME_SIZE];	/* interface name. */
} __attribute__((__packed__)) DSCPVlanPCPMapCmd, *PDSCPVlanPCPMapCmd;

/*
 * This structure to get dscp vlan pcp map status on given interface
 * and if it is enable it gets the each dscp mapped vlan pcp configuration.
*/
typedef struct _tQueryDSCPVlanPCPMapCmd {
	uint16_t	status;				/* query command status. */
	uint8_t		reserved;
	uint8_t 	enable;				/* dscp vlan pcp mapping enable or disable on interface. */
	uint8_t		ifname[IF_NAME_SIZE];		/* interface name */
	uint8_t		vlan_pcp[MAX_VLAN_PCP + 1];	/* DSCP mapped vlan pcp */
} __attribute__((__packed__)) QueryDSCPVlanPCPMapCmd, *PQueryDSCPVlanPCPMapCmd;

typedef struct tDSCP_Vlan_PCP_Map_context {
	int32_t			portid;
} __attribute__((aligned(32))) DSCP_Vlan_PCP_Map_context, *PDSCP_Vlan_PCP_Map_context;


int tx_init(void);
void tx_exit(void);

int get_dscp_vlan_pcp_map_cfg(PQueryDSCPVlanPCPMapCmd pDscpVlanPcpMap);
int set_dscp_vlan_pcp_map_cfg(uint8_t dscp, uint8_t vlan_pcp);
int reset_dscp_vlan_pcp_map_cfg(void);
bool cdx_get_tx_dscp_vlanpcp_map_enable(uint32_t portid);

#endif /* _CONTROL_TX_H_ */

