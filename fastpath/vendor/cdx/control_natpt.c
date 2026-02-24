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
#include "control_socket.h"
#include "control_natpt.h"


int NATPT_Open(U16 *p, U16 Length)
{
	NATPTOpenCommand OpenCmd;
	PSockEntry pSocketA;
	PSockEntry pSocketB;
	PCT_PAIR ppair;
	PCtEntry pEntry_6to4, pEntry_4to6;

	// Check length
	if (Length != sizeof(NATPTOpenCommand))
		return ERR_WRONG_COMMAND_SIZE;
	// Ensure alignment
	memcpy((U8*)&OpenCmd, (U8*)p, sizeof(NATPTOpenCommand));

	// Make sure sockets exist but are unused
	pSocketA = SOCKET_find_entry_by_id(OpenCmd.socketA);
	pSocketB = SOCKET_find_entry_by_id(OpenCmd.socketB);
	if (!pSocketA || !pSocketB)
		return ERR_SOCKID_UNKNOWN;
	if (pSocketA->owner || pSocketB->owner)
		return ERR_SOCK_ALREADY_IN_USE;

	// Socket A must be IPv6, and Socket B must be IPv4
	if (pSocketA->SocketFamily != PROTO_IPV6 || pSocketB->SocketFamily != PROTO_IPV4)
		return ERR_WRONG_SOCK_FAMILY;

	pEntry_6to4 = IPv6_find_ctentry(pSocketA->Saddr_v6, pSocketA->Daddr_v6, pSocketA->Sport, pSocketA->Dport, pSocketA->proto);
	pEntry_4to6 = IPv4_find_ctentry(pSocketB->Saddr_v4, pSocketB->Daddr_v4, pSocketB->Sport, pSocketB->Dport, pSocketB->proto);
	if (pEntry_6to4 || pEntry_4to6)
		return ERR_CT_ENTRY_ALREADY_REGISTERED; //trying to add exactly the same conntrack

	if ((ppair = ct_alloc()) == NULL)
	{
		return ERR_NOT_ENOUGH_MEMORY;
	}
	pEntry_6to4 = &ppair->orig;
	pEntry_4to6 = &ppair->repl;

	pEntry_6to4->fftype = FFTYPE_IPV6 | FFTYPE_NATPT;
	pEntry_6to4->hash = HASH_CT6(pSocketA->Saddr_v6, pSocketA->Daddr_v6, pSocketA->Sport, pSocketA->Dport, pSocketA->proto);
	memcpy(pEntry_6to4->Daddr_v6, pSocketA->Daddr_v6, IPV6_ADDRESS_LENGTH);
	memcpy(pEntry_6to4->Saddr_v6, pSocketA->Saddr_v6, IPV6_ADDRESS_LENGTH);
	pEntry_6to4->Sport = pSocketA->Sport;
	pEntry_6to4->Dport = pSocketA->Dport;
	pEntry_6to4->proto = pSocketA->proto;
	pEntry_6to4->socket = OpenCmd.socketA;
	pEntry_6to4->status = CONNTRACK_ORIG;
	if (OpenCmd.control & NATPT_CONTROL_6to4)
	{
		pEntry_6to4->route_id = pSocketB->route_id;
		IP_Check_Route(pEntry_6to4);
	}
	else
		pEntry_6to4->status |= CONNTRACK_FF_DISABLED;

	pEntry_4to6->fftype = FFTYPE_IPV4 | FFTYPE_NATPT;
	pEntry_4to6->hash = HASH_CT(pSocketB->Saddr_v4, pSocketB->Daddr_v4, pSocketB->Sport, pSocketB->Dport, pSocketB->proto);
	pEntry_4to6->Saddr_v4 = pSocketB->Saddr_v4;
	pEntry_4to6->Daddr_v4 = pSocketB->Daddr_v4;
	pEntry_4to6->Sport = pSocketB->Sport;
	pEntry_4to6->Dport = pSocketB->Dport;
	pEntry_4to6->proto = pSocketB->proto;
	pEntry_4to6->socket = OpenCmd.socketB;
	pEntry_4to6->status = 0;
	if (OpenCmd.control & NATPT_CONTROL_4to6)
	{
		pEntry_4to6->route_id = pSocketA->route_id;
		IP_Check_Route(pEntry_4to6);
	}
	else
		pEntry_4to6->status |= CONNTRACK_FF_DISABLED;

	if (ct_add(pEntry_6to4, NULL) != NO_ERR)	// TODO: add aging timer
		return ERR_CREATION_FAILED;

	SOCKET_bind(pEntry_6to4->socket, (PVOID)pEntry_6to4, SOCK_OWNER_NATPT);
	SOCKET_bind(pEntry_4to6->socket, (PVOID)pEntry_4to6, SOCK_OWNER_NATPT);

	return NO_ERR;
}


int NATPT_Close(U16 *p, U16 Length)
{
	NATPTCloseCommand CloseCmd;
	PCtEntry pEntry_6to4, pEntry_4to6;
	PSockEntry pSocketA;
	PSockEntry pSocketB;

	// Check length
	if (Length != sizeof(NATPTCloseCommand))
		return ERR_WRONG_COMMAND_SIZE;

	// Ensure alignment
	memcpy((U8*)&CloseCmd, (U8*)p, sizeof(NATPTCloseCommand));

	pSocketA = SOCKET_find_entry_by_id(CloseCmd.socketA);
	pSocketB = SOCKET_find_entry_by_id(CloseCmd.socketB);
	if (!pSocketA || !pSocketB)
		return ERR_NATPT_UNKNOWN_CONNECTION;

	pEntry_6to4 = IPv6_find_ctentry(pSocketA->Saddr_v6, pSocketA->Daddr_v6, pSocketA->Sport, pSocketA->Dport, pSocketA->proto);
	pEntry_4to6 = IPv4_find_ctentry(pSocketB->Saddr_v4, pSocketB->Daddr_v4, pSocketB->Sport, pSocketB->Dport, pSocketB->proto);
	if (!pEntry_6to4 || !IS_NATPT(pEntry_6to4) || !pEntry_4to6 || !IS_NATPT(pEntry_4to6))
		return ERR_NATPT_UNKNOWN_CONNECTION;

	SOCKET_unbind(pEntry_6to4->socket);
	SOCKET_unbind(pEntry_4to6->socket);

	ct_remove(pEntry_6to4);

	return NO_ERR;
}


int NATPT_Query(U16 *p, U16 Length)
{
	NATPTQueryCommand QueryCmd;
	PNATPTQueryResponse pResp;
	PCtEntry pEntry_6to4, pEntry_4to6;
	PSockEntry pSocketA;
	PSockEntry pSocketB;
	NATPT_Stats stats;

	// Check length
	if (Length != sizeof(NATPTQueryCommand))
		return ERR_WRONG_COMMAND_SIZE;
	// Ensure alignment
	memcpy((U8*)&QueryCmd, (U8*)p, sizeof(NATPTQueryCommand));

	pSocketA = SOCKET_find_entry_by_id(QueryCmd.socketA);
	pSocketB = SOCKET_find_entry_by_id(QueryCmd.socketB);
	if (!pSocketA || !pSocketB)
		return ERR_NATPT_UNKNOWN_CONNECTION;

	pEntry_6to4 = IPv6_find_ctentry(pSocketA->Saddr_v6, pSocketA->Daddr_v6, pSocketA->Sport, pSocketA->Dport, pSocketA->proto);
	pEntry_4to6 = IPv4_find_ctentry(pSocketB->Saddr_v4, pSocketB->Daddr_v4, pSocketB->Sport, pSocketB->Dport, pSocketB->proto);
	if (!pEntry_6to4 || !IS_NATPT(pEntry_6to4) || !pEntry_4to6 || !IS_NATPT(pEntry_4to6))
		return ERR_NATPT_UNKNOWN_CONNECTION;

	pResp = (PNATPTQueryResponse)p;
	memset((U8 *)pResp, 0, sizeof(NATPTQueryResponse));
	pResp->socketA = pEntry_6to4->socket;
	pResp->socketB = pEntry_4to6->socket;
	//pResp->control = 0;
	if (!(pEntry_6to4->status & CONNTRACK_FF_DISABLED))
		pResp->control |= NATPT_CONTROL_6to4;
	if (!(pEntry_4to6->status & CONNTRACK_FF_DISABLED))
		pResp->control |= NATPT_CONTROL_4to6;

	// update stats
	memset(&stats, 0, sizeof(stats));
#ifdef CDX_TODO_STATS
	// fill in stats structure
#endif
	pResp->stat_v6_received = stats.stat_v6_received;
	pResp->stat_v6_transmitted = stats.stat_v6_transmitted;
	pResp->stat_v6_dropped = stats.stat_v6_dropped;
	pResp->stat_v6_sent_to_ACP = stats.stat_v6_sent_to_ACP;
	pResp->stat_v4_received = stats.stat_v4_received;
	pResp->stat_v4_transmitted = stats.stat_v4_transmitted;
	pResp->stat_v4_dropped = stats.stat_v4_dropped;
	pResp->stat_v4_sent_to_ACP = stats.stat_v4_sent_to_ACP;

	return NO_ERR;
}


U16 M_natpt_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 cmdrc;
	U16 cmdlen = 2;

	switch (cmd_code)
	{
		case CMD_NATPT_OPEN:
			cmdrc = NATPT_Open(pcmd, cmd_len);
			break;

		case CMD_NATPT_CLOSE:
			cmdrc = NATPT_Close(pcmd, cmd_len);
			break;

		case CMD_NATPT_QUERY:
			cmdrc = NATPT_Query(pcmd, cmd_len);
			cmdlen = sizeof(NATPTQueryResponse);
			break;

		default:
			cmdrc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = cmdrc;
	return cmdlen;
}

BOOL natpt_init(void)
{
	set_cmd_handler(EVENT_NATPT, M_natpt_cmdproc);

	return 0;
}

void natpt_exit(void)
{
}
