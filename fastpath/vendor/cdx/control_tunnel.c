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
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_tunnel.h"
#include "misc.h"
#include "control_stat.h"

extern spinlock_t dpa_devlist_lock;

U8 gStatTunnelQueryStatus;

/**
 * M_tnl_get_by_name
 *
 *
 *
 */
static PTnlEntry M_tnl_get_by_name(U8 *tnl_name)
{
	PTnlEntry pTunnelEntry;
	struct slist_entry *entry;
	U32 hash;

	if (tnl_name)
	{
		hash = HASH_TUNNEL_NAME(tnl_name);
		slist_for_each(pTunnelEntry, entry, &tunnel_name_cache[hash], list)
		{
			if(!strcmp((const char*)tnl_name, pTunnelEntry->tnl_name))
				return pTunnelEntry;
		}
	}
	return NULL;
}


static PTnlEntry tunnel_alloc(void)
{
	return kzalloc(sizeof(TnlEntry), GFP_KERNEL);
}

static void tunnel_free(PTnlEntry pEntry)
{
	kfree(pEntry);
}


/**
 * M_tnl_add
 *
 *
 */
static int M_tnl_add(PTnlEntry pTunnelEntry)
{
	int rc = 0;
	U32 hash;

	/* Add to our local hash */
	hash = HASH_TUNNEL_NAME(pTunnelEntry->tnl_name);
	slist_add(&tunnel_name_cache[hash], &pTunnelEntry->list);

	dpa_add_tunnel_if(&pTunnelEntry->itf, (pTunnelEntry->pRtEntry) ? pTunnelEntry->pRtEntry->itf : NULL  , pTunnelEntry);
	return rc;
}




/**
 * M_tnl_delete
 *
 *
 *
 */
static BOOL M_tnl_delete(PTnlEntry pTunnelEntry)
{
	struct slist_entry *prev;
	U32 hash;

#ifdef CDX_TODO_TUNNEL
	// delete hw entry
#endif

	/* Free the software entry */
	hash = HASH_TUNNEL_NAME(pTunnelEntry->tnl_name);
	prev = slist_prev(&tunnel_name_cache[hash], &pTunnelEntry->list);
	slist_remove_after(prev);
	tunnel_free(pTunnelEntry);
	return TRUE;
}


/**
 * M_tnl_build_header
 *
 *
 *
 */
static void M_tnl_build_header(PTnlEntry pTunnelEntry)
{
	ipv6_hdr_t ip6_hdr;
	ipv4_hdr_t ip4_hdr;

	switch (pTunnelEntry->mode)
	{
		/* EtherIP over IPv6 case : MAC|IPV6|ETHIP|MAC|IPV4 */
		/* Here IPV6|ETHIP part is pre-built            */

		case TNL_MODE_ETHERIPV6:

			/* add IPv6 header */
			memcpy((U8*)ip6_hdr.DestinationAddress, (U8*)pTunnelEntry->remote, IPV6_ADDRESS_LENGTH);
			memcpy((U8*)ip6_hdr.SourceAddress, (U8*)pTunnelEntry->local, IPV6_ADDRESS_LENGTH);
			IPV6_SET_VER_TC_FL(&ip6_hdr, pTunnelEntry->fl);
			ip6_hdr.HopLimit = pTunnelEntry->hlim;
			ip6_hdr.TotalLength = 0; //to be computed for each packet
			ip6_hdr.NextHeader = IPV6_ETHERIP;

			pTunnelEntry->header_size = sizeof(ipv6_hdr_t);
			memcpy(pTunnelEntry->header, (U8*)&ip6_hdr, pTunnelEntry->header_size);

			/* add EtherIP header */
			*(U16*)(pTunnelEntry->header + pTunnelEntry->header_size) = htons(TNL_ETHERIP_VERSION);
			pTunnelEntry->header_size += TNL_ETHERIP_HDR_LEN;
			break;

			/* EtherIP over IPv4 case : MAC|IPV4|ETHIP|MAC|IPV4 */
			/* Here IPV4|ETHIP part is pre-built            */

		case TNL_MODE_ETHERIPV4:
			/* add IPv4 header */
			ip4_hdr.SourceAddress = pTunnelEntry->local[0];
			ip4_hdr.DestinationAddress = pTunnelEntry->remote[0];
			ip4_hdr.Version_IHL = 0x45;
			ip4_hdr.Protocol = IPPROTOCOL_ETHERIP;
			ip4_hdr.TypeOfService = pTunnelEntry->fl & 0xFF;
			ip4_hdr.TotalLength = 0; //to be computed for each packet
			ip4_hdr.TTL = pTunnelEntry->hlim;
			ip4_hdr.Identification = 0;
			ip4_hdr.HeaderChksum = 0; //to be computed
			ip4_hdr.Flags_FragmentOffset = 0;

			pTunnelEntry->header_size = sizeof(ipv4_hdr_t);
			memcpy(pTunnelEntry->header, (U8*)&ip4_hdr, pTunnelEntry->header_size);

			/* add EtherIP header */
			*(U16*)(pTunnelEntry->header + pTunnelEntry->header_size) = htons(TNL_ETHERIP_VERSION);
			pTunnelEntry->header_size += TNL_ETHERIP_HDR_LEN;
			break;


			/* 6o4 case : MAC|IPV4|IPV6 		*/
			/* Here IPV4 part is pre-built	*/

		case TNL_MODE_6O4:
			ip4_hdr.SourceAddress = pTunnelEntry->local[0];
			ip4_hdr.DestinationAddress = pTunnelEntry->remote[0];
			ip4_hdr.Version_IHL = 0x45;
			ip4_hdr.Protocol = IPPROTOCOL_IPV6;
			ip4_hdr.TypeOfService = pTunnelEntry->fl & 0xFF;
			ip4_hdr.TotalLength = 0; //to be computed for each packet
			ip4_hdr.TTL = pTunnelEntry->hlim;
			ip4_hdr.Identification = 0;
			ip4_hdr.HeaderChksum = 0; //to be computed
			ip4_hdr.Flags_FragmentOffset = 0;

			pTunnelEntry->header_size = sizeof(ipv4_hdr_t);
			memcpy(pTunnelEntry->header, (U8*)&ip4_hdr, pTunnelEntry->header_size);
			break;

			/* 4o6 case : MAC|IPV6|IPV4             */
			/* Here IPV6 part is pre-built  */


		case TNL_MODE_4O6:

			memcpy((U8*)ip6_hdr.DestinationAddress, (U8*)pTunnelEntry->remote, IPV6_ADDRESS_LENGTH);
			memcpy((U8*)ip6_hdr.SourceAddress, (U8*)pTunnelEntry->local, IPV6_ADDRESS_LENGTH);
			IPV6_SET_VER_TC_FL(&ip6_hdr, pTunnelEntry->fl);
			ip6_hdr.HopLimit = pTunnelEntry->hlim;
			ip6_hdr.TotalLength = 0; //to be computed for each packet
			ip6_hdr.NextHeader = IPPROTOCOL_IPIP;

			pTunnelEntry->header_size = sizeof(ipv6_hdr_t);
			memcpy(pTunnelEntry->header, (U8*)&ip6_hdr, pTunnelEntry->header_size);

			break;

		case TNL_MODE_GRE_IPV6:

			/* add IPv6 header */
			memset(&ip6_hdr, 0, sizeof(ip6_hdr));
			memcpy((U8*)ip6_hdr.DestinationAddress, (U8*)pTunnelEntry->remote, IPV6_ADDRESS_LENGTH);
			memcpy((U8*)ip6_hdr.SourceAddress, (U8*)pTunnelEntry->local, IPV6_ADDRESS_LENGTH);
			IPV6_SET_VER_TC_FL(&ip6_hdr, pTunnelEntry->fl);
			ip6_hdr.HopLimit = pTunnelEntry->hlim;
			//ip6_hdr.TotalLength = 0; //to be computed for each packet
			ip6_hdr.NextHeader = IPV6_GRE;

			pTunnelEntry->header_size = sizeof(ipv6_hdr_t);
			memcpy(pTunnelEntry->header, (U8*)&ip6_hdr, pTunnelEntry->header_size);

			/* add GRE header */
			*(U32*)(pTunnelEntry->header + pTunnelEntry->header_size) = htonl(TNL_GRE_HEADER);
			pTunnelEntry->header_size += TNL_GRE_HDRSIZE;
			break;

		default:
			break;
	}
}


/**
 * TNL_handle_CREATE
 *
 *
 */
static int TNL_handle_CREATE(U16 *p, U16 Length)
{
	TNLCommand_create cmd;
	PTnlEntry pTunnelEntry;
	int rc = 0;

	/* Check length */
	if (Length != sizeof(TNLCommand_create))
	{
		rc = ERR_WRONG_COMMAND_SIZE;
		goto err0;
	}


	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_create));

	if (get_onif_by_name(cmd.name))
	{
		rc = ERR_TNL_ALREADY_CREATED;
		goto err0;
	}

	/* Get the tunnel entry */
	pTunnelEntry = tunnel_alloc();
	if (!pTunnelEntry)
	{
		rc = ERR_NOT_ENOUGH_MEMORY;
		goto err0;
	}

	strncpy(pTunnelEntry->tnl_name, cmd.name, sizeof(pTunnelEntry->tnl_name) - 1);

	switch (cmd.mode)
	{
		case TNL_MODE_ETHERIPV6:
			pTunnelEntry->proto = PROTO_IPV6;
			pTunnelEntry->output_proto = PROTO_NONE;

			break;

		case TNL_MODE_ETHERIPV4:
			pTunnelEntry->proto = PROTO_IPV4;
			pTunnelEntry->output_proto = PROTO_NONE;

			break;

		case TNL_MODE_6O4:
			if (cmd.secure)
			{
				rc = ERR_TNL_NOT_SUPPORTED;
				goto err1;
			}

			pTunnelEntry->proto = PROTO_IPV4;
			pTunnelEntry->output_proto = PROTO_IPV6;
			pTunnelEntry->frag_off = cmd.frag_off;

			break;

		case TNL_MODE_4O6:
			if (cmd.secure)
			{
				rc = ERR_TNL_NOT_SUPPORTED;
				goto err1;
			}

			pTunnelEntry->proto = PROTO_IPV6;
			pTunnelEntry->output_proto = PROTO_IPV4;

			break;

		case TNL_MODE_GRE_IPV6:
			pTunnelEntry->proto = PROTO_IPV6;
			pTunnelEntry->output_proto = PROTO_NONE;

			break;

		default:
			rc = ERR_TNL_NOT_SUPPORTED;
			goto err1;
			//		break;
	}

	pTunnelEntry->mode = cmd.mode;

	/* For copy we don't care to copy useless data in IPv4 case */
	memcpy(pTunnelEntry->local, cmd.local, IPV6_ADDRESS_LENGTH);
	memcpy(pTunnelEntry->remote, cmd.remote, IPV6_ADDRESS_LENGTH);
	pTunnelEntry->secure = cmd.secure;
	pTunnelEntry->fl = cmd.fl;
	pTunnelEntry->hlim = cmd.hlim;
	pTunnelEntry->elim = cmd.elim;
	pTunnelEntry->route_id = cmd.route_id;
	pTunnelEntry->pRtEntry = L2_route_get(pTunnelEntry->route_id);
	pTunnelEntry->tnl_mtu  = cmd.mtu;
	pTunnelEntry->flags = cmd.flags;


	/* Now create a new interface in the Interface Manager */
	if (!add_onif(cmd.name, &pTunnelEntry->itf, NULL, IF_TYPE_TUNNEL))
	{
		rc = ERR_CREATION_FAILED;
		goto err1;
	}
	//	pTunnelEntry->output_port_id =  (pTunnelEntry->onif->flags & PHY_PORT_ID) >> PHY_PORT_ID_LOG; /* FIXME */

	M_tnl_build_header(pTunnelEntry);

	pTunnelEntry->state = TNL_STATE_CREATED;

	if(((pTunnelEntry->proto == PROTO_IPV4) && (!pTunnelEntry->remote[0])) ||
			is_ipv6_addr_any(pTunnelEntry->remote))
		pTunnelEntry->state |= TNL_STATE_REMOTE_ANY;

	if (cmd.enabled)
		pTunnelEntry->state |= TNL_STATE_ENABLED;

	if ((rc = M_tnl_add(pTunnelEntry)) != 0)
		goto err1;

	return NO_ERR;

err1:
	tunnel_free(pTunnelEntry);

err0:
	return rc;
}

/**
 * TNL_reset_IPSEC
 *
 *
 */
#ifdef CDX_TODO_IPSEC
static void TNL_reset_IPSEC(PTnlEntry pTunnelEntry)
{
	pTunnelEntry->SA_nr =  0;
	pTunnelEntry->SAReply_nr =  0;
	pTunnelEntry->state &= ~TNL_STATE_SA_COMPLETE;
	pTunnelEntry->state &= ~TNL_STATE_SAREPLY_COMPLETE;
}
#endif


/**
 * TNL_handle_UPDATE
 *
 *
 */
static int TNL_handle_UPDATE(U16 *p, U16 Length)
{
	TNLCommand_create cmd;
	PTnlEntry pTunnelEntry;

	/* Check length */
	if (Length != sizeof(TNLCommand_create))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_create));

	pTunnelEntry = M_tnl_get_by_name(cmd.name);
	if (!pTunnelEntry)
		return ERR_TNL_ENTRY_NOT_FOUND;

	if (pTunnelEntry->mode != cmd.mode)
		return ERR_TNL_NOT_SUPPORTED;

	if (pTunnelEntry->pRtEntry)
	{
		L2_route_put(pTunnelEntry->pRtEntry);

		pTunnelEntry->pRtEntry = NULL;
	}

	pTunnelEntry->state &= ~TNL_STATE_REMOTE_ANY;
	/* For copy we don't care to copy useless data in IPv4 case */
	memcpy(pTunnelEntry->local, cmd.local, IPV6_ADDRESS_LENGTH);
	memcpy(pTunnelEntry->remote, cmd.remote, IPV6_ADDRESS_LENGTH);


	if(((pTunnelEntry->proto == PROTO_IPV4) && (!pTunnelEntry->remote[0])) ||
			is_ipv6_addr_any(pTunnelEntry->remote))
		pTunnelEntry->state |= TNL_STATE_REMOTE_ANY;


#ifdef CDX_TODO_IPSEC
	if((!cmd.secure) && (pTunnelEntry->secure))
		TNL_reset_IPSEC(pTunnelEntry);
#endif

	pTunnelEntry->secure = cmd.secure;
	pTunnelEntry->fl = cmd.fl;
	pTunnelEntry->hlim = cmd.hlim;
	pTunnelEntry->elim = cmd.elim;
	pTunnelEntry->route_id = cmd.route_id;
	pTunnelEntry->pRtEntry = L2_route_get(pTunnelEntry->route_id);
	pTunnelEntry->tnl_mtu  = cmd.mtu;
	pTunnelEntry->flags = cmd.flags;

	M_tnl_build_header(pTunnelEntry);

	if (cmd.enabled)
		pTunnelEntry->state |= TNL_STATE_ENABLED;
	else
		pTunnelEntry->state &= ~TNL_STATE_ENABLED;

	tnl_update(pTunnelEntry);
	return NO_ERR;
}


/**
 * TNL_handle_DELETE
 *
 *
 */
static int TNL_handle_DELETE(U16 *p, U16 Length)
{
	TNLCommand_delete cmd;
	PTnlEntry pTunnelEntry = NULL;

	/* Check length */
	if (Length != sizeof(TNLCommand_delete))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_delete));

	if((pTunnelEntry = M_tnl_get_by_name(cmd.name)) == NULL)
		return ERR_TNL_ENTRY_NOT_FOUND;

	/* Tell the Interface Manager to remove the tunnel IF */
	remove_onif_by_index(pTunnelEntry->itf.index);
	M_tnl_delete(pTunnelEntry);

	return NO_ERR;
}


/**
 * TNL_handle_IPSEC
 *
 *
 */
#ifdef CDX_TODO_IPSEC
static int TNL_handle_IPSEC(U16 *p, U16 Length)
{
	TNLCommand_ipsec cmd;
	PTnlEntry pTunnelEntry = NULL;
	int i;

	/* Check length */
	if (Length != sizeof(TNLCommand_ipsec))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_ipsec));

	if((pTunnelEntry = M_tnl_get_by_name(cmd.name)) == NULL)
		return ERR_TNL_ENTRY_NOT_FOUND;

	if(pTunnelEntry->secure == 0)
		return ERR_WRONG_COMMAND_PARAM;

	if (cmd.SA_nr > SA_MAX_OP)
		return ERR_CT_ENTRY_TOO_MANY_SA_OP;

	for (i=0;i<cmd.SA_nr;i++) {
		if (M_ipsec_sa_cache_lookup_by_h( cmd.SA_handle[i]) == NULL)
			return ERR_CT_ENTRY_INVALID_SA;
	}

	if (cmd.SAReply_nr > SA_MAX_OP)
		return ERR_CT_ENTRY_TOO_MANY_SA_OP;

	for (i=0;i<cmd.SAReply_nr;i++) {
		if (M_ipsec_sa_cache_lookup_by_h(cmd.SAReply_handle[i]) == NULL)
			return ERR_CT_ENTRY_INVALID_SA;
	}

	for (i=0;i<cmd.SA_nr;i++) {
		pTunnelEntry->hSAEntry_out[i]= cmd.SA_handle[i];
		pTunnelEntry->SA_nr = cmd.SA_nr;
		pTunnelEntry->state |= TNL_STATE_SA_COMPLETE;
	}

	for (i=0;i<cmd.SAReply_nr;i++)  {
		pTunnelEntry->hSAEntry_in[i]= cmd.SAReply_handle[i];
		pTunnelEntry->SAReply_nr = cmd.SAReply_nr;
		pTunnelEntry->state |= TNL_STATE_SAREPLY_COMPLETE;
	}

	if(pTunnelEntry->mode == TNL_MODE_GRE_IPV6)
	{
		tnl_update_gre(pTunnelEntry);
	}
	else
	{
		tnl_update(pTunnelEntry->tunnel_index);
	}

	return NO_ERR;
}
#endif


void TNL_set_id_conv_seed( sam_port_info_t * sp, U8 IdConvEnable, PTnlEntry t )
{
	t->sam_id_conv_enable = (IdConvEnable) ? SAM_ID_CONV_PSID: SAM_ID_CONV_NONE;
	if(!t->sam_id_conv_enable)
		return;
	// initialize global value
	t->sam_abit     = 0;
	t->sam_abit_len = sp->psid_offset;

	t->sam_kbit     = sp->port_set_id;
	t->sam_kbit_len = sp->port_set_id_length;

	t->sam_mbit     = 0;
	t->sam_mbit_len = 16 - (t->sam_abit_len + t->sam_kbit_len);

	// set the maximum value for a bit and m bit
	t->sam_abit_max = ~(0xffff<<t->sam_abit_len);
	t->sam_mbit_max = ~(0xffff<<t->sam_mbit_len);

	return;
}


/**
 * TNL_handle_IdConv_psid
 *
 *
 */

#ifdef CDX_TODO_TUNNEL
static int TNL_handle_IdConv_psid(U16 *p, U16 Length)
{
	TNLCommand_IdConvPsid cmd;
	PTnlEntry pTunnelEntry = NULL;

	/* Check length */
	if (Length != sizeof(TNLCommand_IdConvPsid))
		return ERR_WRONG_COMMAND_SIZE;
	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_IdConvPsid));
	if((pTunnelEntry = M_tnl_get_by_name(cmd.name)) == NULL)
		return ERR_TNL_ENTRY_NOT_FOUND;
	TNL_set_id_conv_seed(&cmd.sam_port_info,cmd.IdConvStatus,pTunnelEntry);
	tnl_update(pTunnelEntry);
	return 0;
}
#endif


/**
 * TNL_handle_IdConv_dupsport
 *
 *
 */

#ifdef CDX_TODO_TUNNEL
static int TNL_handle_IdConv_dupsport(U16 *p, U16 Length)
{
	TNLCommand_IdConvDP cmd;
	PTnlEntry pTunnelEntry = NULL;
	int i = 0;

	/* Check length */
	if (Length != sizeof(TNLCommand_IdConvDP))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy((U8*)&cmd, (U8*)p,  sizeof(TNLCommand_IdConvDP));

	for (i = 0; i < TNL_MAX_TUNNEL_DMEM; i++)
	{
		pTunnelEntry = &gTNLCtx.tunnel_table[i];
		if(pTunnelEntry->mode == TNL_MODE_4O6)
		{
			pTunnelEntry->sam_id_conv_enable = (cmd.IdConvStatus) ? SAM_ID_CONV_DUPSPORT: SAM_ID_CONV_NONE;
			tnl_update(pTunnelEntry);
		}
	}

	return 0;
}
#endif


/**
 * tnl_update
 *
 * Update the hardware tunnel tables
 */

void tnl_update(PTnlEntry pTunnelEntry)
{

	dpa_update_tunnel_if(&pTunnelEntry->itf, (pTunnelEntry->pRtEntry) ? pTunnelEntry->pRtEntry->itf : NULL  , pTunnelEntry);
}


/**
 * M_tnl_cmdproc
 *
 *
 *
 */
static U16 M_tnl_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc;
	U16 retlen = 2;

	switch (cmd_code)
	{
		case CMD_TNL_CREATE:
			rc = TNL_handle_CREATE(pcmd, cmd_len);
			break;

		case CMD_TNL_UPDATE:
			rc = TNL_handle_UPDATE(pcmd, cmd_len);
			break;

		case CMD_TNL_DELETE:
			rc = TNL_handle_DELETE(pcmd, cmd_len);
			break;

#ifdef CDX_TODO_IPSEC
		case CMD_TNL_IPSEC:
			rc = TNL_handle_IPSEC(pcmd, cmd_len);
			break;
#endif

#ifdef CDX_TODO_TUNNEL
		case CMD_TNL_4o6_ID_CONVERSION_dupsport:
			rc = TNL_handle_IdConv_dupsport(pcmd, cmd_len);
			break;

		case CMD_TNL_4o6_ID_CONVERSION_psid:
			rc = TNL_handle_IdConv_psid(pcmd, cmd_len);
			break;
#endif

		case CMD_TNL_QUERY:
		case CMD_TNL_QUERY_CONT:
			{
				PTNLCommand_query ptnl_cmd_qry = (PTNLCommand_query) (pcmd);
				rc = Tnl_Get_Next_Hash_Entry(ptnl_cmd_qry, cmd_code == CMD_TNL_QUERY);
				if (rc == NO_ERR)
					retlen = sizeof(TNLCommand_query);
				break;
			}

		default:
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;
	return retlen;
}



int tunnel_init(void)
{
	int i = 0;
	set_cmd_handler(EVENT_TNL_IN, M_tnl_cmdproc);

	for(i = 0; i < NUM_TUNNEL_ENTRIES; i++)
	{
		slist_head_init(&tunnel_name_cache[i]);
	}

	return 0;
}


void tunnel_exit(void)
{
	int i;
	struct slist_entry *entry;
	PTnlEntry pTunnelEntry;

	for (i = 0; i < NUM_TUNNEL_ENTRIES; i++)
	{
		slist_for_each_safe(pTunnelEntry, entry, &tunnel_name_cache[i], list) {
			M_tnl_delete(pTunnelEntry);
		}
	}
}

static int Tnl_Get_Hash_Entries(int hash_index)
{
	int tot_tunnels = 0;
	PTnlEntry pTunnelEntry;
	struct slist_entry *entry;
	slist_for_each(pTunnelEntry, entry, &tunnel_name_cache[hash_index], list)
	{
		tot_tunnels++;
	}
	return tot_tunnels;
}


/* This function fills in the snapshot of all tunnel entries of a tunnel cache */

static void fill_snapshot(PTNLCommand_query pTnlSnapshot, PTnlEntry pTnlEntry)
{
	memset(pTnlSnapshot , 0, sizeof(TNLCommand_query));
	pTnlSnapshot->mode = pTnlEntry->mode;
	pTnlSnapshot->secure = pTnlEntry->secure;
	memcpy(pTnlSnapshot->name, pTnlEntry->tnl_name, 16);
	memcpy(pTnlSnapshot->local, pTnlEntry->local, IPV6_ADDRESS_LENGTH);
	memcpy(pTnlSnapshot->remote, pTnlEntry->remote, IPV6_ADDRESS_LENGTH);
	pTnlSnapshot->fl=pTnlEntry->fl;
	pTnlSnapshot->frag_off = pTnlEntry->frag_off;
	pTnlSnapshot->enabled = pTnlEntry->state;
	pTnlSnapshot->elim = pTnlEntry->elim;
	pTnlSnapshot->hlim = pTnlEntry->hlim;
	pTnlSnapshot->mtu = pTnlEntry->tnl_mtu;
}

static int Tnl_Get_Hash_Snapshot(int hash_index, int tnl_entries, PTNLCommand_query pTnlSnapshot)
{
	int tot_tnls = 0;
	PTnlEntry pTnlEntry;

	struct slist_entry *entry;
	slist_for_each(pTnlEntry, entry, &tunnel_name_cache[hash_index], list)
	{
		fill_snapshot(pTnlSnapshot, pTnlEntry);
		pTnlSnapshot++;
		tot_tnls++;
		tnl_entries--;
		if (tnl_entries == 0)
			break;
	}
	return tot_tnls;
}

U16 Tnl_Get_Next_Hash_Entry(PTNLCommand_query pTnlCmd, int reset_action)
{
	int total_tnl_entries;
	PTNLCommand_query pTnl;
	static PTNLCommand_query pTnlSnapshot = NULL;
	static int tnl_hash_index = 0, tnl_snapshot_entries = 0, tnl_snapshot_index = 0;

	if(reset_action)
	{
		tnl_hash_index = 0;
		tnl_snapshot_entries = 0;
		tnl_snapshot_index = 0;
		if (pTnlSnapshot)
		{
			Heap_Free(pTnlSnapshot);
			pTnlSnapshot = NULL;
		}
	}

	if (tnl_snapshot_index == 0)
	{
		while (tnl_hash_index < NUM_TUNNEL_ENTRIES)
		{
			total_tnl_entries = Tnl_Get_Hash_Entries(tnl_hash_index);
			if (total_tnl_entries == 0)
			{
				tnl_hash_index++;
				continue;
			}
			if (pTnlSnapshot)
				Heap_Free(pTnlSnapshot);
			pTnlSnapshot = Heap_Alloc(total_tnl_entries * sizeof(TNLCommand_query));
			if (!pTnlSnapshot)
				return ERR_NOT_ENOUGH_MEMORY;
			tnl_snapshot_entries = Tnl_Get_Hash_Snapshot(tnl_hash_index, total_tnl_entries, pTnlSnapshot);
			break;
		}
		if (tnl_hash_index >= NUM_TUNNEL_ENTRIES)
		{
			tnl_hash_index = 0;
			if (pTnlSnapshot)
			{
				Heap_Free(pTnlSnapshot);
				pTnlSnapshot = NULL;
			}
			return ERR_TNL_ENTRY_NOT_FOUND;
		}
	}

	pTnl = &pTnlSnapshot[tnl_snapshot_index++];
	memcpy(pTnlCmd, pTnl, sizeof(TNLCommand_query));
	if (tnl_snapshot_index == tnl_snapshot_entries)
	{
		tnl_snapshot_index = 0;
		tnl_hash_index ++;
	}

	return NO_ERR;
}

static U16 tunnel_stats_get(PTnlEntry pEntry, PStatTunnelEntryResponse snapshot, U32 do_reset)
{
	struct iface_stats ifstats;
	struct dpa_iface_info *iface_info = NULL;
	struct iface_stats *last_stats;
	U16 ret = 0;

	spin_lock(&dpa_devlist_lock);
	if ((iface_info = dpa_get_ifinfo_by_itfid((uint32_t)pEntry->itf.index)) == NULL)
	{
		spin_unlock(&dpa_devlist_lock);
		DPA_ERROR("%s:: Failed to find the interface index 0x%x\n", __FUNCTION__, pEntry->itf.index);
		return ERR_UNKNOWN_INTERFACE;
	}
	spin_unlock(&dpa_devlist_lock);
	if ((ret = dpa_iface_stats_get(iface_info, &ifstats)) != NO_ERR)
	{
		DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __FUNCTION__, ret);
		return ret;
	}

	last_stats = iface_info->last_stats;
	snapshot->total_packets_received = ifstats.rx_packets - last_stats->rx_packets;
	snapshot->total_bytes_received[0] = statistics_get_lsb(ifstats.rx_bytes - last_stats->rx_bytes);
	snapshot->total_bytes_received[1] = statistics_get_msb(ifstats.rx_bytes - last_stats->rx_bytes);

	snapshot->total_packets_transmitted = ifstats.tx_packets - last_stats->tx_packets;
	snapshot->total_bytes_transmitted[0] = statistics_get_lsb(ifstats.tx_bytes - last_stats->tx_bytes);
	snapshot->total_bytes_transmitted[1] = statistics_get_msb(ifstats.tx_bytes - last_stats->tx_bytes);

	if (do_reset)
		dpa_iface_stats_reset(iface_info, &ifstats);

	return NO_ERR;
}

/* This function fills in the snapshot of all tunnel entries of a tunnel cache along with statistics information*/

static U16 stat_tunnel_Get_Session_Snapshot(int hash_index, int stat_tunnel_entries,
		PStatTunnelEntryResponse pStatTunnelSnapshot, int *stat_tot_tunnel)
{
	PTnlEntry pStatTunnelEntry;
	struct slist_entry *entry;
	U16 ret = 0;

	*stat_tot_tunnel = 0;
	slist_for_each(pStatTunnelEntry, entry, &tunnel_name_cache[hash_index], list)
	{
		memset(pStatTunnelSnapshot, 0, sizeof(StatTunnelEntryResponse));
		strcpy((char *)pStatTunnelSnapshot->ifname, get_onif_name(pStatTunnelEntry->itf.index));
		if ((ret = tunnel_stats_get(pStatTunnelEntry, pStatTunnelSnapshot,
						gStatTunnelQueryStatus & STAT_TUNNEL_QUERY_RESET)) != NO_ERR)
		{
			DPA_ERROR("%s:: Failed to get interface stats, return value %d\n", __FUNCTION__, ret);
			return ret;
		}

		pStatTunnelSnapshot++;
		(*stat_tot_tunnel)++;

		if (--stat_tunnel_entries <= 0)
			break;
	}

	return NO_ERR;
}


U16 stat_tunnel_Get_Next_SessionEntry(PStatTunnelEntryResponse pResponse, int reset_action)
{
	int stat_total_tunnel_entries;
	PStatTunnelStatusCmd pCommand = (PStatTunnelStatusCmd)pResponse;
	PStatTunnelEntryResponse pStatTunnel;
	static PStatTunnelEntryResponse pStatTunnelSnapshot = NULL;
	static int stat_tunnel_hash_index = 0, stat_tunnel_snapshot_entries = 0, stat_tunnel_snapshot_index = 0;
	static char stat_tunnel_name[IF_NAME_SIZE];
	U16 ret = 0;

	if(reset_action)
	{
		stat_tunnel_hash_index = 0;
		stat_tunnel_snapshot_entries = 0;
		stat_tunnel_snapshot_index = 0;
		if (pStatTunnelSnapshot)
		{
			Heap_Free(pStatTunnelSnapshot);
			pStatTunnelSnapshot = NULL;
		}
		memcpy(stat_tunnel_name, pCommand->ifname, IF_NAME_SIZE - 1);
		return NO_ERR;
	}

top:
	if (stat_tunnel_snapshot_index == 0)
	{
		while(stat_tunnel_hash_index < NUM_TUNNEL_ENTRIES)
		{
			stat_total_tunnel_entries = Tnl_Get_Hash_Entries(stat_tunnel_hash_index);
			if (stat_total_tunnel_entries == 0)
			{
				stat_tunnel_hash_index++;
				continue;
			}

			if(pStatTunnelSnapshot)
				Heap_Free(pStatTunnelSnapshot);
			pStatTunnelSnapshot = Heap_Alloc(stat_total_tunnel_entries * sizeof(StatTunnelEntryResponse));
			if (!pStatTunnelSnapshot)
			{
				stat_tunnel_hash_index = 0;
				return ERR_NOT_ENOUGH_MEMORY;
			}

			if ((ret = stat_tunnel_Get_Session_Snapshot(stat_tunnel_hash_index,
							stat_total_tunnel_entries,pStatTunnelSnapshot,
							&stat_tunnel_snapshot_entries)) != NO_ERR)
			{
				return ret;
			}
			break;
		}

		if (stat_tunnel_hash_index >= NUM_TUNNEL_ENTRIES)
		{
			stat_tunnel_hash_index = 0;
			if(pStatTunnelSnapshot)
			{
				Heap_Free(pStatTunnelSnapshot);
				pStatTunnelSnapshot = NULL;
			}
			return ERR_TNL_ENTRY_NOT_FOUND;
		}
	}

	pStatTunnel = &pStatTunnelSnapshot[stat_tunnel_snapshot_index++];

	memcpy(pResponse, pStatTunnel, sizeof(StatTunnelEntryResponse));
	if (stat_tunnel_snapshot_index == stat_tunnel_snapshot_entries)
	{
		stat_tunnel_snapshot_index = 0;
		stat_tunnel_hash_index++;
	}

	if (stat_tunnel_name[0])
	{
		// If name is specified, and no match, keep looking
		if (strcmp(stat_tunnel_name, pResponse->ifname) != 0)
			goto top;
		// If name matches, force EOF on next call
		stat_tunnel_hash_index = NUM_TUNNEL_ENTRIES;
		stat_tunnel_snapshot_index = 0;
	}

	return NO_ERR;
}

