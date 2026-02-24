/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_TUNNEL_H_
#define _CONTROL_TUNNEL_H_

#include "cdx_common.h"
#include "control_ipv4.h"

#define TNL_MAX_HEADER		(40 + 14 + 4) /* Max header size matches that of a gre tunnel */
#define TUNNEL_HASH_MASK	(NUM_TUNNEL_ENTRIES - 1)


#define TNL_STATE_CREATED 			0x01
#define TNL_STATE_ENABLED			0x02
#define TNL_STATE_SA_COMPLETE			0x04
#define TNL_STATE_SAREPLY_COMPLETE		0x08
#define TNL_STATE_REMOTE_ANY			0x10

#define TNL_NOSET_PRIV				0
#define TNL_SET_PRIV				1


/* PBUF route entry memory chunk is used to allocated a new GRE tnl entry. At the time the packet reaches
 * the tunnel module, the Bridge data will no longer be used. So it is safe to use the same memory. */
#define M_tnl_get_DMEM_buffer()\
	((PVOID)(CLASS_ROUTE0_BASE_ADDR))

enum TNL_MODE {
	TNL_MODE_ETHERIPV6,
	TNL_MODE_6O4,
	TNL_MODE_4O6,
	TNL_MODE_ETHERIPV4,
	TNL_MODE_GRE_IPV6 = 4,
};

enum SAM_ID_CONV_TYPE {
	SAM_ID_CONV_NONE =0,
	SAM_ID_CONV_DUPSPORT =1,
	SAM_ID_CONV_PSID =2,
};

#define TNL_ETHERIP_VERSION 0x3000
#define TNL_ETHERIP_HDR_LEN 2

#define TNL_GRE_PROTOCOL	0x6558		// Transparent Ethernet Bridging
#define TNL_GRE_HDRSIZE		4
#define TNL_GRE_VERSION		0x0
#define TNL_GRE_FLAGS		(0x0000 | TNL_GRE_VERSION)	// no flags are supported
#define TNL_GRE_HEADER		((TNL_GRE_FLAGS << 16) | TNL_GRE_PROTOCOL)
/* dscp propagation */
#define INHERIT_TC 0x1
#define DSCP_COPY  0x2


/***********************************
* Tunnel API Command and Entry strutures
*
************************************/

typedef struct _tTNLCommand_create {
	U8	name[16];
	U32 	local[4];
	U32	remote[4];
	U8	output_device[16];
	U8	mode;
	/* options */
	U8 	secure;
	U8	elim;
	U8	hlim;
	U32	fl;
	U16	frag_off;
	U16	enabled;
	U32	route_id;
	U16	mtu;
	U8	flags;
	U8	pad;
}TNLCommand_create , *PTNLCommand_create;

typedef struct _tTNLCommand_delete {
	U8	name[16];
}TNLCommand_delete, *PTNLCommand_delete;


typedef struct _tTNLCommand_ipsec {
	U8	name[16];
	U16 	SA_nr;
	U16	SAReply_nr;
	U16	SA_handle[4];
	U16	SAReply_handle[4];
} TNLCommand_ipsec, *PTNLCommand_ipsec;

typedef struct _tTNLCommand_query{
	U16     result;
	U16     unused;
	U8      name[16];
	U32     local[4];
	U32     remote[4];
	U8      mode;
	U8      secure;
	U8			elim;
	U8			hlim;
	U32     fl;
	U16     frag_off;
	U16     enabled;
	U32			route_id;
	U16			mtu;
	U16			pad;
}TNLCommand_query , *PTNLCommand_query;

typedef struct {
        int  port_set_id;          /* Port Set ID               */
        int  port_set_id_length;   /* Port Set ID length        */
        int  psid_offset;          /* PSID offset               */
}sam_port_info_t;

typedef struct _tTNLCommand_IdConvDP {
        U16      IdConvStatus;
				U16	 Pad;
}TNLCommand_IdConvDP, *pTNLCommand_IdConvDP;

typedef struct _tTNLCommand_IdConvPsid {
        U8       name[16];
				sam_port_info_t sam_port_info;
        U32      IdConvStatus:1,
								 unused:31;
}TNLCommand_IdConvPsid, *pTNLCommand_IdConvPsid;


// Structure used by tunnel entries in sw

typedef struct _tTnlEntry{
	itf_t itf;
	U8       tnl_name[16];

	union {
	  U8	header[TNL_MAX_HEADER];
	  ipv4_hdr_t header_v4;
	};
	U8	header_size;
	U8	mode;
	U8	proto;
	U8	secure;
	U8	state;
	U8	hlim;
	U8	elim;
	U8	output_proto;
	U32 	local[4];
	U32	remote[4];
	U32 fl;
	U16 frag_off;
	U16 SAReply_nr;
	U16 SA_nr;
	U16 hSAEntry_in[SA_MAX_OP];
	U16 hSAEntry_out[SA_MAX_OP];
	U16 sam_abit;
	U16 sam_abit_max;
	U16 sam_kbit;
	U16 sam_mbit;
	U16 sam_mbit_max;
	U8 sam_mbit_len;
	U8 sam_abit_len;
	U8 sam_kbit_len;
	U8 sam_id_conv_enable;
	U16 tnl_mtu;
	U8 flags;
	U8 pad;

	U32 route_id;
	PRouteEntry pRtEntry;
	struct slist_entry  list;
}TnlEntry, *PTnlEntry;

int tunnel_init(void);
void tunnel_exit(void);
void tnl_update(PTnlEntry pTunnelEntry);

U16 Tnl_Get_Next_Hash_Entry(PTNLCommand_query pTnlCmd, int reset_action);

int dpa_add_tunnel_if(itf_t *itf, itf_t *phys_itf, PTnlEntry pTunnelEntry);
int dpa_update_tunnel_if(itf_t *itf,  itf_t *phys_itf, PTnlEntry pTunnelEntry);

static __inline U32 HASH_TUNNEL_NAME(U8 *tnlname)
{
	U32 hash = 0;
	while (*tnlname)
	{
		hash <<= 3;
		hash ^= *tnlname++;
	}
	return (hash & TUNNEL_HASH_MASK);
}

#endif /* _CONTROL_TUNNEL_H_ */
