/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_IPV4_H_
#define _CONTROL_IPV4_H_

#include"cdx_common.h"
#include"layer2.h"

#define MAX_L2_HEADER	18

#define SA_MAX_OP		2	// maximum of stackable SA (ESP+AH)

#define GET_L2HDR(mtd)  (mtd->data + mtd->offset)

/* IP flags. */
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

union ctentry_qosmark {
	U32 markval;

	struct {
		U32 queue : 4;	
		U32 reserved_1: 1;
		U32 vlan_pbits : 3;
		U32 dscp_mark_flag : 1;
		U32 dscp_mark_value : 6;
		U32 vlan_pbits_valid : 1;
		U32 iqid : 4;		/* ingres Qos id, qualify with valid bit*/ 
		U32 reserved_2: 3; 
		U32 iqid_valid : 1;	/* if set, iqid is valid */
		U32 chnl_id : 4;	/* egress Qos channel id */
		U32 reserved_3: 3; 
		U32 ds_info_valid: 1; 	/* bit indicates qosconmark specified values for DS direction */
	};
};

typedef struct _tCtEntry {
	struct slist_entry list;
	U16	Sport;
	U16	Dport;
	U8	proto;
	U8	inPhyPortNum;
	U16	hash;

	union {
		struct {
			U32 Saddr_v4;
			U32 Daddr_v4;
			U32 unused1;
			U32 unused2;
			U32 twin_Saddr;
			U32 twin_Daddr;
			U16 twin_Sport;
			U16 twin_Dport;
			U32 unused3;
		};

		struct {
			U32 Saddr_v6[4];
			U32 Daddr_v6[4];
		};
	};

	/* End of fields used by hardware */

	U32 route_id;
	PRouteEntry pRtEntry;
	union ctentry_qosmark qosmark;
	U16 status;
	cdx_timer_t last_ct_timer;

	U16 ip_chksm_corr;
	U16 tcp_udp_chksm_corr;

	PRouteEntry tnl_route;
	U16 hSAEntry[SA_MAX_OP];
	
	U8	rtpqos_slot;
	U8 fftype;

	U16 socket;

	struct _tCtEntry *twin;
	struct hw_ct *ct;       /** pointer to the hardware conntrack */

}CtEntry, *PCtEntry;



typedef struct _ctPair
{
	CtEntry	orig;
	CtEntry	repl;
	TIMER_ENTRY timer;
} CT_PAIR, *PCT_PAIR;

/* Conntrack status */
#define CONNTRACK_4O6			0x4000
#define	CONNTRACK_RTP_STATS		0x2000
#define CONNTRACK_SEC			0x1000
#define CONNTRACK_SEC_noSA     		0x800
#define CONNTRACK_TCP_FIN		0x400
#define CONNTRACK_FF_DISABLED		0x100
#define CONNTRACK_DEL_FAILED	0x40
#define CONNTRACK_NAT			0x20
#define CONNTRACK_SNAT			CONNTRACK_NAT
#define CONNTRACK_DNAT			0x10
//#define CONNTRACK_IPv6			0x08
#define CONNTRACK_ORIG			0x04
#define CONNTRACK_HWSET			0x02
#define CONNTRACK_IPv6_PORTNAT		0x01

// Fast-forward "type"

#define	FFTYPE_IPV4	0x01
#define FFTYPE_IPV6	0x02
#define FFTYPE_TUNNEL	0x04
#define FFTYPE_NATPT	0x08


static inline U8 GET_PROTOCOL(PCtEntry pCtEntry)
{
	return pCtEntry->proto; 
}

static inline void SET_PROTOCOL(PCtEntry pCtEntry_orig,PCtEntry pCtEntry_rep, U8 Proto)
{
	pCtEntry_orig->proto = Proto;
	pCtEntry_rep->proto  = Proto;
}

#define IS_HASH_ARRAY(ctrl, ct_addr)	(((unsigned long)(ct_addr) >= (unsigned long)(ctrl->hash_array_baseaddr)) \
	&& ((unsigned long)(ct_addr) < ((unsigned long)(ctrl->hash_array_baseaddr) + (NUM_CT_ENTRIES * CLASS_ROUTE_SIZE))))

#define CT_TWIN(pentry)		(((PCtEntry)(pentry))->twin)
#define CT_ORIG(pentry)		((((PCtEntry)(pentry))->status & CONNTRACK_ORIG) ? (PCtEntry)(pentry) : ((PCtEntry)(pentry))->twin)
#define CT_REPLY_BIT(pentry)	(!(((PCtEntry)(pentry))->status & CONNTRACK_ORIG))

#define IS_BIDIR(pEntry_orig, pEntry_repl) (!(pEntry_orig->status & CONNTRACK_FF_DISABLED) &&	\
						!(pEntry_repl->status & CONNTRACK_FF_DISABLED))

U32 get_timeout_value(U32 Proto,int sam_flag, int bidir_flag);
#define GET_TIMEOUT_VALUE(CtEntry,bidir_flag) get_timeout_value(CtEntry->proto,CtEntry->status & (CONNTRACK_4O6 | CONNTRACK_SEC),bidir_flag)

PCT_PAIR ct_alloc(void);
void ct_free(PCtEntry pEntry_orig);
void ct_timer_update(PCT_PAIR ppair);
int ct_add(PCtEntry pEntry_orig, TIMER_HANDLER handler);
void ct_update(PCtEntry pEntry_orig);
void ct_remove(PCtEntry pEntry_orig);

int ct_aging_handler(TIMER_ENTRY *timer);

int ipv4_init(void);
void ipv4_exit(void);

int IPv4_delete_CTpair(PCtEntry ctEntry);
void IP_deleteCt_from_onif_index(U32 if_index);
void IP_MarkSwap(PCtEntry pCtEntry, PCtEntry pCtTwin);
PRouteEntry IP_Check_Route(PCtEntry pCtEntry);
void IP_delete_CT_route(PCtEntry pCtEntry);
U64 IP_get_qosconnmark(PCtEntry pOrigEntry, PCtEntry pReplEntry);
cdx_timer_t ct_get_time_remaining(PCT_PAIR ppair);

int insert_entry_in_classif_table(PCtEntry entry);
int delete_entry_from_classif_table(PCtEntry entry);

PCtEntry IPv4_find_ctentry(U32 saddr, U32 daddr, U16 sport, U16 dport, U8 proto);

void display_ctentry(PCtEntry entry);
void display_route_entry(PRouteEntry entry);
int add_incoming_iface_info(PCtEntry entry);

#define CT_VALID	(1 << 0)
#define CT_USED		(1 << 1)
#define CT_UPDATING	(1 << 2)

extern U32 class_route_table_base;
extern U32 class_route_table_hash_mask;

#define CRCPOLY_BE 0x04c11db7
static inline U32 crc32_be(U8 *data)
{
	int i, j;
	U32 crc = 0xffffffff;

	for (i = 0; i < 4; i++) {
		crc ^= *data++ << 24;

		for (j = 0; j < 8; j++)
			crc = (crc << 1) ^ ((crc & 0x80000000) ? CRCPOLY_BE : 0);
	}

	return crc;
}

static __inline U32 HASH_CT(U32 Saddr, U32 Daddr, U32 Sport, U32 Dport, U16 Proto)
{
	U32 sum;

	sum = Saddr ^ htonl(ntohs(Sport));
	sum = crc32_be((u8 *)&sum);

	sum += ntohl(Daddr);
	sum += Proto;
	sum += ntohs(Dport);

	return sum & CT_TABLE_HASH_MASK;
}

static __inline U32 HASH_CT6(U32 *Saddr, U32 *Daddr, U32 Sport, U32 Dport, U16 Proto)
{
	int i;
	U32 sum;

	sum = 0;
	for (i = 0; i < 4; i++)
		sum += ntohl(READ_UNALIGNED_INT(Saddr[i]));
	sum = htonl(sum) ^ htonl(ntohs(Sport));
	sum = crc32_be((u8 *)&sum);

	for (i = 0; i < 4; i++)
		sum += ntohl(READ_UNALIGNED_INT(Daddr[i]));
	sum += Proto;
	sum += ntohs(Dport);

	return sum & CT_TABLE_HASH_MASK;
}
#endif /* _CONTROL_IPV4_H_ */
