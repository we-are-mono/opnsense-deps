/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _FE_H_
#define _FE_H_

#include "list.h"
#include "cdx_hal.h"

/* Nb buckets in cache tables */
#define NUM_ROUTE_ENTRIES	256 

#define ROUTE_TABLE_HASH_BITS	15
#define NUM_CT_ENTRIES		(1 << (ROUTE_TABLE_HASH_BITS))
#define	CT_TABLE_HASH_MASK	(NUM_CT_ENTRIES - 1)

#define NUM_VLAN_ENTRIES	64
#define NUM_PPPOE_ENTRIES	16
#define NUM_TUNNEL_ENTRIES	64

#define NUM_BT_ENTRIES 		256
#define NUM_BT_L3_ENTRIES 	1024

#define NUM_SA_ENTRIES 	16
#define NUM_SOCK_ENTRIES 	1024
#define NUM_IPSEC_SOCK_ENTRIES 	16
#define NUM_L2TP_ENTRIES 		16

/* Actions */
#define ACTION_REGISTER		0
#define ACTION_DEREGISTER	1
#define ACTION_REMOVED		3
#define ACTION_UPDATE		4
#define ACTION_QUERY            6
#define ACTION_QUERY_CONT       7
/* 8 is locally used by CMM */
#define ACTION_TCP_FIN		9

/* Actions allowed for multicast entry managment*/
#define MC_ACTION_ADD		0
#define MC_ACTION_REMOVE	1
#define MC_ACTION_REFRESH	2


#define 	OUTPUT_ACP		1
#define 	OUTPUT_GEM		0



/* Error codes */
enum return_code {
	NO_ERR = 0,
	ERR_UNKNOWN_COMMAND = 1,
	ERR_WRONG_COMMAND_SIZE = 2,
	ERR_WRONG_COMMAND_PARAM = 3,

	ERR_UNKNOWN_ACTION = 4,
	ERR_UNKNOWN_INTERFACE = 5,
	ERR_NOT_ENOUGH_MEMORY = 6,
	ERR_CREATION_FAILED = 7,
	ERR_INVALID_INTERFACE_TYPE = 8,
	
	ERR_BRIDGE_ENTRY_NOT_FOUND = 50,
	ERR_BRIDGE_ENTRY_ALREADY_EXISTS = 51,
	ERR_BRIDGE_WRONG_MODE = 52,
	ERR_BRIDGE_ENTRY_ADD_FAILURE = 53,

	ERR_MACVLAN_ALREADY_REGISTERED = 60,
	ERR_MACVLAN_ENTRY_NOT_FOUND = 61,
	ERR_MACVLAN_ENTRY_INVALID = 62,

	ERR_CT_ENTRY_ALREADY_REGISTERED = 100,
	ERR_CT_ENTRY_NOT_FOUND = 101,
	ERR_CT_ENTRY_INVALID_SA = 102,
	ERR_CT_ENTRY_TOO_MANY_SA_OP = 103,



	ERR_RT_ENTRY_ALREADY_REGISTERED = 200,
	ERR_RT_ENTRY_NOT_FOUND = 201,
	ERR_RT_ENTRY_LINKED = 202,
	ERR_RT_LINK_NOT_POSSIBLE = 203,


	ERR_QM_QUEUE_RATE_LIMITED = 500,
	ERR_QM_RATE_LIMIT_NOT_APPLIED_TO_OFF = 501,
	ERR_QM_QUEUE_OUT_OF_RANGE = 502,
	ERR_QM_NUM_DSCP_OUT_OF_RANGE = 503,
	ERR_QM_DSCP_OUT_OF_RANGE = 504,
	ERR_QM_NO_FREE_SHAPER = 505,
	ERR_QM_NO_QUEUE_SPECIFIED = 506,
	ERR_QM_INGRESS_POLICER_HANDLE_NULL = 507,
	ERR_QM_INGRESS_SET_PROFILE_FAILED = 508,


	ERR_VLAN_ENTRY_ALREADY_REGISTERED = 600,
	ERR_VLAN_ENTRY_NOT_FOUND = 601,

	ERR_MC_ENTRY_NOT_FOUND = 700,
	ERR_MC_MAX_LISTENERS = 701,
	ERR_MC_DUP_LISTENER = 702,
	ERR_MC_ENTRY_OVERLAP = 703,
	ERR_MC_INVALID_ADDR = 704,
	ERR_MC_INTERFACE_NOT_ALLOWED = 705,
	ERR_MC_MAX_LISTENERS_PER_GROUP = 706,
	ERR_MC_CONFIG = 707,

	ERR_PPPOE_ENTRY_ALREADY_REGISTERED = 800,
	ERR_PPPOE_ENTRY_NOT_FOUND = 801,

	ERR_SA_DUPLICATED = 904,
	ERR_SA_DUPLICATED_HANDLE = 905,
	ERR_SA_UNKNOWN = 906,
	ERR_SA_INVALID_CIPHER_KEY = 907,
	ERR_SA_INVALID_DIGEST_KEY = 908,
	ERR_SA_ENTRY_NOT_FOUND = 909,
	ERR_SA_SOCK_ENTRY_NOT_FOUND = 910,
	ERR_SA_INVALID_MODE = 911,

	ERR_TNL_MAX_ENTRIES = 1000,
	ERR_TNL_ENTRY_NOT_FOUND = 1001,
	ERR_TNL_NOT_SUPPORTED = 1002,
	ERR_TNL_NO_FREE_ENTRY = 1003,
	ERR_TNL_ALREADY_CREATED = 1004,

	ERR_STAT_FEATURE_NOT_ENABLED = 1100,

	ERR_EXPT_QUEUE_OUT_OF_RANGE = 1101,
	ERR_EXPT_NUM_DSCP_OUT_OF_RANGE = 1102,
	ERR_EXPT_DSCP_OUT_OF_RANGE = 1103,

	ERR_STAT_FEATURE_NOT_ALLOWED_TO_DISABLE = 1110,

	ERR_SOCK_ALREADY_OPEN	= 1200,
	ERR_SOCKID_ALREADY_USED	= 1201,
	ERR_SOCK_ALREADY_OPENED_WITH_OTHER_ID	= 1202,
	ERR_TOO_MANY_SOCKET_OPEN = 1203,
	ERR_SOCKID_UNKNOWN = 1204,
	ERR_SOCK_ALREADY_IN_USE	= 1206,
	ERR_RTP_CALLID_IN_USE	= 1207,
	ERR_RTP_UNKNOWN_CALL = 1208,
	ERR_WRONG_SOCKID = 1209,
	ERR_RTP_SPECIAL_PKT_LEN = 1210,
	ERR_RTP_CALL_TABLE_FULL = 1211,
	ERR_WRONG_SOCK_FAMILY = 1212,
	ERR_WRONG_SOCK_PROTO = 1213,
	ERR_WRONG_SOCK_TYPE = 1214,
	ERR_MSP_NOT_READY = 1215,
	ERR_WRONG_SOCK_MODE = 1216,
	ERR_NO_ROUTE_TO_SOCK = 1217,
	ERR_SOCK_UPDATE_ERR = 1218,

	ERR_NATPT_UNKNOWN_CONNECTION = 1220,

	ERR_RTP_STATS_MAX_ENTRIES = 1230,
	ERR_RTP_STATS_STREAMID_ALREADY_USED = 1231,
	ERR_RTP_STATS_STREAMID_UNKNOWN = 1232,
	ERR_RTP_STATS_DUPLICATED = 1233,
	ERR_RTP_STATS_WRONG_DTMF_PT = 1234,
	ERR_RTP_STATS_WRONG_TYPE = 1235,
	ERR_RTP_STATS_NOT_AVAILABLE = 1236,
	ERR_RTP_STATS_RESET = 1237,

	ERR_VOICE_BUFFER_UNKNOWN = 1240,
	ERR_VOICE_BUFFER_USED = 1241,
	ERR_VOICE_BUFFER_PT = 1242,
	ERR_VOICE_BUFFER_FRAME_SIZE = 1243,
	ERR_VOICE_BUFFER_ENTRIES = 1244,
	ERR_VOICE_BUFFER_SIZE = 1245,
	ERR_VOICE_BUFFER_STARTED = 1246,

	ERR_ALTCONF_OPTION_NOT_SUPPORTED = 1300,
	ERR_ALTCONF_MODE_NOT_SUPPORTED = 1301,	
	ERR_ALTCONF_WRONG_NUM_PARAMS = 1302,

	ERR_WLAN_DUPLICATE_OPERATION = 2001,

	ERR_PKTCAP_ALREADY_ENABLED = 1400,
	ERR_PKTCAP_NOT_ENABLED	= 1401,
	ERR_PKTCAP_FLF_RESET	= 1402,

	ERR_ICC_TOO_MANY_ENTRIES = 1500,
	ERR_ICC_ENTRY_ALREADY_EXISTS = 1501,
	ERR_ICC_ENTRY_NOT_FOUND = 1502,
	ERR_ICC_THRESHOLD_OUT_OF_RANGE = 1503,
	ERR_ICC_INVALID_MASKLEN = 1504,

	ERR_FLOW_ENTRY_NOT_FOUND = 1600,
	ERR_INVALID_IP_FAMILY = 1601,
};




/******************************
* Forward Engine Common Definitions
*
******************************/

#define IPPROTOCOL_ICMP 	1
#define IPPROTOCOL_IGMP 	2
#define IPPROTOCOL_TCP 		6
#define IPPROTOCOL_UDP		17
#define IPPROTOCOL_IPIP		4
#define IPPROTOCOL_IPV6		41
#define IPPROTOCOL_ESP 		 50            /* Encapsulation Security Payload protocol */
#define IPPROTOCOL_AH 		 51             /* Authentication Header protocol       */
#define IPPROTOCOL_ICMPV6 	58
#define IPPROTOCOL_ETHERIP	97



// connection timer settings
#define TCP_TIMEOUT			432000		/*5 days*/
#define UDP_UNIDIR_TIMEOUT		30		/*30s*/
#define UDP_BIDIR_TIMEOUT		180		/*180s*/
#define OTHER_PROTO_TIMEOUT		600		/*10 minutes*/

#define CT_TIMER_INTERVAL_MS	100
#define CT_SCAN_TIME_MS		2000

#define SA_TIMER_INTERVAL	(CT_TIMER_INTERVAL *300) 
#define CT_TIMER_INTERVAL	((CT_TIMER_INTERVAL_MS * HZ) / 1000)
#define CT_TIMER_TICKS_PER_SECOND	(1000 / CT_TIMER_INTERVAL_MS)
#define	CT_TIMER_BINSIZE	((NUM_CT_ENTRIES * 1000) / (CT_SCAN_TIME_MS * CT_TIMER_TICKS_PER_SECOND))

#if ((CT_TIMER_TICKS_PER_SECOND * CT_TIMER_INTERVAL) != HZ)
#	error "HZ has to be multiple of CT_TIMER_INTERVAL_MS"
#endif

#define CT_TICKS_PER_SECOND	HZ

// Ethernet definitions

#define ETHER_ADDR_LEN				6
#define ETHER_TYPE_LEN			2

#define ETH_HEADER_SIZE			14
#define ETH_VLAN_HEADER_SIZE		18	// DST MAC + SRC MAC + TPID + TCI + Packet/Length
#define ETH_MAX_HEADER_SIZE		ETH_VLAN_HEADER_SIZE

/* ethernet packet types */
#define ETHERTYPE_IPV4			0x0800	// 	IP protocol version 4
#define ETHERTYPE_ARP			0x0806	//  ARP
#define ETHERTYPE_VLAN			0x8100	// 	VLAN 
#define ETHERTYPE_IPV6			0x86dd	//	IP protocol version 6
#define ETHERTYPE_MPT			0x889B 	//  IEEE mindspeed packet type
#define ETHERTYPE_PPPOE			0x8864  //  PPPoE Session packet
#define ETHERTYPE_PPPOED		0x8863  //  PPPoE Discovery packet
#define ETHERTYPE_PAE                   0x888E   /* Port Access Entity (IEEE 802.1X) */
#define ETHERTYPE_VLAN_STAG		0x88a8	// 	VLAN S-TAG
#define ETHERTYPE_UNKNOWN		0xFFFF

/* Packet type in big endianness	*/
#define ETHERTYPE_IPV4_END		htons(ETHERTYPE_IPV4)
#define ETHERTYPE_ARP_END		htons(ETHERTYPE_ARP)
#define ETHERTYPE_VLAN_END		htons(ETHERTYPE_VLAN)
#define ETHERTYPE_IPV6_END		htons(ETHERTYPE_IPV6)
#define ETHERTYPE_MPT_END		htons(ETHERTYPE_MPT)
#define ETHERTYPE_PPPOE_END		htons(ETHERTYPE_PPPOE)
#define ETHERTYPE_PPPOED_END		htons(ETHERTYPE_PPPOED)
#define ETHERTYPE_PAE_END               htons(ETHERTYPE_PAE)

typedef struct _tETHVLANHDR
{
	U8	DstMAC[6];				// Ethernet EMAC Destionation address
	U8	SrcMAC[6];				// Ethernet EMAC Source address
	U16	TPID;					// Tag Protocol Identifier or Ethernet Packet Type if packet not tagged
	U16	TCI;					// Tag Control Identifier
	U16	PacketType;				// Ethernet Packet Type / Length
	U16	RC;						// E-RIF Route Control
} ETHVLANHdr, *PETHVLANHdr;

typedef struct tEthernetFrame {
	union {
		struct {
			U8		DstMAC[ETHER_ADDR_LEN];
			U8		SrcMAC[ETHER_ADDR_LEN];
		};
		U32	dst_src_x[3];
	};
	U16		PacketType;
	U8		Payload[0];
} EthernetFrame, *PEthernetFrame;

typedef struct tEthernetHdr {
	U8	Header[ETH_MAX_HEADER_SIZE];
	U8	Length;
}EthernetHdr, *PEthernetHdr;

/******************************
* IPv4 API Command and Entry strutures
*
******************************/

#define CTCMD_FLAGS_ORIG_DISABLED	(1 << 0)
#define CTCMD_FLAGS_REP_DISABLED	(1 << 1)


typedef struct _tCtCommand {
	U16		action;
	U16		rsvd1;
	U32		Saddr;
	U32		Daddr;
	U16		Sport;
	U16		Dport;
	U32		SaddrReply;
	U32		DaddrReply;
	U16		SportReply;
	U16		DportReply;
	U16		protocol;
	U16		flags;
	U64		qosconnmark;
	U32		route_id;
	U32		route_id_reply;
}__attribute__((__packed__)) CtCommand, *PCtCommand;


/*Structure representing the command sent to add or remove a Conntrack when extentions (IPsec SA) is available*/
typedef struct _tCtExCommand {
	U16 		action;			/*Action to perform*/
	U16 		format;			/* bit 0 : indicates if SA info are present in command */ 		
							/* bit 1 : indicates if orig Route info is present in command  */ 		
							/* bit 2 : indicates if repl Route info is present in command  */ 		
	U32 		Saddr;			/*Source IP address*/
	U32 		Daddr;			/*Destination IP address*/
	U16 		Sport;			/*Source Port*/
	U16 		Dport;			/*Destination Port*/
	U32 		SaddrReply;
	U32 		DaddrReply;
	U16 		SportReply;
	U16 		DportReply;
	U16 		protocol;		/*TCP, UDP ...*/
	U16 		flags;
	U64 		qosconnmark;
	U32		route_id;
	U32		route_id_reply;
	// optional security parameters
	U8 		SA_dir;
	U8 		SA_nr;
	U16 	SA_handle[4];
	U8 		SAReply_dir;
	U8 		SAReply_nr;
	U16 	SAReply_handle[4];
	U32 	tunnel_route_id;
	U32		tunnel_route_id_reply;
}__attribute__((__packed__)) CtExCommand, *PCtExCommand;

#define RTCMD_FLAGS_6o4			(1<<0)	/* A IPv4 tunnel destination address is present */
#define RTCMD_FLAGS_4o6			(1<<1)	/* A IPv6 tunnel destination address is present */

#ifdef VLAN_FILTER
#define RTCMD_VLAN_FILTER_EN		(1<<2)	/* A IPv4 tunnel destination address is present */
#define RTCMD_EGRESS_UNTAG		(1<<3)	/* A IPv6 tunnel destination address is present */
#define RTCMD_VLAN_FILTER_INGRESS_EN	(1<<4)	/* A IPv4 tunnel destination address is present */
#define RTCMD_INGRESS_PVID		(1<<5)	/* A IPv6 tunnel destination address is present */
#endif

typedef struct _tRtCommand {
	U16		action;
	U16		mtu;
	U8		macAddr[ETHER_ADDR_LEN];
#ifdef VLAN_FILTER
	U16   egress_vid;
	U16   underlying_vid;
#endif
	U16   pad;
	U8    outputDevice[IF_NAME_SIZE];
	U8    inputDevice[IF_NAME_SIZE];
	U8    UnderlyingInputDevice[IF_NAME_SIZE];
	U32		id;
	U32		flags;
	/* Optional parameters */
	U32		daddr[4];
}RtCommand, *PRtCommand;

typedef struct _tTimeoutCommand {
	U16 	protocol;
	U16		sam_4o6_timeout;
	U32		timeout_value1;
	U32		timeout_value2;
}TimeoutCommand , *PTimeoutCommand;


typedef struct _tFFControlCommand {
	U16 enable;
	U16 reserved;
} FFControlCommand, *PFFControlCommand;		 	


typedef struct _tSockOpenCommand {
	U16		SockID;
	U8		SockType;
	U8		mode;		// 0 : not connected -> use 3 tuples.  1 : connected -> use 5 tuples
	U32		Saddr;
	U32		Daddr;
	U16		Sport;
	U16		Dport;
	U8		proto;
	U8		queue;
	U16		dscp;
	U32		route_id;
	U16		expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	U16		iifindex; /* iifindex is required for slow path voice frame queues sockets.*/
#else
	U16		rsvd;
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	U16		secure;
	U16 		SA_nr_rx;
	U16 		SA_handle_rx[4];
	U16 		SA_nr_tx;
	U16 		SA_handle_tx[4];
	U16 		pad;
}__attribute__((__packed__)) SockOpenCommand, *PSockOpenCommand;

typedef struct _tSockCloseCommand {
	U16		SockID;
	U16		rsvd1;
}__attribute__((__packed__)) SockCloseCommand, *PSockCloseCommand;


typedef struct _tSockUpdateCommand {
	U16 SockID;
	U16 rsvd1;
	U32 Saddr;
	U16 Sport;
	U8   rsvd2;
	U8 	queue;
	U16 dscp;
	U16 pad;
	U32 route_id;
	U16		expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
	U16		rsvd3;
	U16		secure;
	U16 		SA_nr_rx;
	U16 		SA_handle_rx[4];
	U16 		SA_nr_tx;
	U16 		SA_handle_tx[4];
	U16 		pad2;
}__attribute__((__packed__)) SockUpdateCommand, *PSockUpdateCommand;


/******************************
* IPv6 API Command and Entry strutures
*
******************************/
typedef struct _tCtCommandIPv6 {
	U16		action;
	U16		rsvd1;
	U32		Saddr[4];
	U32		Daddr[4];
	U16		Sport;
	U16		Dport;
	U32		SaddrReply[4];
	U32		DaddrReply[4];
	U16		SportReply;
	U16		DportReply;
	U16		protocol;
	U16		flags;
	U64		qosconnmark;
	U32		route_id;
	U32		route_id_reply;
}__attribute__((__packed__)) CtCommandIPv6, *PCtCommandIPv6;

typedef struct _tCtExCommandIPv6 {
	U16		action;
	U16		format;	/* indicates if SA or tunnel info is present in command */ 
	U32		Saddr[4];
	U32		Daddr[4];
	U16		Sport;
	U16		Dport;
	U32		SaddrReply[4];
	U32		DaddrReply[4];
	U16		SportReply;
	U16		DportReply;
	U16		protocol;
	U16		flags;
	U64		qosconnmark;
	U32		route_id;
	U32		route_id_reply;
      	U8 		SA_dir;
	U8 		SA_nr;
	U16 		SA_handle[4];
	U8 		SAReply_dir;
	U8 		SAReply_nr;
	U16 		SAReply_handle[4];
	U32 		tunnel_route_id;
	U32		tunnel_route_id_reply;
}__attribute__((__packed__)) CtExCommandIPv6, *PCtExCommandIPv6;

/* CtExCommand	FORMAT bitfield DEFINES*/ 
#define	CT_SECURE		(1 << 0)
#define	CT_ORIG_TUNNEL	(1 << 1)
#define	CT_REPL_TUNNEL	(1 << 2)

typedef struct _tSock6OpenCommand {
	U16		SockID;
	U8		SockType;
	U8		mode;		// 0 : not connected -> use 3 tuples.  1 : connected -> use 5 tuples
	U32		Saddr[4];
	U32		Daddr[4];
	U16		Sport;
	U16		Dport;
	U8		proto;
	U8		queue;
	U16		dscp;
	U32		route_id;
	U16		expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	U16		iifindex; /* iifindex is required for slow path voice frame queues sockets.*/
#else
	U16		rsvd1;
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	U16		secure;
	U16 		SA_nr_rx;
	U16 		SA_handle_rx[4];
	U16 		SA_nr_tx;
	U16 		SA_handle_tx[4];
	U16		pad;
}__attribute__((__packed__)) Sock6OpenCommand, *PSock6OpenCommand;

typedef struct _tSock6CloseCommand {
	U16		SockID;
	U16		rsvd1;
}__attribute__((__packed__)) Sock6CloseCommand, *PSock6CloseCommand;


typedef struct _tFragTimeoutCommand {
	U16		timeout;
	U16		mode;
}__attribute__((__packed__)) FragTimeoutCommand, *PFragTimeoutCommand;


typedef struct _tSock6UpdateCommand {
	U16 SockID;
	U16 rsvd1;
	U32 Saddr[4];
	U16 Sport;
	U8   rsvd2;
	U8 	queue;
	U16 dscp;
	U16 pad;
	U32	route_id;
	U16		expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
	U16		rsvd3;
	U16		secure;
	U16 		SA_nr_rx;
	U16 		SA_handle_rx[4];
	U16 		SA_nr_tx;
	U16 		SA_handle_tx[4];
	U16 		pad2;
}__attribute__((__packed__)) Sock6UpdateCommand, *PSock6UpdateCommand;

/******************************
* TCP definitions
*
******************************/
typedef struct TCP_HDR_STRUCT
{
	unsigned short 	SourcePort;
	unsigned short 	DestinationPort;
	unsigned int	SequenceNumber;
	unsigned int	AckNumber;
	unsigned short	TcpFlags;
#ifdef ENDIAN_LITTLE
#define TCPFLAGS_FIN	htons(0x0001)
#define TCPFLAGS_SYN	htons(0x0002)
#define TCPFLAGS_RST	htons(0x0004)
#define TCPFLAGS_PSH	htons(0x0008)
#else
#define TCPFLAGS_FIN	0x0001
#define TCPFLAGS_SYN	0x0002
#define TCPFLAGS_RST	0x0004
#define TCPFLAGS_PSH	0x0008
#define TCPFLAGS_ACK	0x0010
#define TCPFLAGS_URG	0x0020
#define TCPFLAGS_ECE	0x0040
#define TCPFLAGS_CWR	0x0080
#define TCPFLAGS_DOFF(flags)	((flags & 0xF000) >> 12)
#endif
	unsigned short 	Window;
	unsigned short	Checksum;
	unsigned short 	UrgentPtr;
} tcp_hdr_t;

/******************************
* UDP definitions
*
******************************/
typedef struct UDP_HDR_STRUCT
{
	unsigned short SourcePort;
	unsigned short DestinationPort;
	unsigned short Length;
	unsigned short Chksum;
} udp_hdr_t;

/******************************
* Macros
*
******************************/

#define IS_IPV4(pEntry) (pEntry->fftype == FFTYPE_IPV4)
#define IS_IPV4_FLOW(pEntry) ((pEntry->fftype & FFTYPE_IPV4) != 0)
#define IS_IPV6(pEntry) (pEntry->fftype == FFTYPE_IPV6)
#define IS_IPV6_FLOW(pEntry) ((pEntry->fftype & FFTYPE_IPV6) != 0)
#define IS_TUNNEL(pEntry) ((pEntry->fftype & FFTYPE_TUNNEL) != 0)
#define IS_NATPT(pEntry) ((pEntry->fftype & FFTYPE_NATPT) != 0)

static __inline U32 HASH_RT(U32 id)
{
	U16 sum;
	U32 tmp32;
	tmp32 = ((id << 7) | (id >> 25));
	sum = (tmp32 >> 16) + (tmp32 & 0xffff);
	return (sum ^ (sum >> 8)) & (NUM_ROUTE_ENTRIES - 1);
}

#define IP6_LO_ADDR	3

static __inline void COPY_MACHEADER(void *pheader, void *pdstmacaddr, void *psrcmacaddr, U16 typeid)
{
	U16 *pto_U16;
	U16 *pdst_U16;
	U16 *psrc_U16;
	pto_U16 = (U16 *)pheader;
	pdst_U16 = (U16 *)pdstmacaddr;
	psrc_U16 = (U16 *)psrcmacaddr;

	pto_U16[0] = pdst_U16[0];
	pto_U16[1] = pdst_U16[1];
	pto_U16[2] = pdst_U16[2];
	pto_U16[3] = psrc_U16[0];
	pto_U16[4] = psrc_U16[1];
	pto_U16[5] = psrc_U16[2];
	pto_U16[6] = typeid;
}

static __inline void COPY_MACADDR(void *ptomacaddr, void *pfrommacaddr)
{
	((U16 *)ptomacaddr)[0] = ((U16 *)pfrommacaddr)[0];
	((U16 *)ptomacaddr)[1] = ((U16 *)pfrommacaddr)[1];
	((U16 *)ptomacaddr)[2] = ((U16 *)pfrommacaddr)[2];
}

static __inline int TESTEQ_MACADDR(void *pmacaddr1, void *pmacaddr2)
{
	return ((U16 *)pmacaddr1)[0] == ((U16 *)pmacaddr2)[0] &&
					((U16 *)pmacaddr1)[1] == ((U16 *)pmacaddr2)[1] &&
					((U16 *)pmacaddr1)[2] == ((U16 *)pmacaddr2)[2];
}

static __inline int TESTEQ_NULL_MACADDR(void *pmacaddr1)
{
	return ((U16 *)pmacaddr1)[0] == 0 && ((U16 *)pmacaddr1)[1] == 0 && ((U16 *)pmacaddr1)[2] == 0;
}

static __inline void COPY_MACADDR2(void *ptomacaddr, void *pfrommacaddr)
{
	U16 *pto;
	U16 *pfrom;
	pto = (U16 *)ptomacaddr;
	pfrom = (U16 *)pfrommacaddr;
	pto[0] = pfrom[0];
	pto[1] = pfrom[1];
	pto[2] = pfrom[2];
	pto[3] = pfrom[3];
	pto[4] = pfrom[4];
	pto[5] = pfrom[5];
}

static __inline int TESTEQ_MACADDR2(void *pmacaddr1, void *pmacaddr2)
{
	U16 *p1;
	U16 *p2;
	p1 = (U16 *)pmacaddr1;
	p2 = (U16 *)pmacaddr2;
	return p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2] &&
					p1[3] == p2[3] && p1[4] == p2[4] && p1[5] == p2[5];
}


#endif /* _FE_H_ */
