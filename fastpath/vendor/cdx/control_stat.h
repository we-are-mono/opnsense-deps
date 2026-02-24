/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _CONTROL_STAT_H_
#define _CONTROL_STAT_H_

#define	pktstat_t	u32		/* change to u64 when supported in ucode */
#define	bytestat_t	u64

#define FPP_STAT_RESET  		0x0001
#define FPP_STAT_QUERY 			0x0002
#define FPP_STAT_QUERY_RESET   (FPP_STAT_RESET|FPP_STAT_QUERY)

#define FPP_STAT_ENABLE		0x0001
#define FPP_STAT_DISABLE		0x0000

#define STAT_PPPOE_QUERY_NOT_READY	0
#define STAT_PPPOE_QUERY_READY	1
#define STAT_PPPOE_QUERY_RESET      2

#define STAT_BRIDGE_QUERY_NOT_READY	0
#define STAT_BRIDGE_QUERY_READY	1
#define STAT_BRIDGE_QUERY_RESET    2

#define STAT_IPSEC_QUERY_NOT_READY	0
#define STAT_IPSEC_QUERY_READY	1
#define STAT_IPSEC_QUERY_RESET    2
#define STAT_VLAN_QUERY_NOT_READY	0
#define STAT_VLAN_QUERY_READY			1
#define STAT_VLAN_QUERY_RESET      		2

#define STAT_TUNNEL_QUERY_NOT_READY	0
#define STAT_TUNNEL_QUERY_READY		1
#define STAT_TUNNEL_QUERY_RESET      	2


/* Definitions of Bit Masks for the features */
#define STAT_QUEUE_BITMASK 		0x00000001
#define STAT_INTERFACE_BITMASK 		0x00000002
#define STAT_PPPOE_BITMASK 		0x00000008
#define STAT_BRIDGE_BITMASK 		0x00000010
#define STAT_IPSEC_BITMASK 		0x00000020
#define STAT_VLAN_BITMASK 		0x00000040
#define STAT_TUNNEL_BITMASK 		0x00000080
#define STAT_FLOW_BITMASK 	        0x00000100

#define statistics_get_lsb(val64)	((uint32_t)((val64) & 0xFFFFFFFFLL))
#define statistics_get_msb(val64)	((uint32_t)(((val64) & 0xFFFFFFFF00000000LL) >> 32))

typedef struct _tStatEnableCmd {
	U16 action; /* 1 - Enable, 0 - Disable */
	U32 bitmask; /* Specifies the feature to be enabled or disabled */ 
}StatEnableCmd, *PStatEnableCmd;

typedef struct _tStatQueueCmd {
	unsigned short action; /* Reset, Query, Query & Reset */
	unsigned short interface;
	unsigned short queue;
}StatQueueCmd, *PStatQueueCmd;

typedef struct _tStatInterfaceCmd {
	unsigned short action; /* Reset, Query, Query & Reset */
	unsigned short interface;
}StatInterfaceCmd, *PStatInterfaceCmd;

typedef struct _tStatConnectionCmd {
	unsigned short action; /* Reset, Query, Query & Reset */
}StatConnectionCmd, *PStatConnectionCmd;

typedef struct _tStatPPPoEStatusCmd {
	unsigned short action; /* Reset, Query, Query & Reset */
}StatPPPoEStatusCmd, *PStatPPPoEStatusCmd;

typedef struct _tStatBridgeStatusCmd {
	unsigned short action; /* Reset, Query, Query & Reset */
}StatBridgeStatusCmd, *PStatBridgeStatusCmd;

typedef struct _tStatIpsecStatusCmd {
	unsigned short action; /* Reset, Query, Query & Reset */
	unsigned short pad;
	int	iQueryTimerVal;	
}StatIpsecStatusCmd, *PStatIpsecStatusCmd;

typedef struct _tStatVlanStatusCmd {
	unsigned short action; /* Reset, Query, Query & Reset */
}StatVlanStatusCmd, *PStatVlanStatusCmd;

typedef struct _tStatTunnelStatusCmd {
	unsigned short action; /* Reset, Query, Query & Reset */
	unsigned short pad;
	char ifname[IF_NAME_SIZE];
}StatTunnelStatusCmd, *PStatTunnelStatusCmd;

typedef struct _tStatQueueResponse {
	U16 ackstatus;
	U16 rsvd1;
	unsigned int peak_queue_occ; 
	unsigned int emitted_pkts; 
	unsigned int dropped_pkts; 
	
}StatQueueResponse, *PStatQueueResponse;

typedef struct _tStatInterfacePktResponse {
	U16 ackstatus;
	U16 rsvd1;
	U32 total_pkts_transmitted;
	U32 total_pkts_received;
	U32 total_bytes_transmitted[2]; /* 64 bit counter stored as 2*32 bit counters */ 
	U32 total_bytes_received[2]; /* 64 bit counter stored as 2*32 bit counters */

}StatInterfacePktResponse, *PStatInterfacePktResponse;

typedef struct _tStatConnResponse {
	U16 ackstatus;
	U16 rsvd1;
	U32 max_active_connections;
	U32 num_active_connections;
}StatConnResponse, *PStatConnResponse;

typedef struct _tStatPPPoEEntryResponse {
	U16 ackstatus;
	U16 eof;
	U16 sessionID;
	U16 interface_no; /* physical output port id */
	U32 total_packets_received;  
	U32 total_packets_transmitted; 
}StatPPPoEEntryResponse, *PStatPPPoEEntryResponse;

typedef struct _tStatBridgeEntryResponse {
	U16 ackstatus;
	U16 eof;
	U16 input_interface;
	U16 input_svlan; 
	U16 input_cvlan; 
	U8 dst_mac[6];
	U8 src_mac[6];
	U16 etherType;
	U16 output_interface;
	U16 output_svlan; 
	U16 output_cvlan; 
	U16 session_id;
	U32 total_packets_transmitted; 
	U8 input_name[IF_NAME_SIZE];
	U8 output_name[IF_NAME_SIZE];
}StatBridgeEntryResponse, *PStatBridgeEntryResponse;

typedef struct _tStatIpsecEntryResponse {
	U16 ackstatus;
	U16 eof;
	U16 family;
	U16 proto;
	U32 spi;
	U32 dstIP[4];
	U32 total_pkts_processed;
	U32 total_bytes_processed[2];
	U16 sagd;
	U8  seqOverflow;
	U8  pad;
}StatIpsecEntryResponse, *PStatIpsecEntryResponse;

typedef struct _tStatVlanEntryResponse {
	U16 ackstatus;
	U16 eof;
	U16 vlanID;
	U16 rsvd; 
	U32 total_packets_received;
	U32 total_packets_transmitted;
	U32 total_bytes_received[2];
	U32 total_bytes_transmitted[2];
	U8 vlanifname[IF_NAME_SIZE];
	U8 phyifname[IF_NAME_SIZE];
}StatVlanEntryResponse, *PStatVlanEntryResponse;

typedef struct _tStatTunnelEntryResponse {
	U16 ackstatus;
	U16 eof;
	U32 rsvd;
	U32 total_packets_received;
	U32 total_packets_transmitted;
	U32 total_bytes_received[2];
	U32 total_bytes_transmitted[2];
	U8 ifname[IF_NAME_SIZE];
}StatTunnelEntryResponse, *PStatTunnelEntryResponse;

typedef struct _tStatFlowStatusCmd {
	U8	action;	/* This command specifies the action, query or query_reset or reset */                         
	U8	pad;
	U8	ip_family;
	U8	Protocol;  
	U16	Sport;                  /*Source Port*/
	U16	Dport;                  /*Destination Port*/
	union {
		struct {
			U32	Saddr;                  /*Source IPv4 address*/
			U32	Daddr;                  /*Destination IPv4 address*/
		};
		struct {
			U32	Saddr_v6[4];                  /*Source IPv6 address*/
			U32	Daddr_v6[4];                  /*Destination IPv6 address*/
		};
	};
} StatFlowStatusCmd, *PStatFlowStatusCmd;

typedef struct _tStatFlowEntryResp {
	U16	ackstatus;
	U8	ip_family;
	U8	Protocol;  
	U16	Sport;                  /*Source Port*/
	U16	Dport;                  /*Destination Port*/
	union {
		struct {
			U32	Saddr;                  /*Source IPv4 address*/
			U32	Daddr;                  /*Destination IPv4 address*/
		};
		struct {
			U32	Saddr_v6[4];                  /*Source IPv6 address*/
			U32	Daddr_v6[4];                  /*Destination IPv6 address*/
		};
	};
	U64	TotalPackets;
	U64	TotalBytes;
} StatFlowEntryResp, *PStatFlowEntryResp;

int statistics_init(void);
void statistics_exit(void);

extern int gStatBridgeQueryStatus;
extern U8 gStatPPPoEQueryStatus;
extern int gStatIpsecQueryStatus;
extern U8 gStatVlanQueryStatus;
extern U8 gStatTunnelQueryStatus;

U16 interface_stats_reset(uint32_t interface);
U16 stat_PPPoE_Get_Next_SessionEntry(PStatPPPoEEntryResponse pStatSessionCmd, int reset_action);
U16 stat_VLAN_Get_Next_SessionEntry(PStatVlanEntryResponse pStatVlanCmd, int reset_action);
U16 stat_tunnel_Get_Next_SessionEntry(PStatTunnelEntryResponse pResponse, int reset_action);

#endif /* _CONTROL_STAT_H_ */
