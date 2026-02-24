/*
 *  Copyright 2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _MODULE_RTP_RELAY_H_
#define _MODULE_RTP_RELAY_H_

#define NUM_RTPFLOW_ENTRIES 	256

#define MAX_RTP_STATS_ENTRY 64

#define RTP_SPECIAL_PAYLOAD_LEN	160

#define RTP_MIN_SEQUENTIAL	2
#define RTP_MAX_DROPOUT 	3000
#define RTP_LATE_THRESH 	0xFF00
#define RTP_SEQ_MOD			1 << 16

#define RTP_MAX_SEQNUM	0xFFFF

enum {
	RCVD_OK,
	RCVD_ERR,
	RCVD_FIRST_PACKET,				// 1st received packet
	RCVD_IN_ORDER_PACKET,			// sequential packet
	RCVD_OUT_OF_ORDER_PACKET,		// out-of-order packet (could be late or duplicated)
	RCVD_FIRST_UNEXPECTED_PACKET,	// large jump of seq.
	RCVD_SECOND_SEQUENTIAL_PACKET,	// 2nd of the new seq.
	RCVD_LATE_PACKET,
	RCVD_DUPLICATED_PACKET,
	RCVD_NEW_SSRC_DECTECTED,
	INVALID
};


typedef enum {
	RTCP_SR		= 200,
	RTCP_RR		= 201,
	RTCP_SDES	= 202,
	RTCP_BYE	= 203,
	RTCP_APP	= 204,
	RTCP_XR 	= 207
}rtcp_type_t;


typedef enum {
	RTP_PT_G711U	= 0,
	RTP_PT_G711A	= 8,
} rtp_pt_t;


#ifdef ENDIAN_LITTLE
typedef struct RTP_HDR_STRUCT
{
	U8	cc:4;		// CSRC count
	U8	x:1;		// header extension flag
	U8	p:1;		// padding flag
	U8	version:2;	// protocol version
	U8	pt:7;		// payload type
	U8	m:1;		// marker bit
	U16 seq;		// sequence number
	U32 ts;			// timestamp
	U32 ssrc;		// synchronization source
} __attribute__((packed)) rtp_hdr_t;
#else
typedef struct RTP_HDR_STRUCT
{
	U8	version:2;	// protocol version
	U8	p:1;		// padding flag
	U8	x:1;		// header extension flag
	U8	cc:4;		// CSRC count
	U8	m:1;		// marker bit
	U8	pt:7;		// payload type
	U16 seq;		// sequence number
	U32 ts;			// timestamp
	U32 ssrc;		// synchronization source
} __attribute__((packed)) rtp_hdr_t;
#endif


#define  RTP_HDR_SIZE	12

#define RTP_DISCARD	0x0
#define RTP_RELAY		0x1

#define FLOW_VALID		(1 << 0)
#define FLOW_USED		(1 << 1)
#define FLOW_UPDATING	(1 << 2)


#define	RTP_OFFLOAD_PROCESS_PKT		0x01 // state to mention whether to discard or process
#define	RTP_OFFLOAD_TAKEOVER_RESYNC 	0x02
#define RTP_OFFLOAD_SSRC_TAKEOVER	0x04
#define RTP_OFFLOAD_SEQ_TAKEOVER	0x08
#define RTP_OFFLOAD_TS_TAKEOVER		0x10
#define RTP_OFFLOAD_IPV4_PACKET		0x20
#define RTP_OFFLOAD_SPECIAL_TX_ACTIVE	0x40
#define RTP_OFFLOAD_CALL_UPDATE_SEEN	0x80
#define RTP_OFFLOAD_UDP_PROTOCOL		0x100
#define RTP_OFFLOAD_SSRC_AUTO_TAKEOVER	0x200
//#define RTP_OFFLOAD_RTP_PROBATION		0x200
#define RTP_OFFLOAD_RTP_FIRST_PACKET		0x400
#define RTP_OFFLOAD_TS_TAKEOVER_SAMPL_FREQ	0x800
#define RTP_OFFLOAD_VERIFY_SOURCE_ADDR		0x1000
#define RTP_OFFLOAD_RESET_MARKER_BIT		0x2000
#define RTP_OFFLOAD_SSRC_1_TAKEOVER		0x4000

struct _thw_RTPinfo {
	STIME	last_rx_time; // to store the last packet received time
	uint32_t	   	last_TS;  // Timestamp of last packet
	uint32_t	   	last_SSRC;  // SSRC received in last packet
// can make it as redundant by using sock stats cycles field
// uint32_t		cycles;		// incremented with (1<<16) in cases where sequence number wrapped up
	// special case generation of SSRC value: first packet or new ssrc detection and call_update_seen is false
	uint32_t	   	SSRC; // configured or generated SSRC value,
	uint32_t	   	TimestampBase; // configured timestamp base value in case of timestamp takeover
	// value getting modified for every packet in case of takeover
	uint16_t	   	last_Seq; // last received sequence number 
	
//	uint16_t		mode;
//	U16 	hash;
	uint16_t	   	Seq;
	uint16_t		flags;
//	uint8_t	   	state; 
//	U8  	first_packet;
	uint8_t		probation;
//	uint8_t 	pad1;
//	U8  	takeover_resync;
//	U8		SSRC_takeover;
//	U8		Seq_takeover;
//	U8		TS_takeover;
//	U8		call_update_seen;
//	uint8_t		takeover_mode;
//	U8		Special_tx_active;
//	uint8_t		Special_tx_type;
//	uint8_t		first_packet;
}__attribute__ ((packed));


typedef struct _tRTPinfo {
	BOOL  first_packet;
	BOOL	probation;
	U16	  last_Seq;
	STIME	last_rx_time;
	U32	  last_TS;
	U32	  last_SSRC;
	U32		last_transit;
	U16		seq_base;
	U16		mode;
	U32		cycles;
}RTPinfo, *PRTPinfo;



//macros for flags of typedef struct _thw_rtpflow
#define RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING  0x01

/* control path HW flow entry */
typedef struct _thw_rtpflow {
	U32 	flags;

	void *fm_ctx;
	void *td;
	uint8_t *ehash_rtp_relay_params;
	uint32_t *vlan_hdr_ptr;

	uint32_t timestamp;
	uint64_t pkts;
	uint64_t bytes;
	uint64_t reset_pkts;
	uint64_t reset_bytes;

	struct _thw_RTPinfo	*rtp_info;
	void 				*eeh_entry_handle;
	uint16_t 			 eeh_entry_index;
	uint8_t	num_vlan_hdrs;


	/* following part 2*160 bytes is fetched (efet) only if special packet feature is active */
	U8		Special_payload1[RTP_SPECIAL_PAYLOAD_LEN];
	U8		Special_payload2[RTP_SPECIAL_PAYLOAD_LEN];
	
	/* These fields are only used by host software (not fetched by data path), so keep them at the end of the structure */
	struct dlist_head 	list;
	unsigned long		removal_time;
}hw_rtpflow, *Phw_rtpflow;

/* control path SW flow entry */
typedef struct _tRTPflow {
	struct slist_entry	list;
	struct _tRTPflow *next;
	struct _tRTPcall *RTPcall;
	hw_rtpflow *hw_flow;

	struct _tRTPinfo	rtp_info;

	U16	   	ingress_socketID;
	U16	   	egress_socketID;
	U8	   	state; 			// 0 discard, 1 relay
	BOOL  	takeover_resync;
//	U8		SSRC_takeover;	// 0 transparent / 1 mangle
//	U8		SSRC_1_takeover; // 0 transparent / 1 mangle
//	U8		Seq_takeover;   // 0 transparent / 1 mangle
//	U8		TS_takeover;     // 0 transparent / 1 mangle	
//	U8		marker_bit_takeover; //0 transparent / 1 set bit
	U8		call_update_seen;
	U8		takeover_flags;
	U8		takeover_mode;
	U8		inPhyPortNum;
	U8		MarkerBitConfMode;
	U8		pkt_dup_enable;
	U8		vlan_p_bit_val;
	U16 	hash;
	U32	   	SSRC;
	U32	   	SSRC_1;
	U32	   	TimestampBase;
	U32	   	TimeStampIncr;
	U16	   	Seq;

}RTPflow, *PRTPflow;


typedef struct _tRTPcall {
	struct slist_entry	list;
	U16		  call_id;	// unique id
	U16		  valid;
	struct _tRTPflow	*AtoB_flow;
	struct _tRTPflow	*BtoA_flow;	
	U8		Special_payload1[RTP_SPECIAL_PAYLOAD_LEN];
	U8		Special_payload2[RTP_SPECIAL_PAYLOAD_LEN];
	U8		Next_Special_payload1[RTP_SPECIAL_PAYLOAD_LEN];
	U8		Next_Special_payload2[RTP_SPECIAL_PAYLOAD_LEN];
	U8		Special_tx_active;
	U8		Special_tx_type;
}RTPCall, *PRTPCall;

typedef struct _tRTCPStats {
	U64		average_reception_period;
	U32		prev_reception_period;
	U32		last_reception_period;
	U32	  num_tx_pkts;
	U32	  num_rx_pkts;
	U32	  num_rx_pkts_in_seq;
	U32	  last_TimeStamp;
	U32		packets_duplicated;
	U32		num_rx_since_RTCP;
	U32		num_tx_bytes;
	U32		min_jitter;
	U32		max_jitter;
	U32		mean_jitter;
	U32		num_rx_lost_pkts;
	U32		min_reception_period;
	U32		max_reception_period;
	U32		num_expected_pkts;
	U32		num_malformed_pkts;
	U32		cycles;
	U32		num_late_pkts;
	STIME	last_tx_time;
	U32		num_big_jumps;
	U32		num_previous_rx_lost_pkts;
	U16		sport;
	U16		dport;
	U16		last_rx_Seq;
	U16		seq_base;
	U8		state;
	U8		flags;
	U8		first_received_RTP_header[RTP_HDR_SIZE];
	U32		ssrc_overwrite_value; /* make sure to get multiple of 64bits */
}__attribute__ ((packed)) RTCPStats, *PRTCPStats;

typedef struct _tRTPOpenCommand {
	U16		CallID;
	U16		SocketA;
	U16		SocketB;
	U16		rsvd1;
}RTPOpenCommand, *PRTPOpenCommand;

typedef struct _tRTPCloseCommand {
	U16		CallID;
	U16		rsvd1;
}RTPCloseCommand, *PRTPCloseCommand;

typedef struct _tRTPTakeoverCommand {
	U16		CallID;
	U16		Socket;
	U16 	mode;
	U16		SeqNumberBase;
	U32		SSRC;
	U32 	TimeStampBase;
	U32		TimeStampIncr;
	U32		SSRC_1;
	U8		ParamFlags;
	U8		MarkerBitConfMode;
	U16		rsvd;
}RTPTakeoverCommand, *PRTPTakeoverCommand;


/* bit field definition for takeover modes */
#define RTP_TAKEOVER_MODE_TSINCR_FREQ	1
#define RTP_TAKEOVER_MODE_SSRC_AUTO			2

#define RTP_TAKEOVER_SSRC_TRANSPARENT	0
#define RTP_TAKEOVER_SSRC_MANGLE			1
#define RTP_TAKEOVER_SSRC_AUTO			2

#define TIMESTAMP_TAKEOVER      0x01
#define SEQ_NUM_TAKEOVER        0x02
#define SSRC_TAKEOVER           0x04
#define MARKER_BIT_TAKEOVER     0x08
#define SSRC_1_TAKEOVER         0x10
#define FEATURE_TAKEOVER_MASK   0x1F


typedef struct _tRTPControlCommand {
	U16		CallID;
	U16		ControlDir;
	U16		vlanPbitConf;
	U16		rsvd;
}RTPControlCommand, *PRTPControlCommand;

#define RTP_SPEC_TX_START	0
#define RTP_SPEC_TX_RESPONSE	1
#define RTP_SPEC_TX_STOP	2
#define RTP_SPEC_TX_START_ONE_SHOT	3


typedef struct _tRTPSpecTxCtrlCommand {
	U16		CallID;
	U16		Type;	
}RTPSpecTxCtrlCommand, *PRTPSpecTxCtrlCommand;

typedef struct _tRTPSpecTxPayloadCommand {
	U16		CallID;
	U16		payloadID;	
	U16		payloadLength;	
	U16		payload[RTP_SPECIAL_PAYLOAD_LEN/2];
}RTPSpecTxPayloadCommand, *PRTPSpecTxPayloadCommand;


typedef struct _tRTCPQueryCommand {
	U16		SocketID;
	U16		flags;
}RTCPQueryCommand, *PRTCPQueryCommand;

typedef struct _tRTCPQueryResponse {
	U32		prev_reception_period;
	U32		last_reception_period;
	U32	  num_tx_pkts;
	U32	  num_rx_pkts;
	U32	  last_rx_Seq;
	U32	  last_TimeStamp;
	U8		RTP_header[RTP_HDR_SIZE];
	U32		num_rx_dup;
	U32		num_rx_since_RTCP;
	U32		num_tx_bytes;
	U32		min_jitter;
	U32		max_jitter;
	U32		mean_jitter;
	U32		num_rx_lost_pkts;
	U32		min_reception_period;
	U32		max_reception_period;
	U32		average_reception_period;
	U32		num_malformed_pkts;
	U32		num_expected_pkts;
	U32		num_late_pkts;
	U16		sport;
	U16		dport;
	U32		num_cumulative_rx_lost_pkts;
	U32		ssrc_overwrite_value;
}RTCPQueryResponse, *PRTCPQueryResponse;

/**************** RTP Statistics for FF connections *******************/

#define RTP_STATS_FREE 0xFFFF

#define RTP_STATS_FULL_RESET 	1
#define RTP_STATS_PARTIAL_RESET 2
#define RTP_STATS_RX_RESET      3
#define RTP_STATS_FIRST_PACKET  4

#define IP4	0
#define IP6	1
#define MC4	2
#define MC6	3
#define RLY	4
#define RLY6	5

typedef struct _tRTP_enable_stats_command {
	U16 stream_id;
	U16 stream_type;
	U32 saddr[4];
	U32 daddr[4];
	U16 sport;
	U16 dport;
	U16 proto;
	U16 mode;
}RTP_ENABLE_STATS_COMMAND, *PRTP_ENABLE_STATS_COMMAND;

typedef struct _tRTP_disable_stats_command {
	U16 stream_id;
}RTP_DISABLE_STATS_COMMAND, *PRTP_DISABLE_STATS_COMMAND;

typedef struct _tRTP_query_stats_command {
	U16 stream_id;
	U16 flags;
}RTP_QUERY_STATS_COMMAND, *PRTP_QUERY_STATS_COMMAND;

typedef struct _tRTP_dmtf_pt_command {
	U16 pt;
}RTP_DTMF_PT_COMMAND, *PRTP_DTMF_PT_COMMAND;

extern U8 gDTMF_PT[2];

extern struct slist_head rtpflow_cache[];
extern struct slist_head rtpcall_cache;

#ifdef TODO_RTP_QOS

int rtpqos_ipv4_link_stats_entry_by_tuple(PCtEntry pClient, U32 saddr, U32 daddr, U16 sport, U16 dport);
int rtpqos_ipv6_link_stats_entry_by_tuple(PCtEntryIPv6 pClient, U32 *saddr, U32 *daddr, U16 sport, U16 dport);
int rtpqos_mc4_link_stats_entry_by_tuple(PMC4Entry pClient, U32 saddr, U32 daddr);
int rtpqos_mc6_link_stats_entry_by_tuple(PMC6Entry pClient, U32 *saddr, U32 *daddr);
int rtpqos_relay_link_stats_entry_by_tuple(PSockEntry pSocket, U32 saddr, U32 daddr, U16 sport, U16 dport);
int rtpqos_relay6_link_stats_entry_by_tuple(PSock6Entry pSocket, U32 *saddr, U32 *daddr, U16 sport, U16 dport);
#endif  // TODO_RTP_QOS

BOOL rtp_relay_init(void);
void rtp_relay_exit(void);


PRTPflow RTP_find_flow(U16 in_socket);

void cdx_ehash_set_rtp_info_params(uint8_t *rtp_relay_param, PRTPflow pFlow, PSockEntry pSocket);
void cdx_ehash_update_dtmf_rtp_info_params(uint8_t *rtp_relay_param, uint8_t *DTMF_PT);
int cdx_create_rtp_conn_in_classif_table (PRTPflow pFlow, PSockEntry pFromSocket, PSockEntry pToSocket);
void cdx_ehash_update_rtp_info_params(uint8_t *rtp_relay_param, uint32_t *rtpinfo_ptr);
int cdx_rtp_set_hwinfo_fields(PRTPflow pFlow, PSockEntry pFromSocket);

static __inline U32 HASH_RTP(U16 socketID)
{
	return (((socketID & 0xff) ^ (socketID >> 8)) & (NUM_RTPFLOW_ENTRIES - 1));
}

static inline U32 x1000(U32 x)
{
    U32 x125;
    x125 = x + (x << 7) - (x << 2);  // x + 128*x - 4*x => 125*x
    return x125 << 3;                // 8*(125*x) => 1000*x
}



#endif /* _MODULE_RTP_RELAY_H_ */
