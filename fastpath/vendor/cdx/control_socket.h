/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _CONTROL_SOCKET_H_
#define _CONTROL_SOCKET_H_

#include "control_ipv4.h"
#include "control_ipv6.h"

extern struct slist_head sock4_cache[];
extern struct slist_head sock6_cache[];
extern struct slist_head sockid_cache[];

#define SOCKET_TYPE_LRO	4	// Socket for local TCP packets
#define SOCKET_TYPE_L2TP	3	// Socket to LAN or WAN for L2TP
#define SOCKET_TYPE_MSP		2	// Socket to MSP
#define SOCKET_TYPE_ACP		1	// Socket to ACP
#define SOCKET_TYPE_FPP		0 	// Socket to LAN or WAN

#define SOCKET_STATS_SIZE	128	// max socket statistics (in bytes)

enum {
	SOCK_OWNER_RTP_RELAY,
	SOCK_OWNER_L2TP,
	SOCK_OWNER_NATPT,
	SOCK_OWNER_NATT,
	SOCK_OWNER_NONE = 0xff
};

#define SOCKET_CREATE	0
#define SOCKET_BIND		1
#define SOCKET_UNBIND	2
#define SOCKET_UPDATE	3

#define SOCKET_UNCONNECTED	1
#define SOCKET_CONNECTED		0
#define SOCKET_UNCONNECTED_WO_SRC  2

#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
struct eh_table_handle{
	void 		*td;
	void 		*eeh_entry_handle;
	uint16_t 	 eeh_entry_index;
};
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */

// IPv4/v6 control path SW socket entry
typedef struct _tSockEntry{
	struct slist_entry 	list;
	struct slist_entry 	list_id;
	U16 hash;
	U16 hash_by_id;
	U32 nextid;
	U16 SocketID;
	U8 SocketFamily;
	U8 SocketType;	/** 1 -> to ACP  /  0 -> to LAN or WAN (based on pRtEntry) */
	PVOID owner;
	PVOID out_rtp_flow; // This pointer is required in case of socket update command after rtp flow creation
	U16 owner_type;
	PRouteEntry pRtEntry;
	U16 queue;
	U16 dscp;
	U32 *hw_stats;
	U32 SocketStats[SOCKET_STATS_SIZE/4];
	U32 route_id;
	U16 Sport;
	U16 Dport;
	U8 initial_takeover_done;
	BOOL qos_enable;
	U8 rtpqos_slot;

	U8 proto;
	U8 unconnected;
	U8 expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
	union {
		struct {
			U32 Saddr_v4;
			U32 Daddr_v4;
		};
		struct {
			U32 Saddr_v6[4];
			U32 Daddr_v6[4];
		};
	};
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	U16 iifindex; /* iifindex is required for slow path voice frame queues sockets.*/
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
	U16 secure;
	U16 SA_nr_rx;
	U16 SA_handle_rx[SA_MAX_OP];
	U16 SA_nr_tx;
	U16 SA_handle_tx[SA_MAX_OP];
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
	struct eh_table_handle SktEhTblHdl; /*This structure stores the MSP socket(slow path voice traffic) Extended hash table handle entries. */
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */
}SockEntry, *PSockEntry;

typedef SockEntry Sock6Entry;
typedef PSockEntry PSock6Entry;

static __inline U32 HASH_SOCKID(U16 id)
{
	return (id & (NUM_SOCK_ENTRIES - 1));
}

static __inline U32 HASH_SOCK(U32 Daddr, U32 Dport, U16 Proto)
{
	U32 sum;

	Daddr = ntohl(Daddr);
	Dport = ntohs(Dport);
	
	sum = ((Daddr << 7) | (Daddr >> 25));
	sum += ((Dport << 11) | (Dport >> 21));
	sum += (sum >> 16) + Proto;
	return (sum ^ (sum >> 8)) & (NUM_SOCK_ENTRIES - 1);
}

static __inline U32 HASH_SOCK6(U32 Daddr, U32 Dport, U16 Proto)
{
	U32 sum;

	Daddr = ntohl(Daddr);
	Dport = ntohs(Dport);

	sum = ((Daddr << 7) | (Daddr >> 25));
	sum += ((Dport << 11) | (Dport >> 21));
	sum += (sum >> 16) + Proto;
	return (sum ^ (sum >> 8)) & (NUM_SOCK_ENTRIES - 1);
}

BOOL SOCKET4_check_route(PSockEntry pSocket);
BOOL SOCKET6_check_route(PSock6Entry pSocket);

PSockEntry SOCKET_find_entry_by_id(U16 socketID);
PSockEntry SOCKET4_find_entry(U32 saddr, U16 sport, U32 daddr, U16 dport, U16 proto);
PSock6Entry SOCKET6_find_entry(U32 *saddr, U16 sport, U32 *daddr, U16 dport, U16 proto);

void SOCKET4_free_entries(void);
int SOCKET4_HandleIP_Socket_Open (U16 *p, U16 Length);
int SOCKET4_HandleIP_Socket_Update (U16 *p, U16 Length);
int SOCKET4_HandleIP_Socket_Close (U16 *p, U16 Length);
void SOCKET6_free_entries(void);
int SOCKET6_HandleIP_Socket_Open(U16 *p, U16 Length);
int SOCKET6_HandleIP_Socket_Update(U16 *p, U16 Length);
int SOCKET6_HandleIP_Socket_Close(U16 *p, U16 Length);

PSock6Entry socket6_alloc(void);
int socket6_add(PSock6Entry pSocket);
void socket6_remove(PSock6Entry pSocket, U32 hash, U32 hash_by_id);
PSockEntry socket4_alloc(void);
int socket4_add(PSockEntry pSocket);
void socket4_remove(PSockEntry pSocket, U32 hash, U32 hash_by_id);
void socket6_free(PSock6Entry pSocket);
void socket4_free(PSockEntry pSocket);
PSockEntry SOCKET_bind(U16 socketID, PVOID owner, U16 owner_type);
PSockEntry SOCKET_unbind(U16 socketID);
PSockEntry SOCKET_find_entry_by_id(U16 socketID);

void socket4_update(PSockEntry pSocket, u8 event);
void socket6_update(PSock6Entry pSocket, u8 event);
#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
int cdx_create_rtp_qos_slowpath_flow(PSockEntry pSocket);
#endif/*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES */

BOOL socket_init(void);
void socket_exit(void);


#endif	// _CONTROL_SOCKET_H_

