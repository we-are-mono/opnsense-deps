/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_BRIDGE_H_
#define _CONTROL_BRIDGE_H_

#include "types.h"
#include "fe.h"
#include "cdx_timer.h"


/* Modes */
#define L2_BRIDGE_MODE_MANUAL		0	
#define L2_BRIDGE_MODE_AUTO		1

/* Timer */
#define L2_BRIDGE_DEFAULT_TIMEOUT	30

/* Status */
#define L2_BRIDGE_TIMED_OUT		0x1
#define L2FLOW_UPDATING			(1 << 0)

//flow table bucket head
struct flow_bucket {
        U32 num_entries;        //num entries in this bucket
	struct hlist_head flowlist;
};

extern struct flow_bucket l2flow_hash_table[NUM_BT_ENTRIES];

/* VLAN flags */
#define VLAN_FILTERED   	0x1
#define VLAN_UNTAGGED		0x2
#define VLAN_INGRESS_FILTERED	0x4
#define VLAN_PVID		0x8

struct L2Flow {
        U8 da[6];
        U8 sa[6];
        U16 ethertype;
        U16 session_id;
        U16 svlan_tag; /* TCI */
        U16 cvlan_tag; /* TCI */
#ifdef VLAN_FILTER
	U16 vid;
	U8 vlan_flags;
#endif
};

/* control path SW L2 flow entry */
struct L2Flow_entry {
	struct hlist_node node;
	struct L2Flow l2flow;
	cdx_timer_t last_l2flow_timer;
	char out_ifname[IF_NAME_SIZE];
	char in_ifname[IF_NAME_SIZE];
	U16 status;
	U32 hash;
	struct hw_ct *ct;
	TIMER_ENTRY timer;
};

/* L2 Bridging Enable command */
typedef struct _tL2BridgeEnableCommand {
	U16 interface;
	U16 enable_flag;
	U8 input_name[16];
}L2BridgeEnableCommand, *PL2BridgeEnableCommand;

/* L2 Bridging  Flow entry command */
typedef struct _tL2BridgeL2FlowEntryCommand {
	U16		action;				/*Action to perform*/
	U16		ethertype;			/* If VLAN Tag !=0, ethertype of next header */
	U8		destaddr[6];			/* Dst MAC addr */
	U8		srcaddr[6];			/* Src MAC addr */
	U16		svlan_tag; 			/* S TCI */
	U16		cvlan_tag; 			/* C TCI */
	U16		session_id;			/* Meaningful only if ethertype PPPoE */
	U16		vid;
	U8		input_name[IF_NAME_SIZE];	/* Input itf name */
	U8		output_name[IF_NAME_SIZE];	/* Output itf name */
	/* L3-4 optional information*/
	U32		saddr[4];
	U32		daddr[4];
	U16		sport;
	U16		dport;
	U8		proto;
	U8		vlan_flags;
	U16		mark;
	U32		timeout;
} L2BridgeL2FlowEntryCommand, *PL2BridgeL2FlowEntryCommand;


/* L2 Bridging Query Entry response */
typedef struct _tL2BridgeQueryEntryResponse {
        U16 ackstatus;
        U16 eof;
        U16 input_interface;
        U16 input_svlan;
        U16 input_cvlan;
        U8 destaddr[6];
        U8 srcaddr[6];
        U16 ethertype;
        U16 output_interface;
        U16 output_svlan;
        U16 output_cvlan;
        U16 pkt_priority;
        U16 svlan_priority;
        U16 cvlan_priority;
        U8 input_name[16];
        U8 output_name[16];
        U16 qmod;
        U16 session_id;
}L2BridgeQueryEntryResponse, *PL2BridgeQueryEntryResponse;


/* L2 Bridging Control command */
typedef struct _tL2BridgeControlCommand {
	U16 mode_timeout;		/* Either set bridge mode or set timeout for flow entries */
}L2BridgeControlCommand, *PL2BridgeControlCommand;

/* This command is to mark if the interface is bridged or not */
typedef struct _tBridgedItfCommand
{
	U8 ifname[IF_NAME_SIZE]; /* interface name */
	U8 br_macaddr[6]; /* bridge mac address */
	U8 is_bridged;	/* interface is bridged or not */
	U8 pad;		/* unused */
}BridgedItfCommand, *pBridgedItfCommand;
/* Function proto */
int bridge_init(void);
void bridge_exit(void);

int delete_l2br_entry_classif_table(struct L2Flow_entry *entry);
int rx_Get_Next_Hash_L2FlowEntry(PL2BridgeL2FlowEntryCommand pL2FlowCmd, int reset_action);
int add_l2flow_to_hw(struct L2Flow_entry *entry);
cdx_timer_t br_get_time_remaining(struct L2Flow_entry *pEntry);
#endif /* _CONTROL_BRIDGE_H_ */
