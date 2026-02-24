/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


/*******************************************************************
 *
 *    NAME: types.h     
 * 
 *    DESCRIPTION: Defines types
 *
 *******************************************************************/

#ifndef _TYPES_H_
#define _TYPES_H_

// Make sure ENDIAN variable is defined properly
#if !defined(ENDIAN_LITTLE) && !defined(ENDIAN_BIG)
#error Must define either ENDIAN_LITTLE or ENDIAN_BIG
#endif

typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
// NOTE: The 32-bit GNU toolchain aligns doubleword variables on 4-byte boundaries.
//	To keep shared data structures compatible with the 8-byte alignment of
//	the ARM toolchain, we force U64/V64 to be 8-byte aligned.
typedef unsigned long long U64 __attribute__((aligned(8)));

#define u8  U8
#define u16 U16
#define u32 U32
#define u64 U64

typedef volatile unsigned char V8;
typedef volatile unsigned short V16;
typedef volatile unsigned int V32;
typedef volatile unsigned long long V64 __attribute__((aligned(8)));

typedef unsigned char BOOL;

typedef void VOID; 
typedef void *PVOID; 

typedef signed char  S8;
typedef signed short S16;
typedef signed int   S32;

#define IF_NAME_SIZE  	16


typedef struct tSTIME {
	U32 msec;
	U32 cycles;
} STIME;

/** Structure common to all interface types */
typedef struct _itf {
	struct _itf *phys;	/**< pointer to lower lever interface */
	U8 type;		/**< interface type */
	U8 index;		/**< unique interface index */
} itf_t;

struct physical_port {
	itf_t itf;
	U8 mac_addr[6];
	U16 id;
	U16 flags;

#ifdef CFG_STATS
	/*stats*/
	U64 rx_bytes __attribute__((aligned(8)));
	U32 rx_pkts;
#endif
};

/*physical_port flags bit fields */
#define TX_ENABLED		(1 << 0)
#define L2_BRIDGE_ENABLED	(1 << 1)
#define QOS_ENABLED		(1 << 2)

#define INLINE	__inline

#if !defined(TRUE)
#define TRUE   1
#endif
#if !defined(FALSE)
#define FALSE  0
#endif

#define HANDLE	PVOID


#define __TOSTR(v)	#v
#define TOSTR(v)	__TOSTR(v)

// enum used to identify L3 source 
enum FPP_L3_PROTO {
    PROTO_IPV4 = 0,
    PROTO_IPV6,
    PROTO_PPPOE,
    PROTO_MC4,    
    PROTO_MC6,
    MAX_L3_PROTO	
};
#define PROTO_NONE 0xFF

enum FPP_L4_PROTO {
	PROTO_L4_TCP=0,
	PROTO_L4_UDP,
	PROTO_L4_UNKNOWN,
	MAX_L4_PROTO
};

#endif /* _TYPES_H_ */
