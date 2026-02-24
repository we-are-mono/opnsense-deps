/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_IPV6_H_
#define _CONTROL_IPV6_H_


#include"cdx_common.h"

#define IPV6_MIN_MTU		1280


#define IPV6_HDR_SIZE		sizeof(ipv6_hdr_t)

typedef struct IPv6_FRAG_HDR
{
	u8 NextHeader;
	u8 rsvd;
	u16 FragOffset;
	u32 Identification;
} ipv6_frag_hdr_t;


typedef struct IPv6_ROUTING_HDR
{
	u8 NextHeader;
	u8 HdrExtLen;
	u8 RoutingType;
	u8 SegmentsLeft;
	u8 TypeSpecificData[0];
} ipv6_routing_hdr_t;

/* IPv6 Next Header values */
#define IPV6_HOP_BY_HOP		0
#define IPV6_IPIP		4
#define IPV6_TCP		6
#define IPV6_UDP		17
#define IPV6_ROUTING		43
#define IPV6_FRAGMENT		44
#define IPV6_GRE		47
#define IPV6_ESP		50
#define IPV6_AUTHENTICATE	51
#define IPV6_ICMP		58
#define IPV6_NONE		59
#define IPV6_DESTOPT		60
#define IPV6_ETHERIP		IPPROTOCOL_ETHERIP

/* ICMPv6 Type Values */
#define ICMPV6_ROUTER_SOLICIT   133
#define ICMPV6_ROUTER_ADVT      134
#define ICMPV6_NEIGH_SOLICIT    135
#define ICMPV6_NEIGH_ADVT       136


#define ct6_route(entry)	ct_route((PCtEntry)(entry))

int ipv6_cmp(void *src, void *dst);
#define IPV6_CMP(addr1, addr2) ipv6_cmp(addr1, addr2)

int ipv6_init(void);
void ipv6_exit(void);

int IPv6_delete_CTpair(PCtEntry pCtEntry);
int IPv6_Get_Next_Hash_CTEntry(PCtExCommandIPv6 pV6CtCmd, int reset_action);
PCtEntry IPv6_find_ctentry(U32 *saddr, U32 *daddr, U16 sport, U16 dport, U8 proto);

int IPv6_handle_RESET(void);


static inline u32 is_ipv6_addr_any(u32 *addr)
{
       return ((addr[0] | addr[1] | addr[2] | addr[3]) == 0);
}

#ifdef ENDIAN_LITTLE

#define IPV6_GET_VER_TC_FL(phdr) READ_UNALIGNED_INT((phdr)->Ver_TC_FL)

#define IPV6_SET_VER_TC_FL(phdr, ver_tc_fl) do { \
		u32 temp = ver_tc_fl | htonl(0x60000000); \
		WRITE_UNALIGNED_INT((phdr)->Ver_TC_FL, temp); \
		} while (0)

#define IPV6_GET_TRAFFIC_CLASS(phdr) ((((phdr)->Version_TC_FLHi & 0x000F) << 4) | (phdr)->Version_TC_FLHi >> 12)

#define IPV6_SET_TRAFFIC_CLASS(phdr, tc) do { \
		u16 temp = (phdr)->Version_TC_FLHi & 0x0FF0; \
		temp |= (tc) >> 4; \
		temp |= ((tc) & 0xF) << 12; \
		(phdr)->Version_TC_FLHi = temp; \
		} while (0)

#define IPV6_GET_VERSION(phdr) (((phdr)->Version_TC_FLHi >> 4) & 0xF)

#define IPV6_SET_VERSION(phdr, vers) do { \
		u16 temp = (phdr)->Version_TC_FLHi & 0xFF0F; \
		temp |= (vers) << 4; \
		(phdr)->Version_TC_FLHi = temp; \
		} while (0)

#define IPV6_GET_FLOW_LABEL_HI(phdr) (((phdr)->Version_TC_FLHi >> 8) & 0x000F)

#define IPV6_SET_FLOW_LABEL_HI(phdr, flhi) do { \
		u16 temp = (phdr)->Version_TC_FLHi & 0xF0FF; \
		temp |= (flhi) << 8; \
		(phdr)->Version_TC_FLHi = temp; \
		} while (0)

#define IPV6_SET_FLOW_LABEL(phdr, fl) do { \
		u16 flhi = ((fl) >> 16) & 0x000f; \
		IPV6_SET_FLOW_LABEL_HI((phdr), flhi); \
		(phdr)->FlowLabelLo = htons((fl) & 0xffff); \
		} while (0)

#define IPV6_COPY_FLOW_LABEL(phdr_to, phdr_from) do { \
		IPV6_SET_FLOW_LABEL_HI((phdr_to), IPV6_GET_FLOW_LABEL_HI(phdr_from)); \
		(phdr_to)->FlowLabelLo = (phdr_from)->FlowLabelLo; \
		} while (0)

#else	// !LITTLE_ENDIAN => BIG_ENDIAN

#define IPV6_GET_VER_TC_FL(phdr) READ_UNALIGNED_INT((phdr)->Ver_TC_FL)

#define IPV6_SET_VER_TC_FL(phdr, ver_tc_fl) do { \
		u32 temp = ver_tc_fl | 0x60000000; \
		WRITE_UNALIGNED_INT((phdr)->Ver_TC_FL, temp); \
		} while (0)

#define IPV6_GET_TRAFFIC_CLASS(phdr) (((phdr)->Version_TC_FLHi >> 4) & 0xFF)

#define IPV6_SET_TRAFFIC_CLASS(phdr, tc) do { \
		u16 temp = (phdr)->Version_TC_FLHi & 0xF00F; \
		temp |= (tc) << 4; \
		(phdr)->Version_TC_FLHi = temp; \
		} while (0)

#define IPV6_GET_VERSION(phdr) ((phdr)->Version_TC_FLHi >> 12)

#define IPV6_SET_VERSION(phdr, vers) do { \
		u16 temp = (phdr)->Version_TC_FLHi & 0x0FFF; \
		temp |= (vers) << 12; \
		(phdr)->Version_TC_FLHi = temp; \
		} while (0)

#define IPV6_GET_FLOW_LABEL_HI(phdr) ((phdr)->Version_TC_FLHi & 0x000F)

#define IPV6_SET_FLOW_LABEL_HI(phdr, flhi) do { \
		u16 temp = (phdr)->Version_TC_FLHi & 0xFFF0; \
		temp |= (flhi); \
		(phdr)->Version_TC_FLHi = temp; \
		} while (0)

#define IPV6_SET_FLOW_LABEL(phdr, fl) do { \
		u16 flhi = ((fl) >> 16) & 0x000f; \
		IPV6_SET_FLOW_LABEL_HI((phdr), flhi); \
		(phdr)->FlowLabelLo = htons((fl) & 0xffff); \
		} while (0)

#define IPV6_COPY_FLOW_LABEL(phdr_to, phdr_from) do { \
		IPV6_SET_FLOW_LABEL_HI((phdr_to), IPV6_GET_FLOW_LABEL_HI(phdr_from)); \
		(phdr_to)->FlowLabelLo = (phdr_from)->FlowLabelLo; \
		} while (0)

#endif


#endif /* _CONTROL_IPV6_H_ */
