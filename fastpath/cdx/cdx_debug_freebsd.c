/*
 * cdx_debug_freebsd.c — Debug display routines for FreeBSD CDX port
 *
 * Port of cdx-5.03.1/cdx_debug.c.  Provides debug display functions
 * for inspecting CDX data structures (interfaces, routes, conntrack
 * entries, raw buffers).
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "portdefs.h"
#include "cdx.h"
#include "misc.h"
#include "layer2.h"
#include "control_ipv4.h"

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/*
 * display_itf — Print CDX itf structure fields.
 */
void
display_itf(struct _itf *itf)
{

	printf("\nitf entry\t%p\n", itf);
	printf("type\t\t%x\n", itf->type);
	printf("index\t\t%d\n", itf->index);
	printf("parent\t\t%p\n", itf->phys);
}

/*
 * display_route_entry — Print CDX route entry fields.
 */
void
display_route_entry(PRouteEntry entry)
{

	printf("\nRoute entry\t%p\n", entry);
	printf("flags\t\t%x\n", entry->flags);
	printf("mtu\t\t%d\n", entry->mtu);
	printf("underlying_input_itf\t%p\n", entry->underlying_input_itf);
	printf("input_itf\t%p\n", entry->input_itf);

	printf("dest_mac\t");
	display_mac_addr(entry->dstmac);

	if (entry->itf != NULL)
		display_itf(entry->itf);
	else
		printf("itf is NULL\n");
}

/*
 * display_ctentry — Print CDX conntrack entry fields.
 */
void
display_ctentry(PCtEntry entry)
{

	printf("<<<<<\nentry\t%p\n\n", entry);
	printf("status\t\t%x\n\n", entry->status);

	if (entry->status & CONNTRACK_ORIG)
		printf("forward dir, ");
	else
		printf("rev dir, ");

	if (IS_IPV6_FLOW(entry)) {
		printf("ipv6 entry\n");
		printf("source ip\t");
		display_ipv6_addr((uint8_t *)entry->Saddr_v6);
		printf("dest ip\t\t");
		display_ipv6_addr((uint8_t *)entry->Daddr_v6);
	} else {
		printf("ipv4 entry\n");
		printf("source ip\t");
		display_ipv4_addr(entry->Saddr_v4);
		printf("dest ip\t\t");
		display_ipv4_addr(entry->Daddr_v4);
	}

	if ((entry->proto == IPPROTOCOL_UDP) ||
	    (entry->proto == IPPROTOCOL_TCP)) {
		printf("protocol\t%d\n", entry->proto);
		printf("sport\t\t%d\n", ntohs(entry->Sport));
		printf("dport\t\t%d\n", ntohs(entry->Dport));
	}

	printf("twin entry\t%p\n", entry->twin);

	if (entry->pRtEntry != NULL)
		display_route_entry(entry->pRtEntry);
	else
		printf("No route entry\n");

	printf(">>>>>\n");
}

/*
 * display_buf — Hex dump a buffer.
 */
void
display_buf(void *buf, uint32_t size)
{
	uint8_t *ptr;
	uint32_t ii, jj = 0;
	char buff[200];

	ptr = (uint8_t *)buf;
	for (ii = 0; ii < size; ii++) {
		if (ii && ((ii % 16) == 0)) {
			buff[jj] = 0;
			printf("%s\n", buff);
			jj = 0;
		}
		jj += sprintf(buff + jj, "%02x ", *ptr);
		ptr++;
	}
	buff[jj] = 0;
	printf("%s\n", buff);
}
