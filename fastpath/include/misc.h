/*
 * CDX misc helper macros — FreeBSD replacement
 *
 * Replaces the original misc.h which includes Linux-specific logging.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef MISC_H
#define MISC_H

#include "types.h"
#include "fe.h"

#define SUCCESS		0
#define FAILURE		1

#define DPA_ERROR(fmt, args...)	printf("DPA_ERR %s: " fmt, __func__, ##args)
#define DPA_INFO(fmt, args...)	printf("DPA_INFO %s: " fmt, __func__, ##args)

/* Display helpers — Linux uses %pI4/%pI6c/%pM format specifiers.
 * FreeBSD doesn't have these, so we format manually. */
static inline void
display_ipv4_addr(uint32_t addr)
{
	uint8_t *p = (uint8_t *)&addr;

	printf("%u.%u.%u.%u\n", p[0], p[1], p[2], p[3]);
}

static inline void
display_ipv6_addr(uint8_t *addr)
{
	uint16_t *p = (uint16_t *)addr;

	printf("%x:%x:%x:%x:%x:%x:%x:%x\n",
	    ntohs(p[0]), ntohs(p[1]), ntohs(p[2]), ntohs(p[3]),
	    ntohs(p[4]), ntohs(p[5]), ntohs(p[6]), ntohs(p[7]));
}

static inline void
display_mac_addr(uint8_t *addr)
{

	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static inline void
display_buff_data(uint8_t *ptr, uint32_t len)
{
	uint32_t ii, jj = 0;
	char buff[200];

	for (ii = 0; ii < len; ii++) {
		if (ii && ((ii % 16) == 0)) {
			buff[jj] = 0;
			printf("%s\n", buff);
			jj = 0;
		}
		jj += sprintf(buff + jj, "%02x ", ptr[ii]);
	}
	buff[jj] = 0;
	printf("%s\n", buff);
}

#endif /* _MISC_H_ */
