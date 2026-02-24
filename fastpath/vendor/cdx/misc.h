/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**     
 * @file                misc.h
 * @description         helper and other macros  
 */ 

#ifndef MISC_H
#define MISC_H 1

#include "types.h"
#include "fe.h"

#define SUCCESS                 0
#define FAILURE                 -1

//#define CDX_DPA_DEBUG

#define DPA_ERROR(fmt, ...)\
{\
	printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#ifdef CDX_DPA_DEBUG
#define DPA_INFO(fmt, ...)\
{\
	printk(KERN_INFO fmt, ## __VA_ARGS__);\
}
#else
#define DPA_INFO(fmt, ...)
#endif // CDX_DPA_DEBUG
#define DPA_PACKED __attribute__ ((packed))

static inline void display_ipv4_addr(uint32_t addr)
{
	printk("%pI4\n", &addr);
}

static inline void display_ipv6_addr(uint8_t *addr)
{
	printk("%pI6c\n", (void *)addr);
}

static inline void display_mac_addr(uint8_t *addr)
{
	printk("%pM\n", (void *)addr);
}

static inline void display_buff_data(uint8_t *ptr, uint32_t len)
{
        uint32_t ii,jj=0;
	char buff[200];
        for (ii = 0; ii < len; ii++) {
                if ((ii % 16) == 0)
		{
			buff[jj]=0;
                        printk("%s\n",buff);
			jj = 0;
		}
                jj += sprintf(buff+jj,"%02x ", *(ptr + ii));
        }
	buff[jj]=0;
	printk("%s\n",buff);
}

//required by dpa_offload ip address
#define TYPE_IP4	4
#define TYPE_IPV6	6

#define DPA_UNUSED __attribute__((unused))


//used for PCD FQ creation
#define NUM_PKT_DATA_LINES_IN_CACHE     2
#define NUM_ANN_LINES_IN_CACHE          1


void*  M_ipsec_get_sa_netdev( U16 handle);
#endif
