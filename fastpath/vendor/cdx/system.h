/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _SYSTEM_H_
#define _SYSTEM_H_

#include "types.h"
#include "list.h"
#include "fe.h"


#define CFG_WIFI_OFFLOAD

#define MAX_PHY_PORTS           40

/* This should be defined based on board */
#define GEM_PORTS               8
#define WIFI0_PORT              GEM_PORTS
#define MAX_WIFI_VAPS           32

#ifdef CFG_WIFI_OFFLOAD
#define PORT_WIFI_IDX                   WIFI0_PORT
#define IS_WIFI_PORT(port)              (((port) >= WIFI0_PORT) && ((port) < (WIFI0_PORT + MAX_WIFI_VAPS)))
#else
#define IS_WIFI_PORT(port)              0
#endif


#endif

