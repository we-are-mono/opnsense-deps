/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _MODULE_WIFI_H_
#define _MODULE_WIFI_H_

#include "types.h"
#include "layer2.h"
#include "system.h"

#ifdef CFG_WIFI_OFFLOAD

typedef struct tWifiIfDesc
{
	int VAPID;
}WifiIfDesc, *PWifiIfDesc;

typedef struct tRX_wifi_context {
   U16 users;
   U16  enabled;
}RX_wifi_context;

typedef struct wifi_vap_query_response
{
        U16       vap_id;
        char      ifname[IF_NAME_SIZE];
        U16       phy_port_id;
}wifi_vap_query_response_t;

struct wifiCmd
{
	U16 action;
	U16 VAPID; 		/* Virtual AP Id */
	U8  ifname[IF_NAME_SIZE]; /* interface name */
	U8  mac_addr[6];	/* mac address of the interface */
	U16 wifi_guest_flag;	/* wifi guest or not */
};
#define WIFI_ADD_VAP       0
#define WIFI_REMOVE_VAP    1
#define WIFI_UPDATE_VAP    2


int wifi_init(void);
void wifi_exit(void);

//void wifi_tx_generate_csum(struct tMetadata *mtd);
//void wifi_rx_validate_csum(struct tMetadata *mtd);
#endif /* CFG_WIFI_OFFLOAD */

#endif /* _MODULE_WIFI_H_ */
