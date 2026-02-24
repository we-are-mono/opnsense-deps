/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _CDX_DEFS_H_
#define _CDX_DEFS_H_

int dpa_add_ethport_ff_policier_profile(struct dpa_iface_info *iface_info);
int dpa_get_iface_hwid_by_name_and_type(char *name, uint32_t type);
struct dpa_iface_info *dpa_get_iface_by_name(char *name);
int dpa_add_virt_storage_profile(struct net_device *net_dev,
				struct eth_iface_info *eth_info);
int dpa_remove_virt_storage_profile(struct eth_iface_info *eth_info);
#endif /* _CDX_DEFS_H_ */
