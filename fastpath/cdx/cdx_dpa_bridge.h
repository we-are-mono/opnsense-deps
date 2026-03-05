/*
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CDX_DPA_BRIDGE_H
#define CDX_DPA_BRIDGE_H

#include <contrib/ncsw/inc/ncsw_ext.h>

struct dtsec_softc;
struct ifnet;

int	cdx_dpa_bridge_init(void);
void	cdx_dpa_bridge_destroy(void);
int	cdx_dpa_bridge_register_dtsec(void);
void	cdx_dpa_bridge_print_dtsec(void);

/* dtsec lookup helpers for devman */
struct dtsec_softc *cdx_dpa_bridge_find_dtsec(const char *ifname);
struct ifnet *cdx_dpa_bridge_find_ifnet(const char *ifname);
struct dtsec_softc *cdx_dpa_bridge_find_dtsec_by_ethid(uint8_t eth_id);
const char	*cdx_dpa_bridge_find_ifname_by_fman_params(uint32_t fm_index,
		    uint32_t port_idx, uint32_t type);
t_Handle	cdx_dpa_bridge_get_rx_pool(void);
void		*cdx_dpa_bridge_get_rx_sc(void);
void		cdx_dpa_bridge_rx_buf_free(void *sc_opaque, void *buf);
unsigned int	cdx_dpa_bridge_rx_pool_refill(void *sc_opaque,
		    unsigned int count);

/* OH port discovery and lookup (CDX port number is 1-based) */
void		cdx_dpa_bridge_discover_oh_ports(void);
device_t	cdx_dpa_bridge_get_oh_dev(int number);
t_Handle	cdx_dpa_bridge_get_oh_fm_port(int number);
uint32_t	cdx_dpa_bridge_get_oh_channel(int number);
uint32_t	cdx_dpa_bridge_get_oh_dflt_fqid(int number);

/* Access fman device (for chardev handle resolution) */
device_t	cdx_dpa_bridge_get_fman_dev(void);

/* QoS helpers — port handle and PCD accessors */
t_Handle	cdx_dpa_bridge_get_rx_port_handle(uint8_t eth_id);
t_Handle	cdx_dpa_bridge_get_pcd_handle(void);
bool		cdx_dpa_bridge_is_10g_port(uint8_t eth_id);

/* Number of FMan instances (set by bridge init) */
extern uint32_t cdx_num_fmans;

#endif /* CDX_DPA_BRIDGE_H */
