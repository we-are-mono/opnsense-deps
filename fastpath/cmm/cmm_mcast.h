/*
 * cmm_mcast.h — Multicast group offload
 *
 * Maintains a shadow table of multicast groups and their
 * listeners.  Programs CDX hardware multicast replication
 * via FCI CMD_MC4/MC6_MULTICAST.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CMM_MCAST_H
#define CMM_MCAST_H

#include <net/if.h>
#include <net/ethernet.h>
#include <stdint.h>

#include "cmm.h"

/* Hash table sizes — match CDX kernel module */
#define MC_HASH_SIZE		32
#define MC_MAX_LISTENERS	8	/* MC_MAX_LISTENERS_PER_GROUP in CDX */

/* Actions (match CDX_MC_ACTION_*) */
#define MC_ACTION_ADD		0
#define MC_ACTION_REMOVE	1
#define MC_ACTION_UPDATE	2
#define MC_ACTION_REMOVE_LOCAL	11

/*
 * FPP command codes for multicast (match CMD_MC4/MC6_* in
 * cdx_cmdhandler.h).  These are the FCI wire protocol codes
 * that CDX expects.
 */
#define FPP_CMD_MC4_MULTICAST	0x0701
#define FPP_CMD_MC4_RESET	0x0702
#define FPP_CMD_MC6_MULTICAST	0x0703
#define FPP_CMD_MC6_RESET	0x0704

/*
 * Listener — one output port for a multicast group.
 * Wire format matches MC4Output/MC6Output in dpa_control_mc.h.
 */
struct cmm_mc_listener {
	uint32_t	timer;
	char		output_device[IFNAMSIZ];
	uint8_t		shaper_mask;
	uint8_t		uc_bit:1,
			q_bit:1,
			rsvd:6;
	uint8_t		uc_mac[ETHER_ADDR_LEN];
	uint8_t		queue;
	char		new_output_device[IFNAMSIZ];
	uint8_t		ifbit:1,
			rsvd1:7;
	uint8_t		padding[2];
} __packed;

/*
 * Multicast group entry — CMM shadow table.
 * Tracks one (src, dst) multicast group with up to
 * MC_MAX_LISTENERS output ports.
 */
struct cmm_mcast_entry {
	struct list_head	list;
	uint8_t			family;		/* AF_INET or AF_INET6 */
	uint8_t			mode:1,		/* 0=routed, 1=bridged */
				queue:5,
				rsvd:2;
	uint8_t			src_mask_len;
	uint32_t		src_addr[4];	/* IPv4 in [0], IPv6 full */
	uint32_t		dst_addr[4];
	uint8_t			num_output;
	uint8_t			l_program[MC_MAX_LISTENERS];
	char			input_device[IFNAMSIZ];
	struct cmm_mc_listener	listener[MC_MAX_LISTENERS];
};

/*
 * MC4 command payload — wire format for CMD_MC4_MULTICAST.
 * Must match MC4Command in dpa_control_mc.h exactly.
 */
struct cmm_mc4_cmd {
	uint16_t	action;
	uint8_t		src_addr_mask;
	uint8_t		mode:1,
			queue:5,
			rsvd:2;
	uint32_t	src_addr;
	uint32_t	dst_addr;
	uint32_t	num_output;
	char		input_device[IFNAMSIZ];
	struct cmm_mc_listener	output_list[5];
} __packed;

/*
 * MC6 command payload — wire format for CMD_MC6_MULTICAST.
 * Must match MC6Command in dpa_control_mc.h exactly.
 */
struct cmm_mc6_cmd {
	uint16_t	action;
	uint8_t		mode:1,
			queue:5,
			rsvd:2;
	uint8_t		src_mask_len;
	uint32_t	src_addr[4];
	uint32_t	dst_addr[4];
	uint32_t	num_output;
	char		input_device[IFNAMSIZ];
	struct cmm_mc_listener	output_list[5];
} __packed;

/* Initialize / finalize multicast module */
int	cmm_mcast_init(void);
void	cmm_mcast_fini(void);

/*
 * Process MC4/MC6 control commands from the control socket.
 * Handles add/remove/update locally, then forwards to CDX via FCI.
 * Query commands pass straight through to CDX.
 */
void	cmm_mcast_ctrl_mc4(struct cmm_global *g, int client_fd,
	    uint16_t *cmd_buf, uint16_t cmd_len);
void	cmm_mcast_ctrl_mc6(struct cmm_global *g, int client_fd,
	    uint16_t *cmd_buf, uint16_t cmd_len);
void	cmm_mcast_ctrl_mc4_reset(struct cmm_global *g, int client_fd);
void	cmm_mcast_ctrl_mc6_reset(struct cmm_global *g, int client_fd);

/*
 * Re-program multicast groups when an interface changes state.
 * Called from cmm_itf.c on link state changes.
 */
void	cmm_mcast_itf_update(struct cmm_global *g, const char *ifname,
	    int is_up);

#endif /* CMM_MCAST_H */
