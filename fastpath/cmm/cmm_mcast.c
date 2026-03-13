/*
 * cmm_mcast.c — Multicast group offload
 *
 * Maintains a userspace shadow table of multicast groups and
 * forwards add/remove/update commands to CDX via FCI for
 * hardware multicast replication.
 *
 * Ported from NXP ASK module_mcast.c / module_mc4.c / module_mc6.c.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "cmm.h"
#include "cmm_mcast.h"
#include "cmm_ctrl.h"
#include "cmm_itf.h"
#include "libfci.h"

static struct list_head mc_table[MC_HASH_SIZE];

static inline unsigned int
mc_hash_v4(uint32_t dst_addr)
{

	return (ntohl(dst_addr) & (MC_HASH_SIZE - 1));
}

static inline unsigned int
mc_hash_v6(const uint32_t *dst_addr)
{

	return (ntohl(dst_addr[3]) & (MC_HASH_SIZE - 1));
}

static struct cmm_mcast_entry *
mc_find(const void *cmd_payload, sa_family_t family)
{
	struct cmm_mcast_entry *mc;
	struct list_head *pos;
	unsigned int h;
	uint32_t src[4], dst[4];
	int alen;

	if (family == AF_INET) {
		const struct cmm_mc4_cmd *c = cmd_payload;
		src[0] = c->src_addr;
		dst[0] = c->dst_addr;
		alen = 4;
		h = mc_hash_v4(dst[0]);
	} else {
		const struct cmm_mc6_cmd *c = cmd_payload;
		memcpy(src, c->src_addr, 16);
		memcpy(dst, c->dst_addr, 16);
		alen = 16;
		h = mc_hash_v6(dst);
	}

	for (pos = list_first(&mc_table[h]); pos != &mc_table[h];
	    pos = list_next(pos)) {
		mc = container_of(pos, struct cmm_mcast_entry, list);
		if (mc->family == family &&
		    memcmp(mc->src_addr, src, alen) == 0 &&
		    memcmp(mc->dst_addr, dst, alen) == 0)
			return (mc);
	}
	return (NULL);
}

/*
 * Send MC4 FCI command to CDX for a specific listener interface.
 * Builds the wire-format MC4Command with only the listeners that
 * match `ifname` and whose program state differs from `action`.
 */
static int
mc_send_mc4(struct cmm_global *g, unsigned short action,
    struct cmm_mcast_entry *mc, const char *ifname)
{
	struct cmm_mc4_cmd cmd;
	int i, j, rc;
	uint8_t program;

	program = (action == MC_ACTION_ADD) ? 1 : 0;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = action;
	cmd.mode = mc->mode;
	cmd.queue = mc->queue;
	cmd.src_addr_mask = mc->src_mask_len;
	cmd.src_addr = mc->src_addr[0];
	cmd.dst_addr = mc->dst_addr[0];
	strlcpy(cmd.input_device, mc->input_device,
	    sizeof(cmd.input_device));

	for (i = 0, j = 0; i < mc->num_output && j < 5; i++) {
		if ((program ^ mc->l_program[i]) &&
		    ifname != NULL &&
		    strncmp(mc->listener[i].output_device, ifname,
		    IFNAMSIZ) == 0) {
			memcpy(&cmd.output_list[j], &mc->listener[i],
			    sizeof(struct cmm_mc_listener));
			mc->l_program[i] = program;
			j++;
		}
	}
	cmd.num_output = j;

	if (j == 0)
		return (0);

	rc = fci_write(g->fci_handle, FPP_CMD_MC4_MULTICAST,
	    sizeof(cmd), (unsigned short *)&cmd);

	if (rc == FPP_ERR_MC_ENTRY_NOT_FOUND && action == MC_ACTION_REMOVE)
		return (0);

	if (rc != 0)
		cmm_print(CMM_LOG_WARN,
		    "mcast: mc4 send failed: %d (action=%d)", rc, action);

	return (rc);
}

/*
 * Send MC6 FCI command to CDX.
 */
static int
mc_send_mc6(struct cmm_global *g, unsigned short action,
    struct cmm_mcast_entry *mc, const char *ifname)
{
	struct cmm_mc6_cmd cmd;
	int i, j, rc;
	uint8_t program;

	program = (action == MC_ACTION_ADD) ? 1 : 0;

	memset(&cmd, 0, sizeof(cmd));
	cmd.action = action;
	cmd.mode = mc->mode;
	cmd.queue = mc->queue;
	cmd.src_mask_len = mc->src_mask_len;
	memcpy(cmd.src_addr, mc->src_addr, 16);
	memcpy(cmd.dst_addr, mc->dst_addr, 16);
	strlcpy(cmd.input_device, mc->input_device,
	    sizeof(cmd.input_device));

	for (i = 0, j = 0; i < mc->num_output && j < 5; i++) {
		if ((program ^ mc->l_program[i]) &&
		    ifname != NULL &&
		    strncmp(mc->listener[i].output_device, ifname,
		    IFNAMSIZ) == 0) {
			memcpy(&cmd.output_list[j], &mc->listener[i],
			    sizeof(struct cmm_mc_listener));
			mc->l_program[i] = program;
			j++;
		}
	}
	cmd.num_output = j;

	if (j == 0)
		return (0);

	rc = fci_write(g->fci_handle, FPP_CMD_MC6_MULTICAST,
	    sizeof(cmd), (unsigned short *)&cmd);

	if (rc == FPP_ERR_MC_ENTRY_NOT_FOUND && action == MC_ACTION_REMOVE)
		return (0);

	if (rc != 0)
		cmm_print(CMM_LOG_WARN,
		    "mcast: mc6 send failed: %d (action=%d)", rc, action);

	return (rc);
}

/*
 * Add a listener to a group.  Creates the group if it doesn't exist.
 * Returns the group entry, or NULL on failure.
 */
static struct cmm_mcast_entry *
mc_add(struct cmm_mcast_entry *mc, const void *cmd_payload,
    const struct cmm_mc_listener *listener, int num_listeners,
    uint8_t program, sa_family_t family)
{
	unsigned int h;
	int i, j, k, dup;
	int add_group;

	add_group = (mc == NULL);

	if (mc == NULL) {
		mc = calloc(1, sizeof(*mc));
		if (mc == NULL)
			return (NULL);
	}

	if (family == AF_INET) {
		const struct cmm_mc4_cmd *c = cmd_payload;

		if (add_group) {
			mc->mode = c->mode;
			mc->queue = c->queue;
			mc->src_addr[0] = c->src_addr;
			mc->dst_addr[0] = c->dst_addr;
			mc->src_mask_len = c->src_addr_mask;
			mc->family = AF_INET;
			strlcpy(mc->input_device, c->input_device,
			    sizeof(mc->input_device));
		}
		dup = 0;
		for (i = mc->num_output, j = 0;
		    i < MC_MAX_LISTENERS && j < num_listeners; i++, j++) {
			for (k = 0; k < i; k++) {
				if (memcmp(listener[j].uc_mac,
				    mc->listener[k].uc_mac,
				    ETHER_ADDR_LEN) == 0 &&
				    strncmp(listener[j].output_device,
				    mc->listener[k].output_device,
				    IFNAMSIZ) == 0) {
					dup++;
					break;
				}
			}
			if (k == i) {
				memcpy(&mc->listener[i], &listener[j],
				    sizeof(struct cmm_mc_listener));
				mc->l_program[i] = program;
			}
		}
		mc->num_output = i - dup;
	} else {
		const struct cmm_mc6_cmd *c = cmd_payload;

		if (add_group) {
			mc->mode = c->mode;
			mc->queue = c->queue;
			memcpy(mc->src_addr, c->src_addr, 16);
			memcpy(mc->dst_addr, c->dst_addr, 16);
			mc->src_mask_len = c->src_mask_len;
			mc->family = AF_INET6;
			strlcpy(mc->input_device, c->input_device,
			    sizeof(mc->input_device));
		}
		dup = 0;
		for (i = mc->num_output, j = 0;
		    i < MC_MAX_LISTENERS && j < num_listeners; i++, j++) {
			for (k = 0; k < i; k++) {
				if (memcmp(listener[j].uc_mac,
				    mc->listener[k].uc_mac,
				    ETHER_ADDR_LEN) == 0 &&
				    strncmp(listener[j].output_device,
				    mc->listener[k].output_device,
				    IFNAMSIZ) == 0) {
					dup++;
					break;
				}
			}
			if (k == i) {
				memcpy(&mc->listener[i], &listener[j],
				    sizeof(struct cmm_mc_listener));
				mc->l_program[i] = program;
			}
		}
		mc->num_output = i - dup;
	}

	if (add_group) {
		if (family == AF_INET)
			h = mc_hash_v4(mc->dst_addr[0]);
		else
			h = mc_hash_v6(mc->dst_addr);
		list_add(&mc_table[h], &mc->list);

		cmm_print(CMM_LOG_INFO,
		    "mcast: group added (%s, %d listeners)",
		    family == AF_INET ? "IPv4" : "IPv6",
		    mc->num_output);
	}

	return (mc);
}

/*
 * Remove listener(s) from a group.  If no listeners remain,
 * deletes the group from the hash table and frees it.
 */
static int
mc_remove(struct cmm_mcast_entry *mc,
    const struct cmm_mc_listener *listener, int num_listeners)
{
	int i, j;

	for (i = 0; i < num_listeners; i++) {
		for (j = 0; j < mc->num_output; j++) {
			if (listener[i].uc_bit) {
				if (!mc->listener[j].uc_bit)
					continue;
				if (memcmp(listener[i].uc_mac,
				    mc->listener[j].uc_mac,
				    ETHER_ADDR_LEN) != 0)
					continue;
			} else {
				if (mc->listener[j].uc_bit)
					continue;
				if (strncmp(listener[i].output_device,
				    mc->listener[j].output_device,
				    IFNAMSIZ) != 0)
					continue;
			}
			/* Found — compact the array */
			memmove(&mc->listener[j], &mc->listener[j + 1],
			    (mc->num_output - (j + 1)) *
			    sizeof(struct cmm_mc_listener));
			for (; j < mc->num_output - 1; j++)
				mc->l_program[j] = mc->l_program[j + 1];
			mc->num_output--;
			break;
		}
	}

	if (mc->num_output == 0) {
		cmm_print(CMM_LOG_INFO, "mcast: group removed (%s)",
		    mc->family == AF_INET ? "IPv4" : "IPv6");
		list_del(&mc->list);
		free(mc);
	}

	return (0);
}

/*
 * Update listener properties in-place.
 */
static int
mc_update(struct cmm_mcast_entry *mc,
    const struct cmm_mc_listener *listener, int num_listeners)
{
	int i, j;

	for (j = 0; j < num_listeners; j++) {
		for (i = 0; i < mc->num_output; i++) {
			if (memcmp(listener[j].uc_mac,
			    mc->listener[i].uc_mac,
			    ETHER_ADDR_LEN) == 0 &&
			    strncmp(listener[j].output_device,
			    mc->listener[i].output_device,
			    IFNAMSIZ) == 0) {
				memcpy(&mc->listener[i], &listener[j],
				    sizeof(struct cmm_mc_listener));
				break;
			}
		}
	}

	return (0);
}

static void
mc_reset(sa_family_t family)
{
	struct cmm_mcast_entry *mc;
	struct list_head *pos, *tmp;
	int i;

	for (i = 0; i < MC_HASH_SIZE; i++) {
		pos = list_first(&mc_table[i]);
		while (pos != &mc_table[i]) {
			tmp = list_next(pos);
			mc = container_of(pos, struct cmm_mcast_entry, list);
			if (mc->family == family) {
				list_del(&mc->list);
				free(mc);
			}
			pos = tmp;
		}
	}
}

/*
 * Helper: send ctrl response back to client.
 */
static void
ctrl_respond(int client_fd, int16_t rc, const void *data, uint16_t data_len)
{
	struct cmm_ctrl_resp resp;

	resp.rc = rc;
	resp.len = data_len;
	write(client_fd, &resp, sizeof(resp));
	if (data_len > 0 && data != NULL)
		write(client_fd, data, data_len);
}

/*
 * Check if an interface is up and registered with CMM.
 * Returns 1 if the interface is suitable for multicast offload.
 */
static int
itf_is_programmed(const char *ifname)
{
	struct cmm_interface *itf;
	int ifindex;

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
		return (0);

	itf = cmm_itf_find_by_index(ifindex);
	if (itf == NULL)
		return (0);

	/* Interface must be up */
	if (!(itf->flags & IFF_UP))
		return (0);

	return (1);
}

int
cmm_mcast_init(void)
{
	int i;

	for (i = 0; i < MC_HASH_SIZE; i++)
		list_head_init(&mc_table[i]);

	cmm_print(CMM_LOG_INFO, "mcast: initialized");
	return (0);
}

void
cmm_mcast_fini(void)
{
	struct cmm_mcast_entry *mc;
	struct list_head *pos, *tmp;
	int i;

	for (i = 0; i < MC_HASH_SIZE; i++) {
		pos = list_first(&mc_table[i]);
		while (pos != &mc_table[i]) {
			tmp = list_next(pos);
			mc = container_of(pos, struct cmm_mcast_entry, list);
			list_del(&mc->list);
			free(mc);
			pos = tmp;
		}
	}
}

void
cmm_mcast_ctrl_mc4(struct cmm_global *g, int client_fd,
    uint16_t *cmd_buf, uint16_t cmd_len)
{
	struct cmm_mc4_cmd *entry = (struct cmm_mc4_cmd *)cmd_buf;
	struct cmm_mc_listener *listener;
	struct cmm_mcast_entry *mc;
	uint16_t resp_buf[CMM_CTRL_MAX_PAYLOAD / 2];
	unsigned short resp_len;
	int program, rc;

	if (cmd_len < sizeof(struct cmm_mc4_cmd)) {
		ctrl_respond(client_fd, CMM_CTRL_ERR_BAD_LEN, NULL, 0);
		return;
	}

	/* Query commands pass straight through to CDX */
	if (entry->action == FPP_ACTION_QUERY ||
	    entry->action == FPP_ACTION_QUERY_CONT) {
		if (g->fci_handle == NULL) {
			ctrl_respond(client_fd, CMM_CTRL_ERR_NO_FCI, NULL, 0);
			return;
		}
		resp_len = sizeof(resp_buf);
		rc = fci_cmd(g->fci_handle, FPP_CMD_MC4_MULTICAST,
		    cmd_buf, cmd_len, resp_buf, &resp_len);
		if (rc < 0) {
			ctrl_respond(client_fd, CMM_CTRL_ERR_FCI_FAIL,
			    NULL, 0);
			return;
		}
		ctrl_respond(client_fd,
		    (resp_len >= 2) ? (int16_t)resp_buf[0] : 0,
		    resp_buf, resp_len);
		return;
	}

	if (entry->num_output > 5) {
		ctrl_respond(client_fd, FPP_ERR_MC_MAX_LISTENERS, NULL, 0);
		return;
	}

	listener = (struct cmm_mc_listener *)((uint8_t *)cmd_buf +
	    sizeof(struct cmm_mc4_cmd));

	/* Check if the output interface is ready for offload */
	program = 1;
	if (entry->num_output > 0 &&
	    !itf_is_programmed(listener[0].output_device))
		program = 0;

	mc = mc_find(entry, AF_INET);

	switch (entry->action) {
	case MC_ACTION_ADD:
		if (mc != NULL && mc->num_output >= MC_MAX_LISTENERS) {
			ctrl_respond(client_fd, FPP_ERR_MC_MAX_LISTENERS,
			    NULL, 0);
			return;
		}
		mc = mc_add(mc, entry, listener, entry->num_output,
		    program, AF_INET);
		if (mc == NULL) {
			ctrl_respond(client_fd, -1, NULL, 0);
			return;
		}
		break;

	case MC_ACTION_REMOVE:
		if (mc == NULL) {
			ctrl_respond(client_fd, FPP_ERR_MC_ENTRY_NOT_FOUND,
			    NULL, 0);
			return;
		}
		mc_remove(mc, listener, entry->num_output);
		break;

	case MC_ACTION_UPDATE:
		if (mc == NULL) {
			ctrl_respond(client_fd, FPP_ERR_MC_ENTRY_NOT_FOUND,
			    NULL, 0);
			return;
		}
		mc->mode = entry->mode;
		mc->queue = entry->queue;
		mc_update(mc, listener, entry->num_output);
		break;

	case MC_ACTION_REMOVE_LOCAL:
		if (mc != NULL) {
			list_del(&mc->list);
			free(mc);
		}
		ctrl_respond(client_fd, 0, NULL, 0);
		return;

	default:
		ctrl_respond(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD, NULL, 0);
		return;
	}

	/* Forward to CDX via FCI */
	if (g->fci_handle == NULL) {
		ctrl_respond(client_fd, CMM_CTRL_ERR_NO_FCI, NULL, 0);
		return;
	}

	resp_len = sizeof(resp_buf);
	rc = fci_cmd(g->fci_handle, FPP_CMD_MC4_MULTICAST,
	    cmd_buf, cmd_len, resp_buf, &resp_len);
	if (rc < 0) {
		ctrl_respond(client_fd, CMM_CTRL_ERR_FCI_FAIL, NULL, 0);
		return;
	}

	ctrl_respond(client_fd,
	    (resp_len >= 2) ? (int16_t)resp_buf[0] : 0,
	    resp_buf, resp_len);
}

void
cmm_mcast_ctrl_mc6(struct cmm_global *g, int client_fd,
    uint16_t *cmd_buf, uint16_t cmd_len)
{
	struct cmm_mc6_cmd *entry = (struct cmm_mc6_cmd *)cmd_buf;
	struct cmm_mc_listener *listener;
	struct cmm_mcast_entry *mc;
	uint16_t resp_buf[CMM_CTRL_MAX_PAYLOAD / 2];
	unsigned short resp_len;
	int program, rc;

	if (cmd_len < sizeof(struct cmm_mc6_cmd)) {
		ctrl_respond(client_fd, CMM_CTRL_ERR_BAD_LEN, NULL, 0);
		return;
	}

	/* Query commands pass straight through to CDX */
	if (entry->action == FPP_ACTION_QUERY ||
	    entry->action == FPP_ACTION_QUERY_CONT) {
		if (g->fci_handle == NULL) {
			ctrl_respond(client_fd, CMM_CTRL_ERR_NO_FCI, NULL, 0);
			return;
		}
		resp_len = sizeof(resp_buf);
		rc = fci_cmd(g->fci_handle, FPP_CMD_MC6_MULTICAST,
		    cmd_buf, cmd_len, resp_buf, &resp_len);
		if (rc < 0) {
			ctrl_respond(client_fd, CMM_CTRL_ERR_FCI_FAIL,
			    NULL, 0);
			return;
		}
		ctrl_respond(client_fd,
		    (resp_len >= 2) ? (int16_t)resp_buf[0] : 0,
		    resp_buf, resp_len);
		return;
	}

	if (entry->num_output > 5) {
		ctrl_respond(client_fd, FPP_ERR_MC_MAX_LISTENERS, NULL, 0);
		return;
	}

	listener = (struct cmm_mc_listener *)((uint8_t *)cmd_buf +
	    sizeof(struct cmm_mc6_cmd));

	program = 1;
	if (entry->num_output > 0 &&
	    !itf_is_programmed(listener[0].output_device))
		program = 0;

	mc = mc_find(entry, AF_INET6);

	switch (entry->action) {
	case MC_ACTION_ADD:
		if (mc != NULL && mc->num_output >= MC_MAX_LISTENERS) {
			ctrl_respond(client_fd, FPP_ERR_MC_MAX_LISTENERS,
			    NULL, 0);
			return;
		}
		mc = mc_add(mc, entry, listener, entry->num_output,
		    program, AF_INET6);
		if (mc == NULL) {
			ctrl_respond(client_fd, -1, NULL, 0);
			return;
		}
		break;

	case MC_ACTION_REMOVE:
		if (mc == NULL) {
			ctrl_respond(client_fd, FPP_ERR_MC_ENTRY_NOT_FOUND,
			    NULL, 0);
			return;
		}
		mc_remove(mc, listener, entry->num_output);
		break;

	case MC_ACTION_UPDATE:
		if (mc == NULL) {
			ctrl_respond(client_fd, FPP_ERR_MC_ENTRY_NOT_FOUND,
			    NULL, 0);
			return;
		}
		mc->mode = entry->mode;
		mc->queue = entry->queue;
		mc_update(mc, listener, entry->num_output);
		break;

	case MC_ACTION_REMOVE_LOCAL:
		if (mc != NULL) {
			list_del(&mc->list);
			free(mc);
		}
		ctrl_respond(client_fd, 0, NULL, 0);
		return;

	default:
		ctrl_respond(client_fd, CMM_CTRL_ERR_UNKNOWN_CMD, NULL, 0);
		return;
	}

	/* Forward to CDX via FCI */
	if (g->fci_handle == NULL) {
		ctrl_respond(client_fd, CMM_CTRL_ERR_NO_FCI, NULL, 0);
		return;
	}

	resp_len = sizeof(resp_buf);
	rc = fci_cmd(g->fci_handle, FPP_CMD_MC6_MULTICAST,
	    cmd_buf, cmd_len, resp_buf, &resp_len);
	if (rc < 0) {
		ctrl_respond(client_fd, CMM_CTRL_ERR_FCI_FAIL, NULL, 0);
		return;
	}

	ctrl_respond(client_fd,
	    (resp_len >= 2) ? (int16_t)resp_buf[0] : 0,
	    resp_buf, resp_len);
}

void
cmm_mcast_ctrl_mc4_reset(struct cmm_global *g, int client_fd)
{
	int rc = 0;

	if (g->fci_handle != NULL)
		rc = fci_write(g->fci_handle, FPP_CMD_MC4_RESET, 0, NULL);

	if (rc == 0)
		mc_reset(AF_INET);

	ctrl_respond(client_fd, rc, NULL, 0);
}

void
cmm_mcast_ctrl_mc6_reset(struct cmm_global *g, int client_fd)
{
	int rc = 0;

	if (g->fci_handle != NULL)
		rc = fci_write(g->fci_handle, FPP_CMD_MC6_RESET, 0, NULL);

	if (rc == 0)
		mc_reset(AF_INET6);

	ctrl_respond(client_fd, rc, NULL, 0);
}

void
cmm_mcast_itf_update(struct cmm_global *g, const char *ifname, int is_up)
{
	struct cmm_mcast_entry *mc;
	struct list_head *pos;
	unsigned short action;
	int i, j;

	if (g->fci_handle == NULL)
		return;

	action = is_up ? MC_ACTION_ADD : MC_ACTION_REMOVE;

	for (i = 0; i < MC_HASH_SIZE; i++) {
		for (pos = list_first(&mc_table[i]); pos != &mc_table[i];
		    pos = list_next(pos)) {
			mc = container_of(pos, struct cmm_mcast_entry, list);
			for (j = 0; j < mc->num_output; j++) {
				if (strncmp(mc->listener[j].output_device,
				    ifname, IFNAMSIZ) != 0)
					continue;
				if (mc->family == AF_INET)
					mc_send_mc4(g, action, mc, ifname);
				else
					mc_send_mc6(g, action, mc, ifname);
				break;
			}
		}
	}
}
