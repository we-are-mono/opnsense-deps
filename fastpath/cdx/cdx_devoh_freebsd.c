/*
 * cdx_devoh_freebsd.c — Offline handler (OH) port management for FreeBSD
 *
 * Port of cdx-5.03.1/devoh.c.  Manages the mapping between OH ports
 * and their table descriptors, channel IDs, and port type assignments
 * (WiFi / IPsec).  OH ports are used by IPsec and WiFi offload to
 * re-inject packets into FMan for header manipulation.
 *
 * The Linux version creates QMan FQs via cdx_create_fq() and maintains
 * DQRR callbacks for debug/buffer-release.  On FreeBSD, OH port default
 * and error FQs are managed by the NCSW OH port driver (dpaa_oh.c),
 * so this file only handles the CDX-level port tracking and table
 * descriptor management.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "portdefs.h"
#include "cdx.h"
#include "cdx_ioctl.h"
#include "cdx_common.h"
#include "misc.h"

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/* ================================================================
 * OH port info tracking
 * ================================================================ */

struct oh_port_info {
	char name[64];
	uint32_t fm_idx;
	uint32_t flags;
	void *td[MAX_MATCH_TABLES];
	uint32_t channel;
	struct oh_iface_info *ohinfo;
};

struct oh_port_type {
	const char *name;
	uint32_t type;
};

/*
 * Port type assignments.  These match our DTS:
 *   oh@3 → cell-index 3 → port_idx 1 → dpa-fman0-oh@2 → IPsec
 *   oh@4 → cell-index 4 → port_idx 2 → dpa-fman0-oh@3 → WiFi
 */
static struct oh_port_type ohport_assign[] = {
	{ "dpa-fman0-oh@3", PORT_TYPE_WIFI },
	{ "dpa-fman0-oh@2", PORT_TYPE_IPSEC },
};
#define MAX_OH_PORT_ASSIGN \
	(sizeof(ohport_assign) / sizeof(struct oh_port_type))

static struct oh_port_info offline_port_info[MAX_FRAME_MANAGERS][MAX_OF_PORTS];

extern struct dpa_iface_info *dpa_interface_info;
extern spinlock_t dpa_devlist_lock;
extern struct cdx_fman_info *fman_info;

/* ================================================================
 * get_tableInfo_by_portid — ported from dpa_cfg.c
 *
 * Scans fman_info->tbl_info[] for tables attached to the given portid
 * and fills the td[] array + flags with matching table descriptors.
 * ================================================================ */

int
get_tableInfo_by_portid(int fm_index, int portid, void **td, int *flags)
{
	uint32_t jj;
	struct cdx_fman_info *finfo;
	struct table_info *tinfo;

	if (fm_index < 0 || fm_index >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s: invalid fman index %d\n", __func__, fm_index);
		return (-1);
	}

	finfo = &fman_info[fm_index];
	tinfo = finfo->tbl_info;
	for (jj = 0; jj < finfo->num_tables; jj++) {
		if (tinfo->type >= MAX_MATCH_TABLES) {
			tinfo++;
			continue;
		}
		if (tinfo->port_idx == (uint32_t)(1 << portid)) {
			td[tinfo->type] = tinfo->id;
			*flags |= (1 << tinfo->type);
		}
		tinfo++;
	}

	return (0);
}

/* ================================================================
 * OH port query functions
 * ================================================================ */

void *
get_oh_port_td(uint32_t fm_index, uint32_t port_idx, uint32_t type)
{

	if (fm_index >= MAX_FRAME_MANAGERS || port_idx >= MAX_OF_PORTS ||
	    type >= MAX_MATCH_TABLES)
		return (NULL);

	return (offline_port_info[fm_index][port_idx].td[type]);
}

int
get_ofport_fman_and_portindex(uint32_t fm_index, uint32_t handle,
    uint32_t *fm_idx, uint32_t *port_idx, uint32_t *portid)
{
	struct oh_port_info *info;

	info = &offline_port_info[fm_index][handle];
	if (info->ohinfo == NULL)
		return (-1);

	*fm_idx = info->ohinfo->fman_idx;
	*port_idx = info->ohinfo->port_idx;
	*portid = info->ohinfo->portid;

	return (0);
}

int
get_ofport_portid(uint32_t fm_idx, uint32_t handle, uint32_t *portid)
{
	struct oh_port_info *info;

	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s: invalid fman index\n", __func__);
		return (-1);
	}
	if (handle >= MAX_OF_PORTS) {
		DPA_ERROR("%s: invalid ofport handle %u\n", __func__, handle);
		return (-1);
	}

	info = &offline_port_info[fm_idx][handle];
	if (info->ohinfo == NULL)
		return (-1);

	*portid = info->ohinfo->portid;
	return (0);
}

int
get_ofport_info(uint32_t fm_idx, uint32_t handle, uint32_t *channel,
    void **td)
{
	struct oh_port_info *info;
	uint32_t ii;

	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s: invalid fman index\n", __func__);
		return (-1);
	}
	if (handle >= MAX_OF_PORTS) {
		DPA_ERROR("%s: invalid ofport handle %u\n", __func__, handle);
		return (-1);
	}

	info = &offline_port_info[fm_idx][handle];
	if (!(info->flags & IN_USE)) {
		DPA_ERROR("%s: ofport handle %u not in use\n",
		    __func__, handle);
		return (-1);
	}

	*channel = info->channel;
	get_tableInfo_by_portid(fm_idx, info->ohinfo->portid,
	    info->td, (int *)&info->flags);
	for (ii = 0; ii < MAX_MATCH_TABLES; ii++) {
		if (info->flags & (1 << ii))
			*(td + ii) = info->td[ii];
		else
			*(td + ii) = NULL;
	}

	return (0);
}

int
get_ofport_max_dist(uint32_t fm_idx, uint32_t handle, uint32_t *max_dist)
{
	struct oh_port_info *info;

	if (handle >= MAX_OF_PORTS)
		return (-1);

	info = &offline_port_info[fm_idx][handle];
	if (info->ohinfo == NULL)
		return (-1);

	*max_dist = info->ohinfo->max_dist;
	return (0);
}

int
get_oh_port_pcd_fqinfo(uint32_t fm_idx, uint32_t handle, uint32_t type,
    uint32_t *pfqid, uint32_t *count)
{
	uint32_t ii;
	struct oh_iface_info *iface_info;
	struct cdx_dist_info *dist;
	struct oh_port_info *info;

	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s: invalid fman index\n", __func__);
		return (-1);
	}
	if (handle >= MAX_OF_PORTS) {
		DPA_ERROR("%s: invalid ofport handle %u\n", __func__, handle);
		return (-1);
	}

	info = &offline_port_info[fm_idx][handle];
	if (!(info->flags & IN_USE)) {
		DPA_ERROR("%s: ofport handle %u not in use\n",
		    __func__, handle);
		return (-1);
	}

	iface_info = info->ohinfo;
	dist = iface_info->dist_info;
	for (ii = 0; ii < iface_info->max_dist; ii++) {
		if (dist->type == type) {
			*pfqid = dist->base_fqid;
			*count = dist->count;
		}
		dist++;
	}

	return (0);
}

/* ================================================================
 * Port allocation / release
 * ================================================================ */

int
alloc_offline_port(uint32_t fm_idx, uint32_t type,
    qman_cb_dqrr defa_rx __unused, qman_cb_dqrr err_rx __unused)
{
	uint32_t ii;
	struct oh_port_info *info;

	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s: invalid fman index\n", __func__);
		return (-1);
	}

	type &= PORT_TYPE_MASK;
	for (ii = 0; ii < MAX_OF_PORTS; ii++) {
		info = &offline_port_info[fm_idx][ii];
		if (info->flags & PORT_VALID) {
			if ((info->flags & PORT_TYPE_MASK) == type) {
				info->flags |= IN_USE;
				DPA_INFO("cdx: devoh: allocated OH port %u "
				    "(type 0x%x)\n", ii, type);
				return (ii);
			}
		}
	}

	DPA_ERROR("%s: no free OH ports for type 0x%x\n", __func__, type);
	return (-1);
}

int
release_offline_port(uint32_t fm_idx, int handle)
{
	struct oh_port_info *info;

	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s: invalid fman index\n", __func__);
		return (-1);
	}
	if (handle >= MAX_OF_PORTS) {
		DPA_ERROR("%s: invalid port index\n", __func__);
		return (-1);
	}

	info = &offline_port_info[fm_idx][handle];
	if (info->flags & IN_USE) {
		info->flags &= ~IN_USE;
		DPA_INFO("cdx: devoh: released OH port %d\n", handle);
		return (0);
	}

	DPA_ERROR("%s: port %d was not in use\n", __func__, handle);
	return (-1);
}

/* ================================================================
 * Table descriptor management
 * ================================================================ */

void
add_oh_port_tbl_info(uint32_t fm_index, uint32_t port_idx, void *td,
    uint32_t type)
{
	uint32_t ii;

	for (ii = 0; ii < MAX_OF_PORTS; ii++) {
		if (port_idx & (1 << ii)) {
			offline_port_info[fm_index][ii].td[type] = td;
			offline_port_info[fm_index][ii].flags |= (1 << type);
		}
	}
}

/* ================================================================
 * OH port registration — called during CDX init
 *
 * This populates the offline_port_info[][] array from the already-
 * registered OH interfaces in the devman list.  Must be called after
 * dpa_add_oh_if() has run for all OH ports.
 * ================================================================ */

int
cdxdrv_create_of_fqs(struct dpa_iface_info *dpa_oh_iface_info)
{
	struct oh_iface_info *iface_info;
	struct oh_port_info *port_info;
	uint32_t ii;

	iface_info = &dpa_oh_iface_info->oh_info;
	port_info =
	    &offline_port_info[iface_info->fman_idx][iface_info->port_idx];

	port_info->fm_idx = iface_info->fman_idx;
	port_info->ohinfo = iface_info;
	port_info->channel = iface_info->channel_id;

	snprintf(port_info->name, sizeof(port_info->name),
	    "dpa-fman%u-oh@%u",
	    iface_info->fman_idx, iface_info->port_idx + 1);

	/* Assign port type based on name mapping */
	for (ii = 0; ii < MAX_OH_PORT_ASSIGN; ii++) {
		if (strcmp(ohport_assign[ii].name, port_info->name) == 0) {
			port_info->flags |= ohport_assign[ii].type;
			break;
		}
	}

	port_info->flags |= (OF_FQID_VALID | PORT_VALID);

	DPA_INFO("cdx: devoh: registered OH port %s — "
	    "fm=%u port=%u channel=0x%x type=0x%x\n",
	    port_info->name, port_info->fm_idx, iface_info->port_idx,
	    port_info->channel, port_info->flags & PORT_TYPE_MASK);

	return (0);
}

/* ohport_set_ofne, ohport_set_dma — stubs in cdx_dpa_stub.c until
 * FM_PORT_SetOhPortOfne/Rda are added to the kernel NCSW driver */
