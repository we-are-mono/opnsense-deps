/*
 * CDX LAGG (link aggregation) command handler.
 *
 * Follows the control_vlan.c pattern. LAGG is transparent to header
 * manipulation — it only provides a traversable node in the interface
 * chain so that VLAN→LAGG→ETH resolution works.
 *
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "portdefs.h"
#include "cdx.h"
#include "control_lagg.h"
#include "misc.h"

static PLaggEntry lagg_alloc(void)
{
	return kzalloc(sizeof(LaggEntry), GFP_KERNEL);
}

static void lagg_free(PLaggEntry pEntry)
{
	kfree(pEntry);
}

static void lagg_add(PLaggEntry pEntry, const U8 *name)
{
	U32 hash;

	hash = HASH_LAGG(name);
	slist_add(&lagg_cache[hash], &pEntry->list);
}

static void lagg_remove(PLaggEntry pEntry, const U8 *name)
{
	struct slist_entry *prev;
	U32 hash;

	remove_onif_by_index(pEntry->itf.index);

	hash = HASH_LAGG(name);
	prev = slist_prev(&lagg_cache[hash], &pEntry->list);
	if (prev)
		slist_remove_after(prev);
}

static U16 Lagg_handle_reset(void)
{
	PLaggEntry pEntry;
	struct slist_entry *entry;
	int i;

	for (i = 0; i < NUM_LAGG_ENTRIES; i++) {
		slist_for_each_safe(pEntry, entry, &lagg_cache[i], list) {
			lagg_remove(pEntry, get_onif_name(pEntry->itf.index));
			lagg_free(pEntry);
		}
	}
	return NO_ERR;
}

static U16 Lagg_handle_entry(U16 *p, U16 Length)
{
	LaggCommand laggcmd;
	PLaggEntry pEntry;
	struct slist_entry *entry;
	POnifDesc phys_onif;
	U32 hash;
	int rc = NO_ERR;

	if (Length < sizeof(LaggCommand))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy(&laggcmd, p, sizeof(LaggCommand));

	switch (laggcmd.action) {
	case ACTION_DEREGISTER:
		hash = HASH_LAGG(laggcmd.laggifname);
		slist_for_each(pEntry, entry, &lagg_cache[hash], list) {
			if (strcmp(get_onif_name(pEntry->itf.index),
			    (char *)laggcmd.laggifname) == 0)
				goto found;
		}
		rc = ERR_LAGG_ENTRY_NOT_FOUND;
		break;
found:
		lagg_remove(pEntry, laggcmd.laggifname);
		lagg_free(pEntry);
		break;

	case ACTION_REGISTER:
		if (get_onif_by_name(laggcmd.laggifname)) {
			rc = ERR_LAGG_ENTRY_ALREADY_REGISTERED;
			break;
		}

		pEntry = lagg_alloc();
		if (pEntry == NULL) {
			rc = ERR_NOT_ENOUGH_MEMORY;
			break;
		}

		/* Find the physical member port in the onif database */
		phys_onif = get_onif_by_name(laggcmd.phyifname);
		if (!phys_onif) {
			DPA_ERROR("cdx: lagg: phy '%s' not in onif DB\n",
			    laggcmd.phyifname);
			lagg_free(pEntry);
			rc = ERR_UNKNOWN_INTERFACE;
			break;
		}

		/* Register in the interface manager */
		if (!add_onif(laggcmd.laggifname, &pEntry->itf,
		    phys_onif->itf, 0)) {
			lagg_free(pEntry);
			rc = ERR_CREATION_FAILED;
			break;
		}

		/* Register in the DPA device manager */
		if (dpa_add_lagg_if(laggcmd.laggifname, &pEntry->itf,
		    phys_onif->itf, laggcmd.macaddr)) {
			remove_onif_by_index(pEntry->itf.index);
			lagg_free(pEntry);
			rc = ERR_CREATION_FAILED;
			break;
		}

		lagg_add(pEntry, laggcmd.laggifname);
		break;

	default:
		return ERR_UNKNOWN_ACTION;
	}

	return rc;
}

static U16 M_lagg_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc;
	U16 retlen = 2;

	switch (cmd_code) {
	case CMD_LAGG_ENTRY:
		rc = Lagg_handle_entry(pcmd, cmd_len);
		break;
	case CMD_LAGG_RESET:
		rc = Lagg_handle_reset();
		break;
	default:
		rc = ERR_UNKNOWN_COMMAND;
		break;
	}

	*pcmd = rc;
	return retlen;
}

int lagg_init(void)
{
	int i;

	set_cmd_handler(EVENT_LAGG, M_lagg_cmdproc);

	for (i = 0; i < NUM_LAGG_ENTRIES; i++)
		slist_head_init(&lagg_cache[i]);

	return 0;
}

void lagg_exit(void)
{
	PLaggEntry pEntry;
	struct slist_entry *entry;
	int i;

	for (i = 0; i < NUM_LAGG_ENTRIES; i++) {
		slist_for_each_safe(pEntry, entry, &lagg_cache[i], list) {
			lagg_remove(pEntry, get_onif_name(pEntry->itf.index));
			lagg_free(pEntry);
		}
	}
}
