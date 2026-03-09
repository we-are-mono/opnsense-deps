/*
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef _CONTROL_LAGG_H_
#define _CONTROL_LAGG_H_

/* Internal LAGG entry used by the LAGG engine */
typedef struct _tLaggEntry {
	itf_t itf;
	struct slist_entry list;
} LaggEntry, *PLaggEntry;

/* Structure defining the LAGG ENTRY command */
typedef struct _tLaggCommand {
	U16 action;
	U16 pad;
	U8 laggifname[IF_NAME_SIZE];
	U8 phyifname[IF_NAME_SIZE];
	U8 macaddr[6];
	U8 unused[2];
} LaggCommand, *PLaggCommand;

int lagg_init(void);
void lagg_exit(void);

static __inline U32 HASH_LAGG(const U8 *name)
{
	U32 h = 0;
	while (*name)
		h = h * 31 + *name++;
	return (h & (NUM_LAGG_ENTRIES - 1));
}

#endif /* _CONTROL_LAGG_H_ */
