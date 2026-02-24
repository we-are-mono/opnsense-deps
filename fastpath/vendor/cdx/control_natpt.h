/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifndef _CONTROL_NATPT_H_
#define _CONTROL_NATPT_H_

#define NATPT_CONTROL_6to4	0x0001
#define NATPT_CONTROL_4to6	0x0002


/* control path SW natpt entry */

typedef struct _tNATPT_Stats {
	U64	stat_v6_received;
	U64	stat_v6_transmitted;
	U64	stat_v6_dropped;
	U64	stat_v6_sent_to_ACP;
	U64	stat_v4_received;
	U64	stat_v4_transmitted;
	U64	stat_v4_dropped;
	U64	stat_v4_sent_to_ACP;
} NATPT_Stats, *PNATPT_Stats;

typedef struct _tNATPTOpenCommand {
	U16	socketA;
	U16	socketB;
	U16	control;
	U16	reserved;
}NATPTOpenCommand, *PNATPTOpenCommand;

typedef struct _tNATPTCloseCommand {
	U16	socketA;
	U16	socketB;
}NATPTCloseCommand, *PNATPTCloseCommand;

typedef struct _tNATPTQueryCommand {
	U16	reserved1;
	U16	socketA;
	U16	socketB;
	U16	reserved2;
}NATPTQueryCommand, *PNATPTQueryCommand;

typedef struct _tNATPTQueryResponse {
	U16	retcode;
	U16	socketA;
	U16	socketB;
	U16	control;
	U64	stat_v6_received;
	U64	stat_v6_transmitted;
	U64	stat_v6_dropped;
	U64	stat_v6_sent_to_ACP;
	U64	stat_v4_received;
	U64	stat_v4_transmitted;
	U64	stat_v4_dropped;
	U64	stat_v4_sent_to_ACP;
}NATPTQueryResponse, *PNATPTQueryResponse;

BOOL natpt_init(void);
void natpt_exit(void);

#endif /* _CONTROL_NATPT_H_ */
