/*
 * Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#ifdef VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES
/* MACRO definitions */
/* Default dedicated channel is enabled, if comment the below definition pool channel gets enabled. */
#define VOIP_FQ_DEDICATED_CHANNEL
#define DEDICATED_CHANNEL	1
#define	POOL_CHANNEL		2

/* CPU_MASK is required if dedicated channel is used for voip frame queues.
 * It is not required for pool channel.
 */
#define CPU_MASK		0x8 /* Enabled for 4 cores(1111) */		
/* Voip frame queues is for if pool channel is used.
 * It is not required for dedicated channel.
 */
#define VOIP_FRAME_QUEUES	8


#endif /*endif for VOIP_PRIORITY_SLOW_PATH_FRAME_QUEUES*/
