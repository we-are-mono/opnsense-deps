/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _CDX_TIMER_H_
#define _CDX_TIMER_H_

// We use the low 32 bits of the jiffies variable as the current time.

#define cdx_timer_t	u32
#define	JIFFIES32	((cdx_timer_t)jiffies)

#define ct_timer	JIFFIES32

#define TIME_BEFORE(a, b)	((signed int)((cdx_timer_t)a - (cdx_timer_t)b) < 0)
#define TIME_BEFORE_EQ(a, b)	((signed int)((cdx_timer_t)a - (cdx_timer_t)b) <= 0)
#define TIME_AFTER(a, b)	TIME_BEFORE_EQ(b, a)
#define TIME_AFTER_EQ(a, b)	TIME_BEFORE(b, a)

// The inner wheel should have a maximum period of 1 second.
// The outer wheel should have a minimum period of 1 minute.

// The maxtime of the inner wheel should be at least two times the period
//	of the outer wheel.

#define INNER_WHEEL_FREQUENCY	10	/* ticks per second */
#define INNER_WHEEL_PERIOD	(HZ / INNER_WHEEL_FREQUENCY)	/* period, in jiffies */

// Wheel sizes must each be a power of 2
#define INNER_WHEEL_SIZE	2048
#define OUTER_WHEEL_SIZE	512

#define OUTER_WHEEL_PERIOD	(1 * 60 * HZ)	/* period, in jiffies */
#define OUTER_WHEEL_COUNTER	((OUTER_WHEEL_PERIOD / HZ) * INNER_WHEEL_FREQUENCY)

#define INNER_WHEEL_MAXTIME	((INNER_WHEEL_SIZE - 2) * INNER_WHEEL_PERIOD)
#define OUTER_WHEEL_MAXTIME	((OUTER_WHEEL_SIZE - 2) * OUTER_WHEEL_PERIOD)

struct timer_entry_t;
typedef int (* TIMER_HANDLER)(struct timer_entry_t *entry);

typedef struct timer_entry_t
{
	struct hlist_node node;
	TIMER_HANDLER handler;
	cdx_timer_t timeout;
	cdx_timer_t period;
	union {				// reserved for use by timer handlers
		void *ptr;
		uint64_t data64;
		uint32_t data32;
		cdx_timer_t timerdata;
	};
} TIMER_ENTRY;

/** Initializes a timer structure.
* Must be called once for each TIMER_ENTRY structure.
* The caller must be holding the ctrl->mutex.
*
* @param timer		pointer to the timer to be initialized
* @param handler	timer handler function pointer
*
*/
void cdx_timer_init(TIMER_ENTRY *timer, TIMER_HANDLER handler);

/** Adds a timer to the running timer list.
* It's safe to call even if the timer was already running. In this case we just update the period.
* The caller must be holding the ctrl->mutex.
*
* @param timer		pointer to the timer to be added
* @param period		period of the timer (in timer tick units)
*
*/
void cdx_timer_add(TIMER_ENTRY *timer, cdx_timer_t period);

/** Deletes a timer from the running timer list.
* It's safe to call even if the timer is no longer running.
* The caller must be holding the ctrl->mutex.
*
* @param timer	pointer to the timer to be removed
*/
void cdx_timer_del(TIMER_ENTRY *timer);


// Function prototypes

int cdx_ctrl_timer(void *data);
int cdx_ctrl_timer_init(struct _cdx_ctrl *ctrl);

#endif /* _CDX_TIMER_H_ */
