/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/* CDX timer control code */

#include "cdx.h"


u32 x_inner = 0;
u32 x_outer = 0;


void cdx_timer_init(TIMER_ENTRY *timer, TIMER_HANDLER handler)
{
	INIT_HLIST_NODE(&timer->node);
	timer->handler = handler;
	timer->period = 0;		// period must be 0 if not on a timer wheel
	timer->data64 = 0;
}

static inline void __timer_del(TIMER_ENTRY *timer)
{
	hlist_del(&timer->node);
	timer->period = 0;
}

static void __timer_add(struct _cdx_ctrl *ctrl, TIMER_ENTRY *timer)
{
	u32 x;
	signed int this_period;
	this_period = (signed int)(timer->timeout - JIFFIES32);
	if (this_period <= 0)
		this_period = 1;
	if (this_period <= INNER_WHEEL_MAXTIME)
	{
		x = x_inner + (this_period + INNER_WHEEL_PERIOD - 1) / INNER_WHEEL_PERIOD;
		x &= (INNER_WHEEL_SIZE - 1);
		//DPRINT_ERROR("inner wheel: JIFFIES32=%u, period=%u, this_period=%d, timeout=%u, timerdata=%u, x_inner=%u, x=%u\n", JIFFIES32, timer->period, this_period, timer->timeout, timer->timerdata, x_inner, x);
		hlist_add_head(&timer->node, &ctrl->timer_inner_wheel[x]);
	}
	else
	{
		if (this_period > OUTER_WHEEL_MAXTIME)
			this_period = OUTER_WHEEL_MAXTIME;
		x = x_outer + this_period / OUTER_WHEEL_PERIOD;
		x &= (OUTER_WHEEL_SIZE - 1);
		//DPRINT_ERROR("outer wheel: JIFFIES32=%u, period=%u, this_period=%d, timeout=%u, timerdata=%u, x_inner=%u, x=%u\n", JIFFIES32, timer->period, this_period, timer->timeout, timer->timerdata, x_inner, x);
		hlist_add_head(&timer->node, &ctrl->timer_outer_wheel[x]);
	}
}

void cdx_timer_del(TIMER_ENTRY *timer)
{
	if (timer->period)
	{
		__timer_del(timer);
	}
}


void cdx_timer_add(TIMER_ENTRY *timer, cdx_timer_t period)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	if (!timer->handler)
		return;
	if (period == 0)
		cdx_timer_del(timer);
	else if (timer->period == 0)
	{
		timer->period = period;
		timer->timeout = JIFFIES32 + period;
		__timer_add(ctrl, timer);
	}
}


/** Control code timer thread.
*
* A kernel thread is used so that the timer code can be run under the control path mutex.
*
* The thread wakes up regularly and checks the next inner wheel entry for timers to process.
* The timer handler for that timer is called, and if it returns one the timer is added back
* to one of the timer wheels, with the timeout value being set to the old timeout value. If
* the timer handler does not set a new period, then the old period is used again.
*
* If the timer handler returns zero, then the timer is not added back to either timer wheel.
* In this case, it is valid for the timer handler to free the storage for the timer entry.
*
* Every OUTER_WHEEL_COUNTER times through the loop, the outer wheel is processed. Each timer
* for the current outer wheel entry is simply removed from the current list and then added
* back to one of the timer wheels, using the same timeout value.
*
* @param data	Pointer to the control context structure
*
* @return	0 on sucess, a negative value on error
*
*/

void dpa_update_timestamp(uint32_t ts);

int cdx_ctrl_timer(void *data)
{
	struct _cdx_ctrl *ctrl = data;
	TIMER_ENTRY *timer;
	struct hlist_node *temp;

	int outer_wheel_counter = OUTER_WHEEL_COUNTER;

	while (!kthread_should_stop())
	{
		schedule_timeout_uninterruptible(INNER_WHEEL_PERIOD);

		mutex_lock(&ctrl->mutex);

		dpa_update_timestamp(JIFFIES32);

		// Process inner wheel.
		// Note that we will never put a node back onto the same linked list.
		hlist_for_each_entry_safe(timer, temp, &ctrl->timer_inner_wheel[x_inner], node)
		{
			cdx_timer_t old_period = timer->period;
			//DPRINT_ERROR("%p -- x_inner=%u\n", timer, x_inner);
			__timer_del(timer);	// remove from timer wheel and clear period

			// Don't touch the timer entry if timer handler returns 0 --
			//	it is possible the timer may have been freed.
			if (timer->handler(timer))
			{
				if (timer->period == 0)		// reuse old period unless new one is specified
					timer->period = old_period;
				//DPRINT_ERROR("new period=%u\n", timer->period);
				timer->timeout += timer->period;
				__timer_add(ctrl, timer);
			}
		}
		x_inner = (x_inner + 1) & (INNER_WHEEL_SIZE - 1);

		if (--outer_wheel_counter == 0)
		{
			// Process outer wheel.
			// Note that we will never put a node back onto the same linked list.
			hlist_for_each_entry_safe(timer, temp, &ctrl->timer_outer_wheel[x_outer], node)
			{
				hlist_del(&timer->node);
				__timer_add(ctrl, timer);
			}
			x_outer = (x_outer + 1) & (OUTER_WHEEL_SIZE - 1);
			outer_wheel_counter = OUTER_WHEEL_COUNTER;
		}

		mutex_unlock(&ctrl->mutex);
	}

	printk(KERN_INFO "%s exiting\n", __func__);

	return 0;
}

static void cdx_ctrl_timer_exit(void)
{
	struct _cdx_ctrl *ctrl;

	ctrl = &cdx_info->ctrl;
	if (ctrl->timer_thread)
		kthread_stop(ctrl->timer_thread);
	if (ctrl->timer_inner_wheel) kfree(ctrl->timer_inner_wheel);
	if (ctrl->timer_outer_wheel) kfree(ctrl->timer_outer_wheel);
	ctrl->timer_inner_wheel = NULL;
	ctrl->timer_outer_wheel = NULL;
	return;
}

int cdx_ctrl_timer_init(struct _cdx_ctrl *ctrl)
{
	int i;
	int rc = 0;
	ctrl->timer_thread = kthread_create(cdx_ctrl_timer, ctrl, "cdx_ctrl_timer");
	if (IS_ERR(ctrl->timer_thread))
	{
		printk(KERN_ERR "%s: kthread_create() failed\n", __func__);
		rc = PTR_ERR(ctrl->timer_thread);
		goto error;
	}
	ctrl->timer_inner_wheel = kmalloc(INNER_WHEEL_SIZE * sizeof(struct hlist_head), GFP_KERNEL);
	ctrl->timer_outer_wheel = kmalloc(OUTER_WHEEL_SIZE * sizeof(struct hlist_head), GFP_KERNEL);
	if (!ctrl->timer_inner_wheel || !ctrl->timer_outer_wheel)
	{
		printk(KERN_ERR "%s: kmalloc() failed\n", __func__);
		rc = -ENOMEM;
		goto error;
	}
	for (i = 0; i < INNER_WHEEL_SIZE; i++)
		INIT_HLIST_HEAD(&ctrl->timer_inner_wheel[i]);
	for (i = 0; i < OUTER_WHEEL_SIZE; i++)
		INIT_HLIST_HEAD(&ctrl->timer_outer_wheel[i]);
error:
	register_cdx_deinit_func(cdx_ctrl_timer_exit);
	return rc;
}

