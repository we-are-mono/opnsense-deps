/*
 * CDX timer control code — FreeBSD port
 *
 * Replaces cdx_timer.c. Key changes:
 * - kthread_create → kthread_add (via wrapper)
 * - kthread_should_stop → volatile flag
 * - schedule_timeout_uninterruptible → pause(9)
 * - wake_up_process → thread starts immediately on FreeBSD
 *
 * The timer wheel logic itself (inner/outer wheel, __timer_add,
 * __timer_del) is OS-independent, using hlist_* from compat headers.
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "cdx.h"

u32 x_inner = 0;
u32 x_outer = 0;

/* Thread control */
static struct thread *timer_td;
static volatile int timer_should_stop;
static volatile int timer_exited;

void
cdx_timer_init(TIMER_ENTRY *timer, TIMER_HANDLER handler)
{
	INIT_HLIST_NODE(&timer->node);
	timer->handler = handler;
	timer->period = 0;
	timer->data64 = 0;
}

static inline void
__timer_del(TIMER_ENTRY *timer)
{
	hlist_del(&timer->node);
	timer->period = 0;
}

static void
__timer_add(struct _cdx_ctrl *ctrl, TIMER_ENTRY *timer)
{
	u32 x;
	signed int this_period;

	this_period = (signed int)(timer->timeout - JIFFIES32);
	if (this_period <= 0)
		this_period = 1;

	if (this_period <= INNER_WHEEL_MAXTIME) {
		x = x_inner + (this_period + INNER_WHEEL_PERIOD - 1) /
		    INNER_WHEEL_PERIOD;
		x &= (INNER_WHEEL_SIZE - 1);
		hlist_add_head(&timer->node, &ctrl->timer_inner_wheel[x]);
	} else {
		if (this_period > OUTER_WHEEL_MAXTIME)
			this_period = OUTER_WHEEL_MAXTIME;
		x = x_outer + this_period / OUTER_WHEEL_PERIOD;
		x &= (OUTER_WHEEL_SIZE - 1);
		hlist_add_head(&timer->node, &ctrl->timer_outer_wheel[x]);
	}
}

void
cdx_timer_del(TIMER_ENTRY *timer)
{
	if (timer->period)
		__timer_del(timer);
}

void
cdx_timer_add(TIMER_ENTRY *timer, cdx_timer_t period)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	if (!timer->handler)
		return;
	if (period == 0)
		cdx_timer_del(timer);
	else if (timer->period == 0) {
		timer->period = period;
		timer->timeout = JIFFIES32 + period;
		__timer_add(ctrl, timer);
	}
}

/*
 * Timer thread function.
 *
 * On FreeBSD, kthread_add takes void (*)(void *) so we match that
 * signature directly (unlike Linux which returns int).
 */

void dpa_update_timestamp(uint32_t ts);

static void
cdx_ctrl_timer_fn(void *data)
{
	struct _cdx_ctrl *ctrl = data;
	TIMER_ENTRY *timer;
	struct hlist_node *temp;
	int outer_wheel_counter = OUTER_WHEEL_COUNTER;

	while (!timer_should_stop) {
		pause("cdxtmr", INNER_WHEEL_PERIOD);

		mutex_lock(&ctrl->mutex);

		dpa_update_timestamp(JIFFIES32);

		/* Process inner wheel */
		hlist_for_each_entry_safe(timer, temp,
		    &ctrl->timer_inner_wheel[x_inner], node) {
			cdx_timer_t old_period = timer->period;
			__timer_del(timer);

			if (timer->handler(timer)) {
				if (timer->period == 0)
					timer->period = old_period;
				timer->timeout += timer->period;
				__timer_add(ctrl, timer);
			}
		}
		x_inner = (x_inner + 1) & (INNER_WHEEL_SIZE - 1);

		if (--outer_wheel_counter == 0) {
			/* Process outer wheel */
			hlist_for_each_entry_safe(timer, temp,
			    &ctrl->timer_outer_wheel[x_outer], node) {
				hlist_del(&timer->node);
				__timer_add(ctrl, timer);
			}
			x_outer = (x_outer + 1) & (OUTER_WHEEL_SIZE - 1);
			outer_wheel_counter = OUTER_WHEEL_COUNTER;
		}

		mutex_unlock(&ctrl->mutex);
	}

	printf("cdx: timer thread exiting\n");
	timer_exited = 1;
	wakeup(__DEVOLATILE(void *, &timer_exited));
	kthread_exit();
}

/* Kept for source compat — Linux version returns int */
int
cdx_ctrl_timer(void *data)
{
	cdx_ctrl_timer_fn(data);
	return (0);
}

static void
cdx_ctrl_timer_exit(void)
{
	struct _cdx_ctrl *ctrl;

	ctrl = &cdx_info->ctrl;

	if (timer_td != NULL) {
		timer_should_stop = 1;
		while (!timer_exited)
			tsleep(__DEVOLATILE(void *, &timer_exited),
			    0, "cdxstop", hz);
		timer_td = NULL;
	}

	if (ctrl->timer_inner_wheel)
		kfree(ctrl->timer_inner_wheel);
	if (ctrl->timer_outer_wheel)
		kfree(ctrl->timer_outer_wheel);
	ctrl->timer_inner_wheel = NULL;
	ctrl->timer_outer_wheel = NULL;
}

int
cdx_ctrl_timer_init(struct _cdx_ctrl *ctrl)
{
	int i;
	int rc = 0;

	timer_should_stop = 0;
	timer_exited = 0;
	timer_td = NULL;

	ctrl->timer_inner_wheel = kmalloc(INNER_WHEEL_SIZE *
	    sizeof(struct hlist_head), GFP_KERNEL);
	ctrl->timer_outer_wheel = kmalloc(OUTER_WHEEL_SIZE *
	    sizeof(struct hlist_head), GFP_KERNEL);
	if (!ctrl->timer_inner_wheel || !ctrl->timer_outer_wheel) {
		printf("cdx: timer wheel allocation failed\n");
		rc = -ENOMEM;
		goto error;
	}

	for (i = 0; i < INNER_WHEEL_SIZE; i++)
		INIT_HLIST_HEAD(&ctrl->timer_inner_wheel[i]);
	for (i = 0; i < OUTER_WHEEL_SIZE; i++)
		INIT_HLIST_HEAD(&ctrl->timer_outer_wheel[i]);

	rc = kthread_add(cdx_ctrl_timer_fn, ctrl, NULL,
	    &timer_td, 0, 0, "cdx_ctrl_timer");
	if (rc != 0) {
		printf("cdx: kthread_add() failed: %d\n", rc);
		goto error;
	}

error:
	register_cdx_deinit_func(cdx_ctrl_timer_exit);
	return (rc);
}
