/*
 * Linux-to-FreeBSD kernel compatibility shim — workqueue → taskqueue
 *
 * Maps Linux work_struct/INIT_WORK/schedule_work to FreeBSD taskqueue.
 *
 * Used by: cdx_main.c (INIT_WORK), cdx_cmdhandler.c (schedule_work),
 *          cdx_ctrl.h (struct work_struct member)
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_WORKQUEUE_COMPAT_H_
#define _LINUX_WORKQUEUE_COMPAT_H_

#include <sys/taskqueue.h>

struct work_struct {
	struct task task;
	void (*func)(struct work_struct *);
};

static inline void __work_trampoline(void *ctx, int pending)
{
	struct work_struct *work = ctx;

	(void)pending;
	work->func(work);
}

#define INIT_WORK(w, f) do {					\
	(w)->func = (f);					\
	TASK_INIT(&(w)->task, 0, __work_trampoline, (w));	\
} while (0)

#define schedule_work(w) \
	taskqueue_enqueue(taskqueue_thread, &(w)->task)

#define cancel_work_sync(w) \
	taskqueue_drain(taskqueue_thread, &(w)->task)

#endif /* _LINUX_WORKQUEUE_COMPAT_H_ */
