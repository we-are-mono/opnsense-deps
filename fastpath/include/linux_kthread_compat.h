/*
 * Linux-to-FreeBSD kernel compatibility shim — kernel threads
 *
 * Maps Linux kthread_create/kthread_should_stop to FreeBSD kthread_add.
 *
 * Linux kthread_create returns struct task_struct * and the thread fn
 * returns int. FreeBSD kthread_add takes void (*)(void *) and returns
 * struct thread * via out-param.
 *
 * Used by: cdx_timer.c (cdx_ctrl_timer thread),
 *          cdx_reassm.c (ipr_timer_thread)
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_KTHREAD_COMPAT_H_
#define _LINUX_KTHREAD_COMPAT_H_

#include <sys/kthread.h>
#include <sys/proc.h>
#include <sys/unistd.h>

/*
 * Wrapper struct for Linux-style kernel threads.
 * Each thread user (timer, reassembly) should embed or allocate one.
 */
struct kthread_wrapper {
	int (*fn)(void *);
	void *data;
	struct thread *td;
	volatile int should_stop;
};

static inline void __kthread_trampoline(void *arg)
{
	struct kthread_wrapper *kw = arg;

	kw->fn(kw->data);
	kthread_exit();
}

/*
 * Create a kernel thread (not yet started — FreeBSD starts immediately,
 * so this combines kthread_create + wake_up_process).
 *
 * Returns 0 on success, error code on failure.
 * On success, kw->td is set to the new thread.
 */
static inline int kthread_wrapper_create(struct kthread_wrapper *kw,
    int (*fn)(void *), void *data, const char *name)
{
	kw->fn = fn;
	kw->data = data;
	kw->should_stop = 0;
	kw->td = NULL;
	return kthread_add(__kthread_trampoline, kw, NULL,
	    &kw->td, 0, 0, "%s", name);
}

/*
 * Request thread stop and wait for it.
 */
static inline void kthread_wrapper_stop(struct kthread_wrapper *kw)
{
	kw->should_stop = 1;
	/* Give the thread time to notice and exit */
	tsleep(kw, 0, "ktstop", hz * 2);
}

#define kthread_should_stop(kw)	((kw)->should_stop)

/* schedule_timeout_uninterruptible(ticks) → pause(9) */
#define schedule_timeout_uninterruptible(t)	pause("cdxtmr", (t))

#endif /* _LINUX_KTHREAD_COMPAT_H_ */
