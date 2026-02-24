/*
 * Linux-to-FreeBSD kernel compatibility shim — synchronization primitives
 *
 * Maps Linux mutex → FreeBSD sx (sleep-capable)
 * Maps Linux spinlock → FreeBSD mtx (non-sleep)
 * Maps Linux rcu → FreeBSD epoch or simple stubs
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_MUTEX_COMPAT_H_
#define _LINUX_MUTEX_COMPAT_H_

#include <sys/sx.h>
#include <sys/mutex.h>

/* ----------------------------------------------------------------
 * Linux mutex → FreeBSD sx lock (sleep-capable, like Linux mutex)
 * ---------------------------------------------------------------- */
struct mutex {
	struct sx sx;
};

#define mutex_init(m)		sx_init(&(m)->sx, "ask_mutex")
#define mutex_lock(m)		sx_xlock(&(m)->sx)
#define mutex_unlock(m)		sx_xunlock(&(m)->sx)
#define mutex_destroy(m)	sx_destroy(&(m)->sx)
#define mutex_trylock(m)	sx_try_xlock(&(m)->sx)

/* ----------------------------------------------------------------
 * Linux spinlock → FreeBSD mtx (non-sleep)
 *
 * spin_lock_irqsave/irqrestore: on FreeBSD, mtx_lock already
 * provides the necessary atomicity. The flags variable is unused
 * but kept to avoid changing call sites.
 *
 * spin_lock_bh/spin_unlock_bh: Linux disables softirqs. On FreeBSD,
 * mtx_lock is sufficient since our context is different.
 * ---------------------------------------------------------------- */
typedef struct {
	struct mtx mtx;
} spinlock_t;

#define spin_lock_init(s)		mtx_init(&(s)->mtx, "ask_spin", NULL, MTX_DEF)
#define spin_lock(s)			mtx_lock(&(s)->mtx)
#define spin_unlock(s)			mtx_unlock(&(s)->mtx)
#define spin_lock_irqsave(s, f)		do { (void)(f); mtx_lock(&(s)->mtx); } while (0)
#define spin_unlock_irqrestore(s, f)	do { mtx_unlock(&(s)->mtx); (void)(f); } while (0)
#define spin_lock_bh(s)			mtx_lock(&(s)->mtx)
#define spin_unlock_bh(s)		mtx_unlock(&(s)->mtx)
#define spin_lock_destroy(s)		mtx_destroy(&(s)->mtx)

/* Linux DEFINE_SPINLOCK — declares and initializes a static spinlock.
 * On FreeBSD, mtx_init must be called at runtime, so we just declare
 * the variable and rely on spin_lock_init being called before use.
 * For devman.c / cdx_ifstats.c compatibility. */
#define DEFINE_SPINLOCK(name)		spinlock_t name

/* ----------------------------------------------------------------
 * Linux RCU → simple lock-based stubs
 *
 * devman.c uses rcu_read_lock/rcu_read_unlock around device list
 * traversal. For correctness without full RCU, we use a global
 * sx lock in shared (read) mode. The actual performance benefit
 * of RCU is not critical for the control path.
 *
 * The lock must be initialized by the module that uses RCU.
 * ---------------------------------------------------------------- */
extern struct sx ask_rcu_lock;

#define rcu_read_lock()		sx_slock(&ask_rcu_lock)
#define rcu_read_unlock()	sx_sunlock(&ask_rcu_lock)
#define synchronize_rcu()	do { sx_xlock(&ask_rcu_lock); sx_xunlock(&ask_rcu_lock); } while (0)

#endif /* _LINUX_MUTEX_COMPAT_H_ */
