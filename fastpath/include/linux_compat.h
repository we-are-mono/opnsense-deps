/*
 * Linux-to-FreeBSD kernel compatibility shim — core APIs
 *
 * Maps the most pervasive Linux kernel APIs to FreeBSD equivalents.
 * Used by virtually every CDX source file.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_COMPAT_H_
#define _LINUX_COMPAT_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/types.h>
#include <sys/libkern.h>

MALLOC_DECLARE(M_ASK);

/* ----------------------------------------------------------------
 * Memory allocation: kmalloc/kfree → malloc/free(9)
 * ---------------------------------------------------------------- */
#define GFP_KERNEL	M_WAITOK
#define GFP_ATOMIC	M_NOWAIT
#define GFP_DMA		0		/* no separate DMA flag on FreeBSD */

#define kmalloc(size, flags)	malloc((size), M_ASK, (flags) | M_ZERO)
#define kzalloc(size, flags)	malloc((size), M_ASK, (flags) | M_ZERO)
#define kcalloc(n, size, flags)	malloc((n) * (size), M_ASK, (flags) | M_ZERO)
#define kfree(ptr)		free((ptr), M_ASK)
#define vmalloc(size)		malloc((size), M_ASK, M_WAITOK)
#define vfree(ptr)		free((ptr), M_ASK)

/* ----------------------------------------------------------------
 * Printing: printk → printf
 * ---------------------------------------------------------------- */
#define printk		printf
#define KERN_ERR	""
#define KERN_INFO	""
#define KERN_DEBUG	""
#define KERN_CRIT	""
#define KERN_WARNING	""
#define KERN_WARN	""
#define KERN_NOTICE	""
#define KERN_ALERT	""
#define KERN_EMERG	""
#define pr_err(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	do { } while (0)
#define printk_ratelimit()	1

/* print_hex_dump: used by cdx_cmdhandler.c for debug output */
static inline void print_hex_dump(const char *level, const char *prefix_str,
    int prefix_type, int rowsize, int groupsize,
    const void *buf, size_t len, int ascii)
{
	const uint8_t *p = buf;
	size_t i;

	for (i = 0; i < len; i++) {
		if (i % rowsize == 0)
			printf("%s%.8zx: ", prefix_str, i);
		printf("%02x ", p[i]);
		if ((i + 1) % rowsize == 0 || i + 1 == len)
			printf("\n");
	}
}

/* ----------------------------------------------------------------
 * Module macros (no-ops for external KLD)
 * ---------------------------------------------------------------- */
#define __init
#define __exit
#define __maybe_unused		__unused
#define __user			/* user-space pointer annotation: no-op */
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_VERSION_LINUX(x)	/* avoid collision with FreeBSD MODULE_VERSION */
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define THIS_MODULE		NULL
#define module_param(name, type, perm)

/* ----------------------------------------------------------------
 * Atomic operations
 * ---------------------------------------------------------------- */
#include <machine/atomic.h>

typedef struct { volatile int counter; } atomic_t;
#define ATOMIC_INIT(i)			{ .counter = (i) }
#define atomic_read(v)			((v)->counter)
#define atomic_set(v, i)		((v)->counter = (i))
#define atomic_inc(v)			atomic_add_int(&(v)->counter, 1)
#define atomic_dec(v)			atomic_subtract_int(&(v)->counter, 1)
#define atomic_dec_and_test(v)		(atomic_fetchadd_int(&(v)->counter, -1) == 1)
#define atomic_inc_return(v)		(atomic_fetchadd_int(&(v)->counter, 1) + 1)
#define atomic_add(i, v)		atomic_add_int(&(v)->counter, (i))
#define atomic_sub(i, v)		atomic_subtract_int(&(v)->counter, (i))

/* ----------------------------------------------------------------
 * Error codes & pointer tricks
 * ---------------------------------------------------------------- */
#define IS_ERR(ptr)		((unsigned long)(ptr) >= (unsigned long)-4095)
#define PTR_ERR(ptr)		((long)(ptr))
#define ERR_PTR(err)		((void *)((long)(err)))
#define IS_ERR_OR_NULL(ptr)	(!(ptr) || IS_ERR(ptr))

/* ----------------------------------------------------------------
 * container_of — already in sys/param.h on some versions, but
 * define our own to be safe (matches Linux semantics exactly)
 * ---------------------------------------------------------------- */
#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#endif

/* ----------------------------------------------------------------
 * Jiffies → ticks (FreeBSD equivalent)
 * ---------------------------------------------------------------- */
#define jiffies			((unsigned long)ticks)
/* HZ must be a compile-time constant — CDX fe.h uses it in #if directives.
 * FreeBSD defaults to 1000 Hz on arm64 (see sys/kern/kern_clock.c). */
#define HZ			1000
#define msecs_to_jiffies(ms)	((ms) * HZ / 1000)
#define jiffies_to_msecs(j)	((j) * 1000 / HZ)

/* ----------------------------------------------------------------
 * Branch prediction hints
 * ---------------------------------------------------------------- */
#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

/* ----------------------------------------------------------------
 * Assertion / panic macros
 * ---------------------------------------------------------------- */
#define BUG_ON(cond)	KASSERT(!(cond), ("BUG_ON: %s:%d", __FILE__, __LINE__))
#define WARN_ON(cond)	do { if (cond) printf("WARN_ON: %s:%d\n", __FILE__, __LINE__); } while (0)

/* ----------------------------------------------------------------
 * Delay / sleep functions
 * ---------------------------------------------------------------- */
#include <sys/proc.h>

#define udelay(us)	DELAY(us)
#define mdelay(ms)	DELAY((ms) * 1000)

/* ----------------------------------------------------------------
 * Memory-mapped I/O: writel/readl
 * FreeBSD has these but with different (addr, val) arg order.
 * CDX uses Linux semantics: writel(val, addr).
 * ---------------------------------------------------------------- */
#undef writel
#undef readl
#undef writew
#undef readw
#undef writeb
#undef readb
#define writel(val, addr)	do { wmb(); *(volatile uint32_t *)(addr) = (uint32_t)(val); } while (0)
#define readl(addr)		(*(volatile uint32_t *)(addr))
#define writew(val, addr)	do { wmb(); *(volatile uint16_t *)(addr) = (uint16_t)(val); } while (0)
#define readw(addr)		(*(volatile uint16_t *)(addr))
#define writeb(val, addr)	do { wmb(); *(volatile uint8_t *)(addr) = (uint8_t)(val); } while (0)
#define readb(addr)		(*(volatile uint8_t *)(addr))

/* ----------------------------------------------------------------
 * User/kernel space copy functions
 * ---------------------------------------------------------------- */
#define copy_from_user(to, from, n)	copyin((from), (to), (n))
#define copy_to_user(to, from, n)	copyout((from), (to), (n))

/* ----------------------------------------------------------------
 * Byte-order conversion: Linux cpu_to_be* → FreeBSD htobe*
 * ---------------------------------------------------------------- */
#include <sys/endian.h>

#define cpu_to_be16(x)	htobe16(x)
#define cpu_to_be32(x)	htobe32(x)
#define cpu_to_be64(x)	htobe64(x)
#define be16_to_cpu(x)	be16toh(x)
#define be32_to_cpu(x)	be32toh(x)
#define be64_to_cpu(x)	be64toh(x)
#define cpu_to_le16(x)	htole16(x)
#define cpu_to_le32(x)	htole32(x)
#define cpu_to_le64(x)	htole64(x)
#define le16_to_cpu(x)	le16toh(x)
#define le32_to_cpu(x)	le32toh(x)
#define le64_to_cpu(x)	le64toh(x)
/* htonl/htons/ntohl/ntohs already provided by sys/param.h */

/* ----------------------------------------------------------------
 * Misc
 * ---------------------------------------------------------------- */
#define in_interrupt()		(curthread->td_intr_nesting_level > 0)
#define smp_processor_id()	curcpu
#define smp_wmb()		wmb()
#define smp_rmb()		rmb()
#define smp_mb()		mb()

/* Boolean — FreeBSD kernel has stdbool.h, but keep this for compat */
#ifndef __bool_true_false_are_defined
typedef int bool;
#define true	1
#define false	0
#endif

/* Suppress Linux version checks that appear in some CDX files */
#define LINUX_VERSION_CODE	0
#define KERNEL_VERSION(a,b,c)	1

#endif /* _LINUX_COMPAT_H_ */
