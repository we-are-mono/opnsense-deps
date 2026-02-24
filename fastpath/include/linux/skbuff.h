/*
 * Shadow header for <linux/skbuff.h>
 * Provides minimal sk_buff stub for type declarations.
 * CDX does not use sk_buff directly — it operates on DPAA frame descriptors.
 */
#ifndef _LINUX_SKBUFF_H_COMPAT_
#define _LINUX_SKBUFF_H_COMPAT_

#include <sys/types.h>

/* Minimal sk_buff stub — only needed for type declarations in headers */
struct sk_buff {
	void *data;
	uint32_t len;
};

#endif
