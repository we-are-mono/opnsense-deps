/*
 * Shadow header for <linux/types.h>
 * FreeBSD provides standard types in <sys/types.h>.
 */
#ifndef _LINUX_TYPES_H_COMPAT_
#define _LINUX_TYPES_H_COMPAT_

#include <sys/types.h>
#include <sys/stdint.h>

/* CDX's own types.h defines u16/u32/u64 via U16/U32/U64 macros.
 * Only provide these if not already defined. */
#ifndef u16
typedef uint16_t u16;
#endif
#ifndef u32
typedef uint32_t u32;
#endif
#ifndef u64
typedef uint64_t u64;
#endif
#ifndef s16
typedef int16_t  s16;
#endif
#ifndef s32
typedef int32_t  s32;
#endif
#ifndef s64
typedef int64_t  s64;
#endif

#endif
