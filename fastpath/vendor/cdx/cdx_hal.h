/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _CDX_HAL_H_
#define _CDX_HAL_H_

#define ALIGN64(x)      (((u32)(x)) & ~0x7)
#define ROUND_UP64(x)   (((u32)(x) + 0x7) & ~0x7)

#define ALIGN32(x)      (((u32)(x)) & ~0x3)
#define ROUND_UP32(x)   (((u32)(x) + 0x3) & ~0x3)


static __inline U32 __READ_UNALIGNED_INT(void *_addr) 
{
	U16 *addr16 = (U16 *)_addr;

#if defined(ENDIAN_LITTLE)
	return ((addr16[1] << 16) | addr16[0]);
#else
	return ((addr16[0] << 16) | addr16[1]);
#endif
}

#define READ_UNALIGNED_INT(var) __READ_UNALIGNED_INT(&(var))

static __inline void __WRITE_UNALIGNED_INT(void *_addr, U32 _val)
{
	U16 *addr16 = (U16 *)_addr;

#if defined(ENDIAN_LITTLE)
	addr16[0] = _val & 0x0000ffff;
	addr16[1] = _val >> 16;
#else
	addr16[0] = _val >> 16;
	addr16[1] = _val & 0x0000ffff;
#endif
}

#define WRITE_UNALIGNED_INT(var, val) __WRITE_UNALIGNED_INT(&(var), (val))

typedef struct tHostMessage {
	u16	length;
	u16	code;
	u16	data[128];
} HostMessage;

HostMessage *msg_alloc(void);
void msg_free(HostMessage *msg);
int msg_send(HostMessage *msg);

void *Heap_Alloc(int size);

#define Heap_Alloc_ARAM(s)	Heap_Alloc(s)
#define __Heap_Alloc(h, s)		Heap_Alloc(s)
void Heap_Free(void *p);

#endif /* _CDX_HAL_H_ */
