/*
 * Copyright 2008-2016 Freescale Semiconductor Inc.
 * Copyright 2017-2018 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of the above-listed copyright holders nor the
 *        names of any contributors may be used to endorse or promote products
 *        derived from this software without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TYPES_LINUX_H
#define __TYPES_LINUX_H
#ifdef __GNUC__
/* __inline__ is already valid in GNUC */
#define _Packed
#define _PackedType __attribute__ ((packed))
#else   /* ! __GNUC__ */
#define _PackedType
#endif

#ifdef DIAB
#define _Packed __packed__
#endif

#ifdef _DIAB_TOOL
#define _Packed __packed__
#define __asm__ asm
#define __volatile__ volatile
#endif

/* type definitions */
#if defined(__KERNEL__)
# include <linux/types.h>
#else
# include <stdint.h>
# include <stddef.h>
# include <stdbool.h>
#endif

#ifdef NETCOMMSW_ALIASING
#define uint8_t        _NETCOMMSW_UINT8_T_
#define uint16_t       _NETCOMMSW_UINT16_T_
#define uint32_t       _NETCOMMSW_UINT32_T_
#define uint64_t       _NETCOMMSW_UINT64_T_
#define int8_t         _NETCOMMSW_INT8_T_
#define int16_t        _NETCOMMSW_INT16_T_
#define int32_t        _NETCOMMSW_INT32_T_
#define int64_t        _NETCOMMSW_INT64_T_
#define float_t        _NETCOMMSW_FLOAT_T_
#define double_t       _NETCOMMSW_DOUBLE_T_
#define bool           _NETCOMMSW_BOOL_
#endif /* NETCOMMSW_ALIASING */

/* physAddress_t should be uintptr_t */
typedef uint64_t physAddress_t;

#if (defined(__cplusplus))
#undef FALSE
#undef TRUE
#define FALSE   false
#define TRUE    true
/* bool is already defined */

#else
#undef FALSE
#undef TRUE
#define FALSE   0
#define TRUE    1
/* TOBE removed: typedef char bool;*/
#endif /* defined(__cplusplus) */

/************************/
/* Memory access macros */
/************************/
#define GET_UINT32(arg)             *(volatile uint32_t*)(&(arg))
#define GET_UINT64(arg)             *(volatile uint64_t*)(&(arg))

#define _WRITE_UINT32(arg, data)    *(volatile uint32_t*)(&(arg)) = (data)
#define _WRITE_UINT64(arg, data)    *(volatile uint64_t*)(&(arg)) = (data)

#ifndef QE_32_BIT_ACCESS_RESTRICTION

#define GET_UINT8(arg)              *(volatile uint8_t *)(&(arg))
#define GET_UINT16(arg)             *(volatile uint16_t*)(&(arg))

#define _WRITE_UINT8(arg, data)     *(volatile uint8_t *)(&(arg)) = (data)
#define _WRITE_UINT16(arg, data)    *(volatile uint16_t*)(&(arg)) = (data)

#else  /* QE_32_BIT_ACCESS_RESTRICTION */

#define QE_32_BIT_ADDR(_arg)        (uint32_t)((uint32_t)&(_arg) & 0xFFFFFFFC)
#define QE_32_BIT_SHIFT8(__arg)     (uint32_t)((3 - ((uint32_t)&(__arg) & 0x3)) * 8)
#define QE_32_BIT_SHIFT16(__arg)    (uint32_t)((2 - ((uint32_t)&(__arg) & 0x3)) * 8)

#define GET_UINT8(arg)              (uint8_t)((*(volatile uint32_t *)QE_32_BIT_ADDR(arg)) >> QE_32_BIT_SHIFT8(arg))
#define GET_UINT16(arg)             (uint16_t)((*(volatile uint32_t *)QE_32_BIT_ADDR(arg)) >> QE_32_BIT_SHIFT16(arg))

#define _WRITE_UINT8(arg, data)                                                                         \
    do                                                                                                  \
    {                                                                                                   \
        uint32_t addr = QE_32_BIT_ADDR(arg);                                                            \
        uint32_t shift = QE_32_BIT_SHIFT8(arg);                                                         \
        uint32_t tmp = *(volatile uint32_t *)addr;                                                      \
        tmp = (uint32_t)((tmp & ~(0x000000FF << shift)) | ((uint32_t)(data & 0x000000FF) << shift));    \
        *(volatile uint32_t *)addr = tmp;                                                               \
    } while (0)

#define _WRITE_UINT16(arg, data)                                                                        \
    do                                                                                                  \
    {                                                                                                   \
        uint32_t addr = QE_32_BIT_ADDR(arg);                                                            \
        uint32_t shift = QE_32_BIT_SHIFT16(arg);                                                        \
        uint32_t tmp = *(volatile uint32_t *)addr;                                                      \
        tmp = (uint32_t)((tmp & ~(0x0000FFFF << shift)) | ((uint32_t)(data & 0x0000FFFF) << shift));    \
        *(volatile uint32_t *)addr = tmp;                                                               \
    } while (0)

#endif /* QE_32_BIT_ACCESS_RESTRICTION */


#ifdef VERBOSE_WRITE

#define WRITE_UINT8(arg, data)  \
    do { XX_Print("ADDR: 0x%08x, VAL: 0x%02x\r\n",    (uint32_t)&(arg), (data)); _WRITE_UINT8((arg), (data)); } while (0)
#define WRITE_UINT16(arg, data) \
    do { XX_Print("ADDR: 0x%08x, VAL: 0x%04x\r\n",    (uint32_t)&(arg), (data)); _WRITE_UINT16((arg), (data)); } while (0)
#define WRITE_UINT32(arg, data) \
    do { XX_Print("ADDR: 0x%08x, VAL: 0x%08x\r\n",    (uint32_t)&(arg), (data)); _WRITE_UINT32((arg), (data)); } while (0)
#define WRITE_UINT64(arg, data) \
    do { XX_Print("ADDR: 0x%08x, VAL: 0x%016llx\r\n", (uint32_t)&(arg), (data)); _WRITE_UINT64((arg), (data)); } while (0)

#else  /* not VERBOSE_WRITE */

#define WRITE_UINT8                 _WRITE_UINT8
#define WRITE_UINT16                _WRITE_UINT16
#define WRITE_UINT32                _WRITE_UINT32
#define WRITE_UINT64                _WRITE_UINT64

#endif /* not VERBOSE_WRITE */
#endif /* __TYPES_LINUX_H */
