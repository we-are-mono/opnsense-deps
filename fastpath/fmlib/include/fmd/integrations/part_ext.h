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

/**************************************************************************//**
 @File          part_ext.h

 @Description   Definitions for the part (integration) module.
*//***************************************************************************/

#ifndef __PART_EXT_H
#define __PART_EXT_H

#include "std_ext.h"
#include "part_integration_ext.h"



/**************************************************************************//*
 @Description   Part data structure - must be contained in any integration
                data structure.
*//***************************************************************************/
typedef struct t_Part
{
    uintptr_t   (* f_GetModuleBase)(t_Handle h_Part, e_ModuleId moduleId);
                /**< Returns the address of the module's memory map base. */
    e_ModuleId  (* f_GetModuleIdByBase)(t_Handle h_Part, uintptr_t baseAddress);
                /**< Returns the module's ID according to its memory map base. */
} t_Part;

#ifdef P1023
#include "part_P1023.h"
#elif defined FMAN_V3H
#include "part_B4_T4.h"
#elif defined FMAN_V3L
#include "part_FMAN_V3L.h"
#else
#include "part_P3_P4_P5.h"
#endif

#endif /* __PART_EXT_H */
