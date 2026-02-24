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
 @File          part_integration_ext.h

 @Description   P4080/P5020/P3041/P1023 external definitions and structures.
*//***************************************************************************/
#ifndef __PART_INTEGRATION_EXT_H
#define __PART_INTEGRATION_EXT_H

#ifdef P1023
#include "part_integration_P1023.h"
#elif defined LS1043
#include "part_integration_LS1043.h"
#elif defined FMAN_V3H
#include "part_integration_B4_T4.h"
#elif defined FMAN_V3L
#include "part_integration_FMAN_V3L.h"
#else
#include "part_integration_P3_P4_P5.h"
#endif

/*****************************************************************************
 *  UNIFIED MODULE CODES
 *****************************************************************************/
  #define MODULE_UNKNOWN          0x00000000
  #define MODULE_FM               0x00010000
  #define MODULE_FM_MURAM         0x00020000
  #define MODULE_FM_PCD           0x00030000
  #define MODULE_FM_RTC           0x00040000
  #define MODULE_FM_MAC           0x00050000
  #define MODULE_FM_PORT          0x00060000
  #define MODULE_MM               0x00070000
  #define MODULE_FM_SP            0x00080000

#endif /* __PART_INTEGRATION_EXT_H */
