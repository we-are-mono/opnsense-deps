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
 @File          dpaa_integration_B4_T4.h

 @Description   B4860/T4240 FM external definitions and structures.
*//***************************************************************************/
#ifndef __DPAA_INTEGRATION_B4_T4_H
#define __DPAA_INTEGRATION_B4_T4_H

#include "std_ext.h"

#ifdef P1023
#error "file for B4, T4"
#endif


#define DPAA_VERSION    11

/**************************************************************************//**
 @Description   DPAA SW Portals Enumeration.
*//***************************************************************************/
typedef enum
{
    e_DPAA_SWPORTAL0 = 0,
    e_DPAA_SWPORTAL1,
    e_DPAA_SWPORTAL2,
    e_DPAA_SWPORTAL3,
    e_DPAA_SWPORTAL4,
    e_DPAA_SWPORTAL5,
    e_DPAA_SWPORTAL6,
    e_DPAA_SWPORTAL7,
    e_DPAA_SWPORTAL8,
    e_DPAA_SWPORTAL9,
    e_DPAA_SWPORTAL10,
    e_DPAA_SWPORTAL11,
    e_DPAA_SWPORTAL12,
    e_DPAA_SWPORTAL13,
    e_DPAA_SWPORTAL14,
    e_DPAA_SWPORTAL15,
    e_DPAA_SWPORTAL16,
    e_DPAA_SWPORTAL17,
    e_DPAA_SWPORTAL18,
    e_DPAA_SWPORTAL19,
    e_DPAA_SWPORTAL20,
    e_DPAA_SWPORTAL21,
    e_DPAA_SWPORTAL22,
    e_DPAA_SWPORTAL23,
    e_DPAA_SWPORTAL24,
    e_DPAA_SWPORTAL_DUMMY_LAST
} e_DpaaSwPortal;

/**************************************************************************//**
 @Description   DPAA Direct Connect Portals Enumeration.
*//***************************************************************************/
typedef enum
{
    e_DPAA_DCPORTAL0 = 0,
    e_DPAA_DCPORTAL1,
    e_DPAA_DCPORTAL2,
    e_DPAA_DCPORTAL_DUMMY_LAST
} e_DpaaDcPortal;

#define DPAA_MAX_NUM_OF_SW_PORTALS      e_DPAA_SWPORTAL_DUMMY_LAST
#define DPAA_MAX_NUM_OF_DC_PORTALS      e_DPAA_DCPORTAL_DUMMY_LAST

/*****************************************************************************
 QMan INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define QM_MAX_NUM_OF_POOL_CHANNELS     15      /**< Total number of channels, dedicated and pool */
#define QM_MAX_NUM_OF_WQ                8       /**< Number of work queues per channel */
#define QM_MAX_NUM_OF_CGS               256     /**< Congestion groups number */
#define QM_MAX_NUM_OF_FQIDS             (16 * MEGABYTE)
                                                /**< FQIDs range - 24 bits */

/**************************************************************************//**
 @Description   Work Queue Channel assignments in QMan.
*//***************************************************************************/
typedef enum
{
    e_QM_FQ_CHANNEL_SWPORTAL0 = 0x0,              /**< Dedicated channels serviced by software portals 0 to 24 */
    e_QM_FQ_CHANNEL_SWPORTAL1,
    e_QM_FQ_CHANNEL_SWPORTAL2,
    e_QM_FQ_CHANNEL_SWPORTAL3,
    e_QM_FQ_CHANNEL_SWPORTAL4,
    e_QM_FQ_CHANNEL_SWPORTAL5,
    e_QM_FQ_CHANNEL_SWPORTAL6,
    e_QM_FQ_CHANNEL_SWPORTAL7,
    e_QM_FQ_CHANNEL_SWPORTAL8,
    e_QM_FQ_CHANNEL_SWPORTAL9,
    e_QM_FQ_CHANNEL_SWPORTAL10,
    e_QM_FQ_CHANNEL_SWPORTAL11,
    e_QM_FQ_CHANNEL_SWPORTAL12,
    e_QM_FQ_CHANNEL_SWPORTAL13,
    e_QM_FQ_CHANNEL_SWPORTAL14,
    e_QM_FQ_CHANNEL_SWPORTAL15,
    e_QM_FQ_CHANNEL_SWPORTAL16,
    e_QM_FQ_CHANNEL_SWPORTAL17,
    e_QM_FQ_CHANNEL_SWPORTAL18,
    e_QM_FQ_CHANNEL_SWPORTAL19,
    e_QM_FQ_CHANNEL_SWPORTAL20,
    e_QM_FQ_CHANNEL_SWPORTAL21,
    e_QM_FQ_CHANNEL_SWPORTAL22,
    e_QM_FQ_CHANNEL_SWPORTAL23,
    e_QM_FQ_CHANNEL_SWPORTAL24,

    e_QM_FQ_CHANNEL_POOL1 = 0x401,               /**< Pool channels that can be serviced by any of the software portals */
    e_QM_FQ_CHANNEL_POOL2,
    e_QM_FQ_CHANNEL_POOL3,
    e_QM_FQ_CHANNEL_POOL4,
    e_QM_FQ_CHANNEL_POOL5,
    e_QM_FQ_CHANNEL_POOL6,
    e_QM_FQ_CHANNEL_POOL7,
    e_QM_FQ_CHANNEL_POOL8,
    e_QM_FQ_CHANNEL_POOL9,
    e_QM_FQ_CHANNEL_POOL10,
    e_QM_FQ_CHANNEL_POOL11,
    e_QM_FQ_CHANNEL_POOL12,
    e_QM_FQ_CHANNEL_POOL13,
    e_QM_FQ_CHANNEL_POOL14,
    e_QM_FQ_CHANNEL_POOL15,

    e_QM_FQ_CHANNEL_FMAN0_SP0 = 0x800,           /**< Dedicated channels serviced by Direct Connect Portal 0:
                                                      connected to FMan 0; assigned in incrementing order to
                                                      each sub-portal (SP) in the portal */
    e_QM_FQ_CHANNEL_FMAN0_SP1,
    e_QM_FQ_CHANNEL_FMAN0_SP2,
    e_QM_FQ_CHANNEL_FMAN0_SP3,
    e_QM_FQ_CHANNEL_FMAN0_SP4,
    e_QM_FQ_CHANNEL_FMAN0_SP5,
    e_QM_FQ_CHANNEL_FMAN0_SP6,
    e_QM_FQ_CHANNEL_FMAN0_SP7,
    e_QM_FQ_CHANNEL_FMAN0_SP8,
    e_QM_FQ_CHANNEL_FMAN0_SP9,
    e_QM_FQ_CHANNEL_FMAN0_SP10,
    e_QM_FQ_CHANNEL_FMAN0_SP11,
    e_QM_FQ_CHANNEL_FMAN0_SP12,
    e_QM_FQ_CHANNEL_FMAN0_SP13,
    e_QM_FQ_CHANNEL_FMAN0_SP14,
    e_QM_FQ_CHANNEL_FMAN0_SP15,

    e_QM_FQ_CHANNEL_RMAN_SP0 = 0x820,            /**< Dedicated channels serviced by Direct Connect Portal 1: connected to RMan */
    e_QM_FQ_CHANNEL_RMAN_SP1,

    e_QM_FQ_CHANNEL_CAAM = 0x840                 /**< Dedicated channel serviced by Direct Connect Portal 2:
                                                      connected to SEC */
} e_QmFQChannel;

/*****************************************************************************
 BMan INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define BM_MAX_NUM_OF_POOLS         64          /**< Number of buffers pools */

/*****************************************************************************
 SEC INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define SEC_NUM_OF_DECOS            3
#define SEC_ALL_DECOS_MASK          0x00000003


/*****************************************************************************
 FM INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define INTG_MAX_NUM_OF_FM          2
/* Ports defines */
#define FM_MAX_NUM_OF_1G_MACS       6
#define FM_MAX_NUM_OF_10G_MACS      2
#define FM_MAX_NUM_OF_MACS          (FM_MAX_NUM_OF_1G_MACS + FM_MAX_NUM_OF_10G_MACS)
#define FM_MAX_NUM_OF_OH_PORTS      6

#define FM_MAX_NUM_OF_1G_RX_PORTS   FM_MAX_NUM_OF_1G_MACS
#define FM_MAX_NUM_OF_10G_RX_PORTS  FM_MAX_NUM_OF_10G_MACS
#define FM_MAX_NUM_OF_RX_PORTS      (FM_MAX_NUM_OF_10G_RX_PORTS + FM_MAX_NUM_OF_1G_RX_PORTS)

#define FM_MAX_NUM_OF_1G_TX_PORTS   FM_MAX_NUM_OF_1G_MACS
#define FM_MAX_NUM_OF_10G_TX_PORTS  FM_MAX_NUM_OF_10G_MACS
#define FM_MAX_NUM_OF_TX_PORTS      (FM_MAX_NUM_OF_10G_TX_PORTS + FM_MAX_NUM_OF_1G_TX_PORTS)

#define FM_PORT_MAX_NUM_OF_EXT_POOLS            4           /**< Number of external BM pools per Rx port */
#define FM_PORT_NUM_OF_CONGESTION_GRPS          256         /**< Total number of congestion groups in QM */
#define FM_MAX_NUM_OF_SUB_PORTALS               16
#define FM_PORT_MAX_NUM_OF_OBSERVED_EXT_POOLS   0

#define FM_VSP_MAX_NUM_OF_ENTRIES               64
#define FM_MAX_NUM_OF_PFC_PRIORITIES            8

/* RAMs defines */
#define FM_MURAM_SIZE                   (384 * KILOBYTE)
#define FM_IRAM_SIZE                    ( 64 * KILOBYTE)

/* PCD defines */
#define FM_PCD_PLCR_NUM_ENTRIES         256                 /**< Total number of policer profiles */
#define FM_PCD_KG_NUM_OF_SCHEMES        32                  /**< Total number of KG schemes */
#define FM_PCD_MAX_NUM_OF_CLS_PLANS     256                 /**< Number of classification plan entries. */
#define FM_PCD_PRS_SW_PATCHES_SIZE      0x00000600          /**< Number of bytes saved for patches */
#define FM_PCD_SW_PRS_SIZE              0x00000800          /**< Total size of SW parser area */

/* RTC defines */
#define FM_RTC_NUM_OF_ALARMS            2                   /**< RTC number of alarms */
#define FM_RTC_NUM_OF_PERIODIC_PULSES   3                   /**< RTC number of periodic pulses */
#define FM_RTC_NUM_OF_EXT_TRIGGERS      2                   /**< RTC number of external triggers */

/* QMI defines */
#define QMI_MAX_NUM_OF_TNUMS            64
#define QMI_DEF_TNUMS_THRESH            48

/* FPM defines */
#define FM_NUM_OF_FMAN_CTRL_EVENT_REGS  4

/* DMA defines */
#define DMA_THRESH_MAX_COMMQ            83
#define DMA_THRESH_MAX_BUF              127

/* BMI defines */
#define BMI_MAX_NUM_OF_TASKS            128
#define BMI_MAX_NUM_OF_DMAS             84

#define BMI_MAX_FIFO_SIZE               (FM_MURAM_SIZE)
#define PORT_MAX_WEIGHT                 16

#define FM_CHECK_PORT_RESTRICTIONS(__validPorts, __newPortIndx)   TRUE

/* Unique T4240 */
#define FM_OP_OPEN_DMA_MIN_LIMIT
#define FM_NO_RESTRICT_ON_ACCESS_RSRC
#define FM_NO_OP_OBSERVED_POOLS
#define FM_FRAME_END_PARAMS_FOR_OP
#define FM_DEQ_PIPELINE_PARAMS_FOR_OP
#define FM_NO_TOTAL_DMAS
#define FM_QMI_NO_SINGLE_ECC_EXCEPTION
//TODO - for simulator only, due to wrong reset values. Remove when fixed,
//and also search for the places it appears in the source files and remove
//comments of majorRev<6
#define FM_NO_GUARANTEED_RESET_VALUES

/* FM erratas */
//#define FM_TX_ECC_FRMS_ERRATA_10GMAC_A004

#define FM_RX_PREAM_4_ERRATA_DTSEC_A001
#define FM_MAGIC_PACKET_UNRECOGNIZED_ERRATA_DTSEC2              /* No implementation, Out of LLD scope */


#define FM_UCODE_NOT_RESET_ERRATA_BUGZILLA6173

#define FM_LEN_CHECK_ERRATA_FMAN_SW002


#endif /* __DPAA_INTEGRATION_B4_T4_H */
