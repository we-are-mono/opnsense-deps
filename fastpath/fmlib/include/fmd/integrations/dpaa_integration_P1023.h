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
 @File          dpaa_integration_P1023.h

 @Description   P1023 FM external definitions and structures.
*//***************************************************************************/
#ifndef __DPAA_INTEGRATION_P1023_H
#define __DPAA_INTEGRATION_P1023_H

#include "std_ext.h"

#ifdef P1023

#define CONFIG_FMAN_P1023
#define DPAA_VERSION 10

typedef enum e_DpaaSwPortal {
    e_DPAA_SWPORTAL0 = 0,
    e_DPAA_SWPORTAL1,
    e_DPAA_SWPORTAL2,
    e_DPAA_SWPORTAL_DUMMY_LAST
} e_DpaaSwPortal;

typedef enum {
    e_DPAA_DCPORTAL0 = 0,
    e_DPAA_DCPORTAL2,
    e_DPAA_DCPORTAL_DUMMY_LAST
} e_DpaaDcPortal;

#define DPAA_MAX_NUM_OF_SW_PORTALS      e_DPAA_SWPORTAL_DUMMY_LAST
#define DPAA_MAX_NUM_OF_DC_PORTALS      e_DPAA_DCPORTAL_DUMMY_LAST

/*****************************************************************************
 QMAN INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define QM_MAX_NUM_OF_POOL_CHANNELS 3
#define QM_MAX_NUM_OF_WQ            8
#define QM_MAX_NUM_OF_SWP_AS        2
#define QM_MAX_NUM_OF_CGS           64
#define QM_MAX_NUM_OF_FQIDS         (16*MEGABYTE)

typedef enum {
    e_QM_FQ_CHANNEL_SWPORTAL0 = 0,
    e_QM_FQ_CHANNEL_SWPORTAL1,
    e_QM_FQ_CHANNEL_SWPORTAL2,

    e_QM_FQ_CHANNEL_POOL1 = 0x21,
    e_QM_FQ_CHANNEL_POOL2,
    e_QM_FQ_CHANNEL_POOL3,

    e_QM_FQ_CHANNEL_FMAN0_SP0 = 0x40,
    e_QM_FQ_CHANNEL_FMAN0_SP1,
    e_QM_FQ_CHANNEL_FMAN0_SP2,
    e_QM_FQ_CHANNEL_FMAN0_SP3,
    e_QM_FQ_CHANNEL_FMAN0_SP4,
    e_QM_FQ_CHANNEL_FMAN0_SP5,
    e_QM_FQ_CHANNEL_FMAN0_SP6,


    e_QM_FQ_CHANNEL_CAAM = 0x80
} e_QmFQChannel;

/*****************************************************************************
 BMAN INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define BM_MAX_NUM_OF_POOLS         8

/*****************************************************************************
 SEC INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define SEC_NUM_OF_DECOS    2
#define SEC_ALL_DECOS_MASK  0x00000003

/*****************************************************************************
 FM INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define INTG_MAX_NUM_OF_FM          1

/* Ports defines */
#define FM_MAX_NUM_OF_1G_RX_PORTS   2
#define FM_MAX_NUM_OF_10G_RX_PORTS  0
#define FM_MAX_NUM_OF_RX_PORTS      (FM_MAX_NUM_OF_10G_RX_PORTS+FM_MAX_NUM_OF_1G_RX_PORTS)
#define FM_MAX_NUM_OF_1G_TX_PORTS   2
#define FM_MAX_NUM_OF_10G_TX_PORTS  0
#define FM_MAX_NUM_OF_TX_PORTS      (FM_MAX_NUM_OF_10G_TX_PORTS+FM_MAX_NUM_OF_1G_TX_PORTS)
#define FM_MAX_NUM_OF_OH_PORTS      5
#define FM_MAX_NUM_OF_1G_MACS       (FM_MAX_NUM_OF_1G_RX_PORTS)
#define FM_MAX_NUM_OF_10G_MACS      (FM_MAX_NUM_OF_10G_RX_PORTS)
#define FM_MAX_NUM_OF_MACS          (FM_MAX_NUM_OF_1G_MACS+FM_MAX_NUM_OF_10G_MACS)
#define FM_MAX_NUM_OF_MACSECS       1

#define FM_MACSEC_SUPPORT
#define FM_DISABLE_SEC_ERRORS

#define FM_LOW_END_RESTRICTION      /* prevents the use of TX port 1 with OP port 0 */

#define FM_PORT_MAX_NUM_OF_EXT_POOLS            4           /**< Number of external BM pools per Rx port */
#define FM_PORT_MAX_NUM_OF_OBSERVED_EXT_POOLS   2           /**< Number of Offline parsing port external BM pools per Rx port */
#define FM_PORT_NUM_OF_CONGESTION_GRPS          32          /**< Total number of congestion groups in QM */
#define FM_MAX_NUM_OF_SUB_PORTALS               7

/* Rams defines */
#define FM_MURAM_SIZE               (64*KILOBYTE)
#define FM_IRAM_SIZE                (32*KILOBYTE)

/* PCD defines */
#define FM_PCD_PLCR_NUM_ENTRIES         32                  /**< Total number of policer profiles */
#define FM_PCD_KG_NUM_OF_SCHEMES        16                  /**< Total number of KG schemes */
#define FM_PCD_MAX_NUM_OF_CLS_PLANS     128                 /**< Number of classification plan entries. */

/* RTC defines */
#define FM_RTC_NUM_OF_ALARMS            2
#define FM_RTC_NUM_OF_PERIODIC_PULSES   2
#define FM_RTC_NUM_OF_EXT_TRIGGERS      2

/* QMI defines */
#define QMI_MAX_NUM_OF_TNUMS            15

/* FPM defines */
#define FM_NUM_OF_FMAN_CTRL_EVENT_REGS  4

/* DMA defines */
#define DMA_THRESH_MAX_COMMQ            15
#define DMA_THRESH_MAX_BUF              7

/* BMI defines */
#define BMI_MAX_NUM_OF_TASKS            64
#define BMI_MAX_NUM_OF_DMAS             16
#define BMI_MAX_FIFO_SIZE              (FM_MURAM_SIZE)
#define PORT_MAX_WEIGHT                 4

/**************************************************************************//**
 @Description   Enum for inter-module interrupts registration
*//***************************************************************************/
typedef enum e_FmEventModules{
    e_FM_MOD_PRS,                   /**< Parser event */
    e_FM_MOD_KG,                    /**< Keygen event */
    e_FM_MOD_PLCR,                  /**< Policer event */
    e_FM_MOD_10G_MAC,               /**< 10G MAC  error event */
    e_FM_MOD_1G_MAC,                /**< 1G MAC  error event */
    e_FM_MOD_TMR,                   /**< Timer event */
    e_FM_MOD_1G_MAC_TMR,            /**< 1G MAC  Timer event */
    e_FM_MOD_FMAN_CTRL,             /**< FMAN Controller  Timer event */
    e_FM_MOD_MACSEC,
    e_FM_MOD_DUMMY_LAST
} e_FmEventModules;

/**************************************************************************//**
 @Description   Enum for interrupts types
*//***************************************************************************/
typedef enum e_FmIntrType {
    e_FM_INTR_TYPE_ERR,
    e_FM_INTR_TYPE_NORMAL
} e_FmIntrType;

/**************************************************************************//**
 @Description   Enum for inter-module interrupts registration
*//***************************************************************************/
typedef enum e_FmInterModuleEvent {
    e_FM_EV_PRS,                    /**< Parser event */
    e_FM_EV_ERR_PRS,                /**< Parser error event */
    e_FM_EV_KG,                     /**< Keygen event */
    e_FM_EV_ERR_KG,                 /**< Keygen error event */
    e_FM_EV_PLCR,                   /**< Policer event */
    e_FM_EV_ERR_PLCR,               /**< Policer error event */
    e_FM_EV_ERR_10G_MAC0,           /**< 10G MAC 0 error event */
    e_FM_EV_ERR_1G_MAC0,            /**< 1G MAC 0 error event */
    e_FM_EV_ERR_1G_MAC1,            /**< 1G MAC 1 error event */
    e_FM_EV_ERR_1G_MAC2,            /**< 1G MAC 2 error event */
    e_FM_EV_ERR_1G_MAC3,            /**< 1G MAC 3 error event */
    e_FM_EV_ERR_MACSEC_MAC0,        /**< MACSEC MAC 0 error event */
    e_FM_EV_TMR,                    /**< Timer event */
    e_FM_EV_1G_MAC0_TMR,            /**< 1G MAC 0 Timer event */
    e_FM_EV_1G_MAC1_TMR,            /**< 1G MAC 1 Timer event */
    e_FM_EV_1G_MAC2_TMR,            /**< 1G MAC 2 Timer event */
    e_FM_EV_1G_MAC3_TMR,            /**< 1G MAC 3 Timer event */
    e_FM_EV_MACSEC_MAC0,            /**< MACSEC MAC 0 event */
    e_FM_EV_FMAN_CTRL_0,            /**< Fman controller event 0 */
    e_FM_EV_FMAN_CTRL_1,            /**< Fman controller event 1 */
    e_FM_EV_FMAN_CTRL_2,            /**< Fman controller event 2 */
    e_FM_EV_FMAN_CTRL_3,            /**< Fman controller event 3 */
    e_FM_EV_DUMMY_LAST
} e_FmInterModuleEvent;

#define GET_FM_MODULE_EVENT(mod, id, intrType, event)                                                  \
    switch(mod){                                                                                    \
        case e_FM_MOD_PRS:                                                                          \
            if (id) event = e_FM_EV_DUMMY_LAST;                                                     \
            else event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_ERR_PRS:e_FM_EV_PRS;            \
            break;                                                                                  \
        case e_FM_MOD_KG:                                                                           \
            if (id) event = e_FM_EV_DUMMY_LAST;                                                     \
            else event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_ERR_KG:e_FM_EV_DUMMY_LAST;      \
            break;                                                                                  \
        case e_FM_MOD_PLCR:                                                                         \
            if (id) event = e_FM_EV_DUMMY_LAST;                                                     \
            else event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_ERR_PLCR:e_FM_EV_PLCR;          \
            break;                                                                                  \
        case e_FM_MOD_1G_MAC:                                                                       \
            switch(id){                                                                             \
                 case(0): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_ERR_1G_MAC0:e_FM_EV_DUMMY_LAST; break; \
                 case(1): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_ERR_1G_MAC1:e_FM_EV_DUMMY_LAST; break;    \
                 case(2): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_ERR_1G_MAC2:e_FM_EV_DUMMY_LAST; break;    \
                 case(3): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_ERR_1G_MAC3:e_FM_EV_DUMMY_LAST; break;    \
                 }                                                                                  \
            break;                                                                                  \
        case e_FM_MOD_TMR:                                                                          \
            if (id) event = e_FM_EV_DUMMY_LAST;                                                     \
            else event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_DUMMY_LAST:e_FM_EV_TMR;         \
            break;                                                                                  \
        case e_FM_MOD_1G_MAC_TMR:                                                                   \
            switch(id){                                                                             \
                 case(0): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_DUMMY_LAST:e_FM_EV_1G_MAC0_TMR; break; \
                 case(1): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_DUMMY_LAST:e_FM_EV_1G_MAC1_TMR; break; \
                 case(2): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_DUMMY_LAST:e_FM_EV_1G_MAC2_TMR; break; \
                 case(3): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_DUMMY_LAST:e_FM_EV_1G_MAC3_TMR; break; \
                 }                                                                                  \
            break;                                                                                  \
        case e_FM_MOD_MACSEC:                                                                   \
            switch(id){                                                                             \
                 case(0): event = (intrType == e_FM_INTR_TYPE_ERR) ? e_FM_EV_ERR_MACSEC_MAC0:e_FM_EV_MACSEC_MAC0; break; \
                 }                                                                                  \
            break;                                                                                  \
        case e_FM_MOD_FMAN_CTRL:                                                                    \
            if (intrType == e_FM_INTR_TYPE_ERR) event = e_FM_EV_DUMMY_LAST;                         \
            else switch(id){                                                                        \
                 case(0): event = e_FM_EV_FMAN_CTRL_0; break;                                       \
                 case(1): event = e_FM_EV_FMAN_CTRL_1; break;                                       \
                 case(2): event = e_FM_EV_FMAN_CTRL_2; break;                                       \
                 case(3): event = e_FM_EV_FMAN_CTRL_3; break;                                       \
                 }                                                                                  \
            break;                                                                                  \
        default:event = e_FM_EV_DUMMY_LAST;                                                         \
        break;}

/*****************************************************************************
 FM MACSEC INTEGRATION-SPECIFIC DEFINITIONS
******************************************************************************/
#define NUM_OF_RX_SC                16
#define NUM_OF_TX_SC                16

#define NUM_OF_SA_PER_RX_SC         2
#define NUM_OF_SA_PER_TX_SC         2

/**************************************************************************//**
 @Description   Enum for inter-module interrupts registration
*//***************************************************************************/

typedef enum e_FmMacsecEventModules{
    e_FM_MACSEC_MOD_SC_TX,
    e_FM_MACSEC_MOD_DUMMY_LAST
} e_FmMacsecEventModules;

typedef enum e_FmMacsecInterModuleEvent {
    e_FM_MACSEC_EV_SC_TX,
    e_FM_MACSEC_EV_ERR_SC_TX,
    e_FM_MACSEC_EV_DUMMY_LAST
} e_FmMacsecInterModuleEvent;

#define NUM_OF_INTER_MODULE_EVENTS (NUM_OF_TX_SC * 2)

#define GET_MACSEC_MODULE_EVENT(mod, id, intrType, event) \
    switch(mod){                                          \
        case e_FM_MACSEC_MOD_SC_TX:                       \
             event = (intrType == e_FM_INTR_TYPE_ERR) ?   \
                        e_FM_MACSEC_EV_ERR_SC_TX:         \
                        e_FM_MACSEC_EV_SC_TX;             \
             event += (uint8_t)(2 * id);break;            \
            break;                                        \
        default:event = e_FM_MACSEC_EV_DUMMY_LAST;        \
        break;}


/* 1023 unique features */
#define FM_QMI_NO_ECC_EXCEPTIONS
#define FM_CSI_CFED_LIMIT
#define FM_PEDANTIC_DMA
#define FM_QMI_NO_DEQ_OPTIONS_SUPPORT
#define FM_FIFO_ALLOCATION_ALG
#define FM_DEQ_PIPELINE_PARAMS_FOR_OP
#define FM_HAS_TOTAL_DMAS
#define FM_KG_NO_IPPID_SUPPORT
#define FM_NO_GUARANTEED_RESET_VALUES
#define FM_MAC_RESET

/* FM erratas */
#define FM_RX_PREAM_4_ERRATA_DTSEC_A001
#define FM_MAGIC_PACKET_UNRECOGNIZED_ERRATA_DTSEC2      /* No implementation */

#define FM_DEBUG_TRACE_FMAN_A004                        /* No implementation */
#define FM_INT_BUF_LEAK_FMAN_A005                       /* No implementation. App must avoid S/G */


#define FM_LOCKUP_ALIGNMENT_ERRATA_FMAN_SW004

#endif /* P1023 */

#endif /* __FM_INTEGRATION_P1023_H */
