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
 @File          fm_ext.h

 @Description   FM Application Programming Interface.
*//***************************************************************************/
#ifndef __FM_EXT
#define __FM_EXT

#include "error_ext.h"
#include "std_ext.h"
#include "dpaa_ext.h"


/**************************************************************************//**
 @Group         lnx_usr_FM_grp Frame Manager API

 @Description   FM API functions, definitions and enums.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Group         lnx_usr_FM_lib_grp FM library

 @Description   FM API functions, definitions and enums

                The FM module is the main driver module and is a mandatory module
                for FM driver users. This module must be initialized first prior
                to any other drivers modules.
                The FM is a "singleton" module. It is responsible of the common
                HW modules: FPM, DMA, common QMI and common BMI initializations and
                run-time control routines. This module must be initialized always
                when working with any of the FM modules.
                NOTE - We assume that the FM library will be initialized only by core No. 0!

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   Enum for defining port types
*//***************************************************************************/
typedef enum e_FmPortType {
    e_FM_PORT_TYPE_OH_OFFLINE_PARSING = 0,  /**< Offline parsing port */
    e_FM_PORT_TYPE_RX,                      /**< 1G Rx port */
    e_FM_PORT_TYPE_RX_10G,                  /**< 10G Rx port */
    e_FM_PORT_TYPE_TX,                      /**< 1G Tx port */
    e_FM_PORT_TYPE_TX_10G,                  /**< 10G Tx port */
    e_FM_PORT_TYPE_DUMMY
} e_FmPortType;

/**************************************************************************//**
 @Description   Parse results memory layout
*//***************************************************************************/
typedef _Packed struct t_FmPrsResult {
    volatile uint8_t     lpid;               /**< Logical port id */
    volatile uint8_t     shimr;              /**< Shim header result  */
    volatile uint16_t    l2r;                /**< Layer 2 result */
    volatile uint16_t    l3r;                /**< Layer 3 result */
    volatile uint8_t     l4r;                /**< Layer 4 result */
    volatile uint8_t     cplan;              /**< Classification plan id */
    volatile uint16_t    nxthdr;             /**< Next Header  */
    volatile uint16_t    cksum;              /**< Running-sum */
    volatile uint16_t    flags_frag_off;     /**< Flags & fragment-offset field of the last IP-header */
    volatile uint8_t     route_type;         /**< Routing type field of a IPv6 routing extension header */
    volatile uint8_t     rhp_ip_valid;       /**< Routing Extension Header Present; last bit is IP valid */
    volatile uint8_t     shim_off[2];        /**< Shim offset */
    volatile uint8_t     ip_pid_off;         /**< IP PID (last IP-proto) offset */
    volatile uint8_t     eth_off;            /**< ETH offset */
    volatile uint8_t     llc_snap_off;       /**< LLC_SNAP offset */
    volatile uint8_t     vlan_off[2];        /**< VLAN offset */
    volatile uint8_t     etype_off;          /**< ETYPE offset */
    volatile uint8_t     pppoe_off;          /**< PPP offset */
    volatile uint8_t     mpls_off[2];        /**< MPLS offset */
    volatile uint8_t     ip_off[2];          /**< IP offset */
    volatile uint8_t     gre_off;            /**< GRE offset */
    volatile uint8_t     l4_off;             /**< Layer 4 offset */
    volatile uint8_t     nxthdr_off;         /**< Parser end point */
} _PackedType t_FmPrsResult;

/**************************************************************************//**
 @Collection   FM Parser results
*//***************************************************************************/
#define FM_PR_L2_VLAN_STACK         0x00000100  /**< Parse Result: VLAN stack */
#define FM_PR_L2_ETHERNET           0x00008000  /**< Parse Result: Ethernet*/
#define FM_PR_L2_VLAN               0x00004000  /**< Parse Result: VLAN */
#define FM_PR_L2_LLC_SNAP           0x00002000  /**< Parse Result: LLC_SNAP */
#define FM_PR_L2_MPLS               0x00001000  /**< Parse Result: MPLS */
#define FM_PR_L2_PPPoE              0x00000800  /**< Parse Result: PPPoE */
/* @} */

/**************************************************************************//**
 @Collection   FM Frame descriptor macros
*//***************************************************************************/
#define FM_FD_CMD_FCO                   0x80000000  /**< Frame queue Context Override */
#define FM_FD_CMD_RPD                   0x40000000  /**< Read Prepended Data */
#define FM_FD_CMD_UPD                   0x20000000  /**< Update Prepended Data */
#define FM_FD_CMD_DTC                   0x10000000  /**< Do L4 Checksum */
#define FM_FD_CMD_DCL4C                 0x10000000  /**< Didn't calculate L4 Checksum */
#define FM_FD_CMD_CFQ                   0x00ffffff  /**< Confirmation Frame Queue */

#define FM_FD_ERR_UNSUPPORTED_FORMAT    0x04000000  /**< Not for Rx-Port! Unsupported Format */
#define FM_FD_ERR_LENGTH                0x02000000  /**< Not for Rx-Port! Length Error */
#define FM_FD_ERR_DMA                   0x01000000  /**< DMA Data error */

#define FM_FD_IPR                       0x00000001  /**< IPR frame (not error) */

#define FM_FD_ERR_IPR_NCSP              (0x00100000 | FM_FD_IPR)    /**< IPR non-consistent-sp */
#define FM_FD_ERR_IPR                   (0x00200000 | FM_FD_IPR)    /**< IPR error */
#define FM_FD_ERR_IPR_TO                (0x00300000 | FM_FD_IPR)    /**< IPR timeout */

#ifdef FM_CAPWAP_SUPPORT
#define FM_FD_ERR_CRE                   0x00200000
#define FM_FD_ERR_CHE                   0x00100000
#endif /* FM_CAPWAP_SUPPORT */

#define FM_FD_ERR_PHYSICAL              0x00080000  /**< Rx FIFO overflow, FCS error, code error, running disparity
                                                         error (SGMII and TBI modes), FIFO parity error. PHY
                                                         Sequence error, PHY error control character detected. */
#define FM_FD_ERR_SIZE                  0x00040000  /**< Frame too long OR Frame size exceeds max_length_frame  */
#define FM_FD_ERR_CLS_DISCARD           0x00020000  /**< classification discard */
#define FM_FD_ERR_EXTRACTION            0x00008000  /**< Extract Out of Frame */
#define FM_FD_ERR_NO_SCHEME             0x00004000  /**< No Scheme Selected */
#define FM_FD_ERR_KEYSIZE_OVERFLOW      0x00002000  /**< Keysize Overflow */
#define FM_FD_ERR_COLOR_RED             0x00000800  /**< Frame color is red */
#define FM_FD_ERR_COLOR_YELLOW          0x00000400  /**< Frame color is yellow */
#define FM_FD_ERR_ILL_PLCR              0x00000200  /**< Illegal Policer Profile selected */
#define FM_FD_ERR_PLCR_FRAME_LEN        0x00000100  /**< Policer frame length error */
#define FM_FD_ERR_PRS_TIMEOUT           0x00000080  /**< Parser Time out Exceed */
#define FM_FD_ERR_PRS_ILL_INSTRUCT      0x00000040  /**< Invalid Soft Parser instruction */
#define FM_FD_ERR_PRS_HDR_ERR           0x00000020  /**< Header error was identified during parsing */
#define FM_FD_ERR_BLOCK_LIMIT_EXCEEDED  0x00000008  /**< Frame parsed beyind 256 first bytes */

#define FM_FD_TX_STATUS_ERR_MASK        (FM_FD_ERR_UNSUPPORTED_FORMAT   | \
                                         FM_FD_ERR_LENGTH               | \
                                         FM_FD_ERR_DMA) /**< TX Error FD bits */

#define FM_FD_RX_STATUS_ERR_MASK        (FM_FD_ERR_UNSUPPORTED_FORMAT   | \
                                         FM_FD_ERR_LENGTH               | \
                                         FM_FD_ERR_DMA                  | \
                                         FM_FD_ERR_IPR                  | \
                                         FM_FD_ERR_IPR_TO               | \
                                         FM_FD_ERR_IPR_NCSP             | \
                                         FM_FD_ERR_PHYSICAL             | \
                                         FM_FD_ERR_SIZE                 | \
                                         FM_FD_ERR_CLS_DISCARD          | \
                                         FM_FD_ERR_COLOR_RED            | \
                                         FM_FD_ERR_COLOR_YELLOW         | \
                                         FM_FD_ERR_ILL_PLCR             | \
                                         FM_FD_ERR_PLCR_FRAME_LEN       | \
                                         FM_FD_ERR_EXTRACTION           | \
                                         FM_FD_ERR_NO_SCHEME            | \
                                         FM_FD_ERR_KEYSIZE_OVERFLOW     | \
                                         FM_FD_ERR_PRS_TIMEOUT          | \
                                         FM_FD_ERR_PRS_ILL_INSTRUCT     | \
                                         FM_FD_ERR_PRS_HDR_ERR          | \
                                         FM_FD_ERR_BLOCK_LIMIT_EXCEEDED) /**< RX Error FD bits */

#define FM_FD_RX_STATUS_ERR_NON_FM      0x00400000  /**< non Frame-Manager error */
/* @} */


/**************************************************************************//**
 @Description   FM Exceptions
*//***************************************************************************/
typedef enum e_FmExceptions {
    e_FM_EX_DMA_BUS_ERROR = 0,          /**< DMA bus error. */
    e_FM_EX_DMA_READ_ECC,               /**< Read Buffer ECC error (Valid for FM rev < 6)*/
    e_FM_EX_DMA_SYSTEM_WRITE_ECC,       /**< Write Buffer ECC error on system side (Valid for FM rev < 6)*/
    e_FM_EX_DMA_FM_WRITE_ECC,           /**< Write Buffer ECC error on FM side (Valid for FM rev < 6)*/
    e_FM_EX_DMA_SINGLE_PORT_ECC,        /**< Single Port ECC error on FM side (Valid for FM rev > 6)*/
    e_FM_EX_FPM_STALL_ON_TASKS,         /**< Stall of tasks on FPM */
    e_FM_EX_FPM_SINGLE_ECC,             /**< Single ECC on FPM. */
    e_FM_EX_FPM_DOUBLE_ECC,             /**< Double ECC error on FPM ram access */
    e_FM_EX_QMI_SINGLE_ECC,             /**< Single ECC on QMI. */
    e_FM_EX_QMI_DOUBLE_ECC,             /**< Double bit ECC occurred on QMI */
    e_FM_EX_QMI_DEQ_FROM_UNKNOWN_PORTID,/**< Dequeue from unknown port id */
    e_FM_EX_BMI_LIST_RAM_ECC,           /**< Linked List RAM ECC error */
    e_FM_EX_BMI_STORAGE_PROFILE_ECC,    /**< Storage Profile ECC Error */
    e_FM_EX_BMI_STATISTICS_RAM_ECC,     /**< Statistics Count RAM ECC Error Enable */
    e_FM_EX_BMI_DISPATCH_RAM_ECC,       /**< Dispatch RAM ECC Error Enable */
    e_FM_EX_IRAM_ECC,                   /**< Double bit ECC occurred on IRAM*/
    e_FM_EX_MURAM_ECC                   /**< Double bit ECC occurred on MURAM*/
} e_FmExceptions;

/**************************************************************************//**
 @Description   Enum for defining port DMA swap mode
*//***************************************************************************/
typedef enum e_FmDmaSwapOption {
    e_FM_DMA_NO_SWP,           /**< No swap, transfer data as is.*/
    e_FM_DMA_SWP_PPC_LE,       /**< The transferred data should be swapped
                                    in PowerPc Little Endian mode. */
    e_FM_DMA_SWP_BE            /**< The transferred data should be swapped
                                    in Big Endian mode */
} e_FmDmaSwapOption;

/**************************************************************************//**
 @Description   Enum for defining port DMA cache attributes
*//***************************************************************************/
typedef enum e_FmDmaCacheOption {
    e_FM_DMA_NO_STASH = 0,     /**< Cacheable, no Allocate (No Stashing) */
    e_FM_DMA_STASH = 1         /**< Cacheable and Allocate (Stashing on) */
} e_FmDmaCacheOption;
/**************************************************************************//**
 @Group         lnx_usr_FM_init_grp FM Initialization Unit

 @Description   FM Initialization Unit

                Initialization Flow
                Initialization of the FM Module will be carried out by the application
                according to the following sequence:
                -  Calling the configuration routine with basic parameters.
                -  Calling the advance initialization routines to change driver's defaults.
                -  Calling the initialization routine.

 @{
*//***************************************************************************/

t_Handle FM_Open(uint8_t id);
void     FM_Close(t_Handle h_Fm);


/**************************************************************************//**
 @Description   A structure for defining buffer prefix area content.
*//***************************************************************************/
typedef struct t_FmBufferPrefixContent {
    uint16_t    privDataSize;       /**< Number of bytes to be left at the beginning
                                         of the external buffer; Note that the private-area will
                                         start from the base of the buffer address. */
    bool        passPrsResult;      /**< TRUE to pass the parse result to/from the FM;
                                         User may use FM_PORT_GetBufferPrsResult() in order to
                                         get the parser-result from a buffer. */
    bool        passTimeStamp;      /**< TRUE to pass the timeStamp to/from the FM
                                         User may use FM_PORT_GetBufferTimeStamp() in order to
                                         get the parser-result from a buffer. */
    bool        passHashResult;     /**< TRUE to pass the KG hash result to/from the FM
                                         User may use FM_PORT_GetBufferHashResult() in order to
                                         get the parser-result from a buffer. */
    bool        passAllOtherPCDInfo;/**< Add all other Internal-Context information:
                                         AD, hash-result, key, etc. */
    uint16_t    dataAlign;          /**< 0 to use driver's default alignment [64],
                                         other value for selecting a data alignment (must be a power of 2);
                                         if write optimization is used, must be >= 16. */
    uint8_t     manipExtraSpace;    /**< Maximum extra size needed (insertion-size minus removal-size);
                                         Note that this field impacts the size of the buffer-prefix
                                         (i.e. it pushes the data offset);
                                         This field is irrelevant if DPAA_VERSION==10 */
} t_FmBufferPrefixContent;

/**************************************************************************//**
 @Description   A structure of information about each of the external
                buffer pools used by a port or storage-profile.
*//***************************************************************************/
typedef struct t_FmExtPoolParams {
    uint8_t                 id;     /**< External buffer pool id */
    uint16_t                size;   /**< External buffer pool buffer size */
} t_FmExtPoolParams;

/**************************************************************************//**
 @Description   A structure for informing the driver about the external
                buffer pools allocated in the BM and used by a port or a
                storage-profile.
*//***************************************************************************/
typedef struct t_FmExtPools {
    uint8_t                 numOfPoolsUsed;     /**< Number of pools use by this port */
    t_FmExtPoolParams       extBufPool[FM_PORT_MAX_NUM_OF_EXT_POOLS];
                                                /**< Parameters for each port */
} t_FmExtPools;

/**************************************************************************//**
 @Description   A structure for defining backup BM Pools.
*//***************************************************************************/
typedef struct t_FmBackupBmPools {
    uint8_t     numOfBackupPools;       /**< Number of BM backup pools -
                                             must be smaller than the total number of
                                             pools defined for the specified port.*/
    uint8_t     poolIds[FM_PORT_MAX_NUM_OF_EXT_POOLS];
                                        /**< numOfBackupPools pool id's, specifying which
                                             pools should be used only as backup. Pool
                                             id's specified here must be a subset of the
                                             pools used by the specified port.*/
} t_FmBackupBmPools;

/**************************************************************************//**
 @Description   A structure for defining BM pool depletion criteria
*//***************************************************************************/
typedef struct t_FmBufPoolDepletion {
    bool        poolsGrpModeEnable;                 /**< select mode in which pause frames will be sent after
                                                         a number of pools (all together!) are depleted */
    uint8_t     numOfPools;                         /**< the number of depleted pools that will invoke
                                                         pause frames transmission. */
    bool        poolsToConsider[BM_MAX_NUM_OF_POOLS];
                                                    /**< For each pool, TRUE if it should be considered for
                                                         depletion (Note - this pool must be used by this port!). */
    bool        singlePoolModeEnable;               /**< select mode in which pause frames will be sent after
                                                         a single-pool is depleted; */
    bool        poolsToConsiderForSingleMode[BM_MAX_NUM_OF_POOLS];
                                                    /**< For each pool, TRUE if it should be considered for
                                                         depletion (Note - this pool must be used by this port!) */
#if (DPAA_VERSION >= 11)
    bool        pfcPrioritiesEn[FM_MAX_NUM_OF_PFC_PRIORITIES];
                                                    /**< This field is used by the MAC as the Priority Enable Vector in the PFC frame which is transmitted */
#endif /* (DPAA_VERSION >= 11) */
} t_FmBufPoolDepletion;


/** @} */ /* end of lnx_usr_FM_init_grp group */


/**************************************************************************//**
 @Group         lnx_usr_FM_runtime_control_grp FM Runtime Control Unit

 @Description   FM Runtime control unit API functions, definitions and enums.
                The FM driver provides a set of control routines.
                These routines may only be called after the module was fully
                initialized (both configuration and initialization routines were
                called). They are typically used to get information from hardware
                (status, counters/statistics, revision etc.), to modify a current
                state or to force/enable a required action. Run-time control may
                be called whenever necessary and as many times as needed.
 @{
*//***************************************************************************/

/**************************************************************************//**
 @Collection   General FM defines.
*//***************************************************************************/
#define FM_MAX_NUM_OF_VALID_PORTS   (FM_MAX_NUM_OF_OH_PORTS +       \
                                     FM_MAX_NUM_OF_1G_RX_PORTS +    \
                                     FM_MAX_NUM_OF_10G_RX_PORTS +   \
                                     FM_MAX_NUM_OF_1G_TX_PORTS +    \
                                     FM_MAX_NUM_OF_10G_TX_PORTS)      /**< Number of available FM ports */
/* @} */

/**************************************************************************//**
 @Description   A structure for Port bandwidth requirement. Port is identified
                by type and relative id.
*//***************************************************************************/
typedef struct t_FmPortBandwidth {
    e_FmPortType        type;           /**< FM port type */
    uint8_t             relativePortId; /**< Type relative port id */
    uint8_t             bandwidth;      /**< bandwidth - (in term of percents) */
} t_FmPortBandwidth;

/**************************************************************************//**
 @Description   A Structure containing an array of Port bandwidth requirements.
                The user should state the ports requiring bandwidth in terms of
                percentage - i.e. all port's bandwidths in the array must add
                up to 100.
*//***************************************************************************/
typedef struct t_FmPortsBandwidthParams {
    uint8_t             numOfPorts;         /**< The number of relevant ports, which is the
                                                 number of valid entries in the array below */
    t_FmPortBandwidth   portsBandwidths[FM_MAX_NUM_OF_VALID_PORTS];
                                            /**< for each port, it's bandwidth (all port's
                                                 bandwidths must add up to 100.*/
} t_FmPortsBandwidthParams;

/**************************************************************************//**
 @Description   Enum for defining FM counters
*//***************************************************************************/
typedef enum e_FmCounters {
    e_FM_COUNTERS_ENQ_TOTAL_FRAME = 0,              /**< QMI total enqueued frames counter */
    e_FM_COUNTERS_DEQ_TOTAL_FRAME,                  /**< QMI total dequeued frames counter */
    e_FM_COUNTERS_DEQ_0,                            /**< QMI 0 frames from QMan counter */
    e_FM_COUNTERS_DEQ_1,                            /**< QMI 1 frames from QMan counter */
    e_FM_COUNTERS_DEQ_2,                            /**< QMI 2 frames from QMan counter */
    e_FM_COUNTERS_DEQ_3,                            /**< QMI 3 frames from QMan counter */
    e_FM_COUNTERS_DEQ_FROM_DEFAULT,                 /**< QMI dequeue from default queue counter */
    e_FM_COUNTERS_DEQ_FROM_CONTEXT,                 /**< QMI dequeue from FQ context counter */
    e_FM_COUNTERS_DEQ_FROM_FD,                      /**< QMI dequeue from FD command field counter */
    e_FM_COUNTERS_DEQ_CONFIRM                       /**< QMI dequeue confirm counter */
} e_FmCounters;

/**************************************************************************//**
 @Description   A structure for returning FM revision information
*//***************************************************************************/
typedef struct t_FmRevisionInfo {
    uint8_t         majorRev;               /**< Major revision */
    uint8_t         minorRev;               /**< Minor revision */
} t_FmRevisionInfo;

/**************************************************************************//**
 @Description   A structure for returning FM ctrl code revision information
*//***************************************************************************/
typedef struct t_FmCtrlCodeRevisionInfo {
    uint16_t        packageRev;             /**< Package revision */
    uint8_t         majorRev;               /**< Major revision */
    uint8_t         minorRev;               /**< Minor revision */
} t_FmCtrlCodeRevisionInfo;

/**************************************************************************//**
 @Description   A Structure for obtaining FM controller monitor values
*//***************************************************************************/
typedef struct t_FmCtrlMon {
    uint8_t percentCnt[2];          /**< Percentage value */
} t_FmCtrlMon;

/**************************************************************************//**
 @Function      FM_SetPortsBandwidth

 @Description   Sets relative weights between ports when accessing common resources.

 @Param[in]     h_Fm                A handle to an FM Module.
 @Param[in]     p_PortsBandwidth    A structure of ports bandwidths in percentage, i.e.
                                    total must equal 100.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_Init().
*//***************************************************************************/
t_Error FM_SetPortsBandwidth(t_Handle h_Fm, t_FmPortsBandwidthParams *p_PortsBandwidth);

/**************************************************************************//**
 @Function      FM_GetRevision

 @Description   Returns the FM revision

 @Param[in]     h_Fm                A handle to an FM Module.
 @Param[out]    p_FmRevisionInfo    A structure of revision information parameters.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_Init().
*//***************************************************************************/
t_Error  FM_GetRevision(t_Handle h_Fm, t_FmRevisionInfo *p_FmRevisionInfo);

/**************************************************************************//**
 @Function      FM_GetFmanCtrlCodeRevision

 @Description   Returns the Fman controller code revision
		(Not implemented in fm-lib just yet!)

 @Param[in]     h_Fm                A handle to an FM Module.
 @Param[out]    p_RevisionInfo      A structure of revision information parameters.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_Init().
*//***************************************************************************/
t_Error FM_GetFmanCtrlCodeRevision(t_Handle h_Fm, t_FmCtrlCodeRevisionInfo *p_RevisionInfo);

/**************************************************************************//**
 @Function      FM_GetCounter

 @Description   Reads one of the FM counters.

 @Param[in]     h_Fm        A handle to an FM Module.
 @Param[in]     counter     The requested counter.

 @Return        Counter's current value.

 @Cautions      Allowed only following FM_Init().
                Note that it is user's responsibility to call this routine only
                for enabled counters, and there will be no indication if a
                disabled counter is accessed.
*//***************************************************************************/
uint32_t  FM_GetCounter(t_Handle h_Fm, e_FmCounters counter);

/**************************************************************************//**
 @Function      FM_ModifyCounter

 @Description   Sets a value to an enabled counter. Use "0" to reset the counter.

 @Param[in]     h_Fm        A handle to an FM Module.
 @Param[in]     counter     The requested counter.
 @Param[in]     val         The requested value to be written into the counter.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_Init().
*//***************************************************************************/
t_Error  FM_ModifyCounter(t_Handle h_Fm, e_FmCounters counter, uint32_t val);

/**************************************************************************//**
 @Function      FM_CtrlMonStart

 @Description   Start monitoring utilization of all available FM controllers.

                In order to obtain FM controllers utilization the following sequence
                should be used:
                -# FM_CtrlMonStart()
                -# FM_CtrlMonStop()
                -# FM_CtrlMonGetCounters() - issued for each FM controller

 @Param[in]     h_Fm            A handle to an FM Module.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_Init().
                This routine should NOT be called from guest-partition
                (i.e. guestId != NCSW_MASTER_ID).
*//***************************************************************************/
t_Error FM_CtrlMonStart(t_Handle h_Fm);

/**************************************************************************//**
 @Function      FM_CtrlMonStop

 @Description   Stop monitoring utilization of all available FM controllers.

                In order to obtain FM controllers utilization the following sequence
                should be used:
                -# FM_CtrlMonStart()
                -# FM_CtrlMonStop()
                -# FM_CtrlMonGetCounters() - issued for each FM controller

 @Param[in]     h_Fm            A handle to an FM Module.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_Init().
                This routine should NOT be called from guest-partition
                (i.e. guestId != NCSW_MASTER_ID).
*//***************************************************************************/
t_Error FM_CtrlMonStop(t_Handle h_Fm);

/**************************************************************************//**
 @Function      FM_CtrlMonGetCounters

 @Description   Obtain FM controller utilization parameters.

                In order to obtain FM controllers utilization the following sequence
                should be used:
                -# FM_CtrlMonStart()
                -# FM_CtrlMonStop()
                -# FM_CtrlMonGetCounters() - issued for each FM controller

 @Param[in]     h_Fm            A handle to an FM Module.
 @Param[in]     fmCtrlIndex     FM Controller index for that utilization results
                                are requested.
 @Param[in]     p_Mon           Pointer to utilization results structure.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_Init().
                This routine should NOT be called from guest-partition
                (i.e. guestId != NCSW_MASTER_ID).
*//***************************************************************************/
t_Error FM_CtrlMonGetCounters(t_Handle h_Fm, uint8_t fmCtrlIndex, t_FmCtrlMon *p_Mon);


/**************************************************************************//*
 @Function      FM_ForceIntr

 @Description   Causes an interrupt event on the requested source.

 @Param[in]     h_Fm            A handle to an FM Module.
 @Param[in]     exception       An exception to be forced.

 @Return        E_OK on success; Error code if the exception is not enabled,
                or is not able to create interrupt.

 @Cautions      Allowed only following FM_Init().
*//***************************************************************************/
t_Error FM_ForceIntr (t_Handle h_Fm, e_FmExceptions exception);

/**************************************************************************//*
 @Function      FM_ReadTimeStamp

 @Description   Reads the FMan engine's timestamp.

 @Param[in]     h_Fm                A handle to an FM Module.

 @Return        The indicated engine's timestamp on success; zero otherwise.

 @Cautions      Allowed only following FM_Init().
                This routine should NOT be called from guest-partition
                (i.e. guestId != NCSW_MASTER_ID)
*//***************************************************************************/
uint32_t FM_ReadTimeStamp(t_Handle h_Fm);

/**************************************************************************//*
 @Function      FM_GetTimeStampIncrementPerUsec

 @Description   Provides the value of the FMan engine's timestamp increment
                per microsecond.

 @Param[in]     h_Fm                A handle to an FM Module.

 @Return        The value the timestamp is incremented with each microsecond
                on success; zero otherwise.

 @Cautions      Allowed only following FM_Init().
                This routine should NOT be called from guest-partition
                (i.e. guestId != NCSW_MASTER_ID)
*//***************************************************************************/
uint32_t FM_GetTimeStampIncrementPerUsec(t_Handle h_Fm);

/** @} */ /* end of lnx_usr_FM_runtime_control_grp group */
/** @} */ /* end of lnx_usr_FM_lib_grp group */
/** @} */ /* end of lnx_usr_FM_grp group */

#ifdef NCSW_BACKWARD_COMPATIBLE_API
typedef t_FmBackupBmPools           t_FmPortBackupBmPools;
typedef t_FmBufPoolDepletion        t_FmPortBufPoolDepletion;
#define e_FM_EX_BMI_PIPELINE_ECC    e_FM_EX_BMI_STORAGE_PROFILE_ECC
#endif /* NCSW_BACKWARD_COMPATIBLE_API */

#endif /* __FM_EXT */
