/* ============================================================================
 *
 * The MIT License (MIT)
 * Copyright (c) 2009-2012, Freescale Semiconductor, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * File Name : fmc.h
 * Author    : Serge Lamikhov-Center
 *
 * ========================================================================= */

#ifndef LIBFMC_H
#define LIBFMC_H

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <std_ext.h>
#include <error_ext.h>
#include <part_ext.h>
#include <fm_ext.h>
#include <Peripherals/fm_pcd_ext.h>
#include <Peripherals/fm_port_ext.h>

#define FMC_OUTPUT_FORMAT_VER 0x106

#define FMC_NAME_LEN             64
#define FMC_FMAN_NUM              2
#define FMC_PORTS_PER_FMAN       16
#define FMC_SCHEMES_NUM          32
#define FMC_SCHEME_PROTOCOLS_NUM 16
#define FMC_CC_NODES_NUM        512
#define FMC_REPLICATORS_NUM      16
#define FMC_PLC_NUM              64
#define MAX_SP_CODE_SIZE      0x7C0
#define FMC_MANIP_MAX            64
#define FMC_HMANIP_MAX          512
#define FMC_INSERT_MAX           56
#define FM_PCD_MAX_NUM_OF_REPS   64

#define FMC_APPLY_ORDER( Index, Type, Element ) \
    .apply_order[Index].type  = Type,                    \
    .apply_order[Index].index = Element

typedef struct fmc_fman_t {
    unsigned int       number;
    unsigned int       port_count;
    unsigned int       ports[FMC_PORTS_PER_FMAN];
    char               name[FMC_NAME_LEN];
    t_Handle           handle;
    char               pcd_name[FMC_NAME_LEN];
    t_Handle           pcd_handle;
	unsigned int       kg_payload_offset;

#ifndef P1023
    unsigned int       offload_support;

    unsigned int       reasm_count;
    t_FmPcdManipParams reasm[FMC_MANIP_MAX];
    char               reasm_name[FMC_MANIP_MAX][FMC_NAME_LEN];
    t_Handle           reasm_handle[FMC_MANIP_MAX];
    t_Handle           reasm_devId[FMC_MANIP_MAX];

    unsigned int       frag_count;
    t_FmPcdManipParams frag[FMC_MANIP_MAX];
    char               frag_name[FMC_MANIP_MAX][FMC_NAME_LEN];
    t_Handle           frag_handle[FMC_MANIP_MAX];
    t_Handle           frag_devId[FMC_MANIP_MAX];

    unsigned int       hdr_count;
    t_FmPcdManipParams hdr[FMC_HMANIP_MAX];
    uint8_t            insertData[FMC_HMANIP_MAX][FMC_INSERT_MAX];
    char               hdr_name[FMC_HMANIP_MAX][FMC_NAME_LEN];
    t_Handle           hdr_handle[FMC_HMANIP_MAX];
    t_Handle           hdr_devId[FMC_HMANIP_MAX];
    unsigned int       hdr_hasNext[FMC_HMANIP_MAX];
    unsigned int       hdr_next[FMC_HMANIP_MAX];
#endif /* P1023 */
} fmc_fman;


typedef struct fmc_port_t {
    e_FmPortType         type;                      ///< Port type
    unsigned int         number;                    ///< Port number
    unsigned int         portid;                    ///< Port identification from xml file
    t_FmPcdNetEnvParams  distinctionUnits;          ///< Port's network env
    t_FmPortPcdParams    pcdParam;
    t_FmPortPcdPrsParams prsParam;
    t_FmPortPcdKgParams  kgParam;
    t_FmPortPcdCcParams  ccParam;
    char                 name[FMC_NAME_LEN];
    char                 cctree_name[FMC_NAME_LEN];
    t_Handle             handle;
    t_Handle             env_id_handle;
    t_Handle             env_id_devId; 				///< handle to net environment allocated by the driver in kernel
    t_Handle             cctree_handle;
    t_Handle             cctree_devId;

    unsigned int         schemes_count;             ///< Number of used schemes
    unsigned int         schemes[FMC_SCHEMES_NUM];  ///< Schemes used by this port

    unsigned int         ccnodes_count;             ///< Number of used CC nodes
    unsigned int         ccnodes[FMC_CC_NODES_NUM]; ///< Class. nodes used by this port

    unsigned int         htnodes_count;             ///< Number of used CC nodes
    unsigned int         htnodes[FMC_CC_NODES_NUM]; ///< Class. nodes used by this port

#if (DPAA_VERSION >= 11)
    unsigned int         replicators_count;         ///< Number of used Frame Replicators
    unsigned int         replicators[FMC_REPLICATORS_NUM]; ///< Replicators used by this port
    t_FmPortVSPAllocParams vspParam;
#endif /* (DPAA_VERSION >= 11) */

    unsigned int         ccroot_count;
    unsigned int         ccroot[FMC_CC_NODES_NUM];
    e_FmPcdEngine        ccroot_type[FMC_CC_NODES_NUM];
#ifndef P1023
    unsigned int         ccroot_manip[FMC_CC_NODES_NUM];
#endif /* P1023 */

    unsigned int         reasm_index;
} fmc_port;


typedef enum fmc_apply_order_e {
    FMCEngineStart,
    FMCEngineEnd,
    FMCPortStart,
    FMCPortEnd,
    FMCScheme,
    FMCCCNode,
    FMCHTNode,
    FMCCCTree,
    FMCPolicer,
    FMCReplicator,
    FMCManipulation
} fmc_apply_order_e;


typedef struct fmc_apply_order_t {
    fmc_apply_order_e type;
    unsigned int      index;
} fmc_apply_order;


typedef struct fmc_model_t {
    unsigned int             format_version;
    unsigned int             sp_enable;           ///< Soft parser enable flag
    t_FmPcdPrsSwParams       sp;                  ///< Soft parser configuration
    uint8_t                  spCode[MAX_SP_CODE_SIZE];

    unsigned int             fman_count;                ///< Number of used FMan engines
    fmc_fman                 fman[FMC_FMAN_NUM];

    unsigned int             port_count;                ///< Number of used FMan ports
    fmc_port                 port[FMC_FMAN_NUM * FMC_PORTS_PER_FMAN];

    unsigned int             scheme_count;     ///< Number of used KeyGen schemes
    char                     scheme_name  [FMC_SCHEMES_NUM][FMC_NAME_LEN];
    t_Handle                 scheme_handle[FMC_SCHEMES_NUM];
    t_Handle                 scheme_devId[FMC_SCHEMES_NUM];
    t_FmPcdKgSchemeParams    scheme       [FMC_SCHEMES_NUM];

    unsigned int             ccnode_count;       ///< Number of used CC nodes
    char                     ccnode_name         [FMC_CC_NODES_NUM][FMC_NAME_LEN];
    t_Handle                 ccnode_handle       [FMC_CC_NODES_NUM];
    t_Handle                 ccnode_devId        [FMC_CC_NODES_NUM];
    t_FmPcdCcNodeParams      ccnode              [FMC_CC_NODES_NUM];
    uint8_t                  cckeydata           [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS]
                                                 [FM_PCD_MAX_SIZE_OF_KEY];
    unsigned char            ccmask              [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS]
                                                 [FM_PCD_MAX_SIZE_OF_KEY];
    unsigned int             ccentry_action_index[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    e_FmPcdEngine            ccentry_action_type [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    unsigned char            ccentry_frag        [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    unsigned int             ccentry_manip       [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    unsigned int             ccmiss_action_index [FMC_CC_NODES_NUM];
    e_FmPcdEngine            ccmiss_action_type  [FMC_CC_NODES_NUM];
    unsigned char            ccmiss_frag         [FMC_CC_NODES_NUM];
    unsigned int             ccmiss_manip        [FMC_CC_NODES_NUM];

    unsigned int             htnode_count;       ///< Number of used HT nodes
    char                     htnode_name         [FMC_CC_NODES_NUM][FMC_NAME_LEN];
    t_Handle                 htnode_handle       [FMC_CC_NODES_NUM];
    t_Handle                 htnode_devId        [FMC_CC_NODES_NUM];
    t_FmPcdHashTableParams   htnode              [FMC_CC_NODES_NUM];
    //-- ht table prefilled entries
    unsigned int             htentry_count       [FMC_CC_NODES_NUM];
    t_FmPcdCcKeyParams       htentry             [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    uint8_t                  htkeydata           [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS]
                                                 [FM_PCD_MAX_SIZE_OF_KEY];
    unsigned int             htentry_action_index[FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    e_FmPcdEngine            htentry_action_type [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    unsigned char            htentry_frag        [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    unsigned int             htentry_manip       [FMC_CC_NODES_NUM][FM_PCD_MAX_NUM_OF_KEYS];
    //-- end of prefilled entries
    unsigned int             htmiss_action_index [FMC_CC_NODES_NUM];
    e_FmPcdEngine            htmiss_action_type  [FMC_CC_NODES_NUM];
    unsigned char            htmiss_frag         [FMC_CC_NODES_NUM];
    unsigned int             htmiss_manip        [FMC_CC_NODES_NUM];


#if (DPAA_VERSION >= 11)
    unsigned int             replicator_count;     ///< Number of used Frame Replicators
    char                     replicator_name       [FMC_REPLICATORS_NUM][FMC_NAME_LEN];
    t_Handle                 replicator_handle     [FMC_REPLICATORS_NUM];
    t_Handle                 replicator_devId      [FMC_REPLICATORS_NUM];
    t_FmPcdFrmReplicGroupParams      replicator    [FMC_REPLICATORS_NUM];
    unsigned int             repentry_action_index [FMC_REPLICATORS_NUM][FM_PCD_MAX_NUM_OF_REPS];
    unsigned char            repentry_frag         [FMC_REPLICATORS_NUM][FM_PCD_MAX_NUM_OF_REPS];
    unsigned int             repentry_manip        [FMC_REPLICATORS_NUM][FM_PCD_MAX_NUM_OF_REPS];
#endif /* (DPAA_VERSION >= 11) */
   
    unsigned int             policer_count; ///< Number of used policers
    char                     policer_name        [FMC_PLC_NUM][FMC_NAME_LEN];
    t_FmPcdPlcrProfileParams policer             [FMC_PLC_NUM];
    t_Handle                 policer_handle      [FMC_PLC_NUM];
    t_Handle                 policer_devId       [FMC_PLC_NUM];
    unsigned int             policer_action_index[FMC_PLC_NUM][3];

    unsigned int             apply_order_count;               ///< Number of 'apply order' elements
    fmc_apply_order          apply_order[FMC_FMAN_NUM*FMC_PORTS_PER_FMAN*(FMC_SCHEMES_NUM+FMC_CC_NODES_NUM)];
} fmc_model;


int fmc_compile(
        fmc_model*   model,
        const char*  nameCfg,
        const char*  namePCD,
        const char*  namePDL,
        const char*  nameSP,
        unsigned int swOffset,
        unsigned int dontWarn,
        const char** dump
);

int fmc_execute( fmc_model* model );

int fmc_clean( fmc_model* model );

bool fmc_load( fmc_model* pmodel );

bool fmc_save( fmc_model* pmodel );

void fmc_release( fmc_model* pmodel );

const char* fmc_get_error( void );

t_Handle fmc_get_handle(
            fmc_model*   model,
            const char*  name
);


#define LOG_NONE 0
#define LOG_ERR  1
#define LOG_WARN 2
#define LOG_INFO 3
#define LOG_DBG1 4
#define LOG_DBG2 5
#define LOG_DBG3 6

int32_t fmc_log( int32_t level );

void fmc_log_write( int32_t level, const char* format, ... );


#ifdef __cplusplus
}  // extern "C"
#endif

#endif // LIBFMC_H
