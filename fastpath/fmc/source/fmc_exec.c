/* ============================================================================
 *
 * The MIT License (MIT)
 * Copyright (c) 2009-2012, Freescale Semiconductor, Inc.
 * Copyright 2021 NXP
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
 * File Name : fmc_exec.c
 * Author    : Serge Lamikhov-Center
 *
 * ========================================================================= */

#include <string.h>
#include <stdio.h>

#ifdef NETCOMM_SW
    #include "sys_ext.h"
#endif

#include "fmc.h"

#if defined(NETCOMM_SW) || defined(NO_FMC_LOG)
    #define fmc_log_write( ... )
#endif

/* Forward declaration of static functions */
static int fmc_exec_engine_start( fmc_model* model, unsigned int index,
                                  unsigned int* p_relative_scheme_index );
static int fmc_exec_engine_end  ( fmc_model* model, unsigned int index );
static int fmc_exec_port_start  ( fmc_model* model, unsigned int engine,
                                  unsigned int index );
static int fmc_exec_port_end    ( fmc_model* model, unsigned int engine,
                                  unsigned int index );
static int fmc_exec_scheme      ( fmc_model* model,  unsigned int engine,
                                  unsigned int port, unsigned int index,
                                  unsigned int relative_scheme_index );
static int fmc_exec_ccnode      ( fmc_model* model, unsigned int engine,
                                  unsigned int index );
static int fmc_exec_htnode      ( fmc_model* model, unsigned int engine,
                                  unsigned int index );
static int fmc_exec_cctree      ( fmc_model* model,  unsigned int engine,
                                  unsigned int port );
static int fmc_exec_policer     ( fmc_model* model, unsigned int engine,
                                  unsigned int index );
#if (DPAA_VERSION >= 11)
static int fmc_exec_replicator  ( fmc_model* model, unsigned int engine,
                                  unsigned int index );
#endif /* (DPAA_VERSION >= 11) */
static int fmc_exec_manip       ( fmc_model* model, unsigned int engine,
                                  unsigned int index );

static int fmc_clean_engine_start( fmc_model* model, unsigned int index );
static int fmc_clean_engine_end  ( fmc_model* model, unsigned int index );
static int fmc_clean_port_start  ( fmc_model* model, unsigned int engine,
                                   unsigned int index );
static int fmc_clean_port_end    ( fmc_model* model, unsigned int engine,
                                   unsigned int index );
static int fmc_clean_scheme      ( fmc_model* model,  unsigned int engine,
                                   unsigned int port, unsigned int index );
static int fmc_clean_ccnode      ( fmc_model* model, unsigned int engine,
                                   unsigned int index );
static int fmc_clean_htnode      ( fmc_model* model, unsigned int engine,
                                   unsigned int index );
static int fmc_clean_cctree      ( fmc_model* model,  unsigned int engine,
                                   unsigned int port );
static int fmc_clean_policer     ( fmc_model* model, unsigned int engine,
                                   unsigned int index );
static int fmc_clean_manip       ( fmc_model* model, unsigned int engine,
                                   unsigned int index );

typedef struct t_DirectSchemeInfo {

	int					index;
	e_FmPcdEngine		nextEngine;
    union {                                                     /**< depends on nextEngine */
        e_FmPcdDoneAction               doneAction;             /**< Used when next engine is BMI (done) */
        t_FmPcdKgPlcrProfile            plcrProfile;            /**< Used when next engine is PLCR */
        t_FmPcdKgCc                     cc;                     /**< Used when next engine is CC */
    } kgNextEngineParams;
} t_DirectSchemeInfo;

static int						g_crtDirectSchemeCount;
static t_DirectSchemeInfo		g_crtDirectScheme[FMC_SCHEMES_NUM];


#if (DPAA_VERSION >= 11)
static int fmc_clean_replicator  ( fmc_model* model, unsigned int engine,
                                   unsigned int index );
#endif /* (DPAA_VERSION >= 11) */

#define LOG_FMD_CALL( func, name )                                           \
    fmc_log_write( LOG_DBG1, "Invocation of " #func " from %s for %s",       \
                             __FUNCTION__, name );

#define CHECK_HANDLE( func, name, handle )                                   \
    if ( handle == 0 ) {                                                     \
        fmc_log_write( LOG_ERR, "Invocation of " #func " for %s failed",     \
                       name );                                               \
        return 1;                                                            \
    }                                                                        \
    else {                                                                   \
        fmc_log_write( LOG_DBG1, "Invocation of " #func " for %s succeeded", \
                                 name );                                     \
    }

#define CHECK_ERR( func, name )                                              \
    if ( err  != E_OK ) {                                                    \
        fmc_log_write( LOG_ERR, "Invocation of " #func " for %s failed "     \
                                 "with error code 0x%08X",                   \
                       name, err );                                          \
        return 1;                                                            \
    }                                                                        \
    else {                                                                   \
        fmc_log_write( LOG_DBG1, "Invocation of " #func " for %s succeeded", \
                                    name );                                  \
    }



/* -------------------------------------------------------------------------- */
int
fmc_execute( fmc_model* model )
{
    int          ret                   = 0;
    unsigned int current_engine        = 0;
    unsigned int current_port          = 0;
    unsigned int relative_scheme_index = 0;
    unsigned int i;

    if ( model->format_version != FMC_OUTPUT_FORMAT_VER ) {
        return 0xFFFFFFFF;
    }

    for ( i = 0; i < model->apply_order_count; i++ ) {
        switch ( model->apply_order[i].type ) {
            case FMCEngineStart:
                current_engine        = model->apply_order[i].index;
                relative_scheme_index = 0;
                ret = fmc_exec_engine_start( model, current_engine,
                                             &relative_scheme_index );
                break;
            case FMCEngineEnd:
                ret = fmc_exec_engine_end( model, current_engine );
                break;
            case FMCPortStart:
                current_port = model->apply_order[i].index;
                ret = fmc_exec_port_start( model, current_engine, current_port );
                break;
            case FMCPortEnd:
                ret = fmc_exec_port_end( model, current_engine, current_port );
                break;
            case FMCScheme:
                ret = fmc_exec_scheme( model, current_engine, current_port,
                                       model->apply_order[i].index, relative_scheme_index++ );
                break;
            case FMCCCNode:
                ret = fmc_exec_ccnode( model, current_engine, model->apply_order[i].index );
                break;
            case FMCHTNode:
                ret = fmc_exec_htnode( model, current_engine, model->apply_order[i].index );
                break;
#if (DPAA_VERSION >= 11)
            case FMCReplicator:
                ret = fmc_exec_replicator( model, current_engine, model->apply_order[i].index );
                break;
#endif /* (DPAA_VERSION >= 11) */
            case FMCCCTree:
                ret = fmc_exec_cctree( model, current_engine, model->apply_order[i].index );
                break;
            case FMCPolicer:
                ret = fmc_exec_policer( model, current_engine, model->apply_order[i].index );
                break;
            case FMCManipulation:
                ret = fmc_exec_manip( model, current_engine, model->apply_order[i].index );
                break;
            default:
                break;
        }

        /* Exit the loop in case of failure */
        if ( ret != 0 ) {
            break;
        }
    }

    return ret;
}


/* -------------------------------------------------------------------------- */
int
fmc_clean( fmc_model* model )
{
    int          ret            = 0;
    unsigned int current_engine = 0;
    unsigned int current_port   = 0;
    unsigned int i, j;

    if ( model->format_version != FMC_OUTPUT_FORMAT_VER ) {
        return 0xFFFFFFFF;
    }

    for ( j = 0; j < model->apply_order_count; j++ ) {
        /* Clean entities in reverse order of applying */
        i = model->apply_order_count - j - 1;
        switch ( model->apply_order[i].type ) {
            case FMCEngineStart:
                current_engine = model->apply_order[i].index;
                ret = fmc_clean_engine_start( model, current_engine );
                break;
            case FMCEngineEnd:
                current_engine = model->apply_order[i].index;
                ret = fmc_clean_engine_end( model, current_engine );
                break;
            case FMCPortStart:
                current_port = model->apply_order[i].index;
                ret = fmc_clean_port_start( model, current_engine, current_port );
                break;
            case FMCPortEnd:
                current_port = model->apply_order[i].index;
                ret = fmc_clean_port_end( model, current_engine, current_port );
                break;
            case FMCScheme:
                ret = fmc_clean_scheme( model, current_engine, current_port,
                                        model->apply_order[i].index );
                break;
            case FMCCCNode:
                ret = fmc_clean_ccnode( model, current_engine, model->apply_order[i].index );
                break;
            case FMCHTNode:
                ret = fmc_clean_htnode( model, current_engine, model->apply_order[i].index );
                break;
            case FMCCCTree:
                ret = fmc_clean_cctree( model, current_engine, model->apply_order[i].index );
                break;
            case FMCPolicer:
                ret = fmc_clean_policer( model, current_engine, model->apply_order[i].index );
                break;
            case FMCManipulation:
                ret = fmc_clean_manip( model, current_engine, model->apply_order[i].index );
                break;
#if DPAA_VERSION >= 11
            case FMCReplicator:
                ret = fmc_clean_replicator( model, current_engine, model->apply_order[i].index );
                break;
#endif /* DPAA_VERSION >= 11 */
            default:
                break;
        }

        /* Exit the loop in case of failure */
        if ( ret != 0 ) {
            break;
        }
    }

    return ret;
}


/* -------------------------------------------------------------------------- */
t_Handle
fmc_get_handle( fmc_model*  model,
                const char* name
)
{
    unsigned int i;

    for ( i = 0; i < model->fman_count; ++i ) {
        unsigned int j;

        /* Check engine's name */
        if ( strcmp( model->fman[i].name, name ) == 0 ) {
            return model->fman[i].handle;
        }

        /* Check policy's name */
        if ( strcmp( model->fman[i].pcd_name, name ) == 0 ) {
            return model->fman[i].pcd_handle;
        }

#ifndef P1023
        /* Check fragmentation names */
        for ( j = 0; j < model->fman[i].frag_count; j++ ) {
            if ( strcmp( model->fman[i].frag_name[j], name ) == 0 ) {
                return model->fman[i].frag_handle[j];
            }
        }

        /* Check reassembly names */
        for ( j = 0; j < model->fman[i].reasm_count; j++ ) {
            if ( strcmp( model->fman[i].reasm_name[j], name ) == 0 ) {
                return model->fman[i].reasm_handle[j];
            }
        }

        /* Check header manip names */
        for ( j = 0; j < model->fman[i].hdr_count; j++ ) {
            if ( strcmp( model->fman[i].hdr_name[j], name ) == 0 ) {
                return model->fman[i].hdr_handle[j];
            }
        }
#endif /* P1023 */
    }

    /* Check port's and cctree's name */
    for ( i = 0; i < model->port_count; i++ ) {
        if ( strcmp( model->port[i].name, name ) == 0 ) {
            return model->port[i].handle;
        }
        if ( strcmp( model->port[i].cctree_name, name ) == 0 ) {
            return model->port[i].cctree_handle;
        }
    }

    /* Find scheme name */
    for ( i = 0; i < model->scheme_count; i++ ) {
        if ( strcmp( model->scheme_name[i], name ) == 0 ) {
            return model->scheme_handle[i];
        }
    }

    /* Find CC handle according to found engine and port */
    for ( i = 0; i < model->ccnode_count; i++ ) {
        if ( strcmp( model->ccnode_name[i], name ) == 0 ) {
            return model->ccnode_handle[i];
        }
    }

    /* Find HT handle according to found engine and port */
    for ( i =0; i < model->htnode_count; i++ ) {
        if ( strcmp( model->htnode_name[i], name ) == 0 ) {
            return model->htnode_handle[i];
        }
    }

#if (DPAA_VERSION >= 11)
    /* Find replicator handle according to found engine and port */
    for ( i =0; i < model->replicator_count; i++ ) {
        if ( strcmp( model->replicator_name[i], name ) == 0 ) {
            return model->replicator_handle[i];
        }
    }
#endif /* (DPAA_VERSION >= 11) */

    /* Find policer name */
    for ( i = 0; i < model->policer_count; i++ ) {
        if ( strcmp( model->policer_name[i], name ) == 0 ) {
            return model->policer_handle[i];
        }
    }

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_exec_engine_start( fmc_model* model, unsigned int index,
                       unsigned int* p_relative_scheme_index )
{
#ifndef P1023
    unsigned int i;
	bool bIsIPR_IPv4 = false;
	bool bIsIPR_IPv6 = false;
#endif
    t_Error err;
    t_FmPcdParams fmPcdParams = {0};

    fmc_log_write( LOG_DBG1, "fmc_exec_engine_start - execution started" );
    
    /* Open FMan device */
    LOG_FMD_CALL( FM_Open, model->fman[index].name );
#ifndef NETCOMM_SW
    model->fman[index].handle = FM_Open( model->fman[index].number );
#else
    model->fman[index].handle = SYS_GetHandle( e_SYS_SUBMODULE_FM,
                                               model->fman[index].number );
#endif
    CHECK_HANDLE( FM_Open, model->fman[index].name, model->fman[index].handle );

    /* Open FMan device */
    fmPcdParams.h_Fm = model->fman[index].handle;
    LOG_FMD_CALL( FM_PCD_Open, model->fman[index].pcd_name );
#ifndef NETCOMM_SW
    model->fman[index].pcd_handle = FM_PCD_Open( &fmPcdParams );
#else
    model->fman[index].pcd_handle = SYS_GetHandle( e_SYS_SUBMODULE_FM_PCD,
                                                   model->fman[index].number );
#endif
    CHECK_HANDLE( FM_PCD_Open,
                  model->fman[index].pcd_name, model->fman[index].pcd_handle );

    if ( model->sp_enable ) {
        LOG_FMD_CALL( FM_PCD_PrsLoadSw, model->fman[index].pcd_name );
        err = FM_PCD_PrsLoadSw( model->fman[index].pcd_handle, &(model->sp) );
        CHECK_ERR( FM_PCD_PrsLoadSw, model->fman[index].pcd_name );
    }
#ifndef P1023
    if ( model->fman[index].reasm_count     > 0 ||
         model->fman[index].frag_count      > 0 ||
         model->fman[index].offload_support > 0 ) {
        LOG_FMD_CALL( FM_PCD_SetAdvancedOffloadSupport,
                      model->fman[index].pcd_name );
        err = FM_PCD_SetAdvancedOffloadSupport( model->fman[index].pcd_handle );
        CHECK_ERR( FM_PCD_SetAdvancedOffloadSupport, model->fman[index].pcd_name );
    }
#endif /* P1023 */
	if (model->fman[index].kg_payload_offset > 0) {
        LOG_FMD_CALL( FM_PCD_KgSetAdditionalDataAfterParsing,
                      model->fman[index].pcd_name );
        err = FM_PCD_KgSetAdditionalDataAfterParsing( model->fman[index].pcd_handle, model->fman[index].kg_payload_offset );
        CHECK_ERR( FM_PCD_KgSetAdditionalDataAfterParsing, model->fman[index].pcd_name );
	}

    LOG_FMD_CALL( FM_PCD_Enable, model->fman[index].pcd_name );
    err = FM_PCD_Enable( model->fman[index].pcd_handle );
    CHECK_ERR( FM_PCD_Enable, model->fman[index].pcd_name );

#ifndef P1023
    for ( i = 0; i < model->fman[index].reasm_count; i++ ) {
        if ( model->fman[index].reasm[i].u.reassem.hdr == HEADER_TYPE_IPv6 ) {
			bIsIPR_IPv6 = true;
            model->fman[index].reasm[i].u.reassem.u.ipReassem.relativeSchemeId[0] = 0;
            model->fman[index].reasm[i].u.reassem.u.ipReassem.relativeSchemeId[1] = 1;
        }
        else {
			bIsIPR_IPv4 = true;
            model->fman[index].reasm[i].u.reassem.u.ipReassem.relativeSchemeId[0] = 0;
        }

        LOG_FMD_CALL( FM_PCD_ManipNodeSet, model->fman[index].reasm_name[i] );
        model->fman[index].reasm_handle[i] =
            FM_PCD_ManipNodeSet( model->fman[index].pcd_handle,
                                 &model->fman[index].reasm[i] );
        CHECK_HANDLE( FM_PCD_ManipNodeSet,
                      model->fman[index].reasm_name[i], model->fman[index].reasm_handle[i] );

        model->fman[index].reasm_devId[i] = GetDeviceId(model->fman[index].reasm_handle[i]);
    }

	if (bIsIPR_IPv6)
		//allocate TWO IPR relativeSchemeId: one for IPv4 and one for IPv6
		*p_relative_scheme_index = 2;
	else if (bIsIPR_IPv4)
		//allocate ONE IPR relativeSchemeId: one for IPv4
		*p_relative_scheme_index = 1;

    for ( i = 0; i < model->fman[index].frag_count; i++ ) {
        LOG_FMD_CALL( FM_PCD_ManipNodeSet, model->fman[index].frag_name[i] );
        model->fman[index].frag_handle[i] =
            FM_PCD_ManipNodeSet( model->fman[index].pcd_handle,
                                 &model->fman[index].frag[i] );
        CHECK_HANDLE( FM_PCD_ManipNodeSet,
                      model->fman[index].frag_name[i], model->fman[index].frag_handle[i] );

        model->fman[index].frag_devId[i] = GetDeviceId(model->fman[index].frag_handle[i]);
    }

#endif /* P1023 */

    fmc_log_write( LOG_DBG1, "fmc_exec_engine_start - execution ended" );

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_exec_engine_end( fmc_model* model, unsigned int index )
{
    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_exec_port_start( fmc_model* model, unsigned int engine, unsigned int port )
{
    t_FmPortParams  fmPortParam      = {0};

	int portShare, p, portSch, pSch;

    fmc_fman* pengine = &model->fman[engine];
    fmc_port* pport   = &model->port[port];

    fmPortParam.h_Fm     = pengine->handle;
    fmPortParam.portId   = pport->number;
    fmPortParam.portType = pport->type;

	g_crtDirectSchemeCount = 0;

#ifndef NETCOMM_SW
    LOG_FMD_CALL( FM_PORT_Open, pport->name );
    pport->handle = FM_PORT_Open( &fmPortParam );
#else
    if (fmPortParam.portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
        pport->handle = SYS_GetHandle( e_SYS_SUBMODULE_FM_PORT_HO,
        		(uint32_t)(fmPortParam.portId +
                (pengine->number * FM_MAX_NUM_OF_OH_PORTS)));
    else if (fmPortParam.portType == e_FM_PORT_TYPE_RX)
        pport->handle = SYS_GetHandle( e_SYS_SUBMODULE_FM_PORT_1GRx,
        		(uint32_t)(fmPortParam.portId +
                (pengine->number * FM_MAX_NUM_OF_1G_RX_PORTS)));
    else
    {
        pport->handle = SYS_GetHandle( e_SYS_SUBMODULE_FM_PORT_10GRx,
        		(uint32_t)(fmPortParam.portId +
                (pengine->number * FM_MAX_NUM_OF_10G_RX_PORTS)));
    }
#endif
    CHECK_HANDLE( FM_PORT_Open,
                  pport->name, pport->handle );

#if (DPAA_VERSION >= 11)
    if (pport->vspParam.numOfProfiles > 0) {
        //open coupled port
        if (fmPortParam.portType == e_FM_PORT_TYPE_RX || fmPortParam.portType == e_FM_PORT_TYPE_RX_10G ) {
            if (fmPortParam.portType == e_FM_PORT_TYPE_RX)
                fmPortParam.portType = e_FM_PORT_TYPE_TX;
            else if (fmPortParam.portType == e_FM_PORT_TYPE_RX_10G)
                fmPortParam.portType = e_FM_PORT_TYPE_TX_10G;

            pport->vspParam.h_FmTxPort = FM_PORT_Open( &fmPortParam );
            CHECK_HANDLE( FM_PORT_Open,
                             pport->name, pport->vspParam.h_FmTxPort );
        } else if (fmPortParam.portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING) {
            pport->vspParam.h_FmTxPort = NULL;
        }
    }
#endif /* (DPAA_VERSION >= 11) */

	//find if there are schemes shared with any other previous port
	portShare = -1;
	for (p = 0; p < port; p++) {
		for (portSch = 0; portSch < model->port[port].schemes_count; portSch++) {
			for (pSch = 0; pSch < model->port[p].schemes_count; pSch++) {
				if (model->port[port].schemes[portSch] == model->port[p].schemes[pSch]) {
					portShare = p;
					break;
				}
			}
		}
	}

	if (portShare > -1) {
		pport->env_id_handle = model->port[portShare].env_id_handle;
	} else {
		LOG_FMD_CALL( FM_PCD_NetEnvCharacteristicsSet, model->port[port].name );
		pport->env_id_handle = FM_PCD_NetEnvCharacteristicsSet(
								   pengine->pcd_handle,
								   &pport->distinctionUnits );
		CHECK_HANDLE( FM_PCD_NetEnvCharacteristicsSet,
					  model->port[port].name, pport->env_id_handle );

		pport->env_id_devId = GetDeviceId(pport->env_id_handle);
	}

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_exec_port_end( fmc_model* model, unsigned int engine, unsigned int port )
{
    t_Error err;
    fmc_port* pport = &model->port[port];
    unsigned int i;
    unsigned int index;
    unsigned int action_index;
    unsigned int reasm_index = 0;
    unsigned int port_ht_index = 0;

#ifndef P1023
    reasm_index = model->port[port].reasm_index;
    if ( reasm_index > 0 ) {
        pport->pcdParam.h_IpReassemblyManip =
            model->fman[engine].reasm_handle[reasm_index - 1];
    }
#endif

    pport->pcdParam.h_NetEnv    = pport->env_id_handle;
    pport->pcdParam.p_PrsParams = &pport->prsParam;

    /* Modify all current direct schemes for this port */
    for (i = 0; i < g_crtDirectSchemeCount; i++) {
        index = g_crtDirectScheme[i].index;
		if (model->scheme[index].alwaysDirect == TRUE && model->scheme[index].nextEngine == e_FM_PCD_DONE) {
		    model->scheme[index].nextEngine = g_crtDirectScheme[i].nextEngine;
            if ( model->scheme[index].nextEngine == e_FM_PCD_CC ) {
                model->scheme[index].kgNextEngineParams.cc = g_crtDirectScheme[i].kgNextEngineParams.cc;
                model->scheme[index].kgNextEngineParams.cc.h_CcTree = model->port[port].cctree_handle;
			} else if (model->scheme[index].nextEngine == e_FM_PCD_PLCR) {
				model->scheme[index].kgNextEngineParams.plcrProfile = g_crtDirectScheme[i].kgNextEngineParams.plcrProfile;
			}

		    model->scheme[index].modify = TRUE;
			model->scheme[index].id.h_Scheme = model->scheme_handle[index];

		    LOG_FMD_CALL( FM_PCD_KgSchemeSet, model->scheme_name[index] );
		    model->scheme_handle[index] = FM_PCD_KgSchemeSet( model->fman[engine].pcd_handle,
                            &(model->scheme[index]) );
		    CHECK_HANDLE( FM_PCD_KgSchemeSet, model->scheme_name[index],
                  model->scheme_handle[index] );

		    model->scheme_devId[index] = GetDeviceId(model->scheme_handle[index]);

		}
    }
	g_crtDirectSchemeCount = 0;

    /* Add KeyGen runtime parameters */
    if ( pport->schemes_count != 0 ) {
        pport->kgParam.numOfSchemes = pport->schemes_count;

        pport->pcdParam.p_KgParams = &pport->kgParam;
        for ( i = 0; i < pport->schemes_count; ++i ) {
            pport->pcdParam.p_KgParams->h_Schemes[ i ] =
                model->scheme_handle[ pport->schemes[i] ];
        }
    }

    /* Add CC runtime parameters */
    if ( pport->htnodes_count != 0 ||
#if (DPAA_VERSION >= 11)
            pport->replicators_count != 0 ||
#endif /* (DPAA_VERSION >= 11) */
            pport->ccnodes_count != 0 ||
            pport->ccroot_count  != 0 ||
            reasm_index > 0 ) {
        pport->pcdParam.p_CcParams           = &pport->ccParam;
        pport->pcdParam.p_CcParams->h_CcTree = pport->cctree_handle;
    }

    /* Add HT entries (must be called after schemes) */
    for ( port_ht_index = 0; port_ht_index < pport->htnodes_count; port_ht_index++ )
    {
        index = pport->htnodes[port_ht_index];
        for ( i = 0; i < model->htentry_count[index]; ++i ) {
            action_index = model->htentry_action_index[index][i];
            if ( model->htentry[index][i].ccNextEngineParams.nextEngine == e_FM_PCD_KG ) {
                model->htentry[index][i].ccNextEngineParams.params.kgParams.h_DirectScheme =
                                                 model->scheme_handle[action_index];
            }
            else if ( model->htentry[index][i].ccNextEngineParams.nextEngine == e_FM_PCD_CC) {
                if ( model->htentry_action_type[index][i] == e_FM_PCD_CC ) {
                    model->htentry[index][i].ccNextEngineParams.params.ccParams.h_CcNode =
                                                     model->ccnode_handle[action_index];
                }
                else if (model->htentry_action_type[index][i] == e_FM_PCD_HASH) {
                     model->htentry[index][i].ccNextEngineParams.params.ccParams.h_CcNode =
                                                     model->htnode_handle[action_index];
                }
            }
    #if (DPAA_VERSION >= 11)
            else if ( model->htentry[index][i].ccNextEngineParams.nextEngine == e_FM_PCD_FR) {
                model->htentry[index][i].ccNextEngineParams.params.frParams.h_FrmReplic =
                                                 model->replicator_handle[action_index];
            }
    #endif /* (DPAA_VERSION >= 11) */

    #ifndef P1023
            if ( model->htentry_frag[index][i] != 0 ) {
                model->htentry[index][i].ccNextEngineParams.h_Manip =
                    model->fman[engine].frag_handle[ model->htentry_frag[index][i] - 1 ];
            }

            if ( model->htentry_manip[index][i] != 0 ) {
                model->htentry[index][i].ccNextEngineParams.h_Manip =
                    model->fman[engine].hdr_handle[ model->htentry_manip[index][i] - 1 ];
            }
    #endif /* P1023 */

            model->htentry[index][i].p_Key =
                model->htkeydata[index][i];
            model->htentry[index][i].p_Mask = NULL;

            LOG_FMD_CALL( FM_PCD_HashTableAddKey, model->htnode_name[index] );
            err = FM_PCD_HashTableAddKey( model->htnode_handle[index], 
                                model->htnode[index].matchKeySize,
                                &(model->htentry[index][i]) );
            /*CHECK_HANDLE( FM_PCD_HashTableAddKey, model->htnode_name[index], !res ); */
        }
    }
    /* End of adding HT entries */

    LOG_FMD_CALL( FM_PORT_Disable, pport->name );
    err = FM_PORT_Disable( pport->handle );
    CHECK_ERR( FM_PORT_Disable, model->port[port].name );

#if (DPAA_VERSION >= 11)
    if (pport->vspParam.numOfProfiles > 0) {
        if (pport->type != e_FM_PORT_TYPE_OH_OFFLINE_PARSING) {
            LOG_FMD_CALL( FM_PORT_Disable, pport->name );
            err = FM_PORT_Disable( pport->vspParam.h_FmTxPort );
            CHECK_ERR( FM_PORT_Disable, model->port[port].name );
        }
    LOG_FMD_CALL( FM_PORT_VSPAlloc, pport->name );
    err = FM_PORT_VSPAlloc( pport->handle, &pport->vspParam );
    CHECK_ERR( FM_PORT_VSPAlloc, model->port[port].name );
    }
#endif /* (DPAA_VERSION >= 11) */

    LOG_FMD_CALL( FM_PORT_SetPCD, pport->name );
    err = FM_PORT_SetPCD( pport->handle, &pport->pcdParam );
    CHECK_ERR( FM_PORT_SetPCD, model->port[port].name );
    LOG_FMD_CALL( FM_PORT_Enable, pport->name );
    err = FM_PORT_Enable( pport->handle );
    CHECK_ERR( FM_PORT_Enable, model->port[port].name );

#if (DPAA_VERSION >= 11)
    if (pport->vspParam.numOfProfiles > 0) {
        if (pport->type != e_FM_PORT_TYPE_OH_OFFLINE_PARSING) {
            LOG_FMD_CALL( FM_PORT_Enable, pport->name );
            err = FM_PORT_Enable( pport->vspParam.h_FmTxPort );
            CHECK_ERR( FM_PORT_Enable, model->port[port].name );
        }
    }
#endif /* (DPAA_VERSION >= 11) */

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_exec_scheme( fmc_model* model,  unsigned int engine,
                 unsigned int port, unsigned int index,
                 unsigned int relative_scheme_index )
{
    model->scheme[index].netEnvParams.h_NetEnv = model->port[port].env_id_handle;
    model->scheme[index].id.relativeSchemeId   = relative_scheme_index;

	/* Save direct schemes*/
	if (model->scheme[index].alwaysDirect == TRUE) {
		g_crtDirectScheme[g_crtDirectSchemeCount].index = index;
		g_crtDirectScheme[g_crtDirectSchemeCount].nextEngine = model->scheme[index].nextEngine;
		if (model->scheme[index].nextEngine == e_FM_PCD_CC)
			g_crtDirectScheme[g_crtDirectSchemeCount].kgNextEngineParams.cc = model->scheme[index].kgNextEngineParams.cc;
		else if (model->scheme[index].nextEngine == e_FM_PCD_PLCR)
			g_crtDirectScheme[g_crtDirectSchemeCount].kgNextEngineParams.plcrProfile = model->scheme[index].kgNextEngineParams.plcrProfile;
		
		g_crtDirectSchemeCount++;
		model->scheme[index].nextEngine = e_FM_PCD_DONE;
		model->scheme[index].kgNextEngineParams.doneAction = e_FM_PCD_ENQ_FRAME;
	}

	/* Fill next engine handles */
    if ( model->scheme[index].nextEngine == e_FM_PCD_CC ) {
        model->scheme[index].kgNextEngineParams.cc.h_CcTree =
                                                model->port[port].cctree_handle;
    }

    LOG_FMD_CALL( FM_PCD_KgSchemeSet, model->scheme_name[index] );
    model->scheme_handle[index] =
        FM_PCD_KgSchemeSet( model->fman[engine].pcd_handle,
                            &(model->scheme[index]) );
    CHECK_HANDLE( FM_PCD_KgSchemeSet, model->scheme_name[index],
                  model->scheme_handle[index] );

    model->scheme_devId[index] = GetDeviceId(model->scheme_handle[index]);

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_exec_ccnode( fmc_model* model, unsigned int engine,
                 unsigned int index )
{
    unsigned int i;
    unsigned int action_index;

    for ( i = 0; i < model->ccnode[index].keysParams.numOfKeys; ++i ) {
        action_index = model->ccentry_action_index[index][i];
        if ( model->ccnode[index].keysParams.keyParams[i]
                               .ccNextEngineParams.nextEngine == e_FM_PCD_KG ) {
            model->ccnode[index].keysParams.keyParams[i]
                .ccNextEngineParams.params.kgParams.h_DirectScheme =
                                             model->scheme_handle[action_index];
        }
        else if ( model->ccnode[index].keysParams.keyParams[i].ccNextEngineParams.nextEngine == e_FM_PCD_CC) {
            if ( model->ccentry_action_type[index][i] == e_FM_PCD_CC ) {
                model->ccnode[index].keysParams.keyParams[i]
                    .ccNextEngineParams.params.ccParams.h_CcNode =
                                                 model->ccnode_handle[action_index];
            }
            else if (model->ccentry_action_type[index][i] == e_FM_PCD_HASH) {
                 model->ccnode[index].keysParams.keyParams[i]
                    .ccNextEngineParams.params.ccParams.h_CcNode =
                                                 model->htnode_handle[action_index];
            }
        }
#if (DPAA_VERSION >= 11)
        else if ( model->ccnode[index].keysParams.keyParams[i]
                .ccNextEngineParams.nextEngine == e_FM_PCD_FR) {
            model->ccnode[index].keysParams.keyParams[i]
                .ccNextEngineParams.params.frParams.h_FrmReplic =
                                             model->replicator_handle[action_index];
        }
#endif /* (DPAA_VERSION >= 11) */

#ifndef P1023
        if ( model->ccentry_frag[index][i] != 0 ) {
            model->ccnode[index].keysParams.keyParams[i].ccNextEngineParams.h_Manip =
                model->fman[engine].frag_handle[ model->ccentry_frag[index][i] - 1 ];
        }

        if ( model->ccentry_manip[index][i] != 0 ) {
            model->ccnode[index].keysParams.keyParams[i].ccNextEngineParams.h_Manip =
                model->fman[engine].hdr_handle[ model->ccentry_manip[index][i] - 1 ];
        }
#endif /* P1023 */

        if (model->ccnode[index].extractCcParams.extractNonHdr.action == e_FM_PCD_ACTION_INDEXED_LOOKUP) {
            model->ccnode[index].keysParams.keyParams[i].p_Key = NULL;
            model->ccnode[index].keysParams.keyParams[i].p_Mask = NULL;
        } else {
            model->ccnode[index].keysParams.keyParams[i].p_Key =
                model->cckeydata[index][i];
			if (model->ccnode[index].keysParams.maskSupport)
				model->ccnode[index].keysParams.keyParams[i].p_Mask = model->ccmask[index][i];
			else
				model->ccnode[index].keysParams.keyParams[i].p_Mask = NULL;
        }
    }

    action_index = model->ccmiss_action_index[index];
    if ( model->ccnode[index].keysParams.ccNextEngineParamsForMiss
                           .nextEngine == e_FM_PCD_KG ) {
        model->ccnode[index].keysParams.ccNextEngineParamsForMiss
            .params.kgParams.h_DirectScheme =
                                         model->scheme_handle[action_index];
    }
    else if ( model->ccnode[index].keysParams.ccNextEngineParamsForMiss
                           .nextEngine == e_FM_PCD_CC ) {
        model->ccnode[index].keysParams.ccNextEngineParamsForMiss
            .params.ccParams.h_CcNode = model->ccnode_handle[action_index];
        if ( model->ccmiss_action_type[index] == e_FM_PCD_CC ) {
            model->ccnode[index].keysParams.ccNextEngineParamsForMiss
                .params.ccParams.h_CcNode = model->ccnode_handle[action_index];
        } else if (model->ccmiss_action_type[index] == e_FM_PCD_HASH) {
             model->ccnode[index].keysParams.ccNextEngineParamsForMiss
                .params.ccParams.h_CcNode = model->htnode_handle[action_index];
        }
    }


    LOG_FMD_CALL( FM_PCD_MatchTableSet, model->ccnode_name[index] );
    model->ccnode_handle[index] =
        FM_PCD_MatchTableSet( model->fman[engine].pcd_handle,
                            &(model->ccnode[index]) );
    CHECK_HANDLE( FM_PCD_MatchTableSet, model->ccnode_name[index],
                  model->ccnode_handle[index] );

    model->ccnode_devId[index] = GetDeviceId(model->ccnode_handle[index]);

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_exec_htnode( fmc_model* model, unsigned int engine,
                 unsigned int index )
{
    unsigned int action_index;

    action_index = model->htmiss_action_index[index];
    if ( model->htnode[index].ccNextEngineParamsForMiss
                           .nextEngine == e_FM_PCD_KG ) {
        model->htnode[index].ccNextEngineParamsForMiss
            .params.kgParams.h_DirectScheme =
                                         model->scheme_handle[action_index];
    }
    else if ( model->htnode[index].ccNextEngineParamsForMiss
                           .nextEngine == e_FM_PCD_CC ) {
        if ( model->htmiss_action_type[index] == e_FM_PCD_CC ) {
            model->htnode[index].ccNextEngineParamsForMiss
                .params.ccParams.h_CcNode = model->ccnode_handle[action_index];
        } else if (model->htmiss_action_type[index] == e_FM_PCD_HASH) {
             model->htnode[index].ccNextEngineParamsForMiss
                .params.ccParams.h_CcNode = model->htnode_handle[action_index];
        }
    }
#if DPAA_VERSION >= 11
    else if ( model->htnode[index].ccNextEngineParamsForMiss
                           .nextEngine == e_FM_PCD_FR ) {
        model->htnode[index].ccNextEngineParamsForMiss
            .params.frParams.h_FrmReplic = model->replicator_handle[action_index];
    }
#endif /* DPAA_VERSION >= 11 */


    LOG_FMD_CALL( FM_PCD_HashTableSet, model->htnode_name[index] );
    model->htnode_handle[index] =
        FM_PCD_HashTableSet( model->fman[engine].pcd_handle,
                          &(model->htnode[index]) );
    CHECK_HANDLE( FM_PCD_HashTableSet, model->htnode_name[index],
                  model->htnode_handle[index] );

    model->htnode_devId[index] = GetDeviceId(model->htnode_handle[index]);

    return 0;
}


#if (DPAA_VERSION >= 11)
/* -------------------------------------------------------------------------- */
static int
fmc_exec_replicator( fmc_model* model, unsigned int engine,
                 unsigned int index )
{
    unsigned int i;
    unsigned int action_index;

    for ( i = 0; i < model->replicator[index].numOfEntries; ++i ) {
        action_index = model->repentry_action_index[index][i];
        if ( model->replicator[index].nextEngineParams[i].nextEngine == e_FM_PCD_KG ) {
            model->replicator[index].nextEngineParams[i].params.kgParams.h_DirectScheme =
                                             model->scheme_handle[action_index];
        }
        else if ( model->replicator[index].nextEngineParams[i].nextEngine == e_FM_PCD_CC) {
            model->replicator[index].nextEngineParams[i].params.ccParams.h_CcNode =
                                             model->ccnode_handle[action_index];
        }
        else if ( model->replicator[index].nextEngineParams[i].nextEngine == e_FM_PCD_FR) {
            model->replicator[index].nextEngineParams[i].params.frParams.h_FrmReplic =
                                             model->replicator_handle[action_index];
        }

#ifndef P1023
        if ( model->repentry_frag[index][i] != 0 ) {
            model->replicator[index].nextEngineParams[i].h_Manip =
                model->fman[engine].frag_handle[ model->repentry_frag[index][i] - 1 ];
        }

        if ( model->repentry_manip[index][i] != 0 ) {
            model->replicator[index].nextEngineParams[i].h_Manip =
                model->fman[engine].hdr_handle[ model->repentry_manip[index][i] - 1 ];
        }
#endif /* P1023 */
    }

    LOG_FMD_CALL( FM_PCD_FrmReplicSetGroup, model->replicator_name[index] );
    model->replicator_handle[index] =
        FM_PCD_FrmReplicSetGroup( model->fman[engine].pcd_handle,
                          &(model->replicator[index]) );
    CHECK_HANDLE( FM_PCD_FrmReplicSetGroup, model->replicator_name[index],
                  model->replicator_handle[index] );

    model->replicator_devId[index] = GetDeviceId(model->replicator_handle[index]);

    if ( model->replicator_handle[index] == 0 ) {
        return 6;
    }
    return 0;
}
#endif /* (DPAA_VERSION >= 11) */


/* -------------------------------------------------------------------------- */
static int
fmc_exec_cctree( fmc_model* model, unsigned int engine,
                 unsigned int port )
{
    t_FmPcdCcTreeParams ccTreeParams = { 0 };
    unsigned int        i;

    ccTreeParams.numOfGrps = model->port[port].ccroot_count;
    ccTreeParams.h_NetEnv  = model->port[port].env_id_handle;

    for ( i = 0; i < model->port[port].ccroot_count; ++i ) {
        ccTreeParams.ccGrpParams[i].numOfDistinctionUnits = 0;
        if (model->port[port].ccroot_type[i] == e_FM_PCD_CC)
        {
            ccTreeParams.ccGrpParams[i].nextEnginePerEntriesInGrp[0].
                nextEngine = e_FM_PCD_CC;
            ccTreeParams.ccGrpParams[i].nextEnginePerEntriesInGrp[0].
                params.ccParams.h_CcNode =
                model->ccnode_handle[model->port[port].ccroot[i]];
        }
        else if (model->port[port].ccroot_type[i] == e_FM_PCD_HASH)
        {
            ccTreeParams.ccGrpParams[i].nextEnginePerEntriesInGrp[0].
                nextEngine = e_FM_PCD_CC;
            ccTreeParams.ccGrpParams[i].nextEnginePerEntriesInGrp[0].
                params.ccParams.h_CcNode =
                model->htnode_handle[model->port[port].ccroot[i]];
        }
#if DPAA_VERSION >= 11
        else if (model->port[port].ccroot_type[i] == e_FM_PCD_FR)
        {
            ccTreeParams.ccGrpParams[i].nextEnginePerEntriesInGrp[0].
                nextEngine = e_FM_PCD_FR;
            ccTreeParams.ccGrpParams[i].nextEnginePerEntriesInGrp[0].
                params.frParams.h_FrmReplic =
                model->replicator_handle[model->port[port].ccroot[i]];
        }
#endif /* DPAA_VERSION >= 11 */
#ifndef P1023
        if ( model->port[port].ccroot_manip[i] > 0 )
        {
            ccTreeParams.ccGrpParams[i].nextEnginePerEntriesInGrp[0].h_Manip =
                model->fman[engine].hdr_handle[model->port[port].ccroot_manip[i] - 1];
        }
#endif /* P1023 */
    }

    LOG_FMD_CALL( FM_PCD_CcRootBuild, model->port[port].name );
    model->port[port].cctree_handle =
        FM_PCD_CcRootBuild( model->fman[engine].pcd_handle,
                            &ccTreeParams );
    CHECK_HANDLE( FM_PCD_CcRootBuild, model->port[port].name,
                  model->port[port].cctree_handle );

    model->port[port].cctree_devId = GetDeviceId(model->port[port].cctree_handle);

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_exec_policer( fmc_model* model, unsigned int engine,
                  unsigned int index )
{
    unsigned int action_index;

    /* Fill next engine handles */
    action_index = model->policer_action_index[index][0];
    switch ( model->policer[index].nextEngineOnGreen ) {
        case e_FM_PCD_PLCR:
            model->policer[index].paramsOnGreen.h_Profile =
                model->policer_handle[action_index];
            break;
        case e_FM_PCD_KG:
            model->policer[index].paramsOnGreen.h_DirectScheme =
                model->scheme_handle[action_index];
            break;
        default:
            break;
    }
    action_index = model->policer_action_index[index][1];
    switch ( model->policer[index].nextEngineOnYellow ) {
        case e_FM_PCD_PLCR:
            model->policer[index].paramsOnYellow.h_Profile =
                model->policer_handle[action_index];
            break;
        case e_FM_PCD_KG:
            model->policer[index].paramsOnYellow.h_DirectScheme =
                model->scheme_handle[action_index];
            break;
        default:
            break;
    }
    action_index = model->policer_action_index[index][2];
    switch ( model->policer[index].nextEngineOnRed ) {
        case e_FM_PCD_PLCR:
            model->policer[index].paramsOnRed.h_Profile =
                model->policer_handle[action_index];
            break;
        case e_FM_PCD_KG:
            model->policer[index].paramsOnRed.h_DirectScheme =
                model->scheme_handle[action_index];
            break;
        default:
            break;
    }

    LOG_FMD_CALL( FM_PCD_PlcrProfileSet, model->policer_name[index] );
    model->policer_handle[index] =
        FM_PCD_PlcrProfileSet( model->fman[engine].pcd_handle,
                               &(model->policer[index]) );
    CHECK_HANDLE( FM_PCD_PlcrProfileSet, model->policer_name[index],
                  model->policer_handle[index] );

    model->policer_devId[index] = GetDeviceId(model->policer_handle[index]);

    return 0;
}



/* -------------------------------------------------------------------------- */
static int
fmc_exec_manip( fmc_model* model, unsigned int engine,
                  unsigned int index )
{
#ifndef P1023
    if ( model->fman[engine].hdr[index].u.hdr.insrt )
    {
        if (model->fman[engine].hdr[index].u.hdr.insrtParams.type == e_FM_PCD_MANIP_INSRT_GENERIC)
            model->fman[engine].hdr[index].u.hdr.insrtParams.u.generic.p_Data = model->fman[engine].insertData[index];
        if (model->fman[engine].hdr[index].u.hdr.insrtParams.type == e_FM_PCD_MANIP_INSRT_BY_HDR)
            model->fman[engine].hdr[index].u.hdr.insrtParams.u.byHdr.u.specificL2Params.p_Data = model->fman[engine].insertData[index];
    }

    if (model->fman[engine].hdr_hasNext[index])
    {
        model->fman[engine].hdr[index].h_NextManip = model->fman[engine].hdr_handle[model->fman[engine].hdr_next[index]];
    }

    LOG_FMD_CALL( FM_PCD_ManipNodeSet, model->fman[engine].hdr_name[index] );
    model->fman[engine].hdr_handle[index] =
        FM_PCD_ManipNodeSet( model->fman[engine].pcd_handle,
                             &model->fman[engine].hdr[index] );
    CHECK_HANDLE( FM_PCD_ManipNodeSet, model->fman[engine].hdr_name[index],
                  model->fman[engine].hdr_handle[index] );

    model->fman[engine].hdr_devId[index] = GetDeviceId(model->fman[engine].hdr_handle[index]);
#endif /* P1023 */
    
    return 0;
}

/* -------------------------------------------------------------------------- */
static int
fmc_clean_engine_start( fmc_model* model, unsigned int index )
{
    unsigned int i;
    t_Error      err;

#ifndef P1023
    for ( i = 0; i < model->fman[index].frag_count; i++ ) {
        if ( model->fman[index].frag_handle[model->fman[index].frag_count - i - 1] != 0 ) {
            LOG_FMD_CALL( FM_PCD_ManipNodeDelete, model->fman[index].frag_name[model->fman[index].frag_count - i - 1] );
            err = FM_PCD_ManipNodeDelete( model->fman[index].frag_handle[model->fman[index].frag_count - i - 1] );
            CHECK_ERR( FM_PCD_ManipNodeDelete, model->fman[index].frag_name[model->fman[index].frag_count - i - 1] );
        }
    }

    for ( i = 0; i < model->fman[index].reasm_count; i++ ) {
        if ( model->fman[index].reasm_handle[model->fman[index].reasm_count - i - 1] ) {
            LOG_FMD_CALL( FM_PCD_ManipNodeDelete, model->fman[index].reasm_name[model->fman[index].reasm_count - i - 1] );
            err = FM_PCD_ManipNodeDelete( model->fman[index].reasm_handle[model->fman[index].reasm_count - i - 1] );
            CHECK_ERR( FM_PCD_ManipNodeDelete, model->fman[index].reasm_name[model->fman[index].reasm_count - i - 1] );
        }
    }

#endif /* P1023 */

    /* fmc_clean_engine_start is called last:
    * Restore HC usage to be allowed */
    LOG_FMD_CALL( FM_PCD_AllowHcUsage, model->fman[index].pcd_name );
    err = FM_PCD_AllowHcUsage( model->fman[index].pcd_handle, TRUE );
    CHECK_ERR( FM_PCD_AllowHcUsage, model->fman[index].pcd_name );

    if ( model->fman[index].pcd_handle != 0 ) {
#ifndef NETCOMM_SW
        FM_PCD_Close( model->fman[index].pcd_handle );
#endif
    }
    if ( model->fman[index].handle != 0 ) {
#ifndef NETCOMM_SW
        FM_Close( model->fman[index].handle );
#endif
    }

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_clean_engine_end( fmc_model* model, unsigned int index )
{
    t_Error err;

    /* fmc_clean_engine_end is called first:
     * Temporary Deny HC usage
     * to avoid crash of certain HC operations performed under heavy traffic */
    LOG_FMD_CALL( FM_PCD_AllowHcUsage, model->fman[index].pcd_name );
    err = FM_PCD_AllowHcUsage( model->fman[index].pcd_handle, FALSE );
    CHECK_ERR( FM_PCD_AllowHcUsage, model->fman[index].pcd_name );

    LOG_FMD_CALL( FM_PCD_Disable, model->fman[index].pcd_name );
    err = FM_PCD_Disable( model->fman[index].pcd_handle );
    CHECK_ERR( FM_PCD_Disable, model->fman[index].pcd_name );

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_clean_port_start( fmc_model* model, unsigned int engine, unsigned int port )
{
    fmc_port* pport = &model->port[port];
    t_Error   err;

    if ( pport->handle == 0 ) {
        return 0;
    }

    LOG_FMD_CALL( FM_PCD_NetEnvCharacteristicsDelete, pport->name );
    err = FM_PCD_NetEnvCharacteristicsDelete( pport->env_id_handle );
    CHECK_ERR( FM_PCD_NetEnvCharacteristicsDelete, pport->name );

#ifndef NETCOMM_SW
    FM_PORT_Close( pport->handle );
#endif

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_clean_port_end( fmc_model* model, unsigned int engine, unsigned int port )
{
    t_Error err;
    fmc_port* pport = &model->port[port];

    if ( pport->handle == 0 ) {
        return 0;
    }

    LOG_FMD_CALL( FM_PORT_Disable, pport->name );
    err = FM_PORT_Disable( pport->handle );
    CHECK_ERR( FM_PORT_Disable, pport->name );

    LOG_FMD_CALL( FM_PORT_DeletePCD, pport->name );
    err = FM_PORT_DeletePCD( pport->handle );
    CHECK_ERR( FM_PORT_DeletePCD, pport->name );
    if ( err ) { return 6; }

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_clean_scheme( fmc_model* model,  unsigned int engine,
                 unsigned int port, unsigned int index )
{
    t_Error err;
    if ( model->scheme_handle[index] != 0 ) {
        LOG_FMD_CALL( FM_PCD_KgSchemeDelete, model->scheme_name[index] );
        err = FM_PCD_KgSchemeDelete( model->scheme_handle[index] );
        CHECK_ERR( FM_PCD_KgSchemeDelete, model->scheme_name[index] );
    }

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_clean_ccnode( fmc_model* model, unsigned int engine,
                 unsigned int index )
{
    t_Error err;
    if ( model->ccnode_handle[index] != 0 ) {
        LOG_FMD_CALL( FM_PCD_MatchTableDelete, model->ccnode_name[index] );
        err = FM_PCD_MatchTableDelete( model->ccnode_handle[index] );
        CHECK_ERR( FM_PCD_MatchTableDelete, model->ccnode_name[index] );
    }

    return 0;
}

/* -------------------------------------------------------------------------- */
static int
fmc_clean_htnode( fmc_model* model, unsigned int engine,
                 unsigned int index )
{
    t_Error err;
    if ( model->htnode_handle[index] != 0 ) {
        LOG_FMD_CALL( FM_PCD_HashTableDelete, model->htnode_name[index] );
        err = FM_PCD_HashTableDelete( model->htnode_handle[index] );
        CHECK_ERR( FM_PCD_HashTableDelete, model->htnode_name[index] );
    }

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_clean_cctree( fmc_model* model, unsigned int engine,
                 unsigned int port )
{
    t_Error err;
    if ( model->port[port].cctree_handle != 0 ) {
        LOG_FMD_CALL( FM_PCD_CcRootDelete, model->port[port].name );
        err = FM_PCD_CcRootDelete( model->port[port].cctree_handle );
        CHECK_ERR( FM_PCD_CcRootDelete, model->port[port].name );
    }

    return 0;
}


/* -------------------------------------------------------------------------- */
static int
fmc_clean_policer( fmc_model* model, unsigned int engine,
                  unsigned int index )
{
    t_Error err;
    if ( model->policer_handle[index] != 0 ) {
        LOG_FMD_CALL( FM_PCD_PlcrProfileDelete, model->policer_name[index] );
        err = FM_PCD_PlcrProfileDelete( model->policer_handle[index] );
        CHECK_ERR( FM_PCD_PlcrProfileDelete, model->policer_name[index] );
    }

    return 0;
}

/* -------------------------------------------------------------------------- */
static int
fmc_clean_manip( fmc_model* model, unsigned int engine,
                  unsigned int index )
{
#ifndef P1023
    t_Error err;
    if ( model->fman[engine].hdr_handle[index] != 0 ) {
        LOG_FMD_CALL( FM_PCD_ManipNodeDelete, model->fman[engine].hdr_name[index] );
        err = FM_PCD_ManipNodeDelete( model->fman[engine].hdr_handle[index] );
        CHECK_ERR( FM_PCD_ManipNodeDelete, model->fman[engine].hdr_name[index] );
    }
#endif /* P1023 */

    return 0;
}

#if (DPAA_VERSION >= 11)
/* -------------------------------------------------------------------------- */
static int
fmc_clean_replicator( fmc_model* model, unsigned int engine,
                  unsigned int index )
{
    t_Error err;
    if ( model->replicator_handle[index] != 0 ) {
        LOG_FMD_CALL( FM_PCD_FrmReplicDeleteGroup, model->replicator_name[index] );
        err = FM_PCD_FrmReplicDeleteGroup( model->replicator_handle[index] );
        CHECK_ERR( FM_PCD_FrmReplicDeleteGroup, model->replicator_name[index] );
    }

    return 0;
}
#endif /* (DPAA_VERSION >= 11) */
