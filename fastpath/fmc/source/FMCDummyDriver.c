/* =====================================================================
 *
 * The MIT License (MIT)
 * Copyright 2009, 2010, Freescale Semiconductor, Inc.
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
 * File Name : FMCDummyDriver.c
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#include <std_ext.h>
#include <error_ext.h>
#include <part_ext.h>
#include <fm_ext.h>
#include <Peripherals/fm_pcd_ext.h>
#include <Peripherals/fm_port_ext.h>

#include "fmc.h"

/*
   Dummy stub functions' definitions. The file makes it possible
   to compile/link the project without the real driver integration
*/

static unsigned int handle_no = 0;

t_Handle CreateDevice(t_Handle h_UserPriv, t_Handle h_DevId)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::CreateDevice %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}

t_Error ReleaseDevice(t_Handle h_Dev)
{
	fmc_log_write( LOG_DBG2, "Calling IOCTL::ReleaseDevice %d", h_Dev );
	return E_OK;
}

t_Handle GetDeviceId(t_Handle h_Dev)
{
	fmc_log_write( LOG_DBG2, "Calling IOCTL::GetDeviceId %d", h_Dev );
	return h_Dev;
}

t_Handle
FM_Open(uint8_t id)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_Open %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}


void
FM_Close(t_Handle h_Fm)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_Close %d", h_Fm );
}


t_Handle
FM_PCD_Open( t_FmPcdParams *p_FmPcdParams )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_Open %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}


void
FM_PCD_Close(t_Handle h_FmPcd)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_Close %d",  h_FmPcd );
}


t_Handle FM_PORT_Open(t_FmPortParams *p_FmPortParams)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PORT_Open %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}


void FM_PORT_Close(t_Handle h_FmPort)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PORT_Close %d", h_FmPort );
}


t_Error
FM_PORT_SetPCD(t_Handle h_FmPort, t_FmPortPcdParams *p_FmPortPcd)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PORT_SetPCD %d", h_FmPort );
    return E_OK;
}

#if (DPAA_VERSION >= 11)
t_Error
FM_PORT_VSPAlloc(t_Handle h_FmPort, t_FmPortVSPAllocParams *p_Params)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PORT_VSPAlloc %d", h_FmPort );
    return E_OK;
}
#endif /* (DPAA_VERSION >= 11) */

t_Handle
FM_PCD_Config( t_FmPcdParams *p_FmPcdParams )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_Config %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}

t_Error
FM_PCD_Init(t_Handle h_FmPcd)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_Init %d", h_FmPcd );
    return E_OK;
}

t_Handle
FM_PCD_NetEnvCharacteristicsSet( t_Handle h_FmPcd,
                                t_FmPcdNetEnvParams *p_Units )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_SetNetEnvCharacteristics %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}

t_Handle
FM_PCD_KgSchemeSet( t_Handle h_FmPcd,
                    t_FmPcdKgSchemeParams *p_Scheme )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_KgSetScheme %d rel=%d", handle_no + 1, p_Scheme->id.relativeSchemeId );
    return (t_Handle)++handle_no;
}


t_Handle
FM_PCD_PlcrProfileSet( t_Handle  h_FmPcd,
                       t_FmPcdPlcrProfileParams *  p_Profile )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_PlcrSetProfile %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}


t_Handle
FM_PCD_MatchTableSet(t_Handle             h_FmPcd,
                     t_FmPcdCcNodeParams  *p_CcNodeParam)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_CcSetNode %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}

t_Handle
FM_PCD_HashTableSet(t_Handle h_FmPcd, t_FmPcdHashTableParams *p_Param)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_HashTableSet %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}

t_Error
FM_PCD_HashTableAddKey(t_Handle h_HashTbl, uint8_t keySize, t_FmPcdCcKeyParams  *p_KeyParams)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_HashTableAddKey size %d", keySize );
    return E_OK;
}


t_Error
FM_PORT_Enable(t_Handle h_FmPort)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PORT_Enable %d", h_FmPort );
    return E_OK;
}


t_Error
FM_PORT_Disable(t_Handle h_FmPort)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PORT_Disable %d", h_FmPort );
    return E_OK;
}


t_Error
FM_PCD_Enable( t_Handle h_FmPcd )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_Enable %d", h_FmPcd );
    return E_OK;
}

t_Error
FM_PCD_AllowHcUsage( t_Handle h_FmPcd, bool allow )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_AllowHcUsage %d", h_FmPcd );
    return E_OK;
}

t_Error
FM_PCD_Disable( t_Handle h_FmPcd )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_Disable %d", h_FmPcd );
    return E_OK;
}


t_Error
FM_PORT_DeletePCD(t_Handle h_FmPort)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PORT_DeletePCD %d", h_FmPort );
    return E_OK;
}


t_Error
FM_PCD_KgSchemeDelete(t_Handle h_Scheme)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_KgDeleteScheme %d", h_Scheme );
    return E_OK;
}


t_Error
FM_PCD_MatchTableDelete(t_Handle h_CcNode)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_CcDeleteNode %d", h_CcNode );
    return E_OK;
}


t_Error
FM_PCD_PlcrProfileDelete(t_Handle h_Profile)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_PlcrDeleteProfile %d", h_Profile );
    return E_OK;
}


t_Error
FM_PCD_NetEnvCharacteristicsDelete(t_Handle h_NetEnv)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_DeleteNetEnvCharacteristics %d", h_NetEnv );
    return E_OK;
}


t_Handle
FM_PCD_CcRootBuild(t_Handle             h_FmPcd,
                   t_FmPcdCcTreeParams  *p_FmPcdCcTreeParams)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_CcBuildTree %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}


t_Error
FM_PCD_CcRootDelete(t_Handle h_CcTree)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_CcDeleteTree %d", h_CcTree );
    return E_OK;
}


t_Error
FM_PCD_PrsLoadSw(t_Handle h_FmPcd, t_FmPcdPrsSwParams *p_SwPrs)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_PrsLoadSw" );
    return E_OK;
}

t_Error
FM_PCD_KgSetAdditionalDataAfterParsing( t_Handle h_FmPcd, uint8_t payloadOffset )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_KgSetAdditionalDataAfterParsing %d", h_FmPcd );
    return E_OK;
}

#ifndef P1023
t_Error
FM_PCD_SetAdvancedOffloadSupport( t_Handle h_FmPcd )
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_SetAdvancedOffloadSupport %d", h_FmPcd );
    return E_OK;
}

t_Handle
FM_PCD_ManipNodeSet(t_Handle h_FmPcd, t_FmPcdManipParams *p_FmPcdManipParams)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_ManipSetNode %d", handle_no + 1 );
    if ( p_FmPcdManipParams->type == e_FM_PCD_MANIP_REASSEM ) {
        fmc_log_write( LOG_DBG2, "rel= %d %d", p_FmPcdManipParams->u.reassem.u.ipReassem.relativeSchemeId[0],
                                p_FmPcdManipParams->u.reassem.u.ipReassem.relativeSchemeId[1] );
    }
    return (t_Handle)++handle_no;
}

#if (DPAA_VERSION >= 11)
t_Handle
FM_PCD_FrmReplicSetGroup(t_Handle h_FmPcd, t_FmPcdFrmReplicGroupParams *p_FrmReplicGroupParam)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_FrmReplicSetGroup %d", handle_no + 1 );
    return (t_Handle)++handle_no;
}

t_Error
FM_PCD_FrmReplicDeleteGroup(t_Handle h_FrmReplicGroup)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_FrmReplicDeleteGroup %d", h_FrmReplicGroup );
    return E_OK;
}
#endif /* (DPAA_VERSION >= 11) */


t_Error
FM_PCD_ManipNodeDelete(t_Handle h_HdrManipNode)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_ManipDeleteNode %d", h_HdrManipNode );
    return E_OK;
}
#endif /* P1023 */

t_Error
FM_PCD_HashTableDelete(t_Handle h_HashTbl)
{
    fmc_log_write( LOG_DBG2, "Calling IOCTL::FM_PCD_HashTableDelete %d", h_HashTbl );
    return E_OK;
}

#ifdef __cplusplus
}
#endif
