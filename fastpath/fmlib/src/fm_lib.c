/*
 * Copyright 2008-2016 Freescale Semiconductor Inc.
 * Copyright 2017-2018 NXP
 * Copyright 2021 NXP
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
 @File          fm_lib.c

 @Description   Frame Manager Linux User-Space library implementation.
*//***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "fm_ext.h"
#include "fm_pcd_ext.h"
#include "fm_port_ext.h"
#include "fm_mac_ext.h"
#if (DPAA_VERSION >= 11)
#include "fm_vsp_ext.h"
#endif

#include "fm_ioctls.h"
#include "fm_pcd_ioctls.h"
#include "fm_port_ioctls.h"

#define __ERR_MODULE__      MODULE_FM

#define DEV_TO_ID(p) \
    do { \
        t_Device *p_Dev = (t_Device *)p; \
        p = UINT_TO_PTR(p_Dev->id); \
    } while(0)

/* #define FM_LIB_DBG */

#if defined(FM_LIB_DBG)
    #define _fml_dbg(format, arg...) \
        printf("fmlib [%s:%u] - " format, \
            __func__, __LINE__, ##arg)
#else
    #define _fml_dbg(arg...)
#endif

/* Major and minor are in sync with FMD, respin is for fmlib identification */
#define FM_LIB_VERSION_MAJOR    21
#define FM_LIB_VERSION_MINOR     1 
#define FM_LIB_VERSION_RESPIN    0

#if (FMD_API_VERSION_MAJOR != FM_LIB_VERSION_MAJOR) || \
    (FMD_API_VERSION_MINOR != FM_LIB_VERSION_MINOR)
#warning FMD and FMLIB version mismatch
#endif

t_Error FM_GetApiVersion(t_Handle h_Fm, ioc_fm_api_version_t *p_version);


/*******************************************************************************
*  Device functions
*******************************************************************************/

t_Handle CreateDevice(t_Handle h_UserPriv, t_Handle h_DevId)
{
    t_Device *p_UserPrivDev = (t_Device*)h_UserPriv;
    t_Device *p_Dev = NULL;

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("Failed to allocate memory for Device !"));
        return NULL;
    }

    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = h_UserPriv;
    p_UserPrivDev->owners++;
    p_Dev->id = PTR_TO_UINT(h_DevId);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

t_Error ReleaseDevice(t_Handle h_Dev)
{
    t_Device *p_Dev = (t_Device*)h_Dev;
    t_Device *p_UserPrivDev = NULL;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_UserPrivDev =  (t_Device*)p_Dev->h_UserPriv;

    if (p_UserPrivDev->owners > 0)
    	p_UserPrivDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Handle GetDeviceId(t_Handle h_Dev)
{
	t_Device *p_Dev = (t_Device*)h_Dev;

	return UINT_TO_PTR(p_Dev->id);
}


/*******************************************************************************
*  FM FUNCTIONS                                                                *
*******************************************************************************/

t_Handle FM_Open(uint8_t id)
{
    t_Device    *p_Dev;
    int         fd;
    char        devName[20];
    static bool called = FALSE;
    ioc_fm_api_version_t ver;

    _fml_dbg("Calling...\n");

    p_Dev = (t_Device*) malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM device!!"));
        return NULL;
    }

    memset(devName, 0, 20);
    sprintf(devName, "%s%s%d", "/dev/", DEV_FM_NAME, id);
    fd = open(devName, O_RDWR);
    if (fd < 0)
    {
       free(p_Dev);
       REPORT_ERROR(MAJOR, E_NO_DEVICE, ("Could not open FM. Ret code=%d, errno=%d. Aborting!!!",
               fd,
               errno));
       return NULL;
    }

    p_Dev->id = id;
    p_Dev->fd = fd;
    if (!called)
    {
        called = TRUE;

        FM_GetApiVersion((t_Handle)p_Dev, &ver);

        if (FMD_API_VERSION_MAJOR != ver.version.major ||
            FMD_API_VERSION_MINOR != ver.version.minor ||
            FMD_API_VERSION_RESPIN != ver.version.respin)
        {
            printf("Warning:\nCompiled against FMD API version %u.%u.%u\n",
                FMD_API_VERSION_MAJOR, FMD_API_VERSION_MINOR, FMD_API_VERSION_RESPIN);
            printf("Running with FMD API version %u.%u.%u\n",
                ver.version.major, ver.version.minor, ver.version.respin);
            printf("Current fmlib version %u.%u.%u\n",
                FM_LIB_VERSION_MAJOR, FM_LIB_VERSION_MINOR, FM_LIB_VERSION_RESPIN);
        }
    }
    _fml_dbg("Called.\n");

    return (t_Handle)p_Dev;
}

void FM_Close(t_Handle h_Fm)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;

    SANITY_CHECK_RETURN(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    close(p_Dev->fd);
    free(p_Dev);

    _fml_dbg("Called.\n");
}

t_Error FM_SetPortsBandwidth(t_Handle h_Fm, t_FmPortsBandwidthParams *p_PortsBandwidth)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;

    ASSERT_COND(sizeof(t_FmPortsBandwidthParams) == sizeof(ioc_fm_port_bandwidth_params));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_IOC_SET_PORTS_BANDWIDTH, p_PortsBandwidth))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error  FM_GetRevision(t_Handle h_Fm, t_FmRevisionInfo *p_FmRevisionInfo)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;

    ASSERT_COND(sizeof(t_FmRevisionInfo) == sizeof(ioc_fm_revision_info_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_IOC_GET_REVISION, p_FmRevisionInfo))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

uint32_t FM_GetCounter(t_Handle h_Fm, e_FmCounters counter)
{
    t_Device                    *p_Dev = (t_Device*) h_Fm;
    ioc_fm_counters_params_t    params;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, 0);

    _fml_dbg("Calling...\n");

    params.cnt = (ioc_fm_counters) counter;

    if (ioctl(p_Dev->fd, FM_IOC_GET_COUNTER, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return params.val;
}

t_Error  FM_SetCounter(t_Handle h_Fm, e_FmCounters counter, uint32_t val)
{
    t_Device                    *p_Dev = (t_Device*) h_Fm;
    ioc_fm_counters_params_t    params;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, 0);

    _fml_dbg("Calling...\n");

    params.cnt = (ioc_fm_counters) counter;
    params.val = val;

    if (ioctl(p_Dev->fd, FM_IOC_SET_COUNTER, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_ForceIntr(t_Handle h_Fm, e_FmExceptions exception)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_IOC_FORCE_INTR, (ioc_fm_exceptions) exception))
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error  FM_GetApiVersion(t_Handle h_Fm, ioc_fm_api_version_t *p_version)
{
    t_Device                    *p_Dev = (t_Device*) h_Fm;

    _fml_dbg("Calling...\n");

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    if (ioctl(p_Dev->fd, FM_IOC_GET_API_VERSION, p_version))
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

uint32_t FM_ReadTimeStamp(t_Handle h_Fm)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;
    uint32_t    ts = 0;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_IOC_READ_TIMESTAMP, &ts)) {
        REPORT_ERROR(MAJOR, E_INVALID_OPERATION, NO_MSG);
        return 0;
    }

    _fml_dbg("Called.\n");

    return ts;
}

uint32_t FM_GetTimeStampIncrementPerUsec(t_Handle h_Fm)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;
    uint32_t    ts_inc = 0;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_IOC_GET_TIMESTAMP_INCREMENT, &ts_inc)) {
        REPORT_ERROR(MAJOR, E_INVALID_OPERATION, NO_MSG);
        return 0;
    }

    _fml_dbg("Called.\n");

    return ts_inc;
}

/********************************************************************************************/
/*  FM_PCD FUNCTIONS                                                                        */
/********************************************************************************************/

t_Handle FM_PCD_Open(t_FmPcdParams *p_FmPcdParams)
{
    t_Device    *p_Dev;
    int         fd;
    char        devName[20];

    _fml_dbg("Calling...\n");

    if (!p_FmPcdParams->h_Fm)
    {
        REPORT_ERROR(MAJOR, E_NO_DEVICE, ("FM device not available!!"));
        return NULL;
    }

    p_Dev = (t_Device*) malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD device!!"));
        return NULL;
    }

    memset(devName, 0, 20);
    sprintf(devName, "%s%s%u-pcd", "/dev/", DEV_FM_NAME, (uint32_t)((t_Device*) p_FmPcdParams->h_Fm)->id);
    fd = open(devName, O_RDWR);
    if (fd < 0)
    {
       free(p_Dev);
       REPORT_ERROR(MAJOR, E_NO_DEVICE, ("Could not open FM. Ret code=%d, errno=%d. Aborting!!!",
               fd,
               errno));
       return NULL;
    }

    p_Dev->id = ((t_Device*) p_FmPcdParams->h_Fm)->id;
    p_Dev->fd = fd;
    p_Dev->owners = 0;

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

void FM_PCD_Close(t_Handle h_FmPcd)
{
    t_Device    *p_Dev = (t_Device*) h_FmPcd;

    SANITY_CHECK_RETURN(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    close(p_Dev->fd);

    if (p_Dev->owners) {
        XX_Print("Trying to delete a pcd handler that has modules bound to (owners:%u)!!!",
            p_Dev->owners);
        return;
    }

    free(p_Dev);

    _fml_dbg("Called.\n");
}

t_Error FM_PCD_Enable(t_Handle h_FmPcd)
{
    t_Device    *p_Dev = (t_Device*) h_FmPcd;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PCD_IOC_ENABLE))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_Disable(t_Handle h_FmPcd)
{
    t_Device    *p_Dev = (t_Device*) h_FmPcd;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PCD_IOC_DISABLE))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_PrsLoadSw(t_Handle h_FmPcd, t_FmPcdPrsSwParams *p_SwPrs)
{
    t_Device    *p_Dev = (t_Device*) h_FmPcd;

    ASSERT_COND(sizeof(t_FmPcdPrsSwParams) == sizeof(ioc_fm_pcd_prs_sw_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PCD_IOC_PRS_LOAD_SW, p_SwPrs))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_KgSetDfltValue(t_Handle h_FmPcd, uint8_t valueId, uint32_t value)
{
    t_Device    *p_Dev = (t_Device*) h_FmPcd;
    ioc_fm_pcd_kg_dflt_value_params_t params;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    params.value = value;
    params.valueId = valueId;

    if (ioctl(p_Dev->fd, FM_PCD_IOC_KG_SET_DFLT_VALUE, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_KgSetAdditionalDataAfterParsing(t_Handle h_FmPcd, uint8_t payloadOffset)
{
    t_Device    *p_Dev = (t_Device*) h_FmPcd;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PCD_IOC_KG_SET_ADDITIONAL_DATA_AFTER_PARSING, &payloadOffset))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_SetException(t_Handle h_FmPcd, e_FmPcdExceptions exception, bool enable)
{
    t_Device                        *p_Dev = (t_Device*) h_FmPcd;
    ioc_fm_pcd_exception_params_t   params;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    params.exception = (ioc_fm_pcd_exceptions) exception;
    params.enable = enable;

    if (ioctl(p_Dev->fd, FM_PCD_IOC_SET_EXCEPTION, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

uint32_t FM_PCD_GetCounter(t_Handle h_FmPcd, e_FmPcdCounters counter)
{
    t_Device                        *p_Dev = (t_Device*) h_FmPcd;
    ioc_fm_pcd_counters_params_t    params;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    params.cnt = (ioc_fm_pcd_counters) counter;

    if (ioctl(p_Dev->fd, FM_PCD_IOC_GET_COUNTER, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return params.val;
}

#if 0
t_Error FM_PCD_SetCounter(t_Handle h_FmPcd, e_FmPcdCounters counter, uint32_t value)
{
    t_Device                        *p_Dev = (t_Device*) h_FmPcd;
    ioc_fm_pcd_counters_params_t    params;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    params.cnt = (ioc_fm_pcd_counters) counter;
    params.val = value;

    if (ioctl(p_Dev->fd, FM_PCD_IOC_SET_COUNTER, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    return E_OK;
}
#endif

t_Error FM_PCD_ForceIntr (t_Handle h_FmPcd, e_FmPcdExceptions exception)
{
    t_Device    *p_Dev = (t_Device*) h_FmPcd;
    int         intCast = (int) exception;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PCD_IOC_FORCE_INTR, &intCast))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Handle FM_PCD_NetEnvCharacteristicsSet(t_Handle h_FmPcd, t_FmPcdNetEnvParams *p_NetEnvParams)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    t_Device *p_Dev = NULL;
    ioc_fm_pcd_net_env_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_PcdDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_NetEnvParams, sizeof(t_FmPcdNetEnvParams));
    params.id = NULL;

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_NET_ENV_CHARACTERISTICS_SET, &params))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD NetEnv Chrs device!!"));
        return NULL;
    }
    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
    p_PcdDev->owners++;
    p_Dev->id = PTR_TO_UINT(params.id);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;;
}

t_Error FM_PCD_NetEnvCharacteristicsDelete(t_Handle h_NetEnv)
{
    t_Device *p_Dev = (t_Device*) h_NetEnv;
    t_Device *p_PcdDev = NULL;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_NET_ENV_CHARACTERISTICS_DELETE, &id)){
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
    }

    p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_AllowHcUsage(t_Handle h_FmPcd, bool allow)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    uint8_t allow_hc = 0;

    SANITY_CHECK_RETURN_ERROR(p_PcdDev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    allow_hc = allow ? 1 : 0;

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_ALLOW_HC_USAGE, &allow_hc))
    {
    	RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
    }

    _fml_dbg("Called.\n");

    return E_OK;
}

void *FM_PCD_Get_Sch_handle(t_Handle h_Scheme)
{
    t_Device *p_Dev = (t_Device*) h_Scheme;
    return(UINT_TO_PTR(p_Dev->id));
}

t_Handle FM_PCD_KgSchemeSet (t_Handle h_FmPcd, t_FmPcdKgSchemeParams *p_Scheme)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    t_Device *p_Dev = NULL;
    ioc_fm_pcd_kg_scheme_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_PcdDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_Scheme, sizeof(t_FmPcdKgSchemeParams));
    params.id = NULL;

    if (params.modify)
    {
        if (params.scm_id.scheme_id)
            DEV_TO_ID(params.scm_id.scheme_id);
        else
        {
            REPORT_ERROR(MINOR, E_INVALID_HANDLE, NO_MSG);
            return NULL;
        }
    }

    /* correct h_NetEnv param from scheme */
    if (params.net_env_params.net_env_id)
        DEV_TO_ID(params.net_env_params.net_env_id);

    /* correct next engine params handlers: cc*/
    if (params.next_engine == e_IOC_FM_PCD_CC &&
        params.kg_next_engine_params.cc.tree_id)
            DEV_TO_ID(params.kg_next_engine_params.cc.tree_id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_KG_SCHEME_SET, &params))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD KG Scheme device!!"));
        return NULL;
    }

    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
    /* increase owners only if a new scheme is created */
    if (params.modify == FALSE)
	    p_PcdDev->owners++;
    p_Dev->id = PTR_TO_UINT(params.id);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

t_Error FM_PCD_KgSchemeDelete(t_Handle h_Scheme)
{
    t_Device *p_Dev = (t_Device*) h_Scheme;
    t_Device *p_PcdDev = NULL;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev =  (t_Device *)p_Dev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_KG_SCHEME_DELETE, &id)){
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
    }

    if (p_PcdDev->owners > 0)
    	p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

uint32_t FM_PCD_KgSchemeGetCounter(t_Handle h_Scheme)
{
    t_Device *p_Dev = (t_Device*) h_Scheme;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_kg_scheme_spc_t params;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev =  (t_Device *)p_Dev->h_UserPriv;
    params.id = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_KG_SCHEME_GET_CNTR, &params)){
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
    }

    _fml_dbg("Called.\n");

    return params.val;
}

t_Handle FM_PCD_CcRootBuild(t_Handle h_FmPcd, t_FmPcdCcTreeParams *p_PcdTreeParam)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    t_Device *p_Dev = NULL;
    ioc_fm_pcd_cc_tree_params_t params;
    uint32_t i, j;

    SANITY_CHECK_RETURN_VALUE(p_PcdDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_PcdTreeParam, sizeof(t_FmPcdCcTreeParams));
    params.id = NULL;

    /* correct net_env_id */
    if (params.net_env_id)
        DEV_TO_ID(params.net_env_id);

    /* correct next engine kg and cc handlers: cc_node_id, p_direct_scheme */
    for (i = 0; i < IOC_FM_PCD_MAX_NUM_OF_CC_GROUPS; i++)
        for (j = 0; j < IOC_FM_PCD_MAX_NUM_OF_CC_ENTRIES_IN_GRP; j++){
            if (params.fm_pcd_cc_group_params[i].next_engine_per_entries_in_grp[j].next_engine == e_IOC_FM_PCD_CC &&
                params.fm_pcd_cc_group_params[i].next_engine_per_entries_in_grp[j].params.cc_params.cc_node_id)
                    DEV_TO_ID(params.fm_pcd_cc_group_params[i].next_engine_per_entries_in_grp[j].params.cc_params.cc_node_id);

            if (params.fm_pcd_cc_group_params[i].next_engine_per_entries_in_grp[j].next_engine == e_IOC_FM_PCD_KG &&
                params.fm_pcd_cc_group_params[i].next_engine_per_entries_in_grp[j].params.kg_params.p_direct_scheme)
                    DEV_TO_ID(params.fm_pcd_cc_group_params[i].next_engine_per_entries_in_grp[j].params.kg_params.p_direct_scheme);

            /* Convert hdr manip pointer */
            if (params.fm_pcd_cc_group_params[i].next_engine_per_entries_in_grp[j].manip_id) {
            	DEV_TO_ID(params.fm_pcd_cc_group_params[i].next_engine_per_entries_in_grp[j].manip_id);
            }
        }

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_CC_ROOT_BUILD, &params))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD CC Root device!!"));
        return NULL;
    }

    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
    p_PcdDev->owners++;
    p_Dev->id = PTR_TO_UINT(params.id);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

t_Error FM_PCD_CcRootDelete(t_Handle h_CcTree)
{
    t_Device *p_Dev = (t_Device*) h_CcTree;
    t_Device *p_PcdDev = NULL;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_CC_ROOT_DELETE, &id)){
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
    }

    p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Handle FM_PCD_MatchTableSet(t_Handle h_FmPcd, t_FmPcdCcNodeParams *p_CcNodeParam)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    t_Device *p_Dev = NULL;
    ioc_fm_pcd_cc_node_params_t params;
    uint32_t i;

    SANITY_CHECK_RETURN_VALUE(p_PcdDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_CcNodeParam, sizeof(t_FmPcdCcNodeParams));
    params.id = NULL;

    /*correct*/
    for(i = 0; i < params.keys_params.num_of_keys;i++){
        if (params.keys_params.key_params[i].cc_next_engine_params.next_engine == e_IOC_FM_PCD_CC &&
            params.keys_params.key_params[i].cc_next_engine_params.params.cc_params.cc_node_id)
                DEV_TO_ID(params.keys_params.key_params[i].cc_next_engine_params.params.cc_params.cc_node_id);

        if (params.keys_params.key_params[i].cc_next_engine_params.next_engine == e_IOC_FM_PCD_KG &&
            params.keys_params.key_params[i].cc_next_engine_params.params.kg_params.p_direct_scheme)
                DEV_TO_ID(params.keys_params.key_params[i].cc_next_engine_params.params.kg_params.p_direct_scheme);

        if (params.keys_params.key_params[i].cc_next_engine_params.manip_id)
            DEV_TO_ID(params.keys_params.key_params[i].cc_next_engine_params.manip_id);

#if (DPAA_VERSION >= 11)
        if (params.keys_params.key_params[i].cc_next_engine_params.next_engine == e_IOC_FM_PCD_FR &&
            params.keys_params.key_params[i].cc_next_engine_params.params.fr_params.frm_replic_id)
            DEV_TO_ID(params.keys_params.key_params[i].cc_next_engine_params.params.fr_params.frm_replic_id);
#endif /* DPAA_VERSION >= 11 */
    }

    if (params.keys_params.cc_next_engine_params_for_miss.next_engine == e_IOC_FM_PCD_CC &&
        params.keys_params.cc_next_engine_params_for_miss.params.cc_params.cc_node_id)
            DEV_TO_ID(params.keys_params.cc_next_engine_params_for_miss.params.cc_params.cc_node_id);

    if (params.keys_params.cc_next_engine_params_for_miss.next_engine == e_IOC_FM_PCD_KG &&
        params.keys_params.cc_next_engine_params_for_miss.params.kg_params.p_direct_scheme)
            DEV_TO_ID(params.keys_params.cc_next_engine_params_for_miss.params.kg_params.p_direct_scheme);

    if (params.keys_params.cc_next_engine_params_for_miss.manip_id)
        DEV_TO_ID(params.keys_params.cc_next_engine_params_for_miss.manip_id);

#if (DPAA_VERSION >= 11)
    if (params.keys_params.cc_next_engine_params_for_miss.next_engine == e_IOC_FM_PCD_FR &&
        params.keys_params.cc_next_engine_params_for_miss.params.fr_params.frm_replic_id)
            DEV_TO_ID(params.keys_params.cc_next_engine_params_for_miss.params.fr_params.frm_replic_id);

#endif /* DPAA_VERSION >= 11 */

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_SET, &params))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD Match Table device!!"));
        return NULL;
    }
    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
    p_PcdDev->owners++;
    p_Dev->id = PTR_TO_UINT(params.id);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

t_Error FM_PCD_MatchTableDelete(t_Handle h_CcNode)
{
    t_Device *p_Dev = (t_Device *)h_CcNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_DELETE, &id)){
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
    }

    p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_MatchTableGetKeyStatistics(t_Handle                  h_CcNode,
                                          uint16_t                  keyIndex,
                                          t_FmPcdCcKeyStatistics    *p_KeyStatistics)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    ioc_fm_pcd_cc_tbl_get_stats_t params;
    t_Device *p_PcdDev = NULL;

    ASSERT_COND(sizeof(t_FmPcdCcKeyStatistics) == sizeof(ioc_fm_pcd_cc_key_statistics_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    params.key_index = keyIndex;
    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_GET_KEY_STAT, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    memcpy(p_KeyStatistics, &params.statistics, sizeof(t_FmPcdCcKeyStatistics));

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_MatchTableGetMissStatistics(t_Handle                  h_CcNode,
                                           t_FmPcdCcKeyStatistics    *p_MissStatistics)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    ioc_fm_pcd_cc_tbl_get_stats_t params;
    t_Device *p_PcdDev = NULL;

    ASSERT_COND(sizeof(t_FmPcdCcKeyStatistics) == sizeof(ioc_fm_pcd_cc_key_statistics_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_GET_MISS_STAT, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    memcpy(p_MissStatistics, &params.statistics, sizeof(t_FmPcdCcKeyStatistics));

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_CcRootModifyNextEngine(t_Handle                  h_CcTree,
                                      uint8_t                   grpId,
                                      uint8_t                   index,
                                      t_FmPcdCcNextEngineParams *p_FmPcdCcNextEngineParams)
{
    t_Device *p_Dev = (t_Device*) h_CcTree;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_cc_tree_modify_next_engine_params_t  params;

    ASSERT_COND(sizeof(t_FmPcdCcNextEngineParams) == sizeof(ioc_fm_pcd_cc_next_engine_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    params.grp_indx = grpId;
    params.indx = index;
    memcpy(&params.cc_next_engine_params, p_FmPcdCcNextEngineParams, sizeof(t_FmPcdCcNextEngineParams));
    if (p_FmPcdCcNextEngineParams->nextEngine == e_FM_PCD_CC) {
        t_Device *p_NextDev = (t_Device*) p_FmPcdCcNextEngineParams->params.ccParams.h_CcNode;
        params.cc_next_engine_params.params.cc_params.cc_node_id = UINT_TO_PTR(p_NextDev->id);
    }
	if (p_FmPcdCcNextEngineParams->nextEngine == e_FM_PCD_KG) {
        t_Device *p_NextDev = (t_Device*) p_FmPcdCcNextEngineParams->params.kgParams.h_DirectScheme;
        params.cc_next_engine_params.params.kg_params.p_direct_scheme = UINT_TO_PTR(p_NextDev->id);
    }

#if (DPAA_VERSION >= 11)
	if (p_FmPcdCcNextEngineParams->nextEngine == e_FM_PCD_FR) {
        t_Device *p_NextDev = (t_Device*) p_FmPcdCcNextEngineParams->params.frParams.h_FrmReplic;
        params.cc_next_engine_params.params.fr_params.frm_replic_id = UINT_TO_PTR(p_NextDev->id);
    }
#endif /* DPAA_VERSION >= 11 */

	if (p_FmPcdCcNextEngineParams->h_Manip) {
		t_Device *p_NextDev = (t_Device*) p_FmPcdCcNextEngineParams->h_Manip;
		params.cc_next_engine_params.manip_id = UINT_TO_PTR(p_NextDev->id);
	}

	if (ioctl(p_PcdDev->fd, FM_PCD_IOC_CC_ROOT_MODIFY_NEXT_ENGINE, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_MatchTableModifyNextEngine(t_Handle                  h_CcNode,
                                          uint16_t                  keyIndex,
                                          t_FmPcdCcNextEngineParams *p_FmPcdCcNextEngineParams)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_cc_node_modify_next_engine_params_t  params;

    ASSERT_COND(sizeof(t_FmPcdCcNextEngineParams) == sizeof(ioc_fm_pcd_cc_next_engine_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;
    params.id = UINT_TO_PTR(p_Dev->id);
    params.key_indx = keyIndex;
    memcpy(&params.cc_next_engine_params, p_FmPcdCcNextEngineParams, sizeof(t_FmPcdCcNextEngineParams));
    if (p_FmPcdCcNextEngineParams->nextEngine == e_FM_PCD_CC) {
        t_Device *p_NextDev = (t_Device*) p_FmPcdCcNextEngineParams->params.ccParams.h_CcNode;

        params.cc_next_engine_params.params.cc_params.cc_node_id = UINT_TO_PTR(p_NextDev->id);
    }
    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_MODIFY_NEXT_ENGINE, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_MatchTableModifyMissNextEngine(t_Handle                  h_CcNode,
                                              t_FmPcdCcNextEngineParams *p_FmPcdCcNextEngineParams)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_cc_node_modify_next_engine_params_t  params;

    ASSERT_COND(sizeof(t_FmPcdCcNextEngineParams) == sizeof(ioc_fm_pcd_cc_next_engine_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    memcpy(&params.cc_next_engine_params, p_FmPcdCcNextEngineParams, sizeof(t_FmPcdCcNextEngineParams));
    if (p_FmPcdCcNextEngineParams->nextEngine == e_FM_PCD_CC) {
        t_Device *p_NextDev = (t_Device*) p_FmPcdCcNextEngineParams->params.ccParams.h_CcNode;

        params.cc_next_engine_params.params.cc_params.cc_node_id = UINT_TO_PTR(p_NextDev->id);
    }
    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_MODIFY_MISS_NEXT_ENGINE, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_MatchTableAddKey(t_Handle            h_CcNode,
                                uint16_t            keyIndex,
                                uint8_t             keySize,
                                t_FmPcdCcKeyParams  *p_KeyParams)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_cc_node_modify_key_and_next_engine_params_t params;

    ASSERT_COND(sizeof(t_FmPcdCcKeyParams) == sizeof(ioc_fm_pcd_cc_key_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    params.key_indx = keyIndex;
    params.key_size = keySize;
    memcpy(&params.key_params, p_KeyParams, sizeof(t_FmPcdCcKeyParams));
    if (p_KeyParams->ccNextEngineParams.nextEngine == e_FM_PCD_CC) {
        t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.params.ccParams.h_CcNode;
        params.key_params.cc_next_engine_params.params.cc_params.cc_node_id = UINT_TO_PTR(p_NextDev->id);
    } else if (p_KeyParams->ccNextEngineParams.nextEngine == e_FM_PCD_KG) {
    	t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.params.kgParams.h_DirectScheme;
    	params.key_params.cc_next_engine_params.params.kg_params.p_direct_scheme = UINT_TO_PTR(p_NextDev->id);
    }
#if (DPAA_VERSION >= 11)
    else if (p_KeyParams->ccNextEngineParams.nextEngine == e_FM_PCD_FR) {
    	t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.params.frParams.h_FrmReplic;
    	params.key_params.cc_next_engine_params.params.fr_params.frm_replic_id = UINT_TO_PTR(p_NextDev->id);
    }
#endif /* DPAA_VERSION >= 11 */

    /* Convert hdr manip pointer */
    if (p_KeyParams->ccNextEngineParams.h_Manip) {
    	t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.h_Manip;
    	params.key_params.cc_next_engine_params.manip_id = UINT_TO_PTR(p_NextDev->id);
    }

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_ADD_KEY, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_MatchTableRemoveKey(t_Handle h_CcNode, uint16_t keyIndex)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_cc_node_remove_key_params_t  params;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    params.key_indx = keyIndex;

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_REMOVE_KEY, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_MatchTableModifyKeyAndNextEngine(t_Handle            h_CcNode,
                                                uint16_t            keyIndex,
                                                uint8_t             keySize,
                                                t_FmPcdCcKeyParams  *p_KeyParams)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_cc_node_modify_key_and_next_engine_params_t  params;

    ASSERT_COND(sizeof(t_FmPcdCcKeyParams) == sizeof(ioc_fm_pcd_cc_key_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device *)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    params.key_indx = keyIndex;
    params.key_size = keySize;
    memcpy(&params.key_params, p_KeyParams, sizeof(t_FmPcdCcKeyParams));
    if (p_KeyParams->ccNextEngineParams.nextEngine == e_FM_PCD_CC) {
        t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.params.ccParams.h_CcNode;
        params.key_params.cc_next_engine_params.params.cc_params.cc_node_id = UINT_TO_PTR(p_NextDev->id);
    } else if (p_KeyParams->ccNextEngineParams.nextEngine == e_FM_PCD_KG) {
    	t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.params.kgParams.h_DirectScheme;
    	params.key_params.cc_next_engine_params.params.kg_params.p_direct_scheme = UINT_TO_PTR(p_NextDev->id);
    }
#if (DPAA_VERSION >= 11)
    else if (p_KeyParams->ccNextEngineParams.nextEngine == e_FM_PCD_FR) {
    	t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.params.frParams.h_FrmReplic;
    	params.key_params.cc_next_engine_params.params.fr_params.frm_replic_id = UINT_TO_PTR(p_NextDev->id);
    }
#endif /* DPAA_VERSION >= 11 */

    /* Convert hdr manip pointer */
    if (p_KeyParams->ccNextEngineParams.h_Manip) {
    	t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.h_Manip;
    	params.key_params.cc_next_engine_params.manip_id = UINT_TO_PTR(p_NextDev->id);
    }

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_MODIFY_KEY_AND_NEXT_ENGINE, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Handle FM_PCD_HashTableSet(t_Handle h_FmPcd, t_FmPcdHashTableParams *p_Param)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    t_Device *p_Dev = (t_Device*) h_FmPcd;
    ioc_fm_pcd_hash_table_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_PcdDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_Param, sizeof(t_FmPcdHashTableParams));
    params.id = NULL;

    if (params.cc_next_engine_params_for_miss.next_engine == e_IOC_FM_PCD_CC &&
        params.cc_next_engine_params_for_miss.params.cc_params.cc_node_id)
            DEV_TO_ID(params.cc_next_engine_params_for_miss.params.cc_params.cc_node_id);

    if (params.cc_next_engine_params_for_miss.next_engine == e_IOC_FM_PCD_KG &&
        params.cc_next_engine_params_for_miss.params.kg_params.p_direct_scheme)
            DEV_TO_ID(params.cc_next_engine_params_for_miss.params.kg_params.p_direct_scheme);

    if (params.cc_next_engine_params_for_miss.manip_id)
        DEV_TO_ID(params.cc_next_engine_params_for_miss.manip_id);

#if (DPAA_VERSION >= 11)
    if (params.cc_next_engine_params_for_miss.next_engine == e_IOC_FM_PCD_FR &&
        params.cc_next_engine_params_for_miss.params.fr_params.frm_replic_id)
            DEV_TO_ID(params.cc_next_engine_params_for_miss.params.fr_params.frm_replic_id);

#endif /* DPAA_VERSION >= 11 */

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_HASH_TABLE_SET, &params))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD Hash Table device!!"));
        return NULL;
    }
    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
    p_PcdDev->owners++;
    p_Dev->id = PTR_TO_UINT(params.id);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

t_Error FM_PCD_HashTableDelete(t_Handle h_HashTbl)
{
    t_Device *p_Dev = (t_Device*) h_HashTbl;
    t_Device *p_PcdDev = NULL;
    ioc_fm_obj_t id;

    SANITY_CHECK_EXIT(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_HASH_TABLE_DELETE, &id))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_HashTableAddKey(t_Handle            h_HashTbl,
                               uint8_t             keySize,
                               t_FmPcdCcKeyParams  *p_KeyParams)
{
    t_Device *p_Dev = (t_Device*) h_HashTbl;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_hash_table_add_key_params_t params;

    SANITY_CHECK_EXIT(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;

    params.p_hash_tbl = UINT_TO_PTR(p_Dev->id);
    params.key_size = keySize;
    memcpy(&params.key_params, p_KeyParams, sizeof(t_FmPcdCcKeyParams));
    if (p_KeyParams->ccNextEngineParams.nextEngine == e_FM_PCD_CC) {
        t_Device *p_NextDev = (t_Device*) p_KeyParams->ccNextEngineParams.params.ccParams.h_CcNode;

        params.key_params.cc_next_engine_params.params.cc_params.cc_node_id = UINT_TO_PTR(p_NextDev->id);
    }
    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_HASH_TABLE_ADD_KEY, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_HashTableRemoveKey(t_Handle h_HashTbl,
                                  uint8_t  keySize,
                                  uint8_t  *p_Key)
{
    t_Device *p_Dev = (t_Device*) h_HashTbl;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_hash_table_remove_key_params_t params;

    SANITY_CHECK_EXIT(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;

    params.p_hash_tbl = UINT_TO_PTR(p_Dev->id);
    params.key_size = keySize;
    params.p_key = p_Key;

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_HASH_TABLE_REMOVE_KEY, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_MatchTableModifyKey(t_Handle h_CcNode,
                                   uint16_t keyIndex,
                                   uint8_t  keySize,
                                   uint8_t  *p_Key,
                                   uint8_t  *p_Mask)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_cc_node_modify_key_params_t params;
    uint8_t                                key[IOC_FM_PCD_MAX_SIZE_OF_KEY];
    uint8_t                                mask[IOC_FM_PCD_MAX_SIZE_OF_KEY];

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    params.key_indx = keyIndex;
    params.key_size = keySize;
    memcpy(key, p_Key, keySize);
    if (p_Mask)
        memcpy(mask, p_Mask, keySize);
    params.p_key = key;
    params.p_mask = mask;

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MATCH_TABLE_MODIFY_KEY, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_HashTableGetMissStatistics(t_Handle                  h_CcNode,
                                          t_FmPcdCcKeyStatistics    *p_MissStatistics)
{
    t_Device *p_Dev = (t_Device*) h_CcNode;
    ioc_fm_pcd_cc_tbl_get_stats_t params;
    t_Device *p_PcdDev = NULL;

    ASSERT_COND(sizeof(t_FmPcdCcKeyStatistics) == sizeof(ioc_fm_pcd_cc_key_statistics_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_HASH_TABLE_GET_MISS_STAT, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    memcpy(p_MissStatistics, &params.statistics, sizeof(t_FmPcdCcKeyStatistics));

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Handle FM_PCD_PlcrProfileSet(t_Handle h_FmPcd, t_FmPcdPlcrProfileParams *p_Profile)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    t_Device *p_Dev = NULL;
    ioc_fm_pcd_plcr_profile_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_PcdDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_Profile, sizeof(t_FmPcdPlcrProfileParams));
    params.id = NULL;

    if (!params.modify &&
        (params.profile_select.new_params.profile_type
                != (ioc_fm_pcd_profile_type_selection)e_FM_PCD_PLCR_SHARED))
    {
        params.profile_select.new_params.p_fm_port =
            (ioc_fm_pcd_port_params_t*) (((t_Device*) p_Profile->id.newParams.h_FmPort)->h_UserPriv);
    }

    /* correct paramsOnGreen.h_Profile, paramsOnYellow.h_Profile, paramsOnRed.h_Profile
     * if next engine is policer... that means that FM_PCD_PlcrProfileSet was called */
    if (params.next_engine_on_green == e_IOC_FM_PCD_PLCR && params.params_on_green.p_profile)
        DEV_TO_ID(params.params_on_green.p_profile);
    if (params.next_engine_on_yellow == e_IOC_FM_PCD_PLCR && params.params_on_yellow.p_profile)
        DEV_TO_ID(params.params_on_yellow.p_profile);
    if (params.next_engine_on_red == e_IOC_FM_PCD_PLCR && params.params_on_red.p_profile)
        DEV_TO_ID(params.params_on_red.p_profile);

    /* correct paramsOnGreen.h_Profile, paramsOnYellow.h_Profile, paramsOnRed.h_Profile
     * if next engine is kg... that means that FM_PCD_KgSchemeSet was called */
    if (params.next_engine_on_green == e_IOC_FM_PCD_KG && params.params_on_green.p_direct_scheme)
        DEV_TO_ID(params.params_on_green.p_direct_scheme);
    if (params.next_engine_on_yellow == e_IOC_FM_PCD_KG && params.params_on_yellow.p_direct_scheme)
        DEV_TO_ID(params.params_on_yellow.p_direct_scheme);
    if (params.next_engine_on_red == e_IOC_FM_PCD_KG && params.params_on_red.p_direct_scheme)
        DEV_TO_ID(params.params_on_red.p_direct_scheme);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_PLCR_PROFILE_SET, &params))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD Policer Profile device!!"));
        return NULL;
    }

    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
    p_PcdDev->owners++;
    p_Dev->id = PTR_TO_UINT(params.id);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

t_Error FM_PCD_PlcrProfileDelete(t_Handle h_Profile)
{
    t_Device *p_Dev = (t_Device*) h_Profile;
    t_Device *p_PcdDev = NULL;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_PLCR_PROFILE_DELETE, &id)){
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
    }

    p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Handle FM_PCD_ManipNodeSet(t_Handle h_FmPcd, t_FmPcdManipParams *p_FmPcdManipParams)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    t_Device *p_Dev = NULL;
    ioc_fm_pcd_manip_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_PcdDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memset(&params, 0, sizeof(ioc_fm_pcd_manip_params_t));
    memcpy(&params, p_FmPcdManipParams, sizeof(t_FmPcdManipParams));
    if (p_FmPcdManipParams->h_NextManip)
    {
        p_Dev = (t_Device*)p_FmPcdManipParams->h_NextManip;
        params.p_next_manip = UINT_TO_PTR(p_Dev->id);
    }

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MANIP_NODE_SET, &params)){
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD Manip Node device!!"));
        return NULL;
    }

    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
    p_PcdDev->owners++;
    p_Dev->id = PTR_TO_UINT(params.id);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

t_Error FM_PCD_ManipNodeReplace(t_Handle h_ManipNode, t_FmPcdManipParams *p_FmPcdManipParams)
{
    t_Device *p_Dev = (t_Device*)h_ManipNode;
    t_Device *p_PcdDev;
    ioc_fm_pcd_manip_params_t params;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;

    memset(&params, 0, sizeof(ioc_fm_pcd_manip_params_t));
    memcpy(&params, p_FmPcdManipParams, sizeof(t_FmPcdManipParams));
    params.id = UINT_TO_PTR(p_Dev->id);
    /* REMINDER:
       Also take care of params.p_next_manip here, although it's currently
       ignored by the LLD! */

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MANIP_NODE_SET, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error  FM_PCD_ManipNodeDelete(t_Handle h_HdrManipNode)
{
    t_Device *p_Dev = (t_Device*) h_HdrManipNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_obj_t id;

    SANITY_CHECK_EXIT(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MANIP_NODE_DELETE, &id))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_ManipGetStatistics(t_Handle h_ManipNode, t_FmPcdManipStats *p_FmPcdManipStats)
{
    t_Device *p_Dev = (t_Device*) h_ManipNode;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_manip_get_stats_t params;

    ASSERT_COND(sizeof(t_FmPcdManipStats) == sizeof(ioc_fm_pcd_manip_stats_t));
    SANITY_CHECK_EXIT(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;

    params.id = UINT_TO_PTR(p_Dev->id);
    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_MANIP_GET_STATS, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    memcpy(p_FmPcdManipStats, &params.stats, sizeof(t_FmPcdManipStats));

    _fml_dbg("Called.\n");

    return E_OK;
}

#ifdef FM_CAPWAP_SUPPORT
#error CAPWAP feature not supported
#endif

typedef struct {
    e_FmPortType            portType;           /**< Port type */
    uint8_t                 portId;             /**< Port Id - relative to type */
} t_FmPort;

/********************************************************************************************/
/*  FM_PORT FUNCTIONS                                                                       */
/********************************************************************************************/

t_Handle FM_PORT_Open(t_FmPortParams *p_FmPortParams)
{
    t_Device    *p_Dev;
    int         fd;
    char        devName[30];
    t_FmPort    *p_FmPort;

    _fml_dbg("Calling...\n");

    if (!p_FmPortParams->h_Fm)
    {
        REPORT_ERROR(MAJOR, E_NO_DEVICE, ("FM device not available!!"));
        return NULL;
    }

    p_Dev = (t_Device*) malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM Port device!!"));
        return NULL;
    }
    memset(p_Dev, 0, sizeof(t_Device));

    p_FmPort = (t_FmPort*) malloc(sizeof(t_FmPort));
    if (!p_FmPort)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM Port device!!"));
        free(p_Dev);
        return NULL;
    }
    memset(p_FmPort, 0, sizeof(t_FmPort));

    memset(devName, 0, sizeof(devName));
    switch (p_FmPortParams->portType)
    {
        case e_FM_PORT_TYPE_OH_OFFLINE_PARSING:
            sprintf(devName, "%s%s%u-port-oh%d", "/dev/", DEV_FM_NAME,
                    (uint32_t)((t_Device*)p_FmPortParams->h_Fm)->id, p_FmPortParams->portId);
            break;
        case e_FM_PORT_TYPE_RX:
            sprintf(devName, "%s%s%u-port-rx%d", "/dev/", DEV_FM_NAME,
                    (uint32_t)((t_Device*)p_FmPortParams->h_Fm)->id, p_FmPortParams->portId);
            break;
        case e_FM_PORT_TYPE_RX_10G:
            sprintf(devName, "%s%s%u-port-rx%d", "/dev/", DEV_FM_NAME,
                    (uint32_t)((t_Device*)p_FmPortParams->h_Fm)->id, FM_MAX_NUM_OF_1G_RX_PORTS+p_FmPortParams->portId);
            break;
        case e_FM_PORT_TYPE_TX:
            sprintf(devName, "%s%s%u-port-tx%d", "/dev/", DEV_FM_NAME,
                    (uint32_t)((t_Device*)p_FmPortParams->h_Fm)->id, p_FmPortParams->portId);
            break;
        case e_FM_PORT_TYPE_TX_10G:
            sprintf(devName, "%s%s%u-port-tx%d", "/dev/", DEV_FM_NAME,
                    (uint32_t)((t_Device*)p_FmPortParams->h_Fm)->id, FM_MAX_NUM_OF_1G_TX_PORTS+p_FmPortParams->portId);
            break;
        default:
            free(p_FmPort);
            free(p_Dev);
            REPORT_ERROR(MAJOR, E_INVALID_VALUE, ("port id!"));
            return NULL;
    }

    fd = open(devName, O_RDWR);
    if (fd < 0)
    {
       free(p_FmPort);
       free(p_Dev);
       REPORT_ERROR(MAJOR, E_NO_DEVICE, ("Could not open FM-port %s. Ret code=%d, errno=%d. Aborting!!!",
               devName,
               fd,
               errno));
       return NULL;
    }

    p_FmPort->portType = p_FmPortParams->portType;
    p_FmPort->portId = p_FmPortParams->portId;
    p_Dev->id = p_FmPortParams->portId;
    p_Dev->fd = fd;
    p_Dev->h_UserPriv = (t_Handle) p_FmPort;

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

void FM_PORT_Close(t_Handle h_FmPort)
{
    t_Device    *p_Dev = (t_Device *)h_FmPort;

    SANITY_CHECK_RETURN(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    close(p_Dev->fd);
    if (p_Dev->h_UserPriv)
        free(p_Dev->h_UserPriv);
    free(p_Dev);

    _fml_dbg("Called.\n");
}

t_Error FM_PORT_Disable(t_Handle h_FmPort)
{
    t_Device    *p_Dev = (t_Device *)h_FmPort;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_DISABLE))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_Enable(t_Handle h_FmPort)
{
    t_Device    *p_Dev = (t_Device *)h_FmPort;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_ENABLE))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_DeleteRateLimit(t_Handle h_FmPort)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_REMOVE_RATE_LIMIT))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_SetRateLimit(t_Handle h_FmPort, t_FmPortRateLimit *p_RateLimit)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;

    ASSERT_COND(sizeof(t_FmPortRateLimit) == sizeof(ioc_fm_port_rate_limit_t));
    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_SET_RATE_LIMIT, p_RateLimit))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_SetErrorsRoute(t_Handle h_FmPort, fmPortFrameErrSelect_t errs)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;
    int         intCast = (int) errs;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_SET_ERRORS_ROUTE, &intCast))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

uint32_t FM_PORT_AllocPCDFqids (t_Handle h_FmPort, uint32_t numFqids, uint8_t alignment)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;
    ioc_fm_port_pcd_fqids_params_t  param;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    param.num_fqids  = numFqids;
    param.alignment = alignment;
    if (ioctl(p_Dev->fd, FM_PORT_IOC_ALLOC_PCD_FQIDS, &param))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION,
                ("Failed to allocate %d queue IDs!", numFqids));
        return 0;
    }

    _fml_dbg("Called.\n");

    return param.base_fqid;
}

t_Error FM_PORT_FreePCDFqids (t_Handle h_FmPort, uint32_t base_fqid)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_FREE_PCD_FQIDS, &base_fqid))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION,
                ("Invalid base FQID %d or other error!", base_fqid));

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_SetPCD(t_Handle h_FmPort, t_FmPortPcdParams *p_FmPortPcd)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;
    ioc_fm_port_pcd_params_t params;

    ASSERT_COND(sizeof(t_FmPortPcdParams) == sizeof(ioc_fm_port_pcd_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_FmPortPcd, sizeof(t_FmPortPcdParams));

    /* correct h_NetEnv param from t_FmPortPcdParams */
    DEV_TO_ID(params.net_env_id);

    /* correct pcd structures according to what support was set */
    if (params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC ||
        params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR ||
        params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_CC) {

        if (params.p_cc_params && params.p_cc_params->cc_tree_id)
            DEV_TO_ID(params.p_cc_params->cc_tree_id);
        else
            XX_Print("fmlib warning (%s): Coarse Clasification not set ! \n", __func__);
    }

    if (params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG ||
        params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC ||
        params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR ||
        params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR ){

        if (params.p_kg_params){
            uint32_t i;
            for (i = 0; i < params.p_kg_params->num_of_schemes; i++)
                if (params.p_kg_params->scheme_ids[i])
                    DEV_TO_ID(params.p_kg_params->scheme_ids[i]);
                else
                    XX_Print("fmlib warning (%s): Scheme:%u not set!\n", __func__, i);

            if (params.p_kg_params && params.p_kg_params->direct_scheme)
                DEV_TO_ID(params.p_kg_params->direct_scheme_id);
        } else
            XX_Print("fmlib warning (%s): KeyGen not set ! \n", __func__);
    }

    if (params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PLCR_ONLY ||
        params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR ||
        params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR ||
        params.pcd_support == e_IOC_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR){

        if (params.p_plcr_params)
        {
            if (params.p_plcr_params->plcr_profile_id)
                DEV_TO_ID(params.p_plcr_params->plcr_profile_id);
            else
                XX_Print("fmlib warning (%s): Policer not set !\n", __func__);
        }
    }

    if (params.p_ip_reassembly_manip)
        DEV_TO_ID(params.p_ip_reassembly_manip);

#if (DPAA_VERSION >= 11)
    if (params.p_capwap_reassembly_manip)
	DEV_TO_ID(params.p_capwap_reassembly_manip);
#endif

    if (ioctl(p_Dev->fd, FM_PORT_IOC_SET_PCD, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_DeletePCD(t_Handle h_FmPort)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_DELETE_PCD))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_DetachPCD(t_Handle h_FmPort)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_DETACH_PCD))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_AttachPCD(t_Handle h_FmPort)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_ATTACH_PCD))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_PcdPlcrAllocProfiles(t_Handle h_FmPort, uint16_t numOfProfiles)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_PCD_PLCR_ALLOC_PROFILES, &numOfProfiles))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_PcdPlcrFreeProfiles(t_Handle h_FmPort)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_PCD_PLCR_FREE_PROFILES))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_PcdKgModifyInitialScheme(t_Handle h_FmPort, t_FmPcdKgSchemeSelect *p_FmPcdKgScheme)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;

    ASSERT_COND(sizeof(t_FmPcdKgSchemeSelect) == sizeof(ioc_fm_pcd_kg_scheme_select_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_PCD_KG_MODIFY_INITIAL_SCHEME, p_FmPcdKgScheme))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_PcdPlcrModifyInitialProfile (t_Handle h_FmPort, t_Handle h_Profile)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    id.obj = h_Profile;

    if (ioctl(p_Dev->fd, FM_PORT_IOC_PCD_PLCR_MODIFY_INITIAL_PROFILE, &id))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_PcdCcModifyTree (t_Handle h_FmPort, t_Handle h_CcTree)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    id.obj = h_CcTree;

    if (ioctl(p_Dev->fd, FM_PORT_IOC_PCD_CC_MODIFY_TREE, &id))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_PcdKgBindSchemes (t_Handle h_FmPort, t_FmPcdPortSchemesParams *p_PortScheme)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;
    ioc_fm_pcd_port_schemes_params_t params;
    uint32_t i;

    ASSERT_COND(sizeof(t_FmPcdPortSchemesParams) == sizeof(ioc_fm_pcd_port_schemes_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_PortScheme, sizeof(t_FmPcdPortSchemesParams));
    for (i = 0; i < params.num_of_schemes; i++)
	    DEV_TO_ID(params.scheme_ids[i]);

    if (ioctl(p_Dev->fd, FM_PORT_IOC_PCD_KG_BIND_SCHEMES, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_PcdKgUnbindSchemes (t_Handle h_FmPort, t_FmPcdPortSchemesParams *p_PortScheme)
{
    t_Device *p_Dev = (t_Device*) h_FmPort;
    ioc_fm_pcd_port_schemes_params_t params;
    uint32_t i;

    ASSERT_COND(sizeof(t_FmPcdPortSchemesParams) == sizeof(ioc_fm_pcd_port_schemes_params_t));
    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_PortScheme, sizeof(t_FmPcdPortSchemesParams));
    for (i = 0; i < params.num_of_schemes; i++)
	    DEV_TO_ID(params.scheme_ids[i]);

    if (ioctl(p_Dev->fd, FM_PORT_IOC_PCD_KG_UNBIND_SCHEMES, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_SetAdvancedOffloadSupport(t_Handle h_FmPort)
{
    t_Device    *p_Dev = (t_Device *)h_FmPort;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PCD_IOC_SET_ADVANCED_OFFLOAD_SUPPORT))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

#if (DPAA_VERSION >= 11)
t_Handle FM_PCD_FrmReplicSetGroup(t_Handle h_FmPcd, t_FmPcdFrmReplicGroupParams *p_FrmReplicGroupParam)
{
    t_Device *p_PcdDev = (t_Device*) h_FmPcd;
    t_Device *p_Dev = NULL;
    ioc_fm_pcd_frm_replic_group_params_t params;
    uint32_t i;

    SANITY_CHECK_RETURN_VALUE(p_PcdDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memcpy(&params, p_FrmReplicGroupParam, sizeof(t_FmPcdFrmReplicGroupParams));
    params.id = NULL;

    for (i = 0; i < p_FrmReplicGroupParam->numOfEntries; i++)
    {
        if (p_FrmReplicGroupParam->nextEngineParams[i].nextEngine == e_FM_PCD_CC) {
        	t_Device *p_NextDev = (t_Device*) p_FrmReplicGroupParam->nextEngineParams[i].params.ccParams.h_CcNode;
        	params.next_engine_params[i].params.cc_params.cc_node_id = UINT_TO_PTR(p_NextDev->id);
        }
        else if (p_FrmReplicGroupParam->nextEngineParams[i].nextEngine == e_FM_PCD_KG) {
        	t_Device *p_NextDev = (t_Device*) p_FrmReplicGroupParam->nextEngineParams[i].params.kgParams.h_DirectScheme;
        	params.next_engine_params[i].params.kg_params.p_direct_scheme = UINT_TO_PTR(p_NextDev->id);
        }

        /* Convert hdr manip pointer */
        if (p_FrmReplicGroupParam->nextEngineParams[i].h_Manip) {
        	t_Device *p_NextDev = (t_Device*) p_FrmReplicGroupParam->nextEngineParams[i].h_Manip;
        	params.next_engine_params[i].manip_id = UINT_TO_PTR(p_NextDev->id);
        }
    }

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_FRM_REPLIC_GROUP_SET, &params))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_Dev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_Dev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM PCD NetEnv Chrs device!!"));
        return NULL;
    }
    memset(p_Dev, 0, sizeof(t_Device));
    p_Dev->h_UserPriv = (t_Handle)p_PcdDev;
    p_PcdDev->owners++;
    p_Dev->id = PTR_TO_UINT(params.id);

    _fml_dbg("Called.\n");

    return (t_Handle) p_Dev;
}

t_Error FM_PCD_FrmReplicDeleteGroup(t_Handle h_FrmReplicGroup)
{
    t_Device *p_Dev = (t_Device*) h_FrmReplicGroup;
    t_Device *p_PcdDev = NULL;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_Dev->id);

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_FRM_REPLIC_GROUP_DELETE, &id))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_FrmReplicAddMember(t_Handle h_ReplicGroup,
                                  uint16_t memberIndex,
                                  t_FmPcdCcNextEngineParams *p_MemberParams)
{
    t_Device *p_Dev = (t_Device*) h_ReplicGroup;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_frm_replic_member_params_t params;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;

    params.member.h_replic_group = UINT_TO_PTR(p_Dev->id);
    params.member.member_index = memberIndex;
    memcpy(&params.next_engine_params, p_MemberParams, sizeof(*p_MemberParams));
    if (p_MemberParams->nextEngine == e_FM_PCD_CC) {
        t_Device *p_NextDev = (t_Device*) p_MemberParams->params.ccParams.h_CcNode;
        params.next_engine_params.params.cc_params.cc_node_id = UINT_TO_PTR(p_NextDev->id);
    }
    else if (p_MemberParams->nextEngine == e_FM_PCD_KG) {
        t_Device *p_NextDev = (t_Device*) p_MemberParams->params.kgParams.h_DirectScheme;
        params.next_engine_params.params.kg_params.p_direct_scheme = UINT_TO_PTR(p_NextDev->id);
    }

    /* Convert hdr manip pointer */
    if (p_MemberParams->h_Manip) {
    	t_Device *p_NextDev = (t_Device*) p_MemberParams->h_Manip;
    	params.next_engine_params.manip_id = UINT_TO_PTR(p_NextDev->id);
    }

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_FRM_REPLIC_MEMBER_ADD, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PCD_FrmReplicRemoveMember(t_Handle   h_ReplicGroup,
                                     uint16_t   memberIndex)
{
    t_Device *p_Dev = (t_Device*) h_ReplicGroup;
    t_Device *p_PcdDev = NULL;
    ioc_fm_pcd_frm_replic_member_t param;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_PcdDev = (t_Device*)p_Dev->h_UserPriv;

    param.h_replic_group = UINT_TO_PTR(p_Dev->id);
    param.member_index = memberIndex;

    if (ioctl(p_PcdDev->fd, FM_PCD_IOC_FRM_REPLIC_MEMBER_REMOVE, &param))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    p_PcdDev->owners--;
    free(p_Dev);

    _fml_dbg("Called.\n");

    return E_OK;
}
#endif

t_Error FM_MAC_AddHashMacAddr(t_Handle h_FmMac, t_EnetAddr *p_EnetAddr)
{
    t_Device    *p_Dev = (t_Device *)h_FmMac;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_ADD_RX_HASH_MAC_ADDR, p_EnetAddr))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_MAC_RemoveHashMacAddr(t_Handle h_FmMac, t_EnetAddr *p_EnetAddr)
{
    t_Device    *p_Dev = (t_Device *)h_FmMac;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_REMOVE_RX_HASH_MAC_ADDR, p_EnetAddr))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_MAC_SetTxPauseFrames(t_Handle h_FmMac, uint8_t  priority, uint16_t pauseTime, uint16_t threshTime)
{
    t_Device    *p_Dev = (t_Device *)h_FmMac;
    ioc_fm_port_tx_pause_frames_params_t param;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    param.priority = priority;
    param.pause_time = pauseTime;
    param.thresh_time = threshTime;

    if (ioctl(p_Dev->fd, FM_PORT_IOC_SET_TX_PAUSE_FRAMES, &param))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_MAC_GetStatistics (t_Handle h_FmMac, t_FmMacStatistics *p_Statistics)
{
    t_Device    *p_Dev = (t_Device *)h_FmMac;
    ioc_fm_port_mac_statistics_t *param;

    param = (ioc_fm_port_mac_statistics_t *)p_Statistics;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);
    SANITY_CHECK_RETURN_VALUE(param, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_GET_MAC_STATISTICS, param))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_MAC_GetFrameSizeCounters (t_Handle h_FmMac, t_FmMacFrameSizeCounters *p_FrameSizeCounters, e_CommMode type)
{
    t_Device    *p_Dev = (t_Device *)h_FmMac;
    ioc_fm_port_mac_frame_size_counters_t param;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);
    SANITY_CHECK_RETURN_VALUE(p_FrameSizeCounters, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    param.type = type;

    if (ioctl(p_Dev->fd, FM_PORT_IOC_GET_MAC_FRAME_SIZE_COUNTERS, &param))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    p_FrameSizeCounters->count_pkts_64 = param.count_pkts_64;
    p_FrameSizeCounters->count_pkts_65_to_127 = param.count_pkts_65_to_127;
    p_FrameSizeCounters->count_pkts_128_to_255 = param.count_pkts_128_to_255;
    p_FrameSizeCounters->count_pkts_256_to_511 = param.count_pkts_256_to_511;
    p_FrameSizeCounters->count_pkts_512_to_1023 = param.count_pkts_512_to_1023;
    p_FrameSizeCounters->count_pkts_1024_to_1518 = param.count_pkts_1024_to_1518;
    p_FrameSizeCounters->count_pkts_1519_to_1522 = param.count_pkts_1519_to_1522;

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_GetBmiCounters (t_Handle h_FmPort, t_FmPortBmiStats *p_BmiStats)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;
    ioc_fm_port_bmi_stats_t *param;

    param = (ioc_fm_port_bmi_stats_t *)p_BmiStats;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);
    SANITY_CHECK_RETURN_VALUE(param, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_GET_BMI_COUNTERS, param))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_PORT_ConfigBufferPrefixContent(t_Handle h_FmPort, t_FmBufferPrefixContent *p_Params)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_CONFIG_BUFFER_PREFIX_CONTENT, p_Params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

#if (DPAA_VERSION >= 11)

t_Error FM_PORT_VSPAlloc(t_Handle h_FmPort, t_FmPortVSPAllocParams *p_Params)
{
    t_Device    *p_Dev = (t_Device*) h_FmPort;

    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_PORT_IOC_VSP_ALLOC, p_Params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Handle FM_VSP_Config(t_FmVspParams *p_FmVspParams)
{
    t_Device *p_Dev = NULL;
    t_Device *p_VspDev = NULL;
    ioc_fm_vsp_params_t param;

    SANITY_CHECK_RETURN_VALUE((void *)p_FmVspParams, E_INVALID_HANDLE, NULL);
    p_Dev = p_FmVspParams->h_Fm;
    SANITY_CHECK_RETURN_VALUE(p_Dev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    memcpy(&param, p_FmVspParams, sizeof(param));
    param.p_fm = UINT_TO_PTR(p_Dev->id);
    param.id = NULL;

    if (ioctl(p_Dev->fd, FM_IOC_VSP_CONFIG, &param))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    p_VspDev = (t_Device *)malloc(sizeof(t_Device));
    if (!p_VspDev)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM VSP Params!"));
        return NULL;
    }
    memset(p_VspDev, 0, sizeof(t_Device));
    p_VspDev->h_UserPriv = (t_Handle)p_Dev;
    p_Dev->owners++;
    p_VspDev->id = PTR_TO_UINT(param.id);

    _fml_dbg("Called.\n");

    return (t_Handle)p_VspDev;
}

t_Error FM_VSP_Init(t_Handle h_FmVsp)
{
    t_Device *p_Dev = NULL;
    t_Device *p_VspDev = (t_Device *)h_FmVsp;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_VspDev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_Dev = (t_Device*)p_VspDev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_VspDev->id);

    if (ioctl(p_Dev->fd, FM_IOC_VSP_INIT, &id))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_VSP_Free(t_Handle h_FmVsp)
{
    t_Device *p_Dev = NULL;
    t_Device *p_VspDev = (t_Device *)h_FmVsp;
    ioc_fm_obj_t id;

    SANITY_CHECK_RETURN_ERROR(p_VspDev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    p_Dev = (t_Device*)p_VspDev->h_UserPriv;
    id.obj = UINT_TO_PTR(p_VspDev->id);

    if (ioctl(p_Dev->fd, FM_IOC_VSP_FREE, &id))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    p_Dev->owners--;
    free(p_VspDev);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_VSP_ConfigPoolDepletion(t_Handle h_FmVsp, t_FmBufPoolDepletion *p_BufPoolDepletion)
{
    t_Device *p_Dev = NULL;
    t_Device *p_VspDev = (t_Device *)h_FmVsp;
    ioc_fm_buf_pool_depletion_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_VspDev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    p_Dev = (t_Device*)p_VspDev->h_UserPriv;
    params.p_fm_vsp = UINT_TO_PTR(p_VspDev->id);
    memcpy(&params.fm_buf_pool_depletion, p_BufPoolDepletion, sizeof(*p_BufPoolDepletion));

    if (ioctl(p_Dev->fd, FM_IOC_VSP_CONFIG_POOL_DEPLETION, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_VSP_ConfigBufferPrefixContent(t_Handle h_FmVsp, t_FmBufferPrefixContent *p_FmBufferPrefixContent)
{
    t_Device *p_Dev = NULL;
    t_Device *p_VspDev = (t_Device *)h_FmVsp;
    ioc_fm_buffer_prefix_content_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_VspDev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    p_Dev = (t_Device*)p_VspDev->h_UserPriv;
    params.p_fm_vsp = UINT_TO_PTR(p_VspDev->id);
    memcpy(&params.fm_buffer_prefix_content, p_FmBufferPrefixContent, sizeof(*p_FmBufferPrefixContent));

    if (ioctl(p_Dev->fd, FM_IOC_VSP_CONFIG_BUFFER_PREFIX_CONTENT, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_VSP_ConfigNoScatherGather(t_Handle h_FmVsp, bool noScatherGather)
{
    t_Device *p_Dev = NULL;
    t_Device *p_VspDev = (t_Device *)h_FmVsp;
    ioc_fm_vsp_config_no_sg_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_VspDev, E_INVALID_HANDLE, E_OK);

    _fml_dbg("Calling...\n");

    p_Dev = (t_Device*)p_VspDev->h_UserPriv;
    params.p_fm_vsp = UINT_TO_PTR(p_VspDev->id);
    params.no_sg = noScatherGather;

    if (ioctl(p_Dev->fd, FM_IOC_VSP_CONFIG_NO_SG, &params))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_FmPrsResult * FM_VSP_GetBufferPrsResult(t_Handle h_FmVsp, char *p_Data)
{
    t_Device *p_Dev = NULL;
    t_Device *p_VspDev = (t_Device *)h_FmVsp;
    ioc_fm_vsp_prs_result_params_t params;

    SANITY_CHECK_RETURN_VALUE(p_VspDev, E_INVALID_HANDLE, NULL);

    _fml_dbg("Calling...\n");

    p_Dev = (t_Device*)p_VspDev->h_UserPriv;
    params.p_fm_vsp = UINT_TO_PTR(p_VspDev->id);
    params.p_data = p_Data;

    if (ioctl(p_Dev->fd, FM_IOC_VSP_GET_BUFFER_PRS_RESULT, &params))
    {
        REPORT_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);
        return NULL;
    }

    _fml_dbg("Called.\n");

    return params.p_data;
}
#endif

t_Error FM_CtrlMonStart(t_Handle h_Fm)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_IOC_CTRL_MON_START))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_CtrlMonStop(t_Handle h_Fm)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    if (ioctl(p_Dev->fd, FM_IOC_CTRL_MON_STOP))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

t_Error FM_CtrlMonGetCounters(t_Handle h_Fm, uint8_t fmCtrlIndex, t_FmCtrlMon *p_Mon)
{
    t_Device    *p_Dev = (t_Device*) h_Fm;
    ioc_fm_ctrl_mon_counters_params_t param;

    SANITY_CHECK_RETURN_ERROR(p_Dev, E_INVALID_HANDLE);

    _fml_dbg("Calling...\n");

    param.fm_ctrl_index = fmCtrlIndex;
    param.p_mon = (fm_ctrl_mon_t *)p_Mon;

    if (ioctl(p_Dev->fd, FM_IOC_CTRL_MON_GET_COUNTERS, &param))
        RETURN_ERROR(MINOR, E_INVALID_OPERATION, NO_MSG);

    _fml_dbg("Called.\n");

    return E_OK;
}

#ifdef P1023
void Platform_is_P1023()
{
}
#elif defined FMAN_V3H
void Platform_is_FMAN_V3H()
{
}
#elif defined FMAN_V3L
void Platform_is_FMAN_V3L()
{
}
#else
void Platform_is_P3_P4_P5()
{
}
#endif
