/* =====================================================================
 *
 * The MIT License (MIT)
 * Copyright 2009-2012, Freescale Semiconductor, Inc.
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
 * File Name : libfmc.cpp
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#include <typeinfo>
#include <string.h>
#include <stdarg.h>
#include <string>
#include <sstream>

#include "fmc.h"
#include "FMCGenericError.h"
#include "FMCTaskDef.h"
#include "FMCPDLReader.h"
#include "FMCPCDReader.h"
#include "FMCCFGReader.h"
#include "FMCPCDModel.h"
#include "FMCCModelOutput.h"
#include "FMCSP.h"

#define DEFINE_LOGGER_INSTANCE
#include "logger.hpp"

const char* TMPFILENAME = "/tmp/fmc.bin";


#ifdef _MSC_VER
#pragma warning(disable : 4996)
#ifdef _DEBUG
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.VC90.CRT' version='9.0.21022.8' processorArchitecture='x86' publicKeyToken='1fc8b3b9a1e18e3b' language='*'\"")
#endif
#endif


std::string error_text;
std::string compile_dump;

#ifdef __cplusplus
extern "C" {
#endif


int
fmc_compile(
    fmc_model*   cmodel,
    const char*  nameCfg,
    const char*  namePCD,
    const char*  namePDL,
    const char*  nameSP,
    unsigned int swOffset,
    unsigned int dontWarn,
    const char** dump
)
{
    error_text   = "";
    compile_dump = "";

    if ( cmodel == 0 ) {
        return 2;
    }
    
    memset( cmodel, 0, sizeof( *cmodel ) );

    try {
        if ( nameSP != 0 && std::string( nameSP ) == "nodefault" ) {
            nameSP = 0;
        }
        if ( namePCD != 0 && std::string( namePCD ) == "nodefault" ) {
            namePCD = 0;
        }
        if ( nameCfg != 0 && std::string( nameCfg ) == "nodefault" ) {
            nameCfg = 0;
        }

        CGenericError::dontWarn = dontWarn;

        CTaskDef task;

        // Process PDL and SP files
        CPDLReader pdlReader;
        pdlReader.setTaskData( &task );
        pdlReader.parseNetPDL( namePDL );

        // Process custom protocols definition - software parser portion
        if ( nameSP ) {
            pdlReader.setSoftParse(1);
            pdlReader.parseNetPDL( nameSP );
            softparser(&task, nameSP, swOffset);
        }

        if ( namePCD && nameCfg )
        {
            // Process PCD file
            CPCDReader pcdReader;
            pcdReader.setTaskData( &task );
            pcdReader.parseNetPCD( namePCD );

            // Process config file
            CCFGReader cfgReader;
            cfgReader.setTaskData( &task );
            cfgReader.parseCfgData( nameCfg );

            task.checkSemantics();

            CFMCModel model;
            LOG( logger::DBG1 ) << logger::ind( 2 )
                                << "Converting parsed task definition to internal representation ..."
                                << std::endl;
            model.createModel( &task );
            LOG( logger::DBG1 ) << logger::ind( -2 )
                                << "Done"
                                << std::endl;
            LOG( logger::DBG1 ) << std::endl;

            CFMCCModelOutput   modelOut;
            std::ostringstream oss;
            LOG( logger::DBG1 ) << logger::ind( 2 )
                                << "Output structures' initialization started ..."
                                << std::endl;
            modelOut.output( model, cmodel, oss, 0 );
            LOG( logger::DBG1 ) << logger::ind( -2 )
                                << "Done"
                                << std::endl;
            LOG( logger::DBG1 ) << std::endl;

            compile_dump = oss.str();
        }

        LOG( logger::DBG2 ) << "Generated init:"
                            << std::endl
                            << compile_dump
                            << std::endl;
        
        if ( dump != 0 ) {
            *dump = compile_dump.c_str();
        }
    }
    catch ( const CGenericError& genError ) { // Catch known errors generated by FMC
        error_text = genError.getErrorMsg();
        LOG( logger::ERR ) << error_text << std::endl;
        return 3;
    }
    catch ( std::exception &e )
    {
        error_text  = e.what();
        error_text += " Type : ";
        error_text += typeid( e ).name();
        LOG( logger::ERR ) << error_text << std::endl;
        return 4;
    }
    catch ( ... ) {                     // Catch unknown errors
        error_text = "Unrecognized error occured. The program was terminated";
        LOG( logger::ERR ) << error_text << std::endl;
        return 1;
    }

    return 0;
}


const char*
fmc_get_error( void )
{
    return error_text.c_str();
}


int32_t
fmc_log( int32_t level )
{
    using namespace logger;
    
    int32_t ret = LOG_GET_LEVEL();

    LOG_INIT( std::cerr, (log_level_t)level );

    return ret;
}


void
fmc_log_write( int32_t level, const char* format, ... )
{
    using namespace logger;

    va_list args;
    va_start( args, format );

    if ( level <= LOG_GET_LEVEL() ) {
        char buffer[256];
        vsprintf( buffer, format, args );
        LOG( (log_level_t)level ) << (const char*)buffer << std::endl;
    }

    va_end( args );
}


int createDevices( fmc_model* pmodel )
{
	int i, j;
	unsigned int index;
	unsigned int current_engine = 0;
	unsigned int current_port = 0;
	t_FmPcdParams fmPcdParams = {0};
	t_FmPortParams  fmPortParam = {0};

	for (i = 0; i < pmodel->apply_order_count; i++)
	{
		index = pmodel->apply_order[i].index;

		switch (pmodel->apply_order[i].type)
		{
        case FMCEngineStart:
            current_engine = pmodel->apply_order[i].index;

    		if (pmodel->fman[index].handle) {
    			pmodel->fman[index].handle = FM_Open(pmodel->fman[current_engine].number);
    			if (pmodel->fman[index].handle == NULL) {
    				fmc_log_write( LOG_ERR, "Invocation of 'FM_Open' for %s failed", pmodel->fman[index].name );
    				return 1;
    			}
    		}

    		fmPcdParams.h_Fm = pmodel->fman[current_engine].handle;
    		if (pmodel->fman[index].pcd_handle) {
    			pmodel->fman[index].pcd_handle = FM_PCD_Open(&fmPcdParams);
    			if (pmodel->fman[index].pcd_handle == NULL) {
    				fmc_log_write( LOG_ERR, "Invocation of 'FM_PCD_Open' for %s failed", pmodel->fman[index].pcd_name );
    				return 1;
    			}
    		}

    		for (j = 0; j < pmodel->fman[index].reasm_count; j++)
    		{
    			if (pmodel->fman[index].reasm_handle[j])
    				pmodel->fman[index].reasm_handle[j] = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->fman[index].reasm_devId[j]);
    		}

    		for (j = 0; j < pmodel->fman[index].frag_count; j++)
    		{
    			if (pmodel->fman[index].frag_handle[j])
    				pmodel->fman[index].frag_handle[j] = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->fman[index].frag_devId[j]);
    		}
            break;

        case FMCEngineEnd:
        	break;

        case FMCPortStart:
        	current_port = pmodel->apply_order[i].index;

    	    fmPortParam.h_Fm     = pmodel->fman[current_engine].handle;
    	    fmPortParam.portId   = pmodel->port[index].number;
    	    fmPortParam.portType = pmodel->port[index].type;

    	    if (pmodel->port[index].handle) {
    			pmodel->port[index].handle = FM_PORT_Open(&fmPortParam);
    			if (pmodel->port[index].handle == NULL) {
    				fmc_log_write( LOG_ERR, "Invocation of 'FM_PORT_Open' for %s failed", pmodel->port[index].name );
    				return 1;
    			}
    	    }

    	    if (pmodel->port[index].env_id_handle)
    			pmodel->port[index].env_id_handle = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->port[index].env_id_devId);
        	break;

        case FMCPortEnd:
        	break;

        case FMCScheme:
    		if (pmodel->scheme_handle[index])
    			pmodel->scheme_handle[index] = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->scheme_devId[index]);
        	break;

        case FMCCCNode:
    		if (pmodel->ccnode_handle[index])
    			pmodel->ccnode_handle[index] = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->ccnode_devId[index]);
        	break;

        case FMCHTNode:
    		if (pmodel->htnode_handle[index])
    			pmodel->htnode_handle[index] = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->htnode_devId[index]);
        	break;

#if (DPAA_VERSION >= 11)
		case FMCReplicator:
			if (pmodel->replicator_handle[index])
				pmodel->replicator_handle[index] = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->replicator_devId[index]);
			break;
#endif /* (DPAA_VERSION >= 11) */

		case FMCCCTree:
			if (pmodel->port[index].cctree_handle)
				pmodel->port[index].cctree_handle = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->port[index].cctree_devId);
			break;

		case FMCPolicer:
			if (pmodel->policer_handle[index])
				pmodel->policer_handle[index] = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->policer_devId[index]);
			break;

		case FMCManipulation:
			if (pmodel->fman[current_engine].hdr_handle[index])
				pmodel->fman[current_engine].hdr_handle[index] = CreateDevice(pmodel->fman[current_engine].pcd_handle, pmodel->fman[current_engine].hdr_devId[index]);
			break;

		default:
			break;
		}
	}

	return 0;
}

void fmc_release( fmc_model* pmodel )
{
	int i, j, k;
	unsigned int index;
	unsigned int current_engine = 0;
	unsigned int current_port = 0;

	for (k = 0; k < pmodel->apply_order_count; k++) {

		/* Clean entities in reverse order of applying */
        i = pmodel->apply_order_count - k - 1;
		index = pmodel->apply_order[i].index;

		switch (pmodel->apply_order[i].type)
		{
		case FMCEngineStart:
			current_engine = pmodel->apply_order[i].index;

			for (j = 0; j < pmodel->fman[index].reasm_count; j++)
			{
				if (pmodel->fman[index].reasm_handle[j])
					ReleaseDevice(pmodel->fman[index].reasm_handle[j]);
			}

			for (j = 0; j < pmodel->fman[index].frag_count; j++)
			{
				if (pmodel->fman[index].frag_handle[j])
					ReleaseDevice(pmodel->fman[index].frag_handle[j]);
			}

			if (pmodel->fman[index].pcd_handle)
				FM_PCD_Close(pmodel->fman[index].pcd_handle);

			if (pmodel->fman[index].handle)
				FM_Close(pmodel->fman[index].handle);
			break;

		case FMCEngineEnd:
			break;

		case FMCPortStart:
			current_port = pmodel->apply_order[i].index;

			if (pmodel->port[index].env_id_handle)
				ReleaseDevice(pmodel->port[index].env_id_handle);

			if (pmodel->port[index].handle)
				FM_PORT_Close(pmodel->port[index].handle);
			break;

		case FMCPortEnd:
			break;

		case FMCScheme:
			if (pmodel->scheme_handle[index])
				ReleaseDevice(pmodel->scheme_handle[index]);
			break;

		case FMCCCNode:
			if (pmodel->ccnode_handle[index])
				ReleaseDevice(pmodel->ccnode_handle[index]);
			break;

		case FMCHTNode:
			if (pmodel->htnode_handle[index])
				ReleaseDevice(pmodel->htnode_handle[index]);
			break;

#if (DPAA_VERSION >= 11)
		case FMCReplicator:
			if (pmodel->replicator_handle[index])
				ReleaseDevice(pmodel->replicator_handle[index]);
			break;
#endif /* (DPAA_VERSION >= 11) */

		case FMCCCTree:
			if (pmodel->port[index].cctree_handle)
				ReleaseDevice(pmodel->port[index].cctree_handle);
			break;

		case FMCPolicer:
			if (pmodel->policer_handle[index])
				ReleaseDevice(pmodel->policer_handle[index]);
			break;

		case FMCManipulation:
			if (pmodel->fman[current_engine].hdr_handle[index])
				ReleaseDevice(pmodel->fman[current_engine].hdr_handle[index]);
			break;

		default:
			break;
        }
    }
}

bool fmc_load( fmc_model* pmodel )
{
    int res = 0;

    std::ifstream ifs( TMPFILENAME,
        std::ios::in | std::ios::binary );

    if ( !ifs ) {
        return false;
    }

    ifs.read( (char*)pmodel, sizeof( *pmodel ) );
    ifs.close();

	//Recreate old Linux device handles in the context of the current process:
	res = createDevices( pmodel );
	if (res != 0)
		return false;

    return true;
}

bool fmc_save( fmc_model* pmodel )
{
	// Remove FMC data file entirely if model was passed as NULL
	if (pmodel == NULL) {
		int err = std::remove(TMPFILENAME);
		if (err) {
			fmc_log_write( LOG_ERR, "Cannot remove file %s", TMPFILENAME );
			return false;
		}
		return true;
	}

    std::ofstream ofs( TMPFILENAME,
        std::ios::out | std::ios::binary | std::ios::trunc );

    if ( !ofs ) {
        fmc_log_write( LOG_ERR, "Can't open file %s", TMPFILENAME );
        return false;
    }

    ofs.write( (char*)pmodel, sizeof( *pmodel ) );
    ofs.close();

    return true;
}


#ifdef __cplusplus
} // extern "C"
#endif

