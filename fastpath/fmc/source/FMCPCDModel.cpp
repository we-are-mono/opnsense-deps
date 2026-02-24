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
 * File Name : FMCPCDModel.cpp
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#include <assert.h>
#include <string>
#include <string.h>
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include <functional>
#include "FMCTaskDef.h"
#include "FMCPCDModel.h"

#define UNKNOWN_NetCommField 0xFFFFFFFF


unsigned int
FMBlock::assignIndex( std::vector< Engine >& engines )
{
    engines.push_back( Engine() );
    unsigned int index = engines.size() - 1;
    engines[index].index = index;

    return index;
}


unsigned int
FMBlock::assignIndex( std::vector< Port >& ports )
{
    ports.push_back( Port() );
    unsigned int index = ports.size() - 1;
    ports[index].index = index;

    return index;
}


unsigned int
FMBlock::assignIndex( std::vector< Scheme >& schemes )
{
    schemes.push_back( Scheme() );
    unsigned int index = schemes.size() - 1;
    schemes[index].index = index;

    return index;
}


unsigned int
FMBlock::assignIndex( std::vector< CCNode >& ccnodes )
{
    ccnodes.push_back( CCNode() );
    unsigned int index = ccnodes.size() - 1;
    ccnodes[index].index = index;

    return index;
}

unsigned int
FMBlock::assignIndex( std::vector< HTNode >& htnodes )
{
    htnodes.push_back( HTNode() );
    unsigned int index = htnodes.size() - 1;
    htnodes[index].index = index;

    return index;
}

unsigned int
FMBlock::assignIndex( std::vector< CRepl >& repls )
{
    repls.push_back( CRepl() );
    unsigned int index = repls.size() - 1;
    repls[index].index = index;

    return index;
}


unsigned int
FMBlock::assignIndex( std::vector< Policer >& policers )
{
    policers.push_back( Policer() );
    unsigned int index = policers.size() - 1;
    policers[index].index = index;

    return index;
}


////////////////////////////////////////////////////////////////////////////////
/// Default constructor
////////////////////////////////////////////////////////////////////////////////
CFMCModel::CFMCModel()
{
    // Do the placement reservation to prevent containers' memory
    // reallocation and garantee validity of the pointers
    all_engines.reserve( MAX_ENGINES );
    all_ports.reserve( MAX_ENGINES*MAX_PORTS );
    all_schemes.reserve( MAX_ENGINES*MAX_SCHEMES );
    all_policers.reserve( MAX_ENGINES*MAX_POLICERS );
    all_ccnodes.reserve( MAX_ENGINES*MAX_CCNODES );
    all_htnodes.reserve( MAX_ENGINES*MAX_CCNODES );
    all_replicators.reserve( MAX_ENGINES*MAX_REPLICATORS );
    spEnable = 0;
}


HTNode&
CFMCModel::replicateHtNodes(const CTaskDef* pTaskDef, Port& port, HTNode& refnode)
{
    uint32_t ii;
    uint32_t index;

    for( ii = 0; ii < port.htnodes.size(); ii++) {
	if (all_htnodes[port.htnodes[ii]].name == refnode.name) {
		return all_htnodes[ii];
	}
    }

    HTNode& htNode = all_htnodes[FMBlock::assignIndex( all_htnodes )];
    ApplyOrder::Entry n1( ApplyOrder::HTNode, htNode.getIndex() );
    applier.add_edge( n1, ApplyOrder::Entry( ApplyOrder::None, 0 ) );
    port.htnodes.push_back(htNode.getIndex() );

    htNode.name = refnode.name;
    htNode.maxNumOfKeys = refnode.maxNumOfKeys;
    htNode.statistics = refnode.statistics;
    htNode.hashResMask = refnode.hashResMask;
    htNode.matchKeySize = refnode.matchKeySize;
    htNode.hashShift = refnode.hashShift;
    htNode.kgHashShift = refnode.kgHashShift;
    htNode.externalHash = refnode.externalHash;
    htNode.agingSupport = refnode.agingSupport;
    for (ii = 0; ii < refnode.keys.size(); ii++) {
    	htNode.keys.push_back(HTNode::CCData());
    }
    for (ii = 0; ii < refnode.masks.size(); ii++) {
    	htNode.masks.push_back(HTNode::CCData());
    }
    for (ii = 0; ii < refnode.nextEngines.size(); ii++) {
    	htNode.nextEngines.push_back(HTNode::CCNextEngine());
    }

    for (ii = 0; ii < refnode.frag.size(); ii++) {
	index = refnode.frag[ii];
	htNode.frag.push_back(index);
    }
    for (ii = 0; ii < refnode.header.size(); ii++) {
	index = refnode.header[ii];
    	htNode.header.push_back(index);
    }
    for (ii = 0; ii < refnode.indices.size(); ii++) {
	index = refnode.indices[ii];
    	htNode.indices.push_back(index);
    }

    htNode.nextEngineOnMiss = refnode.nextEngineOnMiss;
    htNode.fragOnMiss = refnode.fragOnMiss;
    htNode.headerOnMiss = refnode.headerOnMiss;
    htNode.port_signature = port.name;

    ApplyOrder::Entry root( ApplyOrder::CCTree, port.getIndex() );

    port.cctrees.push_back( htNode.getIndex() );
    port.cctrees_type.push_back( e_FM_PCD_HASH );
    port.hdrmanips.push_back( 0 );
    return htNode;
}

CCNode&
CFMCModel::replicateCCNodes(const CTaskDef* pTaskDef, Port& port, CCNode& refnode)
{
    uint32_t ii;
    uint32_t index;

    CCNode& ccNode = all_ccnodes[FMBlock::assignIndex( all_ccnodes )];

    ApplyOrder::Entry n1( ApplyOrder::CCNode, ccNode.getIndex() );
    applier.add_edge( n1, ApplyOrder::Entry( ApplyOrder::None, 0 ) );

    port.ccnodes.push_back(ccNode.getIndex() );

    ccNode.name = refnode.name;
    ccNode.maxNumOfKeys = refnode.maxNumOfKeys;
    ccNode.statistics = refnode.statistics;
    ccNode.maskSupport = refnode.maskSupport;
    ccNode.shared = 0;
    ccNode.extract = refnode.extract;
    ccNode.keySize = refnode.keySize;
    ccNode.used_protocols.insert(refnode.used_protocols.begin(), refnode.used_protocols.end());
    for (ii = 0; ii < refnode.keys.size(); ii++) {
    	ccNode.keys.push_back(CCNode::CCData());
    }
    for (ii = 0; ii < refnode.masks.size(); ii++) {
    	ccNode.masks.push_back(CCNode::CCData());
    }
    for (ii = 0; ii < refnode.nextEngines.size(); ii++) {
    	ccNode.nextEngines.push_back(CCNode::CCNextEngine());
    }
    for (ii = 0; ii < refnode.frag.size(); ii++) {
	index = refnode.frag[ii];
	ccNode.frag.push_back(index);
    }
    for (ii = 0; ii < refnode.header.size(); ii++) {
	index = refnode.header[ii];
    	ccNode.header.push_back(index);
    }
    for (ii = 0; ii < refnode.indices.size(); ii++) {
	index = refnode.indices[ii];
    	ccNode.indices.push_back(index);
    }
    for (ii = 0; ii < refnode.frameLength.size(); ii++) {
	index = refnode.frameLength[ii];
    	ccNode.frameLength.push_back(index);
    }
    ccNode.nextEngineOnMiss = refnode.nextEngineOnMiss;
    ccNode.fragOnMiss = refnode.fragOnMiss;
    ccNode.headerOnMiss = refnode.headerOnMiss;
    ccNode.port_signature = port.name;
    port.cctrees.push_back( ccNode.getIndex() );
    port.cctrees_type.push_back( e_FM_PCD_CC );
    port.hdrmanips.push_back( 0 );
    return ccNode;
}


////////////////////////////////////////////////////////////////////////////////
/// Create model by building the internal database
////////////////////////////////////////////////////////////////////////////////
bool
CFMCModel::createModel( CTaskDef* pTaskDef )
{
    uint32_t ii;
    uint32_t jj;
    assert( pTaskDef );

    // For all engines
    std::map< std::string, CEngine >::iterator engIt;
    for ( engIt = pTaskDef->engines.begin();
          engIt != pTaskDef->engines.end();
          ++engIt ) {

        Engine& engine = createEngine( engIt->second, pTaskDef );

        applier.add( ApplyOrder::Entry( ApplyOrder::EngineEnd, engine.getIndex() ) );

        // For all ports of this engine
        std::vector< CPort >::iterator portIt;
        for ( portIt = engIt->second.ports.begin();
              portIt != engIt->second.ports.end();
              ++portIt ) {

            // Find the policy
            std::map< std::string, CPolicy >::iterator policyIt =
                pTaskDef->policies.find( portIt->policy );
            if ( policyIt == pTaskDef->policies.end() ) {
                throw CGenericError( ERR_POLICY_NOT_FOUND, portIt->policy,
                                     portIt->type, portIt->number );
            }

            Port& port      = createPort( engine, *portIt, pTaskDef );

            applier.add( ApplyOrder::Entry( ApplyOrder::PortEnd, port.getIndex() ) );

            // For all distributions in this policy
            std::vector< std::string >::reverse_iterator distRefIt;
            uint8_t           scheme_index = 0;
            ApplyOrder::Entry prev_entry( ApplyOrder::Scheme, 0 );
            for ( distRefIt = policyIt->second.dist_order.rbegin();
                  distRefIt != policyIt->second.dist_order.rend();
                  ++distRefIt, ++scheme_index ) {
                unsigned int index = get_scheme_index( pTaskDef,
                    *distRefIt, policyIt->first, port, false );

                // To keep relative order of the distribution inside the policy
                // add dependency edge between previous and current dist
                if ( distRefIt == policyIt->second.dist_order.rbegin() ) {
                    prev_entry.index = index;
                }
                else {
                    ApplyOrder::Entry cur_entry( ApplyOrder::Scheme, index );
                    applier.add_edge( prev_entry, cur_entry );
                    prev_entry.index = index;
                }

                Scheme& scheme = all_schemes[index];
                scheme.scheme_index_per_port = scheme_index;
		if (scheme.shared && (port.name != scheme.port_signature)) {
			 if (scheme.nextEngine == e_FM_PCD_CC) {
                         	std::map< std::string, CClassification >::const_iterator nodeIt;
                                nodeIt = pTaskDef->classifications.find(scheme.nextActionName);
                                if ( nodeIt == pTaskDef->classifications.end() ) {
                        	        throw CGenericError( ERR_CC_NOT_FOUND, scheme.nextActionName,
                                		scheme.name );
                                }
                                if ( nodeIt->second.key.hashTable ) {
                                	HTNode& refnode = all_htnodes[scheme.actionHandleIndex];
                                	CFMCModel::replicateHtNodes(pTaskDef, port, refnode);
                                } else {
                                	CCNode& refnode = all_ccnodes[scheme.actionHandleIndex];
                                	CFMCModel::replicateCCNodes(pTaskDef, port, refnode);
                                }
                	}
		}

                // Add scheme's protocols to the port's protocol list
                std::set< Protocol >::iterator protoIt;
                for ( protoIt  = scheme.used_protocols.begin();
                      protoIt != scheme.used_protocols.end();
                      ++protoIt ) {
                          // Just add an empty element - the real header will be filled in later
                          std::pair< unsigned int, DistinctionUnitElement > empty_element;
                          empty_element.first         = 0;
                          empty_element.second.hdr    = HEADER_TYPE_NONE;
                          empty_element.second.hdrStr = "HEADER_TYPE_NONE";

                          port.protocols[*protoIt] = empty_element;
                }
            }

            for ( unsigned int schIndex = 0; schIndex < all_schemes.size(); schIndex++ ) {
                if (all_schemes[schIndex].scheme_index_per_port == -1) {
                    all_schemes[schIndex].scheme_index_per_port = scheme_index++;
                }
            }

            if ( !port.cctrees.empty() || port.reasm_index != 0 ) {
                applier.add_edge( ApplyOrder::Entry( ApplyOrder::CCTree, port.getIndex() ),
                                  ApplyOrder::Entry( ApplyOrder::None, 0 ) );
            }

            applier.sort();

            // Enumerate and fill used protocols
            std::map< Protocol, std::pair< unsigned int, DistinctionUnitElement > >::iterator protoIt;
            unsigned int i;
            for ( protoIt  = port.protocols.begin(), i = 0;
                  protoIt != port.protocols.end();
                  ++protoIt, ++i ) {
                protoIt->second.first      = i;
                protoIt->second.second.hdr = getNetCommHeaderType( protoIt->first.name );
                protoIt->second.second.opt = protoIt->first.opt;
                if ( protoIt->second.second.hdr == HEADER_TYPE_NONE ) {
                    std::string shim_protocol = pTaskDef->getShimNoFromCustom( protoIt->first.name );
                    if ( !shim_protocol.empty() ) { // Shim header is empty if custom protocol is not found
                        protoIt->second.second.hdr = getNetCommHeaderType( shim_protocol );
                    }
                    else {
                        // Header type HEADER_TYPE_NONE is not accepted as a valid value
                        throw CGenericError( ERR_UNKNOWN_PROTOCOL, protoIt->first.name );
                    }
                }
                protoIt->second.second.hdrStr = getNetCommHeaderTypeStr( protoIt->second.second.hdr );
            }

            applier.add( ApplyOrder::Entry( ApplyOrder::PortStart, port.getIndex() ) );
            engine.offload_support = (unsigned int)(engine.offload_support || port.replicators.size());
        }

#ifndef P1023
        std::map< std::string, CHeaderManip >::iterator manipIt;
        unsigned int idx = 0;
        for ( manipIt = pTaskDef->headermanips.begin(); manipIt != pTaskDef->headermanips.end(); ++manipIt ) {
            if ( manipIt->second.nextManip == "" ) {
                engine.headerManips_hasNext[engine.getHeaderManipIndex(engine.name + "/hdr/" + manipIt->second.name)] = 0;
                applier.add_edge(ApplyOrder::Entry(ApplyOrder::Manipulation, engine.getHeaderManipIndex(engine.name + "/hdr/" + manipIt->second.name)), ApplyOrder::Entry(ApplyOrder::None, 0));
            }
            else {
                applier.add_edge(ApplyOrder::Entry(ApplyOrder::Manipulation, engine.getHeaderManipIndex(engine.name + "/hdr/" + manipIt->second.name)), ApplyOrder::Entry(ApplyOrder::Manipulation, engine.getHeaderManipIndex(engine.name + "/hdr/" + manipIt->second.nextManip)));
                engine.headerManips_hasNext[engine.getHeaderManipIndex(engine.name + "/hdr/" + manipIt->second.name)] = 1;
                engine.headerManips_nextNanip[engine.getHeaderManipIndex(engine.name + "/hdr/" + manipIt->second.name)] = engine.getHeaderManipIndex(engine.name + "/hdr/" + manipIt->second.nextManip);
            }
        }
#endif // P1023

        applier.sort();

        applier.add( ApplyOrder::Entry( ApplyOrder::EngineStart, engine.getIndex() ) );
        createSoftParse( pTaskDef );
    }

    applier.reverse_port_apply_order();

    return true;
}


////////////////////////////////////////////////////////////////////////////////
/// Converts engine parameters provided throught XML file to the internal
/// structure
////////////////////////////////////////////////////////////////////////////////
Engine&
CFMCModel::createEngine( const CEngine& xmlEngine, const CTaskDef* pTaskDef )
{
    assert( xmlEngine.name.length() > 2 );

    Engine& engine = all_engines[FMBlock::assignIndex( all_engines )];

    engine.name            = xmlEngine.name;
    engine.number          = std::strtoul( xmlEngine.name.c_str() + 2, 0, 0 );
    engine.pcd_name        = engine.name + "/pcd";
    engine.offload_support = xmlEngine.offload_support;
	engine.kg_payload_offset = xmlEngine.kg_payload_offset;

#ifndef P1023
    std::map< std::string, CReassembly >::const_iterator reasmit;
    for ( reasmit = pTaskDef->reassemblies.begin(); reasmit != pTaskDef->reassemblies.end(); ++reasmit ) {
        t_FmPcdManipParams reasm;

        reasm.h_NextManip = 0;
        reasm.type = e_FM_PCD_MANIP_REASSEM;
        reasm.u.reassem.hdr                                          = HEADER_TYPE_IPv6;
        reasm.u.reassem.u.ipReassem.maxNumFramesInProcess            = reasmit->second.maxInProcess;
#if (DPAA_VERSION >= 11)
        reasm.u.reassem.u.ipReassem.nonConsistentSpFqid              = reasmit->second.nonConsistentSpFqid;
#else
        reasm.u.reassem.u.ipReassem.sgBpid                           = reasmit->second.sgBpid;
#endif /* (DPAA_VERSION >= 11) */
        reasm.u.reassem.u.ipReassem.dataLiodnOffset                  = reasmit->second.dataLiodnOffset;
        reasm.u.reassem.u.ipReassem.dataMemId                        = reasmit->second.dataMemId;
        reasm.u.reassem.u.ipReassem.minFragSize[0]                   = reasmit->second.ipv4minFragSize;
        reasm.u.reassem.u.ipReassem.minFragSize[1]                   = reasmit->second.ipv6minFragSize;
        reasm.u.reassem.u.ipReassem.timeOutMode                      = (e_FmPcdManipReassemTimeOutMode)reasmit->second.timeOutMode;
        reasm.u.reassem.u.ipReassem.fqidForTimeOutFrames             = reasmit->second.fqidForTimeOutFrames;
        reasm.u.reassem.u.ipReassem.numOfFramesPerHashEntry[0]       = (e_FmPcdManipReassemWaysNumber)reasmit->second.numOfFramesPerHashEntry[0];
        reasm.u.reassem.u.ipReassem.numOfFramesPerHashEntry[1]       = (e_FmPcdManipReassemWaysNumber)reasmit->second.numOfFramesPerHashEntry[1];
        reasm.u.reassem.u.ipReassem.timeoutThresholdForReassmProcess = reasmit->second.timeoutThreshold;

        engine.reasm.push_back( reasm );
        engine.reasm_names.push_back( engine.name + "/reasm/" + reasmit->second.name );
    }

    std::map< std::string, CFragmentation >::const_iterator fragit;
    for ( fragit = pTaskDef->fragmentations.begin(); fragit != pTaskDef->fragmentations.end(); ++fragit ) {
        t_FmPcdManipParams frag;
        frag.h_NextManip                          = 0;
        frag.type                                 = e_FM_PCD_MANIP_FRAG;
        frag.u.frag.hdr                           = HEADER_TYPE_IPv6;
        frag.u.frag.u.ipFrag.sizeForFragmentation = fragit->second.size;
#if (DPAA_VERSION == 10)
        frag.u.frag.u.ipFrag.scratchBpid          = fragit->second.scratchBpid;
#endif /* (DPAA_VERSION == 10) */
#ifdef FM_EXP_FEATURES
        frag.u.frag.u.ipFrag.optionsCounterEn     = fragit->second.optionsCounterEn;
#endif /* FM_EXP_FEATURES */
        frag.u.frag.u.ipFrag.dontFragAction       = (e_FmPcdManipDontFragAction)
                                                    fragit->second.dontFragAction;
        frag.u.frag.u.ipFrag.sgBpid               = fragit->second.sgBpid;
        frag.u.frag.u.ipFrag.sgBpidEn             = fragit->second.sgBpidEn;

        engine.frags.push_back( frag );
        engine.frag_names.push_back( engine.name + "/frag/" + fragit->second.name );
    }

    std::map< std::string, CHeaderManip >::const_iterator headerit;
    for ( headerit = pTaskDef->headermanips.begin(); headerit != pTaskDef->headermanips.end(); ++headerit ) {
        t_FmPcdManipParams hdr;
        Engine::CInsertData insertData;
        hdr.h_NextManip                                         = 0;
        hdr.type                                                = e_FM_PCD_MANIP_HDR;

        hdr.u.hdr.insrt = headerit->second.insert || headerit->second.insertHeader;
        hdr.u.hdr.rmv   = headerit->second.remove || headerit->second.removeHeader;
        hdr.u.hdr.fieldUpdate = headerit->second.update;
        hdr.u.hdr.custom   = headerit->second.custom;
        hdr.u.hdr.dontParseAfterManip = !headerit->second.parse;

        if ( hdr.u.hdr.insrt )
        {
            if (headerit->second.insertHeader)
            {
                hdr.u.hdr.insrtParams.type              = e_FM_PCD_MANIP_INSRT_BY_HDR;
                hdr.u.hdr.insrtParams.u.byHdr.type      = e_FM_PCD_MANIP_INSRT_BY_HDR_SPECIFIC_L2;

                if (headerit->second.hdrInsertHeader[0].type == "mpls")
                    hdr.u.hdr.insrtParams.u.byHdr.u.specificL2Params.specificL2 = e_FM_PCD_MANIP_HDR_INSRT_MPLS;
                else
                     throw CGenericError( ERR_HDR_INSERTPROTOCOL, headerit->second.name );

                hdr.u.hdr.insrtParams.u.byHdr.u.specificL2Params.update = headerit->second.hdrInsertHeader[0].update || headerit->second.hdrInsertHeader[1].update;

                hdr.u.hdr.insrtParams.u.byHdr.u.specificL2Params.size = headerit->second.hdrInsertHeader[0].size + headerit->second.hdrInsertHeader[1].size;
                
                for ( unsigned int j = 0; j < headerit->second.hdrInsertHeader[0].size; ++j ) {
                    insertData.data[j] =
                        headerit->second.hdrInsertHeader[0].data[FM_PCD_MAX_SIZE_OF_KEY - ( headerit->second.hdrInsertHeader[0].size ) + j];
                }

                for (unsigned int field = 0; field < headerit->second.hdrInsertHeader[0].fields.size(); field++)
                {
                    if (headerit->second.hdrInsertHeader[0].fields[field].type == "ttl")
                    {
                    }
                }

                for ( unsigned int j = headerit->second.hdrInsertHeader[0].size; j < headerit->second.hdrInsertHeader[0].size + headerit->second.hdrInsertHeader[1].size; ++j ) {
                    insertData.data[j] =
                        headerit->second.hdrInsertHeader[1].data[FM_PCD_MAX_SIZE_OF_KEY - ( headerit->second.hdrInsertHeader[0].size + headerit->second.hdrInsertHeader[1].size ) + j];
                }
            }
            else
            {
                hdr.u.hdr.insrtParams.type              = e_FM_PCD_MANIP_INSRT_GENERIC;
                hdr.u.hdr.insrtParams.u.generic.size    = headerit->second.hdrInsert.size;
                hdr.u.hdr.insrtParams.u.generic.offset  = headerit->second.hdrInsert.offset;
                hdr.u.hdr.insrtParams.u.generic.replace = headerit->second.hdrInsert.replace;

                for ( unsigned int j = 0; j < headerit->second.hdrInsert.size; ++j ) {
                    insertData.data[j] =
                        headerit->second.hdrInsert.data[MAX_INSERT_SIZE - headerit->second.hdrInsert.size + j];
                }
            }
            
        }
       
        if ( hdr.u.hdr.rmv )
        {
            if (headerit->second.removeHeader)
            {
                hdr.u.hdr.rmvParams.type             = e_FM_PCD_MANIP_RMV_BY_HDR;
                hdr.u.hdr.rmvParams.u.byHdr.type     = e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2;
                hdr.u.hdr.rmvParams.u.byHdr.u.specificL2 = getSpecificL2ByString(headerit->second.hdrRemoveHeader.type);
            }
            else
            {
                hdr.u.hdr.rmvParams.type             = e_FM_PCD_MANIP_RMV_GENERIC;
                hdr.u.hdr.rmvParams.u.generic.size   = headerit->second.hdrRemove.size;
                hdr.u.hdr.rmvParams.u.generic.offset = headerit->second.hdrRemove.offset;
            }
        }

        if ( hdr.u.hdr.custom )
        {
            hdr.u.hdr.customParams.type = e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE;
            hdr.u.hdr.customParams.u.ipHdrReplace.updateIpv4Id = headerit->second.hdrCustom.updateIpv4Id;
            hdr.u.hdr.customParams.u.ipHdrReplace.id = headerit->second.hdrCustom.id;
            if (headerit->second.hdrCustom.type == "ipv4" || headerit->second.hdrCustom.type == "ipv4byipv6")
            {
                hdr.u.hdr.customParams.u.ipHdrReplace.replaceType = e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV4_BY_IPV6;
                hdr.u.hdr.customParams.u.ipHdrReplace.updateIpv4Id = false;
                hdr.u.hdr.customParams.u.ipHdrReplace.id = 0;
            }else if (headerit->second.hdrCustom.type == "ipv6" || headerit->second.hdrCustom.type == "ipv6byipv4")
            {
                hdr.u.hdr.customParams.u.ipHdrReplace.replaceType = e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4;
            }
            hdr.u.hdr.customParams.u.ipHdrReplace.hdrSize = headerit->second.hdrCustom.size;
            hdr.u.hdr.customParams.u.ipHdrReplace.decTtlHl = headerit->second.hdrCustom.decTtl || headerit->second.hdrCustom.decHl;

            std::string data = stripBlanks( headerit->second.hdrCustom.data );
            if ( data.length() > FM_PCD_MANIP_MAX_HDR_SIZE*2 + 2 || data.substr( 0, 2 ) != "0x" ) {
                throw CGenericError( ERR_INVALID_MANIP_DATA,
                                     headerit->second.name );
            }

            // Convert data to numeric array
            data = data.substr( 2 );
            int index = headerit->second.hdrCustom.size;
            while ( data.length() > 0 && index >= 1 ) {
                std::string tmp;
                if ( data.length() > 1 ) {
                    tmp  = "0x" + data.substr( data.length() - 2, 2 );
                    data = data.substr( 0, data.length() - 2 );
                }
                else {
                    tmp  = "0x" + data;
                    data = "";
                }
                hdr.u.hdr.customParams.u.ipHdrReplace.hdr[--index] = (uint8_t)std::strtol( tmp.c_str(), 0, 0 );
            }

        }

        if ( hdr.u.hdr.fieldUpdate )
        {
            hdr.u.hdr.fieldUpdateParams.type = getFieldUpdateTypeByString(headerit->second.hdrUpdate.type);

            //The update can have only one type of update in an header manipulation entry so I check only the first elements in the fields vector
            if (hdr.u.hdr.fieldUpdateParams.type == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN)
            {
                if (headerit->second.hdrUpdate.fields.size())
                {
                    if (headerit->second.hdrUpdate.fields[0].type == "vpri")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.vlan.updateType = e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN_VPRI;
                        hdr.u.hdr.fieldUpdateParams.u.vlan.u.vpri = (uint8_t)std::strtoul( headerit->second.hdrUpdate.fields[0].value.c_str(), 0, 0 );
                    }
                    
                    if (headerit->second.hdrUpdate.fields[0].type == "dscp")
                    {
                        //Fill in the default values
                        hdr.u.hdr.fieldUpdateParams.u.vlan.updateType = e_FM_PCD_MANIP_HDR_FIELD_UPDATE_DSCP_TO_VLAN;
                        hdr.u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.vpriDefVal = 0;
                        for (unsigned int i = 0; i < FM_PCD_MANIP_DSCP_TO_VLAN_TRANS; i++)
                            hdr.u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable[i] = 0;

                        for (unsigned int i = 0; i < headerit->second.hdrUpdate.fields.size(); i++)
                        {
                            if (headerit->second.hdrUpdate.fields[i].fill)
                            {
                                for (unsigned int idx = 0; idx < FM_PCD_MANIP_DSCP_TO_VLAN_TRANS; idx++)
                                    hdr.u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable[idx] = (uint8_t)headerit->second.hdrUpdate.fields[i].fillValue;
                            }

                            if (headerit->second.hdrUpdate.fields[i].defVal)
                                hdr.u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.vpriDefVal = headerit->second.hdrUpdate.fields[i].vpriDefVal;
                        }

                        for (unsigned int i = 0; i < headerit->second.hdrUpdate.fields.size(); i++)
                        {
                            if (!headerit->second.hdrUpdate.fields[i].fill)
                            {
                                hdr.u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable[headerit->second.hdrUpdate.fields[i].index] = (uint8_t)std::strtoul( headerit->second.hdrUpdate.fields[i].value.c_str(), 0, 0 );
                            }
                        }
                    }
                }
            }

            if (hdr.u.hdr.fieldUpdateParams.type == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4)
            {
                hdr.u.hdr.fieldUpdateParams.u.ipv4.validUpdates = 0;
                for (unsigned int i = 0; i < headerit->second.hdrUpdate.fields.size();i++)
                {
                    if (headerit->second.hdrUpdate.fields[i].type == "tos")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.validUpdates |= HDR_MANIP_IPV4_TOS;
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.tos = (uint8_t)std::strtoul( headerit->second.hdrUpdate.fields[0].value.c_str(), 0, 0 );
                    }
                    
                    if (headerit->second.hdrUpdate.fields[i].type == "id")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.validUpdates |= HDR_MANIP_IPV4_ID;
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.id = (uint16_t)std::strtoul( headerit->second.hdrUpdate.fields[0].value.c_str(), 0, 0 );
                    }

                    if (headerit->second.hdrUpdate.fields[i].type == "ttl")
                    {
                        //No value required
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.validUpdates |= HDR_MANIP_IPV4_TTL;
                    }

                    if (headerit->second.hdrUpdate.fields[i].type == "src")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.validUpdates |= HDR_MANIP_IPV4_SRC;
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.src = (uint32_t)std::strtoul( headerit->second.hdrUpdate.fields[0].value.c_str(), 0, 0 );
                    }

                    if (headerit->second.hdrUpdate.fields[i].type == "dst")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.validUpdates |= HDR_MANIP_IPV4_DST;
                        hdr.u.hdr.fieldUpdateParams.u.ipv4.dst = (uint32_t)std::strtoul( headerit->second.hdrUpdate.fields[0].value.c_str(), 0, 0 );
                    }
                }
            }

            if (hdr.u.hdr.fieldUpdateParams.type == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6)
            {
                hdr.u.hdr.fieldUpdateParams.u.ipv6.validUpdates = 0;
                for (unsigned int i = 0; i < headerit->second.hdrUpdate.fields.size(); i++)
                {
                    if (headerit->second.hdrUpdate.fields[i].type == "tc")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.ipv6.validUpdates |= HDR_MANIP_IPV6_TC;
                        hdr.u.hdr.fieldUpdateParams.u.ipv6.trafficClass = (uint8_t)std::strtoul( headerit->second.hdrUpdate.fields[0].value.c_str(), 0, 0 );
                    }
                    
                    if (headerit->second.hdrUpdate.fields[i].type == "hl")
                    {
                        //No value required
                        hdr.u.hdr.fieldUpdateParams.u.ipv6.validUpdates |= HDR_MANIP_IPV6_HL;
                    }

                    if (headerit->second.hdrUpdate.fields[i].type == "src")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.ipv6.validUpdates |= HDR_MANIP_IPV6_SRC;

                        std::string data = stripBlanks( headerit->second.hdrUpdate.fields[i].value );
                        if ( data.length() != 34 || data.substr( 0, 2 ) != "0x" ) {
                            throw CGenericError( ERR_INVALID_ENTRY_DATA,
                                                 "update ipv6 src" );
                        }

                        // Convert data to numeric array
                        data = data.substr( 2 );
                        int index = NET_HEADER_FIELD_IPv6_ADDR_SIZE;
                        while ( data.length() > 0 && index >= 1 ) {
                            std::string tmp;
                            if ( data.length() > 1 ) {
                                tmp  = "0x" + data.substr( data.length() - 2, 2 );
                                data = data.substr( 0, data.length() - 2 );
                            }
                            else {
                                tmp  = "0x" + data;
                                data = "";
                            }
                            hdr.u.hdr.fieldUpdateParams.u.ipv6.src[--index] = (uint8_t)std::strtol( tmp.c_str(), 0, 0 );
                        }
                    }

                    if (headerit->second.hdrUpdate.fields[i].type == "dst")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.ipv6.validUpdates |= HDR_MANIP_IPV6_DST;

                        std::string data = stripBlanks( headerit->second.hdrUpdate.fields[i].value );
                        if ( data.length() != 34 || data.substr( 0, 2 ) != "0x" ) {
                            throw CGenericError( ERR_INVALID_MANIP_DATA,
                                headerit->second.name );
                        }

                        // Convert data to numeric array
                        data = data.substr( 2 );
                        int index = NET_HEADER_FIELD_IPv6_ADDR_SIZE;
                        while ( data.length() > 0 && index >= 1 ) {
                            std::string tmp;
                            if ( data.length() > 1 ) {
                                tmp  = "0x" + data.substr( data.length() - 2, 2 );
                                data = data.substr( 0, data.length() - 2 );
                            }
                            else {
                                tmp  = "0x" + data;
                                data = "";
                            }
                            hdr.u.hdr.fieldUpdateParams.u.ipv6.dst[--index] = (uint8_t)std::strtol( tmp.c_str(), 0, 0 );
                        }
                    }
                }
            }

            if (hdr.u.hdr.fieldUpdateParams.type == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP)
            {
                hdr.u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates = 0;
                for (unsigned int i = 0; i < headerit->second.hdrUpdate.fields.size(); i++)
                {
                    if (headerit->second.hdrUpdate.fields[i].type == "checksum" || headerit->second.hdrUpdate.fields[i].type == "crc")
                    {
                        //No value required
                        hdr.u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates |= HDR_MANIP_TCP_UDP_CHECKSUM;
                    }
                    
                    if (headerit->second.hdrUpdate.fields[i].type == "src")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates |= HDR_MANIP_TCP_UDP_SRC;
                        hdr.u.hdr.fieldUpdateParams.u.tcpUdp.src = (uint16_t)std::strtoul( headerit->second.hdrUpdate.fields[0].value.c_str(), 0, 0 );
                    }

                    if (headerit->second.hdrUpdate.fields[i].type == "dst")
                    {
                        hdr.u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates |= HDR_MANIP_TCP_UDP_DST;
                        hdr.u.hdr.fieldUpdateParams.u.tcpUdp.dst = (uint16_t)std::strtoul( headerit->second.hdrUpdate.fields[0].value.c_str(), 0, 0 );
                    }
                }
            }
        }
        
        engine.headerManips.push_back( hdr );
        engine.insertDatas.push_back( insertData );
        engine.headerManips_names.push_back( engine.name + "/hdr/" + headerit->second.name );
        engine.headerManips_hasNext.push_back((bool)0);
        engine.headerManips_nextNanip.push_back(0);
    }
#endif /* P1023 */

    return engine;
}


////////////////////////////////////////////////////////////////////////////////
/// Converts Port parameters provided throught XML file to the internal
/// structure
////////////////////////////////////////////////////////////////////////////////
Port&
CFMCModel::createPort( Engine& engine, const CPort& xmlPort, const CTaskDef* pTaskDef )
{
    std::string tmp_xmlPort_type;
    unsigned int tmp_xmlPort_number;
    Port& port = all_ports[FMBlock::assignIndex( all_ports )];

    engine.ports.push_back( port.getIndex() );

    tmp_xmlPort_type = xmlPort.type;
    tmp_xmlPort_number = xmlPort.number;

    if (xmlPort.type == "MAC")
    {
        uint8_t lu_n[11] = {  255, 0,   1,   2,   3,   4,   5,   6,   7,   0,    1};
        const char* lu_t[11] =  { "ERR","1G","1G","1G","1G","1G","1G","1G","1G","10G","10G" };

        if(tmp_xmlPort_number > 10) tmp_xmlPort_number = 0;
        tmp_xmlPort_type = lu_t[tmp_xmlPort_number];
        tmp_xmlPort_number = lu_n[tmp_xmlPort_number];
    }

    port.type    = getPortType( tmp_xmlPort_type );
    port.typeStr = getPortTypeStr( port.type );
    std::ostringstream oss;
    oss << engine.name + "/port/" + xmlPort.type + "/" << xmlPort.number;
    port.name   = oss.str();
    port.number = tmp_xmlPort_number;
    port.portid = xmlPort.portid;

    port.reasm_index = 0;
    // Find port's corresponding policy
    CPolicy& policy = ((CTaskDef*)pTaskDef)->policies[xmlPort.policy];
    if ( !policy.reassemblyName.empty() ) {
        unsigned int reasm_index = 1;
        std::map< std::string, CReassembly >::const_iterator reasmit;
        for ( reasmit = pTaskDef->reassemblies.begin(); reasmit != pTaskDef->reassemblies.end(); ++reasmit ) {
            if ( reasmit->first == policy.reassemblyName ) {
                port.reasm_index = reasm_index;
                break;
            }
            ++reasm_index;
        }
    }

    return port;
}


////////////////////////////////////////////////////////////////////////////////
/// Converts Distribution parameters provided throught XML file to the internal
/// scheme structure
////////////////////////////////////////////////////////////////////////////////
Scheme&
CFMCModel::createScheme( const CTaskDef* pTaskDef, Port& port, const CDistribution& xmlDist,
                         bool isDirect )
{
    Scheme& scheme = all_schemes[FMBlock::assignIndex( all_schemes )];

    ApplyOrder::Entry n1( ApplyOrder::Scheme, scheme.getIndex() );
    applier.add_edge( n1, ApplyOrder::Entry( ApplyOrder::None, 0 ) );

	scheme.shared = xmlDist.shared;
	if ( scheme.shared ) {
		scheme.name = port.name.substr( 0, 3 ) + "/dist/" + xmlDist.name;
	} else {
		scheme.name = port.name + "/dist/" + xmlDist.name;
	}
    if ( isDirect ) {
        scheme.name = scheme.name + "/direct";
    }
    scheme.qbase                 = xmlDist.qbase;
    scheme.qcount                = xmlDist.qcount;
    scheme.bypass                = xmlDist.bypass;
    scheme.privateDflt0          = xmlDist.dflt0;
    scheme.privateDflt1          = xmlDist.dflt1;
    scheme.hashShift             = xmlDist.keyShift;
    scheme.symmetricHash         = xmlDist.symmetricHash;
    scheme.relativeSchemeId      = port.schemes.size() - 1;
    scheme.isDirect              = isDirect ? 1 : 0;
    scheme.scheme_index_per_port = -1;
    scheme.port_signature        = port.name;

    // For each 'key' entry
    for ( unsigned int i = 0; i < xmlDist.key.size(); ++i ) {
        ExtractData field;
        if ( xmlDist.key[i].name != "" ) {
            field.type       = e_FM_PCD_EXTRACT_BY_HDR;
            field.typeStr    = "e_FM_PCD_EXTRACT_BY_HDR";

            Protocol tProt;
            tProt.name =
                xmlDist.key[i].name.substr( 0, xmlDist.key[i].name.find_last_of( "." ) );
            tProt.opt = "";
            if ( scheme.isDirect == 0 ) {   // Only for inderect schemes
                scheme.used_protocols.insert( tProt );
            }

            field.fieldName  = xmlDist.key[i].name;
            field.hdrtype    = e_FM_PCD_EXTRACT_FULL_FIELD;
            field.hdrtypeStr = "e_FM_PCD_EXTRACT_FULL_FIELD";
            field.hdr        = getNetCommHeaderType( tProt.name );
            if ( field.hdr == HEADER_TYPE_NONE ) {
                std::string shim_protocol = pTaskDef->getShimNoFromCustom( tProt.name );
                if ( !shim_protocol.empty() ) { // Shim header is empty if a custom protocol is not found
                    field.hdrtype    = e_FM_PCD_EXTRACT_FROM_HDR;
                    field.hdrtypeStr = "e_FM_PCD_EXTRACT_FROM_HDR";
                    field.hdr = getNetCommHeaderType( shim_protocol );
                }
                else {
                    // Header type HEADER_TYPE_NONE is not accepted as a valid value
                    throw CGenericError( ERR_UNKNOWN_PROTOCOL, xmlDist.key[i].name );
                }
            }
            else {
                // Process unknown field of known header
                if ( getNetCommFieldType( field.fieldName ) == UNKNOWN_NetCommField ) {
                    field.hdrtype    = e_FM_PCD_EXTRACT_FROM_HDR;
                    field.hdrtypeStr = "e_FM_PCD_EXTRACT_FROM_HDR";
                }
            }
            field.hdrStr      = getNetCommHeaderTypeStr( field.hdr );
            field.hdrIndex    = getNetCommHeaderIndex( xmlDist.key[i].header_index );
            field.hdrIndexStr = getNetCommHeaderIndexStr( xmlDist.key[i].header_index );

            // Find the protocol and get the field's length
            unsigned int bitsize;
            unsigned int bitoffset;
            if ( pTaskDef->GetFieldProperties( field.fieldName,
                                               bitsize, bitoffset ) ) {
                field.size   = bitsize / 8;
                field.offset = bitoffset / 8;
            }

            field.fieldType    = getNetCommFieldType( field.fieldName );
            field.fieldTypeStr = getNetCommFieldTypeStr( field.fieldName );
        }
        else {
            field.type    = e_FM_PCD_EXTRACT_NON_HDR;
            field.typeStr = "e_FM_PCD_EXTRACT_NON_HDR";
            field.src     = e_FM_PCD_EXTRACT_FROM_FRAME_START;
            field.srcStr  = "e_FM_PCD_EXTRACT_FROM_FRAME_START";
        }

        scheme.key.push_back( field );
    }

    //For each 'nonheader' entry
    for ( unsigned int i = 0; i < xmlDist.nonHeader.size(); ++i ) {
        ExtractData nonheader;

        nonheader.type    = e_FM_PCD_EXTRACT_NON_HDR;
        nonheader.typeStr = "e_FM_PCD_EXTRACT_NON_HDR";

        nonheader.nhSource = (e_FmPcdExtractFrom)xmlDist.nonHeader[i].source;
        switch ( nonheader.nhSource ) {
            case e_FM_PCD_EXTRACT_FROM_FRAME_START:
            case e_FM_PCD_EXTRACT_FROM_DFLT_VALUE:
            case e_FM_PCD_EXTRACT_FROM_CURR_END_OF_PARSE:
            case e_FM_PCD_EXTRACT_FROM_PARSE_RESULT:
            case e_FM_PCD_EXTRACT_FROM_ENQ_FQID:
                nonheader.nhSourceStr = getExtractFromStr( nonheader.nhSource );
                break;
            default:
                nonheader.nhSourceStr  = "e_FM_PCD_EXTRACT_FROM_DFLT_VALUE";
        }

        nonheader.nhSize = xmlDist.nonHeader[i].size;
        nonheader.nhOffset = xmlDist.nonHeader[i].offset;

        scheme.key.push_back( nonheader );
    }

    // For each default group

    for ( unsigned int i = 0; i < xmlDist.defaults.size(); ++i ) {
        DefaultGroup dflt;

        //Set the type value and field
        if ( stripBlanks( xmlDist.defaults[i].type ) == "from_data" || stripBlanks( xmlDist.defaults[i].type ) == "FROM_DATA" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_GENERIC_FROM_DATA") {
            dflt.type    =  e_FM_PCD_KG_GENERIC_FROM_DATA;
            dflt.typeStr = "e_FM_PCD_KG_GENERIC_FROM_DATA";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "from_data_no_v" || stripBlanks( xmlDist.defaults[i].type ) == "FROM_DATA_NO_V" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_GENERIC_FROM_DATA_NO_V") {
            dflt.type    =  e_FM_PCD_KG_GENERIC_FROM_DATA_NO_V;
            dflt.typeStr = "e_FM_PCD_KG_GENERIC_FROM_DATA_NO_V";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "not_from_data" || stripBlanks( xmlDist.defaults[i].type ) == "NOT_FROM_DATA" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_GENERIC_NOT_FROM_DATA") {
            dflt.type    =  e_FM_PCD_KG_GENERIC_NOT_FROM_DATA;
            dflt.typeStr = "e_FM_PCD_KG_GENERIC_NOT_FROM_DATA";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "mac_addr" || stripBlanks( xmlDist.defaults[i].type ) == "MAC_ADDR" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_MAC_ADDR") {
            dflt.type    =  e_FM_PCD_KG_MAC_ADDR;
            dflt.typeStr = "e_FM_PCD_KG_MAC_ADDR";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "tci" || stripBlanks( xmlDist.defaults[i].type ) == "TCI" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_TCI") {
            dflt.type    =  e_FM_PCD_KG_TCI;
            dflt.typeStr = "e_FM_PCD_KG_TCI";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "enet_type" || stripBlanks( xmlDist.defaults[i].type ) == "ENET_TYPE" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_ENET_TYPE") {
            dflt.type    =  e_FM_PCD_KG_ENET_TYPE;
            dflt.typeStr = "e_FM_PCD_KG_ENET_TYPE";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "ppp_session_id" || stripBlanks( xmlDist.defaults[i].type ) == "PPP_SESSION_ID" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_PPP_SESSION_ID") {
            dflt.type    =  e_FM_PCD_KG_PPP_SESSION_ID;
            dflt.typeStr = "e_FM_PCD_KG_PPP_SESSION_ID";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "ppp_protocol_id" || stripBlanks( xmlDist.defaults[i].type ) == "PPP_PROTOCOL_ID" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_PPP_PROTOCOL_ID") {
            dflt.type    =  e_FM_PCD_KG_PPP_PROTOCOL_ID;
            dflt.typeStr = "e_FM_PCD_KG_PPP_PROTOCOL_ID";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "mpls_label" || stripBlanks( xmlDist.defaults[i].type ) == "MPLS_LABEL" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_MPLS_LABEL") {
            dflt.type    =  e_FM_PCD_KG_MPLS_LABEL;
            dflt.typeStr = "e_FM_PCD_KG_MPLS_LABEL";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "ip_addr" || stripBlanks( xmlDist.defaults[i].type ) == "IP_ADDR" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_IP_ADDR") {
            dflt.type    =  e_FM_PCD_KG_IP_ADDR;
            dflt.typeStr = "e_FM_PCD_KG_IP_ADDR";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "protocol_type" || stripBlanks( xmlDist.defaults[i].type ) == "PROTOCOL_TYPE" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_PROTOCOL_TYPE") {
            dflt.type    =  e_FM_PCD_KG_PROTOCOL_TYPE;
            dflt.typeStr = "e_FM_PCD_KG_PROTOCOL_TYPE";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "ip_tos_tc" || stripBlanks( xmlDist.defaults[i].type ) == "IP_TOS_TC" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_IP_TOS_TC") {
            dflt.type    =  e_FM_PCD_KG_IP_TOS_TC;
            dflt.typeStr = "e_FM_PCD_KG_IP_TOS_TC";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "ipv6_flow_label" || stripBlanks( xmlDist.defaults[i].type ) == "IPV6_FLOW_LABEL" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_IPV6_FLOW_LABEL") {
            dflt.type    =  e_FM_PCD_KG_IPV6_FLOW_LABEL;
            dflt.typeStr = "e_FM_PCD_KG_IPV6_FLOW_LABEL";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "ipsec_spi" || stripBlanks( xmlDist.defaults[i].type ) == "IPSEC_SPI" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_IPSEC_SPI") {
            dflt.type    =  e_FM_PCD_KG_IPSEC_SPI;
            dflt.typeStr = "e_FM_PCD_KG_IPSEC_SPI";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "l4_port" || stripBlanks( xmlDist.defaults[i].type ) == "L4_PORT" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_L4_PORT") {
            dflt.type    =  e_FM_PCD_KG_L4_PORT;
            dflt.typeStr = "e_FM_PCD_KG_L4_PORT";
        }
        else if ( stripBlanks( xmlDist.defaults[i].type ) == "tcp_flag" || stripBlanks( xmlDist.defaults[i].type ) == "TCP_FLAG" || stripBlanks( xmlDist.defaults[i].type ) == "e_FM_PCD_KG_TCP_FLAG") {
            dflt.type    =  e_FM_PCD_KG_TCP_FLAG;
            dflt.typeStr = "e_FM_PCD_KG_TCP_FLAG";
        }

        //Set the select value and str
        if ( stripBlanks( xmlDist.defaults[i].select ) == "gbl0" || stripBlanks( xmlDist.defaults[i].select ) == "GBL_0" || stripBlanks( xmlDist.defaults[i].select ) == "e_FM_PCD_KG_DFLT_GBL_0") {
            dflt.select    =  e_FM_PCD_KG_DFLT_GBL_0;
            dflt.selectStr = "e_FM_PCD_KG_DFLT_GBL_0";
        }
        else if ( stripBlanks( xmlDist.defaults[i].select ) == "gbl1" || stripBlanks( xmlDist.defaults[i].select ) == "GBL_1" || stripBlanks( xmlDist.defaults[i].select ) == "e_FM_PCD_KG_DFLT_GBL_1") {
            dflt.select    =  e_FM_PCD_KG_DFLT_GBL_1;
            dflt.selectStr = "e_FM_PCD_KG_DFLT_GBL_1";
        }
        else if ( stripBlanks( xmlDist.defaults[i].select ) == "private0" || stripBlanks( xmlDist.defaults[i].select ) == "PRIVATE_0" || stripBlanks( xmlDist.defaults[i].select ) == "e_FM_PCD_KG_DFLT_PRIVATE_0") {
            dflt.select    =  e_FM_PCD_KG_DFLT_PRIVATE_0;
            dflt.selectStr = "e_FM_PCD_KG_DFLT_PRIVATE_0";
        }
        else if ( stripBlanks( xmlDist.defaults[i].select ) == "private1" || stripBlanks( xmlDist.defaults[i].select ) == "PRIVATE_1" || stripBlanks( xmlDist.defaults[i].select ) == "e_FM_PCD_KG_DFLT_PRIVATE_1") {
            dflt.select    =  e_FM_PCD_KG_DFLT_PRIVATE_1;
            dflt.selectStr = "e_FM_PCD_KG_DFLT_PRIVATE_1";
        }

        scheme.defaults.push_back( dflt );
    }

    // For each 'combine' entry
    for ( unsigned int i = 0; i < xmlDist.combines.size(); ++i ) {
        ExtractData combine;

        combine.offsetInFqid = xmlDist.combines[i].offsetInFqid;
        combine.offset   = xmlDist.combines[i].offset;
        combine.size     = 1; // xmlDist.combines[i].size; All 'combine' elements
                              // have a fixed size due to the HW ability
        combine.mask     = xmlDist.combines[i].mask;
        combine.default_ = xmlDist.combines[i].default_;
        combine.validate = xmlDist.combines[i].validate;

        if ( xmlDist.combines[i].kind == CCombineEntry::PORTDATA ) {
            combine.type    = e_FM_PCD_KG_EXTRACT_PORT_PRIVATE_INFO;
            combine.typeStr = "e_FM_PCD_KG_EXTRACT_PORT_PRIVATE_INFO";
            // The next entries are initialized, but should not have effect when
            // the type is e_FM_PCD_KG_EXTRACT_PORT_PRIVATE_INFO
            combine.src     = e_FM_PCD_EXTRACT_FROM_FRAME_START;
            combine.srcStr  = "e_FM_PCD_EXTRACT_FROM_FRAME_START";
        }
        else if ( xmlDist.combines[i].kind == CCombineEntry::PARSER ) {
            combine.type    = e_FM_PCD_EXTRACT_NON_HDR;
            combine.typeStr = "e_FM_PCD_EXTRACT_NON_HDR";
            combine.src     = e_FM_PCD_EXTRACT_FROM_PARSE_RESULT;
            combine.srcStr  = "e_FM_PCD_EXTRACT_FROM_PARSE_RESULT";
        }
        else if ( xmlDist.combines[i].kind == CCombineEntry::FIELD && xmlDist.combines[i].fieldref != "" ) {
            combine.type       = e_FM_PCD_EXTRACT_BY_HDR;
            combine.typeStr    = "e_FM_PCD_EXTRACT_BY_HDR";
            combine.hdrtype    = e_FM_PCD_EXTRACT_FULL_FIELD;
            combine.hdrtypeStr = "e_FM_PCD_EXTRACT_FULL_FIELD";

            std::string protocol_name =
                xmlDist.combines[i].fieldref.substr( 0, xmlDist.combines[i].fieldref.find_last_of( "." ) );
            combine.hdr         = getNetCommHeaderType( protocol_name );
            if ( combine.hdr == HEADER_TYPE_NONE ) {
                std::string shim_protocol = pTaskDef->getShimNoFromCustom( protocol_name );
                if ( !shim_protocol.empty() ) { // Shim header is empty if custom protocol is not found
                    combine.hdr = getNetCommHeaderType( shim_protocol );
                }
                else {
                    // Header type HEADER_TYPE_NONE is not accepted as a valid value
                    throw CGenericError( ERR_UNKNOWN_PROTOCOL, xmlDist.combines[i].fieldref );
                }
            }
            combine.hdrStr      = getNetCommHeaderTypeStr( combine.hdr );
            // e_FM_PCD_HDR_INDEX_NONE is the only supported option right now
            combine.hdrIndex    = e_FM_PCD_HDR_INDEX_NONE;
            combine.hdrIndexStr = "e_FM_PCD_HDR_INDEX_NONE";

            combine.fieldName    = xmlDist.combines[i].fieldref;
            combine.fieldType    = getNetCommFieldType( combine.fieldName );
            combine.fieldTypeStr = getNetCommFieldTypeStr( combine.fieldName );

            uint32_t bitSize   = 0;
            uint32_t bitOffset = 0;
            if ( pTaskDef->GetFieldProperties( combine.fieldName, bitSize, bitOffset ) ) {
                combine.offset += bitOffset;
            }
        }
        else {  // "Extract from frame" is assumed. isFrame should be true in this case
            combine.type    = e_FM_PCD_EXTRACT_NON_HDR;
            combine.typeStr = "e_FM_PCD_EXTRACT_NON_HDR";
            combine.src     = e_FM_PCD_EXTRACT_FROM_FRAME_START;
            combine.srcStr  = "e_FM_PCD_EXTRACT_FROM_FRAME_START";
        }
        // Offset for the 'combine' elements is measured in bytes in the current HW
        if ( combine.offset % 8 != 0 ) {
            CGenericError::printWarning( WARN_EXTRACTION_BYTE_ALLIGN, scheme.name );
        }
        combine.offset /= 8;

        scheme.combines.push_back( combine );
    }

    // For each 'protocol' entry
    if ( scheme.isDirect == 0 ) {   // Only for inderect schemes
        for ( unsigned int i = 0; i < xmlDist.protocols.size(); ++i ) {
            Protocol tProt;
            tProt.name = xmlDist.protocols[i].name;
            tProt.opt = xmlDist.protocols[i].opt;
            scheme.used_protocols.insert( tProt );
        }
    }

    // Add next engine entry
    scheme.nextEngine        = getEngineByType( xmlDist.action );
    scheme.nextEngineStr     = getEngineByTypeStr( xmlDist.action );
    scheme.nextActionName    = xmlDist.actionName;
    scheme.doneAction        = e_FM_PCD_ENQ_FRAME;
    scheme.doneActionStr     = "e_FM_PCD_ENQ_FRAME";
    scheme.actionHandleIndex = 0xFFFFFFFF;

    if ( scheme.nextEngine == e_FM_PCD_DONE &&
         xmlDist.action == "drop" ) {                   // Is it drop?
        scheme.doneAction    = e_FM_PCD_DROP_FRAME;
        scheme.doneActionStr = "e_FM_PCD_DROP_FRAME";
    }
    else if ( scheme.nextEngine == e_FM_PCD_PLCR ) {    // Is it a policer?
        // Find the policer and add it
        scheme.actionHandleIndex =
            get_policer_index( pTaskDef, xmlDist.actionName, xmlDist.name,
                               port );
        ApplyOrder::Entry n2( ApplyOrder::Policer, scheme.actionHandleIndex );
        applier.add_edge( n1, n2 );
    }
    else if ( scheme.nextEngine == e_FM_PCD_KG ) {      // Is it a distribution?
        // Find the distribution and add it
        scheme.actionHandleIndex =
            get_scheme_index( pTaskDef, xmlDist.actionName, xmlDist.name,
                              port, true );
            ApplyOrder::Entry n2( ApplyOrder::Scheme, scheme.actionHandleIndex );
            applier.add_edge( n1, n2 );
    }
    else if ( scheme.nextEngine == e_FM_PCD_CC ||
#if DPAA_VERSION >= 11
              scheme.nextEngine == e_FM_PCD_FR ||
#endif
               scheme.nextEngine == e_FM_PCD_HASH ) {      // Is it CC/Replicator node ?
        //Find Manip index
        unsigned int hdr_index = 0;
        if ( xmlDist.headerManipName.empty() ) {
            hdr_index = 0;
        }
        else {
            std::map< std::string, CHeaderManip >::const_iterator headerit;
            for ( headerit = pTaskDef->headermanips.begin();
                  headerit != pTaskDef->headermanips.end();
                  ++headerit ) {
                hdr_index++;
                if ( headerit->second.name == xmlDist.headerManipName ) {
                    break;
                }
            }
        }

        // Find CC node
        if ( scheme.nextEngine == e_FM_PCD_CC ||
              scheme.nextEngine == e_FM_PCD_HASH )
        {
            scheme.actionHandleIndex =
            get_ccnode_index( pTaskDef,
                              xmlDist.actionName,
                              xmlDist.name, port, true, scheme.hashShift, hdr_index );
        }
#if (DPAA_VERSION >= 11)
        else
        {
            scheme.actionHandleIndex =
            get_replicator_index( pTaskDef,
                              xmlDist.actionName,
                              xmlDist.name, port, true, hdr_index );
        }
#endif /* (DPAA_VERSION >= 11) */
       
		if (scheme.isDirect) 
		{
			//ENGR00347977
	        ApplyOrder::Entry n0( ApplyOrder::CCTree, port.getIndex() );
		    applier.add_edge( n0, n1 );
		}
		else
		{
	        ApplyOrder::Entry n2( ApplyOrder::CCTree, port.getIndex() );
		    applier.add_edge( n1, n2 );
		}

    }

#if (DPAA_VERSION >= 11)
    //Change the VSP
	scheme.vspAlloc = false;
    if ( xmlDist.vspoverride ) {
        scheme.overrideStorageProfile = true;
        if ( xmlDist.vspName != "" ) {
            std::map< std::string, CVsp >::const_iterator vspIt;
            vspIt = pTaskDef->vsps.find( xmlDist.vspName );
            // Does such VSP exist?
            if ( vspIt == pTaskDef->vsps.end() ) {
                throw CGenericError( ERR_VSP_NOT_FOUND, xmlDist.vspName, xmlDist.name );
            }

            if ( vspIt->second.direct ) {
                scheme.storageProfile.direct = true;
                scheme.storageProfile.profileSelect.directRelativeProfileId = vspIt->second.base;
            }
            else {
                scheme.storageProfile.direct = false;
                scheme.storageProfile.profileSelect.indirectProfile.fqidOffsetShift = vspIt->second.fqshift;
                scheme.storageProfile.profileSelect.indirectProfile.fqidOffsetRelativeProfileIdBase = vspIt->second.vspoffset;
                scheme.storageProfile.profileSelect.indirectProfile.numOfProfiles = vspIt->second.vspcount;
            }
			scheme.vspAlloc = vspIt->second.vspAlloc;
        }
        else {
            if ( xmlDist.vspdirect ) {
                scheme.storageProfile.direct = true;
                scheme.storageProfile.profileSelect.directRelativeProfileId = xmlDist.vspbase;
            }
            else {
                scheme.storageProfile.direct = false;
                scheme.storageProfile.profileSelect.indirectProfile.fqidOffsetShift = xmlDist.vspshift;
                scheme.storageProfile.profileSelect.indirectProfile.fqidOffsetRelativeProfileIdBase = xmlDist.vspoffset;
                scheme.storageProfile.profileSelect.indirectProfile.numOfProfiles = xmlDist.vspcount;
            }
        }
    }
    else {
        scheme.overrideStorageProfile = false;
    }
#endif /* (DPAA_VERSION >= 11) */
    
    return scheme;
}


static uint8_t getByteMask( int size_in_bits, int start_bit_offset, int byteNo )
{
    uint8_t ret = 0xFF;

    uint8_t ending[] = {
        0xFF,
        0xFE,
        0xFC,
        0xF8,
        0xF0,
        0xE0,
        0xC0,
        0x80,
    };
    uint8_t starting[] = {
        0xFF,
        0x7F,
        0x3F,
        0x1F,
        0x0F,
        0x07,
        0x03,
        0x01,
    };

    int len = ( start_bit_offset + size_in_bits + 7 ) / 8;
    if ( ( byteNo >= len ) ||
         ( ( byteNo > 0 ) && ( byteNo < len - 1 ) ) ) {
        return ret;
    }

    if ( byteNo == 0 ) { // First byte from right
        ret &= ending[len * 8 - size_in_bits - start_bit_offset];
    }
    if ( byteNo == len - 1 ) { // Last byte from right
        ret &= starting[start_bit_offset];
    }

    return ret;
}


////////////////////////////////////////////////////////////////////////////////
/// Converts classification parameters provided throught XML file
/// to the internal representation
////////////////////////////////////////////////////////////////////////////////
CCNode&
CFMCModel::createCCNode( const CTaskDef* pTaskDef, Port& port, const CClassification& xmlCCNode, unsigned int kgHashShift)
{
    CCNode& ccNode = all_ccnodes[FMBlock::assignIndex( all_ccnodes )];

    ApplyOrder::Entry n1( ApplyOrder::CCNode, ccNode.getIndex() );
    applier.add_edge( n1, ApplyOrder::Entry( ApplyOrder::None, 0 ) );

    port.ccnodes.push_back( ccNode.getIndex() );

    ccNode.shared = xmlCCNode.shared;
    if ( ccNode.shared ) {
        ccNode.name = port.name.substr( 0, 3 ) + "/ccnode/" + xmlCCNode.name;
    }
    else {
        ccNode.name = port.name + "/ccnode/" + xmlCCNode.name;
    }
    ccNode.port_signature = port.name;

    //Pre-allocation
    ccNode.maxNumOfKeys = xmlCCNode.max;
    ccNode.maskSupport  = xmlCCNode.masks;
    ccNode.statistics   = getStatistic(xmlCCNode.statistics);
    ccNode.shared       = xmlCCNode.shared;

#ifndef P1023
#if (DPAA_VERSION >= 11)
    if (ccNode.statistics == e_FM_PCD_CC_STATS_MODE_RMON)
    {
        if (xmlCCNode.frameLength.size() != 0)
        {
           for (unsigned int i = 0; i < xmlCCNode.frameLength.size() && i < FM_PCD_CC_STATS_MAX_NUM_OF_FLR; i++)
           {
                ccNode.frameLength.push_back(xmlCCNode.frameLength[i]);
           }
        }
    }
#endif /* (DPAA_VERSION >= 11) */
#endif /* P1023 */
    
    if (xmlCCNode.key.header)
    {
        ccNode.extract.type = e_FM_PCD_EXTRACT_BY_HDR;
        ccNode.extract.typeStr = "e_FM_PCD_EXTRACT_BY_HDR";
    }
    else
    {
        ccNode.extract.type = e_FM_PCD_EXTRACT_NON_HDR;
        ccNode.extract.typeStr = "e_FM_PCD_EXTRACT_NON_HDR";
    }
    ccNode.extract.nhAction    = e_FM_PCD_ACTION_NONE;
    ccNode.extract.nhActionStr = "e_FM_PCD_ACTION_NONE";

    ccNode.keySize = 0;

    ExtractData field;
    field.fieldType    = 0;
    field.fieldTypeStr = "";

    unsigned int bitsize   = 0;
    unsigned int bitoffset = 0;

    // For each 'extract key' entry
    if (ccNode.extract.type == e_FM_PCD_EXTRACT_BY_HDR)
    {
        for ( unsigned int i = 0; i < xmlCCNode.key.fields.size(); ++i ) {
            if ( xmlCCNode.key.fields[i].name != "" ) {
                std::string protocol_name =
                    xmlCCNode.key.fields[i].name.substr( 0, xmlCCNode.key.fields[i].name.find_last_of( "." ) );
                ccNode.used_protocols.insert( protocol_name );

                field.hdr = getNetCommHeaderType( protocol_name );
                if ( field.hdr == HEADER_TYPE_NONE ) {
                    std::string shim_protocol = pTaskDef->getShimNoFromCustom( protocol_name );
                    if ( !shim_protocol.empty() ) { // Shim header is empty if custom protocol is not found
                        field.hdr = getNetCommHeaderType( shim_protocol );
                    }
                    else {
                        // Header type HEADER_TYPE_NONE is not accepted as a valid key
                        // for coarce classification
                        throw CGenericError( ERR_UNKNOWN_PROTOCOL, xmlCCNode.key.fields[i].name );
                    }
                }
                field.hdrStr = getNetCommHeaderTypeStr( field.hdr );

                field.hdrIndex    = getNetCommHeaderIndex( xmlCCNode.key.fields[i].header_index );
                field.hdrIndexStr = getNetCommHeaderIndexStr( xmlCCNode.key.fields[i].header_index );

                field.fieldName    = xmlCCNode.key.fields[i].name;
                field.fieldType    |= getNetCommFieldType( field.fieldName );
                if ( !field.fieldTypeStr.empty() ) {
                    field.fieldTypeStr += " | ";
                }
                field.fieldTypeStr += getNetCommFieldTypeStr( field.fieldName );

                // Find the protocol and get the field's length
                if ( pTaskDef->GetFieldProperties( xmlCCNode.key.fields[i].name,
                                                   bitsize, bitoffset ) ) {
                    ccNode.keySize += bitsize;
                }

                field.type    = e_FM_PCD_EXTRACT_BY_HDR;
                field.typeStr = "e_FM_PCD_EXTRACT_BY_HDR";
                if ( ( getNetCommFieldType( field.fieldName ) != UNKNOWN_NetCommField ) &&
                       isFullFieldForCC( field.fieldName ) ) {
                    if (xmlCCNode.key.field)
                    {
                        field.offset     = xmlCCNode.key.fields[i].offset;
                        field.size       = xmlCCNode.key.fields[i].size;
                        field.hdrtype    = e_FM_PCD_EXTRACT_FROM_FIELD;
                        field.hdrtypeStr = "e_FM_PCD_EXTRACT_FROM_FIELD";
                    } else
                    {
                        field.hdrtype    = e_FM_PCD_EXTRACT_FULL_FIELD;
                        field.hdrtypeStr = "e_FM_PCD_EXTRACT_FULL_FIELD";
                    }
                }
                else {
                    field.hdrtype    = e_FM_PCD_EXTRACT_FROM_HDR;
                    field.hdrtypeStr = "e_FM_PCD_EXTRACT_FROM_HDR";
                    field.size       = ( bitsize + 7 ) / 8;
                    field.offset     = bitoffset / 8;
                }
            }
            else {
                field.type    = e_FM_PCD_EXTRACT_NON_HDR;
                field.typeStr = "e_FM_PCD_EXTRACT_NON_HDR";
            }

            ccNode.extract = field;
        }
    }
    else
    {// Non header extract
        ccNode.extract.nhSource    = (e_FmPcdExtractFrom)xmlCCNode.key.nonHeaderEntry.source;
        ccNode.extract.nhSourceStr = getExtractFromStr( ccNode.extract.nhSource );
        ccNode.extract.nhAction    = (e_FmPcdAction)xmlCCNode.key.nonHeaderEntry.action;

        switch (ccNode.extract.nhAction)
        {
        case e_FM_PCD_ACTION_NONE:
            ccNode.extract.nhActionStr = "e_FM_PCD_ACTION_NONE";
            break;
        case e_FM_PCD_ACTION_EXACT_MATCH:
            ccNode.extract.nhActionStr = "e_FM_PCD_ACTION_EXACT_MATCH";
            break;
        case e_FM_PCD_ACTION_INDEXED_LOOKUP:
            ccNode.extract.nhActionStr = "e_FM_PCD_ACTION_INDEXED_LOOKUP";
            break;
        }

        ccNode.extract.nhOffset     = xmlCCNode.key.nonHeaderEntry.offset;
        ccNode.extract.nhSize       = xmlCCNode.key.nonHeaderEntry.size;
        ccNode.extract.nhIcIndxMask = xmlCCNode.key.nonHeaderEntry.icIndxMask;

        ccNode.keySize = ccNode.extract.nhSize * 8;
    }

    ccNode.keySize = ( ccNode.keySize + 7 ) / 8;    // Convert to bytes

    // For each entry ...
    for ( unsigned int i = 0; i < xmlCCNode.entries.size(); ++i ) {
        // ... copy the data according to the key size
        ccNode.keys.push_back( CCNode::CCData() );
        ccNode.masks.push_back( CCNode::CCData() );
        ccNode.indices.push_back( xmlCCNode.entries[i].index );

        if ( xmlCCNode.entries[i].headerManipName.empty() ) {
            ccNode.header.push_back( 0 );
        }
        else {
            std::map< std::string, CHeaderManip >::const_iterator headerit;
            unsigned int hdr_index = 0;
            for ( headerit = pTaskDef->headermanips.begin(); headerit != pTaskDef->headermanips.end(); ++headerit ) {
                hdr_index++;
                if ( headerit->second.name == xmlCCNode.entries[i].headerManipName ) {
                    ccNode.header.push_back( hdr_index );
                    break;
                }
            }

            if (headerit == pTaskDef->headermanips.end())
            {
                 throw CGenericError( ERR_MANIP_NOT_FOUND, xmlCCNode.entries[i].headerManipName, xmlCCNode.name );
            }
        }

        if ( xmlCCNode.entries[i].fragmentationName.empty() ) {
            ccNode.frag.push_back( 0 );
        }
        else {
            std::map< std::string, CFragmentation >::const_iterator fragit;
            unsigned int frag_index = 0;
            for ( fragit = pTaskDef->fragmentations.begin(); fragit != pTaskDef->fragmentations.end(); ++fragit ) {
                frag_index++;
                if (fragit->second.name == xmlCCNode.entries[i].fragmentationName)
                {
                    ccNode.frag.push_back( frag_index );
                    break;
                }
            }

            if (fragit == pTaskDef->fragmentations.end())
            {
                 throw CGenericError( ERR_MANIP_NOT_FOUND, xmlCCNode.entries[i].fragmentationName, xmlCCNode.name );
            }
        }

        for ( unsigned int j = 0; j < ccNode.keySize; ++j ) {
            ccNode.keys[i].data[j] =
                xmlCCNode.entries[i].data[FM_PCD_MAX_SIZE_OF_KEY - ccNode.keySize + j];
            uint8_t byteMask = 0xFF;
            if ( ccNode.extract.type    == e_FM_PCD_EXTRACT_BY_HDR &&
                 ccNode.extract.hdrtype == e_FM_PCD_EXTRACT_FROM_HDR ) {
                byteMask = getByteMask( bitsize, bitoffset % 8, ccNode.keySize - j - 1 );
            }
            ccNode.masks[i].data[j] = byteMask &
                xmlCCNode.entries[i].mask[FM_PCD_MAX_SIZE_OF_KEY - ccNode.keySize + j];
        }

        ccNode.nextEngines.push_back( CCNode::CCNextEngine() );
        ccNode.nextEngines[i].nextEngine        = getEngineByType( xmlCCNode.entries[i].action );

        //Save the true type of the next engine
        ccNode.nextEngines[i].nextEngineTrueType = ccNode.nextEngines[i].nextEngine;
        if ( ccNode.nextEngines[i].nextEngine == e_FM_PCD_CC ) {
            std::map< std::string, CClassification >::const_iterator nodeIt;
            nodeIt = pTaskDef->classifications.find( xmlCCNode.entries[i].actionName );
            // Does such node exist?
            if ( nodeIt == pTaskDef->classifications.end() ) {
                throw CGenericError( ERR_CC_NOT_FOUND, xmlCCNode.entries[i].actionName, xmlCCNode.name );
            }

            if ( nodeIt->second.key.hashTable )
                ccNode.nextEngines[i].nextEngineTrueType = e_FM_PCD_HASH;
            else
                ccNode.nextEngines[i].nextEngineTrueType = e_FM_PCD_CC;
        }

        ccNode.nextEngines[i].nextEngineStr = getEngineByTypeStr( xmlCCNode.entries[i].action );
        ccNode.nextEngines[i].newFqid       = xmlCCNode.entries[i].qbase;
        ccNode.nextEngines[i].statistics    = xmlCCNode.entries[i].statistics;

#if (DPAA_VERSION >= 11)
    //Change the VSP
    if ( xmlCCNode.entries[i].vspOverride ) {
        if ( xmlCCNode.entries[i].vspName != "" ) {
            std::map< std::string, CVsp >::const_iterator vspIt;
            vspIt = pTaskDef->vsps.find( xmlCCNode.entries[i].vspName );
            // Does such VSP exist?
            if ( vspIt == pTaskDef->vsps.end() ) {
                throw CGenericError( ERR_VSP_NOT_FOUND, xmlCCNode.entries[i].vspName, xmlCCNode.name );
            }

            ccNode.nextEngines[i].newRelativeStorageProfileId = vspIt->second.base;
        }
        else {
            ccNode.nextEngines[i].newRelativeStorageProfileId = xmlCCNode.entries[i].vspBase;
        }
    }
    else {
        ccNode.nextEngines[i].newRelativeStorageProfileId = 0;
    }
#endif /* (DPAA_VERSION >= 11) */

        ccNode.nextEngines[i].doneAction        = e_FM_PCD_ENQ_FRAME;
        ccNode.nextEngines[i].doneActionStr     = "e_FM_PCD_ENQ_FRAME";
        ccNode.nextEngines[i].actionHandleIndex = 0xFFFFFFFF;
        if ( ccNode.nextEngines[i].nextEngine == e_FM_PCD_DONE &&
             xmlCCNode.entries[i].action      == "drop" ) {
            ccNode.nextEngines[i].doneAction    = e_FM_PCD_DROP_FRAME;
            ccNode.nextEngines[i].doneActionStr = "e_FM_PCD_DROP_FRAME";
        }
        if ( ccNode.nextEngines[i].nextEngine == e_FM_PCD_CC ||
             ccNode.nextEngines[i].nextEngine == e_FM_PCD_HASH ) {
            if ( ccNode.nextEngines[i].nextEngineTrueType == e_FM_PCD_HASH ) {
                ccNode.nextEngines[i].actionHandleIndex =
                get_htnode_index( pTaskDef,
                                  xmlCCNode.entries[i].actionName,
                                  ccNode.name, port, false, kgHashShift );
                ApplyOrder::Entry n2( ApplyOrder::HTNode,
                                      ccNode.nextEngines[i].actionHandleIndex );
                applier.add_edge( n1, n2 );
            }
            else {
                ccNode.nextEngines[i].actionHandleIndex =
                    get_ccnode_index( pTaskDef,
                                      xmlCCNode.entries[i].actionName,
                                      ccNode.name, port, false, kgHashShift );
                ApplyOrder::Entry n2( ApplyOrder::CCNode,
                                      ccNode.nextEngines[i].actionHandleIndex );
                applier.add_edge( n1, n2 );
            }
        }
        else if ( ccNode.nextEngines[i].nextEngine == e_FM_PCD_KG ) {
            ccNode.nextEngines[i].actionHandleIndex =
                get_scheme_index( pTaskDef, xmlCCNode.entries[i].actionName,
                                  ccNode.name, port, true );
            ApplyOrder::Entry n2( ApplyOrder::Scheme,
                                  ccNode.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
        else if ( ccNode.nextEngines[i].nextEngine == e_FM_PCD_PLCR ) {
            ccNode.nextEngines[i].actionHandleIndex =
                get_policer_index( pTaskDef, xmlCCNode.entries[i].actionName,
                                   ccNode.name, port );
            ApplyOrder::Entry n2( ApplyOrder::Policer,
                                  ccNode.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
#if (DPAA_VERSION >= 11)
        else if ( ccNode.nextEngines[i].nextEngine == e_FM_PCD_FR ) {
            ccNode.nextEngines[i].actionHandleIndex =
                get_replicator_index( pTaskDef, xmlCCNode.entries[i].actionName,
                                   ccNode.name, port, false );
            ApplyOrder::Entry n2( ApplyOrder::Replicator,
                                  ccNode.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
#endif /* (DPAA_VERSION >= 11) */
    }

    ccNode.nextEngineOnMiss.nextEngine        = getEngineByType( xmlCCNode.actionOnMiss );

    //Save the true type of the next engine
    ccNode.nextEngineOnMiss.nextEngineTrueType = ccNode.nextEngineOnMiss.nextEngine;
    if ( ccNode.nextEngineOnMiss.nextEngine == e_FM_PCD_CC ) {
        std::map< std::string, CClassification >::const_iterator nodeIt;
        nodeIt = pTaskDef->classifications.find( xmlCCNode.actionNameOnMiss );
        // Does such node exist?
        if ( nodeIt == pTaskDef->classifications.end() ) {
            throw CGenericError( ERR_CC_NOT_FOUND, xmlCCNode.actionNameOnMiss, xmlCCNode.name );
        }

        if ( nodeIt->second.key.hashTable )
            ccNode.nextEngineOnMiss.nextEngineTrueType = e_FM_PCD_HASH;
        else
            ccNode.nextEngineOnMiss.nextEngineTrueType = e_FM_PCD_CC;
    }

    ccNode.nextEngineOnMiss.nextEngineStr = getEngineByTypeStr( xmlCCNode.actionOnMiss );
    ccNode.nextEngineOnMiss.newFqid       = 0;
    ccNode.nextEngineOnMiss.statistics    = xmlCCNode.statisticsOnMiss;

#if (DPAA_VERSION >= 11)
    //Change the VSP
    if ( xmlCCNode.vspOverrideOnMiss ) {
        if ( xmlCCNode.vspNameOnMiss != "" ) {
            std::map< std::string, CVsp >::const_iterator vspIt;
            vspIt = pTaskDef->vsps.find( xmlCCNode.vspNameOnMiss );
            // Does such VSP exist?
            if ( vspIt == pTaskDef->vsps.end() ) {
                throw CGenericError( ERR_VSP_NOT_FOUND, xmlCCNode.vspNameOnMiss, xmlCCNode.name );
            }

            ccNode.nextEngineOnMiss.newRelativeStorageProfileId = vspIt->second.base;
        }
        else {
            ccNode.nextEngineOnMiss.newRelativeStorageProfileId = xmlCCNode.vspBaseOnMiss;
        }
    }
    else {
        ccNode.nextEngineOnMiss.newRelativeStorageProfileId = 0;
    }
#endif /* (DPAA_VERSION >= 11) */

    ccNode.nextEngineOnMiss.doneAction        = e_FM_PCD_ENQ_FRAME;
    ccNode.nextEngineOnMiss.doneActionStr     = "e_FM_PCD_ENQ_FRAME";
    ccNode.nextEngineOnMiss.actionHandleIndex = 0xFFFFFFFF;
    if ( ccNode.nextEngineOnMiss.nextEngine == e_FM_PCD_DONE &&
         xmlCCNode.actionOnMiss             == "drop" ) {
        ccNode.nextEngineOnMiss.doneAction    = e_FM_PCD_DROP_FRAME;
        ccNode.nextEngineOnMiss.doneActionStr = "e_FM_PCD_DROP_FRAME";
    }
    if ( ccNode.nextEngineOnMiss.nextEngine == e_FM_PCD_CC ||
         ccNode.nextEngineOnMiss.nextEngine == e_FM_PCD_HASH ) {
        //Check if it's a match or hash table
        if ( ccNode.nextEngineOnMiss.nextEngineTrueType == e_FM_PCD_HASH ) {
            ccNode.nextEngineOnMiss.actionHandleIndex =
                get_htnode_index( pTaskDef,
                                  xmlCCNode.actionNameOnMiss,
                                  ccNode.name, port, false, kgHashShift );
            ApplyOrder::Entry n2( ApplyOrder::HTNode,
                                  ccNode.nextEngineOnMiss.actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
        else {
            ccNode.nextEngineOnMiss.actionHandleIndex =
                get_ccnode_index( pTaskDef,
                                  xmlCCNode.actionNameOnMiss,
                                  ccNode.name, port, false, kgHashShift );
            ApplyOrder::Entry n2( ApplyOrder::CCNode,
                                  ccNode.nextEngineOnMiss.actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
    }
    else if ( ccNode.nextEngineOnMiss.nextEngine == e_FM_PCD_KG ) {
        ccNode.nextEngineOnMiss.actionHandleIndex =
            get_scheme_index( pTaskDef, xmlCCNode.actionNameOnMiss,
                              ccNode.name, port, true );
        ApplyOrder::Entry n2( ApplyOrder::Scheme,
                              ccNode.nextEngineOnMiss.actionHandleIndex );
        applier.add_edge( n1, n2 );
    }
    else if ( ccNode.nextEngineOnMiss.nextEngine == e_FM_PCD_PLCR ) {
        ccNode.nextEngineOnMiss.actionHandleIndex =
            get_policer_index( pTaskDef, xmlCCNode.actionNameOnMiss,
                               ccNode.name, port );
        ApplyOrder::Entry n2( ApplyOrder::Policer,
                              ccNode.nextEngineOnMiss.actionHandleIndex );
        applier.add_edge( n1, n2 );
    }
#if (DPAA_VERSION >= 11)
    else if ( ccNode.nextEngineOnMiss.nextEngine == e_FM_PCD_FR ) {
        ccNode.nextEngineOnMiss.actionHandleIndex =
            get_replicator_index( pTaskDef,
                                  xmlCCNode.actionNameOnMiss,
                                  ccNode.name, port, false, kgHashShift );
        ApplyOrder::Entry n2( ApplyOrder::Replicator,
                              ccNode.nextEngineOnMiss.actionHandleIndex );
        applier.add_edge( n1, n2 );
    }
#endif /* (DPAA_VERSION >= 11) */
    else if ( ccNode.nextEngineOnMiss.nextEngine == e_FM_PCD_DONE ) {
        ccNode.nextEngineOnMiss.newFqid = xmlCCNode.qbase;
    }

    for ( unsigned int i = 0; i < xmlCCNode.may_use_action.size(); ++i ) {
        e_FmPcdEngine action     = getEngineByType( xmlCCNode.may_use_action[i] );
        std::string   actionName = xmlCCNode.may_use_actionName[i];
        switch ( action ) {
        case e_FM_PCD_HASH:
        case e_FM_PCD_CC:
            {
            unsigned int index =
                get_ccnode_index( pTaskDef, actionName, ccNode.name, port,
                                  false, kgHashShift );

                std::map< std::string, CClassification >::const_iterator nodeIt = pTaskDef->classifications.find( actionName );
                // Does such node exist?
                if ( nodeIt == pTaskDef->classifications.end() ) {
                    throw CGenericError( ERR_CC_NOT_FOUND, actionName, ccNode.name );
                }

                //determine action node type: CC or HT
                if ( nodeIt->second.key.hashTable ) {
                    ApplyOrder::Entry n2( ApplyOrder::HTNode, index );
                    applier.add_edge( n1, n2 );
                } else {
                    ApplyOrder::Entry n2( ApplyOrder::CCNode, index );
                    applier.add_edge( n1, n2 );
                }

            break;
            }
        case e_FM_PCD_KG:
            {
            unsigned int index =
                get_scheme_index( pTaskDef, actionName, ccNode.name, port,
                                  true );
            ApplyOrder::Entry n2( ApplyOrder::Scheme, index );
            applier.add_edge( n1, n2 );
            break;
            }
        case e_FM_PCD_PLCR:
            {
            unsigned int index =
                get_policer_index( pTaskDef, actionName, ccNode.name, port );
            ApplyOrder::Entry n2( ApplyOrder::Policer, index );
            applier.add_edge( n1, n2 );
            break;
            }
#if (DPAA_VERSION >= 11)
        case e_FM_PCD_FR:
            {
            unsigned int index =
                get_replicator_index( pTaskDef, actionName, ccNode.name, port, false );
            ApplyOrder::Entry n2( ApplyOrder::Replicator, index );
            applier.add_edge( n1, n2 );
            break;
            }
#endif /* (DPAA_VERSION >= 11) */
        default:
            {}
        }
    }

    return ccNode;
}

HTNode&
CFMCModel::createHTNode( const CTaskDef* pTaskDef, Port& port, const CClassification& xmlCCNode, unsigned int kgHashShift)
{
    HTNode& htNode = all_htnodes[FMBlock::assignIndex( all_htnodes )];

    ApplyOrder::Entry n1( ApplyOrder::HTNode, htNode.getIndex() );
    applier.add_edge( n1, ApplyOrder::Entry( ApplyOrder::None, 0 ) );

    port.htnodes.push_back( htNode.getIndex() );

    htNode.name = port.name + "/ccnode/" + xmlCCNode.name;

    
    //Pre-allocation
    htNode.maxNumOfKeys                = xmlCCNode.max;
    htNode.statistics                  = getStatistic(xmlCCNode.statistics);
    htNode.hashResMask                 = xmlCCNode.key.hashTableEntry.mask;
    htNode.hashShift                   = xmlCCNode.key.hashTableEntry.hashShift;
    htNode.kgHashShift                 = kgHashShift;
    htNode.matchKeySize                = xmlCCNode.key.hashTableEntry.keySize;
    htNode.externalHash                = xmlCCNode.key.hashTableEntry.external;
    htNode.agingSupport                = xmlCCNode.key.hashTableEntry.aging;
    htNode.port_signature              = port.name;

    //entries for prefilled ht
    // For each entry ...
    for ( unsigned int i = 0; i < xmlCCNode.entries.size(); ++i ) {
        // ... copy the data according to the key size
        htNode.keys.push_back( HTNode::CCData() );
        htNode.masks.push_back( HTNode::CCData() );
        htNode.indices.push_back( xmlCCNode.entries[i].index );

        if ( xmlCCNode.entries[i].headerManipName.empty() ) {
            htNode.header.push_back( 0 );
        }
        else {
            std::map< std::string, CHeaderManip >::const_iterator headerit;
            unsigned int hdr_index = 0;
            for ( headerit = pTaskDef->headermanips.begin(); headerit != pTaskDef->headermanips.end(); ++headerit ) {
                hdr_index++;
                if ( headerit->second.name == xmlCCNode.entries[i].headerManipName ) {
                    htNode.header.push_back( hdr_index );
                    break;
                }
            }

            if (headerit == pTaskDef->headermanips.end())
            {
                 throw CGenericError( ERR_MANIP_NOT_FOUND, xmlCCNode.entries[i].headerManipName, xmlCCNode.name );
            }
        }

        if ( xmlCCNode.entries[i].fragmentationName.empty() ) {
            htNode.frag.push_back( 0 );
        }
        else {
            std::map< std::string, CFragmentation >::const_iterator fragit;
            unsigned int frag_index = 0;
            for ( fragit = pTaskDef->fragmentations.begin(); fragit != pTaskDef->fragmentations.end(); ++fragit ) {
                frag_index++;
                if (fragit->second.name == xmlCCNode.entries[i].fragmentationName)
                {
                    htNode.frag.push_back( frag_index );
                    break;
                }
            }

            if (fragit == pTaskDef->fragmentations.end())
            {
                 throw CGenericError( ERR_MANIP_NOT_FOUND, xmlCCNode.entries[i].fragmentationName, xmlCCNode.name );
            }
        }

        for ( unsigned int j = 0; j < htNode.matchKeySize; ++j ) {
            htNode.keys[i].data[j] =
                xmlCCNode.entries[i].data[FM_PCD_MAX_SIZE_OF_KEY - htNode.matchKeySize + j];
            htNode.masks[i].data[j] =
                xmlCCNode.entries[i].mask[FM_PCD_MAX_SIZE_OF_KEY - htNode.matchKeySize + j];
        }

        htNode.nextEngines.push_back( HTNode::CCNextEngine() );
        htNode.nextEngines[i].nextEngine        = getEngineByType( xmlCCNode.entries[i].action );

        //Save the true type of the next engine
        htNode.nextEngines[i].nextEngineTrueType = htNode.nextEngines[i].nextEngine;
        if ( htNode.nextEngines[i].nextEngine == e_FM_PCD_CC ) {
            std::map< std::string, CClassification >::const_iterator nodeIt;
            nodeIt = pTaskDef->classifications.find( xmlCCNode.entries[i].actionName );
            // Does such node exist?
            if ( nodeIt == pTaskDef->classifications.end() ) {
                throw CGenericError( ERR_CC_NOT_FOUND, xmlCCNode.entries[i].actionName, xmlCCNode.name );
            }

            if ( nodeIt->second.key.hashTable )
                htNode.nextEngines[i].nextEngineTrueType = e_FM_PCD_HASH;
            else
                htNode.nextEngines[i].nextEngineTrueType = e_FM_PCD_CC;
        }

        htNode.nextEngines[i].nextEngineStr = getEngineByTypeStr( xmlCCNode.entries[i].action );
        htNode.nextEngines[i].newFqid       = xmlCCNode.entries[i].qbase;
        htNode.nextEngines[i].statistics    = xmlCCNode.entries[i].statistics;

#if (DPAA_VERSION >= 11)
    //Change the VSP
    if ( xmlCCNode.entries[i].vspOverride ) {
        if ( xmlCCNode.entries[i].vspName != "" ) {
            std::map< std::string, CVsp >::const_iterator vspIt;
            vspIt = pTaskDef->vsps.find( xmlCCNode.entries[i].vspName );
            // Does such VSP exist?
            if ( vspIt == pTaskDef->vsps.end() ) {
                throw CGenericError( ERR_VSP_NOT_FOUND, xmlCCNode.entries[i].vspName, xmlCCNode.name );
            }

            htNode.nextEngines[i].newRelativeStorageProfileId = vspIt->second.base;
        }
        else {
            htNode.nextEngines[i].newRelativeStorageProfileId = xmlCCNode.entries[i].vspBase;
        }
    }
    else {
        htNode.nextEngines[i].newRelativeStorageProfileId = 0;
    }
#endif /* (DPAA_VERSION >= 11) */

        htNode.nextEngines[i].doneAction        = e_FM_PCD_ENQ_FRAME;
        htNode.nextEngines[i].doneActionStr     = "e_FM_PCD_ENQ_FRAME";
        htNode.nextEngines[i].actionHandleIndex = 0xFFFFFFFF;
        if ( htNode.nextEngines[i].nextEngine == e_FM_PCD_DONE &&
             xmlCCNode.entries[i].action      == "drop" ) {
            htNode.nextEngines[i].doneAction    = e_FM_PCD_DROP_FRAME;
            htNode.nextEngines[i].doneActionStr = "e_FM_PCD_DROP_FRAME";
        }
        if ( htNode.nextEngines[i].nextEngine == e_FM_PCD_CC ||
             htNode.nextEngines[i].nextEngine == e_FM_PCD_HASH ) {
            if ( htNode.nextEngines[i].nextEngineTrueType == e_FM_PCD_HASH ) {
                htNode.nextEngines[i].actionHandleIndex =
                get_htnode_index( pTaskDef,
                                  xmlCCNode.entries[i].actionName,
                                  htNode.name, port, false, kgHashShift );
                ApplyOrder::Entry n2( ApplyOrder::HTNode,
                                      htNode.nextEngines[i].actionHandleIndex );
                applier.add_edge( n1, n2 );
            }
            else {
                htNode.nextEngines[i].actionHandleIndex =
                    get_ccnode_index( pTaskDef,
                                      xmlCCNode.entries[i].actionName,
                                      htNode.name, port, false, kgHashShift );
                ApplyOrder::Entry n2( ApplyOrder::CCNode,
                                      htNode.nextEngines[i].actionHandleIndex );
                applier.add_edge( n1, n2 );
            }
        }
        else if ( htNode.nextEngines[i].nextEngine == e_FM_PCD_KG ) {
            htNode.nextEngines[i].actionHandleIndex =
                get_scheme_index( pTaskDef, xmlCCNode.entries[i].actionName,
                                  htNode.name, port, true );
            ApplyOrder::Entry n2( ApplyOrder::Scheme,
                                  htNode.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
        else if ( htNode.nextEngines[i].nextEngine == e_FM_PCD_PLCR ) {
            htNode.nextEngines[i].actionHandleIndex =
                get_policer_index( pTaskDef, xmlCCNode.entries[i].actionName,
                                   htNode.name, port );
            ApplyOrder::Entry n2( ApplyOrder::Policer,
                                  htNode.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
#if (DPAA_VERSION >= 11)
        else if ( htNode.nextEngines[i].nextEngine == e_FM_PCD_FR ) {
            htNode.nextEngines[i].actionHandleIndex =
                get_replicator_index( pTaskDef, xmlCCNode.entries[i].actionName,
                                   htNode.name, port, false );
            ApplyOrder::Entry n2( ApplyOrder::Replicator,
                                  htNode.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
#endif /* (DPAA_VERSION >= 11) */
    }
    //--end of entry
    htNode.nextEngineOnMiss.nextEngine = getEngineByType( xmlCCNode.actionOnMiss );

    //Save the true type of the next engine
    htNode.nextEngineOnMiss.nextEngineTrueType = htNode.nextEngineOnMiss.nextEngine;
    if ( htNode.nextEngineOnMiss.nextEngine == e_FM_PCD_CC ) {
        std::map< std::string, CClassification >::const_iterator nodeIt;
        nodeIt = pTaskDef->classifications.find( xmlCCNode.actionNameOnMiss );
        // Does such node exist?
        if ( nodeIt == pTaskDef->classifications.end() ) {
            throw CGenericError( ERR_CC_NOT_FOUND, xmlCCNode.actionNameOnMiss, xmlCCNode.name );
        }

        if ( nodeIt->second.key.hashTable )
            htNode.nextEngineOnMiss.nextEngineTrueType = e_FM_PCD_HASH;
        else
            htNode.nextEngineOnMiss.nextEngineTrueType = e_FM_PCD_CC;
    }

    htNode.nextEngineOnMiss.nextEngineStr = getEngineByTypeStr( xmlCCNode.actionOnMiss );
    htNode.nextEngineOnMiss.newFqid       = 0;
    htNode.nextEngineOnMiss.statistics    = xmlCCNode.statisticsOnMiss;

#if (DPAA_VERSION >= 11)
    //Change the VSP
    if ( xmlCCNode.vspOverrideOnMiss ) {
        if ( xmlCCNode.vspNameOnMiss != "" ) {
            std::map< std::string, CVsp >::const_iterator vspIt;
            vspIt = pTaskDef->vsps.find( xmlCCNode.vspNameOnMiss );
            // Does such VSP exist?
            if ( vspIt == pTaskDef->vsps.end() ) {
                throw CGenericError( ERR_VSP_NOT_FOUND, xmlCCNode.vspNameOnMiss, xmlCCNode.name );
            }

            htNode.nextEngineOnMiss.newRelativeStorageProfileId = vspIt->second.base;
        }
        else {
            htNode.nextEngineOnMiss.newRelativeStorageProfileId = xmlCCNode.vspBaseOnMiss;
        }
    }
    else {
        htNode.nextEngineOnMiss.newRelativeStorageProfileId = 0;
    }
#endif /* (DPAA_VERSION >= 11) */

    htNode.nextEngineOnMiss.doneAction        = e_FM_PCD_ENQ_FRAME;
    htNode.nextEngineOnMiss.doneActionStr     = "e_FM_PCD_ENQ_FRAME";
    htNode.nextEngineOnMiss.actionHandleIndex = 0xFFFFFFFF;
    if ( htNode.nextEngineOnMiss.nextEngine == e_FM_PCD_DONE &&
         xmlCCNode.actionOnMiss             == "drop" ) {
        htNode.nextEngineOnMiss.doneAction    = e_FM_PCD_DROP_FRAME;
        htNode.nextEngineOnMiss.doneActionStr = "e_FM_PCD_DROP_FRAME";
    }
    if ( htNode.nextEngineOnMiss.nextEngine == e_FM_PCD_CC ||
         htNode.nextEngineOnMiss.nextEngine == e_FM_PCD_HASH ) {
        //Check if it's a match or hash table
        if ( htNode.nextEngineOnMiss.nextEngineTrueType == e_FM_PCD_HASH ) {
            htNode.nextEngineOnMiss.actionHandleIndex =
            get_htnode_index( pTaskDef,
                                xmlCCNode.actionNameOnMiss,
                                htNode.name, port, false, kgHashShift );
            ApplyOrder::Entry n2( ApplyOrder::HTNode,
                                htNode.nextEngineOnMiss.actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
        else {
            htNode.nextEngineOnMiss.actionHandleIndex =
                get_ccnode_index( pTaskDef,
                                  xmlCCNode.actionNameOnMiss,
                                  htNode.name, port, false, kgHashShift );
            ApplyOrder::Entry n2( ApplyOrder::CCNode,
                                  htNode.nextEngineOnMiss.actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
    }
    else if ( htNode.nextEngineOnMiss.nextEngine == e_FM_PCD_HASH ) {
        htNode.nextEngineOnMiss.actionHandleIndex =
            get_htnode_index( pTaskDef, xmlCCNode.actionNameOnMiss,
                              htNode.name, port, true, kgHashShift  );
        ApplyOrder::Entry n2( ApplyOrder::HTNode,
                              htNode.nextEngineOnMiss.actionHandleIndex );
        applier.add_edge( n1, n2 );
    }
    else if ( htNode.nextEngineOnMiss.nextEngine == e_FM_PCD_KG ) {
        htNode.nextEngineOnMiss.actionHandleIndex =
            get_scheme_index( pTaskDef, xmlCCNode.actionNameOnMiss,
                              htNode.name, port, true );
        ApplyOrder::Entry n2( ApplyOrder::Scheme,
                              htNode.nextEngineOnMiss.actionHandleIndex );
        applier.add_edge( n1, n2 );
    }
    else if ( htNode.nextEngineOnMiss.nextEngine == e_FM_PCD_PLCR ) {
        htNode.nextEngineOnMiss.actionHandleIndex =
            get_policer_index( pTaskDef, xmlCCNode.actionNameOnMiss,
                               htNode.name, port );
        ApplyOrder::Entry n2( ApplyOrder::Policer,
                              htNode.nextEngineOnMiss.actionHandleIndex );
        applier.add_edge( n1, n2 );
    }
    else if ( htNode.nextEngineOnMiss.nextEngine == e_FM_PCD_DONE ) {
        htNode.nextEngineOnMiss.newFqid = xmlCCNode.qbase;
    }

    for ( unsigned int i = 0; i < xmlCCNode.may_use_action.size(); ++i ) {
        e_FmPcdEngine action     = getEngineByType( xmlCCNode.may_use_action[i] );
        std::string   actionName = xmlCCNode.may_use_actionName[i];
        switch ( action ) {
        case e_FM_PCD_HASH:
        case e_FM_PCD_CC:
            {
            unsigned int index =
                get_ccnode_index( pTaskDef, actionName, htNode.name, port,
                                  false, kgHashShift );

                std::map< std::string, CClassification >::const_iterator nodeIt = pTaskDef->classifications.find( actionName );
                // Does such node exist?
                if ( nodeIt == pTaskDef->classifications.end() ) {
                    throw CGenericError( ERR_CC_NOT_FOUND, actionName, htNode.name );
                }

                //determine action node type: CC or HT
                if ( nodeIt->second.key.hashTable ) {
                    ApplyOrder::Entry n2( ApplyOrder::HTNode, index );
                    applier.add_edge( n1, n2 );
                } else {
                    ApplyOrder::Entry n2( ApplyOrder::CCNode, index );
                    applier.add_edge( n1, n2 );
                }

            break;
            }
        case e_FM_PCD_KG:
            {
            unsigned int index =
                get_scheme_index( pTaskDef, actionName, htNode.name, port,
                                  true );
            ApplyOrder::Entry n2( ApplyOrder::Scheme, index );
            applier.add_edge( n1, n2 );
            break;
            }
        case e_FM_PCD_PLCR:
            {
            unsigned int index =
                get_policer_index( pTaskDef, actionName, htNode.name, port );
            ApplyOrder::Entry n2( ApplyOrder::Policer, index );
            applier.add_edge( n1, n2 );
            break;
            }
#if (DPAA_VERSION >= 11)
        case e_FM_PCD_FR:
            {
            unsigned int index =
                get_replicator_index( pTaskDef, actionName, htNode.name, port, false );
            ApplyOrder::Entry n2( ApplyOrder::Replicator, index );
            applier.add_edge( n1, n2 );
            break;
            }
#endif /* (DPAA_VERSION >= 11) */
        default:
            {}
        }
    }

    return htNode;
}

////////////////////////////////////////////////////////////////////////////////
/// Converts replicator parameters provided throught XML file
/// to the internal representation
////////////////////////////////////////////////////////////////////////////////
CRepl&
CFMCModel::createReplicator( const CTaskDef* pTaskDef, Port& port, const CReplicator& xmlRepl )
{
    CRepl& repl = all_replicators[FMBlock::assignIndex( all_replicators )];

    ApplyOrder::Entry n1( ApplyOrder::Replicator, repl.getIndex() );
    applier.add_edge( n1, ApplyOrder::Entry( ApplyOrder::None, 0 ) );

    port.replicators.push_back( repl.getIndex() );
    
    repl.name           = port.name + "/replicator/" + xmlRepl.name;

    //Pre-allocation
    repl.maxNumOfEntries = xmlRepl.max;

    repl.port_signature = port.name;

    // For each entry ...
    for ( unsigned int i = 0; i < xmlRepl.entries.size(); ++i ) {
        repl.indices.push_back( xmlRepl.entries[i].index );

        if ( xmlRepl.entries[i].headerManipName.empty() ) {
            repl.header.push_back( 0 );
        }
        else {
            std::map< std::string, CHeaderManip >::const_iterator headerit;
            unsigned int hdr_index = 0;
            for ( headerit = pTaskDef->headermanips.begin();
                  headerit != pTaskDef->headermanips.end();
                  ++headerit ) {
                hdr_index++;
                if ( headerit->second.name == xmlRepl.entries[i].headerManipName ) {
                    repl.header.push_back( hdr_index );
                    break;
                }
            }

            if (headerit == pTaskDef->headermanips.end())
            {
                throw CGenericError( ERR_MANIP_NOT_FOUND, xmlRepl.entries[i].headerManipName, xmlRepl.name );
            }
        }

        if ( xmlRepl.entries[i].fragmentationName.empty() ) {
            repl.frag.push_back( 0 );
        }
        else {
            std::map< std::string, CFragmentation >::const_iterator fragit;
            unsigned int frag_index = 0;
            for ( fragit = pTaskDef->fragmentations.begin();
                  fragit != pTaskDef->fragmentations.end();
                  ++fragit ) {
                frag_index++;
                if ( fragit->second.name == xmlRepl.entries[i].fragmentationName ) {
                    repl.frag.push_back( frag_index );
                    break;
                }
            }

            if (fragit == pTaskDef->fragmentations.end())
            {
                throw CGenericError( ERR_MANIP_NOT_FOUND, xmlRepl.entries[i].fragmentationName, xmlRepl.name );
            }
        }

        repl.nextEngines.push_back( CRepl::CCNextEngine() );
        repl.nextEngines[i].nextEngine        = getEngineByType( xmlRepl.entries[i].action );

        if ( repl.nextEngines[i].nextEngine == e_FM_PCD_CC ||
             repl.nextEngines[i].nextEngine == e_FM_PCD_HASH ) {

        }

        repl.nextEngines[i].nextEngineStr     = getEngineByTypeStr( xmlRepl.entries[i].action );
        repl.nextEngines[i].newFqid           = xmlRepl.entries[i].qbase;

#if (DPAA_VERSION >= 11)
    //Change the VSP
    if ( xmlRepl.entries[i].vspOverride ) {
        if (xmlRepl.entries[i].vspName != "") {
            std::map< std::string, CVsp >::const_iterator vspIt;
            vspIt = pTaskDef->vsps.find( xmlRepl.entries[i].vspName );
            // Does such VSP exist?
            if ( vspIt == pTaskDef->vsps.end() ) {
                throw CGenericError( ERR_VSP_NOT_FOUND, xmlRepl.entries[i].vspName, xmlRepl.name );
            }

            repl.nextEngines[i].newRelativeStorageProfileId = vspIt->second.base;
        }
        else {
            repl.nextEngines[i].newRelativeStorageProfileId = xmlRepl.entries[i].vspBase;
        }
    }
    else {
        repl.nextEngines[i].newRelativeStorageProfileId = 0;
    }
#endif /* (DPAA_VERSION >= 11) */

        repl.nextEngines[i].doneAction        = e_FM_PCD_ENQ_FRAME;
        repl.nextEngines[i].doneActionStr     = "e_FM_PCD_ENQ_FRAME";
        repl.nextEngines[i].actionHandleIndex = 0xFFFFFFFF;
        if ( repl.nextEngines[i].nextEngine == e_FM_PCD_DONE &&
             xmlRepl.entries[i].action      == "drop" ) {
            repl.nextEngines[i].doneAction    = e_FM_PCD_DROP_FRAME;
            repl.nextEngines[i].doneActionStr = "e_FM_PCD_DROP_FRAME";
        }
        if ( repl.nextEngines[i].nextEngine == e_FM_PCD_CC ||
             repl.nextEngines[i].nextEngine == e_FM_PCD_HASH ) {
            repl.nextEngines[i].actionHandleIndex =
                get_ccnode_index( pTaskDef,
                                  xmlRepl.entries[i].actionName,
                                  repl.name, port, false, 0);
            ApplyOrder::Entry n2( ApplyOrder::CCNode,
                                  repl.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
        else if ( repl.nextEngines[i].nextEngine == e_FM_PCD_KG ) {
            repl.nextEngines[i].actionHandleIndex =
                get_scheme_index( pTaskDef, xmlRepl.entries[i].actionName,
                                  repl.name, port, true );
            ApplyOrder::Entry n2( ApplyOrder::Scheme,
                                  repl.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
        else if ( repl.nextEngines[i].nextEngine == e_FM_PCD_PLCR ) {
            repl.nextEngines[i].actionHandleIndex =
                get_policer_index( pTaskDef, xmlRepl.entries[i].actionName,
                                   repl.name, port );
            ApplyOrder::Entry n2( ApplyOrder::Policer,
                                  repl.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
#if (DPAA_VERSION >= 11)
        else if ( repl.nextEngines[i].nextEngine == e_FM_PCD_FR ) {
            repl.nextEngines[i].actionHandleIndex =
                get_replicator_index( pTaskDef, xmlRepl.entries[i].actionName,
                                   repl.name, port, false );
            ApplyOrder::Entry n2( ApplyOrder::Replicator,
                                  repl.nextEngines[i].actionHandleIndex );
            applier.add_edge( n1, n2 );
        }
#endif /* (DPAA_VERSION >= 11) */
    }

 
    //resource pre-allocation may-use part
    for ( unsigned int i = 0; i < xmlRepl.may_use_action.size(); ++i ) {
        e_FmPcdEngine action     = getEngineByType( xmlRepl.may_use_action[i] );
        std::string   actionName = xmlRepl.may_use_actionName[i];
        switch ( action ) {
        case e_FM_PCD_HASH:
        case e_FM_PCD_CC:
            {
            unsigned int index =
                get_ccnode_index( pTaskDef, actionName, repl.name, port,
                                  false, 0 );

                std::map< std::string, CClassification >::const_iterator nodeIt = pTaskDef->classifications.find( actionName );
                // Does such node exist?
                if ( nodeIt == pTaskDef->classifications.end() ) {
                    throw CGenericError( ERR_CC_NOT_FOUND, actionName, repl.name );
                }

                //determine action node type: CC or HT
                if ( nodeIt->second.key.hashTable ) {
                    ApplyOrder::Entry n2( ApplyOrder::HTNode, index );
                    applier.add_edge( n1, n2 );
                } else {
                    ApplyOrder::Entry n2( ApplyOrder::CCNode, index );
                    applier.add_edge( n1, n2 );
                }

            break;
            }
        case e_FM_PCD_KG:
            {
            unsigned int index =
                get_scheme_index( pTaskDef, actionName, repl.name, port,
                                  true );
            ApplyOrder::Entry n2( ApplyOrder::Scheme, index );
            applier.add_edge( n1, n2 );
            break;
            }
        case e_FM_PCD_PLCR:
            {
            unsigned int index =
                get_policer_index( pTaskDef, actionName, repl.name, port );
            ApplyOrder::Entry n2( ApplyOrder::Policer, index );
            applier.add_edge( n1, n2 );
            break;
            }
#if (DPAA_VERSION >= 11)
        case e_FM_PCD_FR:
            {
            unsigned int index =
                get_replicator_index( pTaskDef, actionName, repl.name, port, false );
            ApplyOrder::Entry n2( ApplyOrder::Replicator, index );
            applier.add_edge( n1, n2 );
            break;
            }
#endif /* (DPAA_VERSION >= 11) */
        default:
            {}
        }
    }

    return repl;
}


////////////////////////////////////////////////////////////////////////////////
/// Finds XML definition for a coarse classification node and adds it
////////////////////////////////////////////////////////////////////////////////
unsigned int
CFMCModel::get_ccnode_index( const CTaskDef* pTaskDef, std::string name,
                             std::string from, Port& port, bool isRoot, unsigned int kgHashShift, unsigned int manip )
{
    std::map< std::string, CClassification >::const_iterator nodeIt;
    nodeIt = pTaskDef->classifications.find( name );
    // Does such node exist?
    if ( nodeIt == pTaskDef->classifications.end() ) {
        throw CGenericError( ERR_CC_NOT_FOUND, name, from );
    }

    if ( nodeIt->second.key.hashTable ) {
        return get_htnode_index(pTaskDef, name, from, port, isRoot, kgHashShift, manip);
    }

    // Check whether this node was already created
    bool         found = false;
    unsigned int index;
    for ( unsigned int i = 0; i < all_ccnodes.size(); ++i ) {
        if ( all_ccnodes[i].shared ) {
            if ( ( all_ccnodes[i].name == port.name.substr( 0, 3 ) + "/ccnode/" + name ) ) {
                found = true;
                index = all_ccnodes[i].getIndex();
            }
        }
        else {
            if ( ( all_ccnodes[i].name           == port.name + "/ccnode/" + name ) &&
                 ( all_ccnodes[i].port_signature == port.name ) ) {
                found = true;
                index = all_ccnodes[i].getIndex();
            }
        }
    }

    if ( !found ) {
        CCNode& ccnode = createCCNode( pTaskDef, port, nodeIt->second, kgHashShift );
        index = ccnode.getIndex();
    }

    ApplyOrder::Entry root( ApplyOrder::CCTree, port.getIndex() );
    ApplyOrder::Entry node( ApplyOrder::CCNode, index );
    applier.add_edge( root, node );

    if ( isRoot ) {
		//ENGR00320235 Optimization: check if this CC Root index already exists with the same manipulation and in this case reuse it 
		for (int i = 0; i < port.cctrees.size(); i++) {
			if (port.cctrees[i] == index && port.cctrees_type[i] == e_FM_PCD_CC && port.hdrmanips[i] == manip)
				return i;
		}
	
		port.cctrees.push_back( index );
		port.cctrees_type.push_back( e_FM_PCD_CC );
		port.hdrmanips.push_back( manip );
        return port.cctrees.size() - 1;
    }
    return index;
}

////////////////////////////////////////////////////////////////////////////////
/// Finds XML definition for a hash table node and adds it
////////////////////////////////////////////////////////////////////////////////
unsigned int
CFMCModel::get_htnode_index( const CTaskDef* pTaskDef, std::string name,
                             std::string from, Port& port, bool isRoot, unsigned int kgHashShift, unsigned int manip )
{
    std::map< std::string, CClassification >::const_iterator nodeIt;
    nodeIt = pTaskDef->classifications.find( name );
    // Does such node exist?
    if ( nodeIt == pTaskDef->classifications.end() ) {
        throw CGenericError( ERR_CC_NOT_FOUND, name, from );
    }

    // Check whether this node was already created
    bool         found = false;
    unsigned int index;
    for ( unsigned int i = 0; i < all_htnodes.size(); ++i ) {
        if ( ( all_htnodes[i].name           == port.name + "/ccnode/" + name ) &&
             ( all_htnodes[i].port_signature == port.name ) ) {
            found = true;
            index = all_htnodes[i].getIndex();
            if (all_htnodes[i].kgHashShift != kgHashShift)
            {
                throw CGenericError( ERR_HT_SHIFT, all_htnodes[i].name );
            }
        }
    }

    if ( !found ) {
        HTNode& htnode = createHTNode( pTaskDef, port, nodeIt->second, kgHashShift );
        index = htnode.getIndex();
    }

    ApplyOrder::Entry root( ApplyOrder::CCTree, port.getIndex() );
    ApplyOrder::Entry node( ApplyOrder::HTNode, index );
    applier.add_edge( root, node );

    if ( isRoot ) {
		//ENGR00320235 Optimization: check if this CC Root index already exists with the same manipulation and in this case reuse it 
		for (int i = 0; i < port.cctrees.size(); i++) {
			if (port.cctrees[i] == index && port.cctrees_type[i] == e_FM_PCD_HASH && port.hdrmanips[i] == manip)
				return i;
		}

		port.cctrees.push_back( index );
		port.cctrees_type.push_back( e_FM_PCD_HASH );
		port.hdrmanips.push_back( manip );
        return port.cctrees.size() - 1;
    }
    return index;
}

#if DPAA_VERSION >= 11
////////////////////////////////////////////////////////////////////////////////
/// Finds XML definition for a replicator node and adds it
////////////////////////////////////////////////////////////////////////////////
unsigned int
CFMCModel::get_replicator_index( const CTaskDef* pTaskDef, std::string name,
                             std::string from, Port& port, bool isRoot, unsigned int manip )
{
    std::map< std::string, CReplicator >::const_iterator replIt;
    replIt = pTaskDef->replicators.find( name );
    // Does such node exist?
    if ( replIt == pTaskDef->replicators.end() ) {
        throw CGenericError( ERR_REP_NOT_FOUND, name, from );
    }

    // Check whether this node was already created
    bool         found = false;
    unsigned int index;
    for ( unsigned int i = 0; i < all_replicators.size(); ++i ) {
        if ( ( all_replicators[i].name           == port.name + "/replicator/" + name ) &&
             ( all_replicators[i].port_signature == port.name ) ) {
            found = true;
            index = all_replicators[i].getIndex();
        }
    }

    if ( !found ) {
        CRepl& replicator = createReplicator( pTaskDef, port, replIt->second );
        index = replicator.getIndex();
    }

    ApplyOrder::Entry root( ApplyOrder::CCTree, port.getIndex() );
    ApplyOrder::Entry node( ApplyOrder::Replicator, index );
    applier.add_edge( root, node );

    if ( isRoot ) {
		//ENGR00320235 Optimization: check if this CC Root index already exists with the same manipulation and in this case reuse it 
		for (int i = 0; i < port.cctrees.size(); i++) {
			if (port.cctrees[i] == index && port.cctrees_type[i] == e_FM_PCD_FR && port.hdrmanips[i] == manip)
				return i;
		}

		port.cctrees.push_back( index );
		port.cctrees_type.push_back( e_FM_PCD_FR );
		port.hdrmanips.push_back( manip );
        return port.cctrees.size() - 1;
    }
    return index;
}
#endif /* DPAA_VERSION >= 11 */

////////////////////////////////////////////////////////////////////////////////
/// Converts Distribution parameters provided throught XML file to the internal
/// softparse result structure
////////////////////////////////////////////////////////////////////////////////
void
CFMCModel::createSoftParse( const CTaskDef* pTaskDef )
{
    const CSoftParseResult& taskSpr = pTaskDef->spr;

    if (!taskSpr.softParseEnabled)
        spEnable = 0;
    else
    {
        spEnable = 1;
        swPrs.override    = TRUE;
        swPrs.size        = taskSpr.size;
        swPrs.base        = taskSpr.base;
        swPrs.numOfLabels = taskSpr.numOfLabels;
        swPrs.p_Code      = spCode;

        // Copy SP code
        unsigned int i, j;
        memset( spCode, 0, CODE_SIZE );
        for ( i = 2*( taskSpr.base - ASSEMBLER_BASE ), j = 0; i < CODE_SIZE - 4; ++i, ++j ) {
            spCode[j] = taskSpr.p_Code[i];
        }

        // Copy SP parameters
        for ( i = 0; i < FM_PCD_PRS_NUM_OF_HDRS; ++i ) {
            swPrs.swPrsDataParams[i] = 0;
        }

        // Copy SP label info
        for ( i = 0; i < swPrs.numOfLabels; ++i ) {
            swPrs.labelsTable[i].indexPerHdr =
                taskSpr.labelsTable[i].indexPerHdr;
            swPrs.labelsTable[i].instructionOffset =
                taskSpr.labelsTable[i].position;
            swPrs.labelsTable[i].hdr =
                getNetCommHeaderType(taskSpr.labelsTable[i].prevNames[0]);
            if ( swPrs.labelsTable[i].hdr == HEADER_TYPE_NONE ) {
                std::string shim_protocol =
                    pTaskDef->getShimNoFromCustom( taskSpr.labelsTable[i].prevNames[0] );
                if ( !shim_protocol.empty() ) { // Shim header is empty if custom protocol is not found
                    swPrs.labelsTable[i].hdr = getNetCommHeaderType( shim_protocol );
                }
                else {
                    // Header type HEADER_TYPE_NONE is not accepted as a valid value
                    throw CGenericError( ERR_UNKNOWN_PROTOCOL, taskSpr.labelsTable[i].prevNames[0] );
                }
            }
        }
    }
}


////////////////////////////////////////////////////////////////////////////////
/// Finds XML definition for a scheme and adds it
////////////////////////////////////////////////////////////////////////////////
unsigned int
CFMCModel::get_scheme_index( const CTaskDef* pTaskDef, std::string name,
                             std::string from, Port& port, bool isDirect )
{
    std::map< std::string, CDistribution >::const_iterator distIt;
    distIt = pTaskDef->distributions.find( name );
    // Does such distribution exist?
    if ( distIt == pTaskDef->distributions.end() ) {
        throw CGenericError( ERR_DISTR_NOT_FOUND, name, from );
    }

    // Check whether this scheme was already created
    bool         found = false;
    unsigned int index;
    for ( unsigned int i = 0; i < all_schemes.size(); ++i ) {
		if ( all_schemes[i].shared ) {
			if ( ( all_schemes[i].name           == port.name.substr( 0, 3 ) + "/dist/" + name + ((isDirect)?"/direct":"") ) &&
				 ( all_schemes[i].isDirect       == ( isDirect ? 1 : 0 ) ) ) {
				found = true;
				index = all_schemes[i].getIndex();
				port.schemes.push_back(index);
			}
		} else {
			if ( ( all_schemes[i].name           == port.name + "/dist/" + name + ((isDirect)?"/direct":"") ) &&
				( all_schemes[i].isDirect       == ( isDirect ? 1 : 0 ) ) &&
				( all_schemes[i].port_signature == port.name ) ) {
					found = true;
					index = all_schemes[i].getIndex();
			}
		}
    }

    if ( !found ) {
        Scheme& scheme = createScheme( pTaskDef, port, distIt->second, isDirect );
        index = scheme.getIndex();
		port.schemes.push_back(index);
    }


    return index;
}

////////////////////////////////////////////////////////////////////////////////
/// Converts Policer parameters provided throught XML file to the internal
/// Policer structure
////////////////////////////////////////////////////////////////////////////////
Policer&
CFMCModel::createPolicer( const CTaskDef* pTaskDef, Port& port, const CPolicer& xmlPolicer )
{
    Policer& policer = all_policers[FMBlock::assignIndex( all_policers )];

    ApplyOrder::Entry n1( ApplyOrder::Policer, policer.getIndex() );
    applier.add_edge( n1, ApplyOrder::Entry( ApplyOrder::None, 0 ) );

    policer.shared = xmlPolicer.shared;
    if ( policer.shared ) {
        policer.name = port.name.substr( 0, 3 ) + "/policer/" + xmlPolicer.name;
    }
    else {
        policer.name = port.name + "/policer/" + xmlPolicer.name;
    }
    policer.port_signature = port.name;

    switch( xmlPolicer.algorithm ) {
        case 1:
            policer.algorithm    = e_FM_PCD_PLCR_RFC_2698;
            policer.algorithmStr = "e_FM_PCD_PLCR_RFC_2698";
            break;
        case 2:
            policer.algorithm    = e_FM_PCD_PLCR_RFC_4115;
            policer.algorithmStr = "e_FM_PCD_PLCR_RFC_4115";
            break;
        default:
            policer.algorithm    = e_FM_PCD_PLCR_PASS_THROUGH;
            policer.algorithmStr = "e_FM_PCD_PLCR_PASS_THROUGH";
            break;
    }

    if ( xmlPolicer.color_mode == 1 ) {
        policer.colorMode    = e_FM_PCD_PLCR_COLOR_AWARE;
        policer.colorModeStr = "e_FM_PCD_PLCR_COLOR_AWARE";
    }
    else {
        policer.colorMode    = e_FM_PCD_PLCR_COLOR_BLIND;
        policer.colorModeStr = "e_FM_PCD_PLCR_COLOR_BLIND";
    }

    if ( xmlPolicer.unit == 1 ) {
        policer.rateMode    = e_FM_PCD_PLCR_PACKET_MODE;
        policer.rateModeStr = "e_FM_PCD_PLCR_PACKET_MODE";
    }
    else {
        policer.rateMode    = e_FM_PCD_PLCR_BYTE_MODE;
        policer.rateModeStr = "e_FM_PCD_PLCR_BYTE_MODE";
    }

    policer.committedInfoRate         = xmlPolicer.CIR;
    policer.peakOrExcessInfoRate  = xmlPolicer.EIR;
    policer.committedBurstSize        = xmlPolicer.CBS;
    policer.peakOrExcessBurstSize = xmlPolicer.EBS;

    policer.dfltColor    = getPlcrColor( xmlPolicer.dfltColor );
    policer.dfltColorStr = getPlcrColorStr( xmlPolicer.dfltColor );

    policer.nextEngineOnGreen        = getEngineByType( xmlPolicer.actionOnGreen );
    policer.nextEngineOnGreenStr     = getEngineByTypeStr( xmlPolicer.actionOnGreen );
    policer.onGreenAction            = e_FM_PCD_ENQ_FRAME;
    policer.onGreenActionStr         = "e_FM_PCD_ENQ_FRAME";
    policer.onGreenActionHandleIndex = 0xFFFFFFFF;
    if ( xmlPolicer.actionOnGreen == "drop" ) {
        policer.onGreenAction    = e_FM_PCD_DROP_FRAME;
        policer.onGreenActionStr = "e_FM_PCD_DROP_FRAME";
    }
    if ( policer.nextEngineOnGreen == e_FM_PCD_KG ) {
        policer.onGreenActionHandleIndex =
            get_scheme_index( pTaskDef, xmlPolicer.actionNameOnGreen,
                              xmlPolicer.name, port, true );
        ApplyOrder::Entry n2( ApplyOrder::Scheme,
                              policer.onGreenActionHandleIndex );
        applier.add_edge( n1, n2 );
    } else if ( policer.nextEngineOnGreen == e_FM_PCD_PLCR ) {
        policer.onGreenActionHandleIndex =
            get_policer_index( pTaskDef, xmlPolicer.actionNameOnGreen,
                               xmlPolicer.name, port );
        ApplyOrder::Entry n2( ApplyOrder::Policer,
                              policer.onGreenActionHandleIndex );
        applier.add_edge( n1, n2 );
    }

    policer.nextEngineOnYellow        = getEngineByType( xmlPolicer.actionOnYellow );
    policer.nextEngineOnYellowStr     = getEngineByTypeStr( xmlPolicer.actionOnYellow );
    policer.onYellowAction            = e_FM_PCD_ENQ_FRAME;
    policer.onYellowActionStr         = "e_FM_PCD_ENQ_FRAME";
    policer.onYellowActionHandleIndex = 0xFFFFFFFF;

    if ( xmlPolicer.actionOnYellow == "drop" ) {
        policer.onYellowAction    = e_FM_PCD_DROP_FRAME;
        policer.onYellowActionStr = "e_FM_PCD_DROP_FRAME";
    }
    if ( policer.nextEngineOnYellow == e_FM_PCD_KG ) {
        policer.onYellowActionHandleIndex =
            get_scheme_index( pTaskDef, xmlPolicer.actionNameOnYellow,
                              xmlPolicer.name, port, true );
        ApplyOrder::Entry n2( ApplyOrder::Scheme,
                              policer.onYellowActionHandleIndex );
        applier.add_edge( n1, n2 );
    } else if ( policer.nextEngineOnYellow == e_FM_PCD_PLCR ) {
        policer.onYellowActionHandleIndex =
            get_policer_index( pTaskDef, xmlPolicer.actionNameOnYellow,
                               xmlPolicer.name, port );
        ApplyOrder::Entry n2( ApplyOrder::Policer,
                              policer.onYellowActionHandleIndex );
        applier.add_edge( n1, n2 );
    }

    policer.nextEngineOnRed        = getEngineByType( xmlPolicer.actionOnRed );
    policer.nextEngineOnRedStr     = getEngineByTypeStr( xmlPolicer.actionOnRed );
    policer.onRedAction            = e_FM_PCD_ENQ_FRAME;
    policer.onRedActionStr         = "e_FM_PCD_ENQ_FRAME";
    policer.onRedActionHandleIndex = 0xFFFFFFFF;
    if ( xmlPolicer.actionOnRed == "drop" ) {
        policer.onRedAction    = e_FM_PCD_DROP_FRAME;
        policer.onRedActionStr = "e_FM_PCD_DROP_FRAME";
    }
    if ( policer.nextEngineOnRed == e_FM_PCD_KG ) {
        policer.onRedActionHandleIndex =
            get_scheme_index( pTaskDef, xmlPolicer.actionNameOnRed,
                              xmlPolicer.name, port, true );
        ApplyOrder::Entry n2( ApplyOrder::Scheme,
                              policer.onRedActionHandleIndex );
        applier.add_edge( n1, n2 );
    } else if ( policer.nextEngineOnRed == e_FM_PCD_PLCR ) {
        policer.onRedActionHandleIndex =
            get_policer_index( pTaskDef, xmlPolicer.actionNameOnRed,
                               xmlPolicer.name, port );
        ApplyOrder::Entry n2( ApplyOrder::Policer,
                              policer.onRedActionHandleIndex );
        applier.add_edge( n1, n2 );
    }

    return policer;
}


////////////////////////////////////////////////////////////////////////////////
/// Finds XML definition for a policer and adds it
////////////////////////////////////////////////////////////////////////////////
unsigned int
CFMCModel::get_policer_index( const CTaskDef* pTaskDef, std::string name,
                              std::string from, Port& port )
{
    std::map< std::string, CPolicer >::const_iterator policerIt;
    policerIt = pTaskDef->policers.find( name );
    // Does such policer exist?
    if ( policerIt == pTaskDef->policers.end() ) {
        throw CGenericError( ERR_POLICER_NOT_FOUND, name, from );
    }

    // Check whether this policer was already created
    bool         found = false;
    unsigned int index;
    for ( unsigned int i = 0; i < all_policers.size(); ++i ) {
        if ( all_policers[i].shared ) {
            if ( ( all_policers[i].name == port.name.substr( 0, 3 ) + "/policer/" + name ) ) {
                found = true;
                index = all_policers[i].getIndex();
            }
        }
        else {
            if ( ( all_policers[i].name           == port.name + "/policer/" + name ) &&
                 ( all_policers[i].port_signature == port.name ) ) {
                found = true;
                index = all_policers[i].getIndex();
            }
         }
    }

    if ( !found ) {
        Policer& policer = createPolicer( pTaskDef, port, policerIt->second );
        index = policer.getIndex();
    }

    return index;
}


////////////////////////////////////////////////////////////////////////////////
/// Returns port type as e_FmPortType
////////////////////////////////////////////////////////////////////////////////
e_FmPortType
CFMCModel::getPortType( std::string type )
{
    if ( "1G" == type ) {
        return e_FM_PORT_TYPE_RX;
    }
    else if ( "10G" == type ) {
        return e_FM_PORT_TYPE_RX_10G;
    }
    else if ( "OFFLINE" == type ) {
        return e_FM_PORT_TYPE_OH_OFFLINE_PARSING;
    }
    else if ( "TX_1G" == type ) {
        return e_FM_PORT_TYPE_TX;
    }
    else if ( "TX_10G" == type ) {
        return e_FM_PORT_TYPE_TX_10G;
    }
    else {
        return e_FM_PORT_TYPE_DUMMY;
    }
}


////////////////////////////////////////////////////////////////////////////////
/// Returns port type as e_FmPortType converted to string
////////////////////////////////////////////////////////////////////////////////
std::string
CFMCModel::getPortTypeStr( e_FmPortType type )
{
    switch ( type ) {
        case e_FM_PORT_TYPE_OH_OFFLINE_PARSING:
            return "e_FM_PORT_TYPE_OH_OFFLINE_PARSING";
        case e_FM_PORT_TYPE_RX:
            return "e_FM_PORT_TYPE_RX";
        case e_FM_PORT_TYPE_RX_10G:
            return "e_FM_PORT_TYPE_RX_10G";
        case e_FM_PORT_TYPE_TX:
            return "e_FM_PORT_TYPE_TX";
        case e_FM_PORT_TYPE_TX_10G:
            return "e_FM_PORT_TYPE_TX_10G";
        case e_FM_PORT_TYPE_DUMMY:
            return "e_FM_PORT_TYPE_DUMMY";
    }

    return "e_FM_PORT_TYPE_DUMMY";
}


////////////////////////////////////////////////////////////////////////////////
/// Returns NetComm header type as e_NetHeaderType
////////////////////////////////////////////////////////////////////////////////
e_NetHeaderType
CFMCModel::getNetCommHeaderType( std::string protoname )
{
    std::map< std::string, e_NetHeaderType > net_types;
    net_types[ "ethernet" ]  = HEADER_TYPE_ETH;
    net_types[ "vlan" ]      = HEADER_TYPE_VLAN;
    net_types[ "llc_snap" ]  = HEADER_TYPE_LLC_SNAP;
    net_types[ "mpls" ]      = HEADER_TYPE_MPLS;
    net_types[ "ipv4" ]      = HEADER_TYPE_IPv4;
    net_types[ "ipv6" ]      = HEADER_TYPE_IPv6;
    net_types[ "ip" ]        = HEADER_TYPE_IP;
    net_types[ "tcp" ]       = HEADER_TYPE_TCP;
    net_types[ "udp" ]       = HEADER_TYPE_UDP;
    net_types[ "gre" ]       = HEADER_TYPE_GRE;
    net_types[ "pppoe" ]     = HEADER_TYPE_PPPoE;
    net_types[ "minencap" ]  = HEADER_TYPE_MINENCAP;
    net_types[ "sctp" ]      = HEADER_TYPE_SCTP;
    net_types[ "dccp" ]      = HEADER_TYPE_DCCP;
    net_types[ "ipsec_ah" ]  = HEADER_TYPE_IPSEC_AH;
    net_types[ "ipsec_esp" ] = HEADER_TYPE_IPSEC_ESP;
	net_types[ "otherl3" ]     = HEADER_TYPE_USER_DEFINED_L3;
	net_types[ "otherl4" ]     = HEADER_TYPE_USER_DEFINED_L4;
    net_types[ "shim1" ]     = HEADER_TYPE_USER_DEFINED_SHIM1;
    net_types[ "shim2" ]     = HEADER_TYPE_USER_DEFINED_SHIM2;
#ifdef FM_SHIM3_SUPPORT
    net_types[ "shim3" ]     = HEADER_TYPE_USER_DEFINED_SHIM3;
#endif /* FM_SHIM3_SUPPORT */


    if ( net_types.find( protoname ) != net_types.end() ) {
        return net_types[protoname];
    }

    return HEADER_TYPE_NONE;
}


////////////////////////////////////////////////////////////////////////////////
/// Returns NetComm header type as e_NetHeaderType converted to string
////////////////////////////////////////////////////////////////////////////////
std::string
CFMCModel::getNetCommHeaderTypeStr( std::string protoname )
{
    std::map< std::string, std::string > net_types;
    net_types[ "ethernet" ]  = "HEADER_TYPE_ETH";
    net_types[ "vlan" ]      = "HEADER_TYPE_VLAN";
    net_types[ "llc_snap" ]  = "HEADER_TYPE_LLC_SNAP";
    net_types[ "mpls" ]      = "HEADER_TYPE_MPLS";
    net_types[ "ipv4" ]      = "HEADER_TYPE_IPv4";
    net_types[ "ipv6" ]      = "HEADER_TYPE_IPv6";
    net_types[ "ip" ]        = "HEADER_TYPE_IP";
    net_types[ "tcp" ]       = "HEADER_TYPE_TCP";
    net_types[ "udp" ]       = "HEADER_TYPE_UDP";
    net_types[ "gre" ]       = "HEADER_TYPE_GRE";
    net_types[ "pppoe" ]     = "HEADER_TYPE_PPPoE";
    net_types[ "minencap" ]  = "HEADER_TYPE_MINENCAP";
    net_types[ "sctp" ]      = "HEADER_TYPE_SCTP";
    net_types[ "dccp" ]      = "HEADER_TYPE_DCCP";
    net_types[ "ipsec_ah" ]  = "HEADER_TYPE_IPSEC_AH";
    net_types[ "ipsec_esp" ] = "HEADER_TYPE_IPSEC_ESP";
	net_types[ "otherl3" ]     = "HEADER_TYPE_USER_DEFINED_L3";
	net_types[ "otherl4" ]     = "HEADER_TYPE_USER_DEFINED_L4";
    net_types[ "shim1" ]     = "HEADER_TYPE_USER_DEFINED_SHIM1";
    net_types[ "shim2" ]     = "HEADER_TYPE_USER_DEFINED_SHIM2";
#ifdef FM_SHIM3_SUPPORT
    net_types[ "shim3" ]     = "HEADER_TYPE_USER_DEFINED_SHIM3";
#endif /* FM_SHIM3_SUPPORT */

    if ( net_types.find( protoname ) != net_types.end() ) {
        return net_types[protoname];
    }

    return "HEADER_TYPE_NONE";
}


////////////////////////////////////////////////////////////////////////////////
/// Returns NetComm header type as e_NetHeaderType converted to string
////////////////////////////////////////////////////////////////////////////////
std::string
CFMCModel::getNetCommHeaderTypeStr( e_NetHeaderType proto )
{
    std::map< e_NetHeaderType, std::string > net_types;
    net_types[ HEADER_TYPE_ETH ]                = "HEADER_TYPE_ETH";
    net_types[ HEADER_TYPE_VLAN ]               = "HEADER_TYPE_VLAN";
    net_types[ HEADER_TYPE_LLC_SNAP ]           = "HEADER_TYPE_LLC_SNAP";
    net_types[ HEADER_TYPE_MPLS ]               = "HEADER_TYPE_MPLS";
    net_types[ HEADER_TYPE_IPv4 ]               = "HEADER_TYPE_IPv4";
    net_types[ HEADER_TYPE_IPv6 ]               = "HEADER_TYPE_IPv6";
    net_types[ HEADER_TYPE_IP ]                 = "HEADER_TYPE_IP";
    net_types[ HEADER_TYPE_TCP ]                = "HEADER_TYPE_TCP";
    net_types[ HEADER_TYPE_UDP ]                = "HEADER_TYPE_UDP";
    net_types[ HEADER_TYPE_GRE ]                = "HEADER_TYPE_GRE";
    net_types[ HEADER_TYPE_PPPoE ]              = "HEADER_TYPE_PPPoE";
    net_types[ HEADER_TYPE_MINENCAP ]           = "HEADER_TYPE_MINENCAP";
    net_types[ HEADER_TYPE_SCTP ]               = "HEADER_TYPE_SCTP";
    net_types[ HEADER_TYPE_DCCP ]               = "HEADER_TYPE_DCCP";
    net_types[ HEADER_TYPE_IPSEC_AH ]           = "HEADER_TYPE_IPSEC_AH";
    net_types[ HEADER_TYPE_IPSEC_ESP ]          = "HEADER_TYPE_IPSEC_ESP";
	net_types[ HEADER_TYPE_USER_DEFINED_L3 ]          = "HEADER_TYPE_USER_DEFINED_L3";
	net_types[ HEADER_TYPE_USER_DEFINED_L4 ]          = "HEADER_TYPE_USER_DEFINED_L4";
    net_types[ HEADER_TYPE_USER_DEFINED_SHIM1 ] = "HEADER_TYPE_USER_DEFINED_SHIM1";
    net_types[ HEADER_TYPE_USER_DEFINED_SHIM2 ] = "HEADER_TYPE_USER_DEFINED_SHIM2";
#ifdef FM_SHIM3_SUPPORT
    net_types[ HEADER_TYPE_USER_DEFINED_SHIM3 ] = "HEADER_TYPE_USER_DEFINED_SHIM3";
#endif /* FM_SHIM3_SUPPORT */

    if ( net_types.find( proto ) != net_types.end() ) {
        return net_types[proto];
    }

    return "HEADER_TYPE_NONE";
}


////////////////////////////////////////////////////////////////////////////////
/// Returns NetComm field type converted to string
////////////////////////////////////////////////////////////////////////////////
unsigned int
CFMCModel::getNetCommFieldType( std::string fieldname )
{
    std::map< std::string, unsigned int > fields;

    fields["ethernet.dst"]        = NET_HEADER_FIELD_ETH_DA;
    fields["ethernet.src"]        = NET_HEADER_FIELD_ETH_SA;
    fields["ethernet.type"]       = NET_HEADER_FIELD_ETH_TYPE;
    fields["vlan.pri"]            = NET_HEADER_FIELD_VLAN_VPRI;
    fields["vlan.cfi"]            = NET_HEADER_FIELD_VLAN_CFI;
    fields["vlan.vlanid"]         = NET_HEADER_FIELD_VLAN_VID;
    fields["vlan.type"]           = NET_HEADER_FIELD_VLAN_TYPE;
    fields["vlan.tci"]            = NET_HEADER_FIELD_VLAN_TCI;
    fields["llc_snap.OUI"]        = NET_HEADER_FIELD_SNAP_OUI;
    fields["llc_snap.type"]       = NET_HEADER_FIELD_LLC_SNAP_TYPE;
    fields["llc_snap.dsap"]       = NET_HEADER_FIELD_LLC_DSAP;
    fields["llc_snap.ssap"]       = NET_HEADER_FIELD_LLC_SSAP;
    fields["mpls.label"]          = NET_HEADER_FIELD_MPLS_LABEL_STACK;
    fields["ipv4.ver"]            = NET_HEADER_FIELD_IPv4_VER;
    fields["ipv4.hlen"]           = NET_HEADER_FIELD_IPv4_HDR_LEN;
    fields["ipv4.tos"]            = NET_HEADER_FIELD_IPv4_TOS;
    fields["ipv4.tlen"]           = NET_HEADER_FIELD_IPv4_TOTAL_LEN;
    fields["ipv4.identification"] = NET_HEADER_FIELD_IPv4_ID;
    fields["ipv4.df"]             = NET_HEADER_FIELD_IPv4_FLAG_D;
    fields["ipv4.mf"]             = NET_HEADER_FIELD_IPv4_FLAG_M;
    fields["ipv4.foffset"]        = NET_HEADER_FIELD_IPv4_OFFSET;
    fields["ipv4.ttl"]            = NET_HEADER_FIELD_IPv4_TTL;
    fields["ipv4.nextp"]          = NET_HEADER_FIELD_IPv4_PROTO;
    fields["ipv4.hchecksum"]      = NET_HEADER_FIELD_IPv4_CKSUM;
    fields["ipv4.src"]            = NET_HEADER_FIELD_IPv4_SRC_IP;
    fields["ipv4.dst"]            = NET_HEADER_FIELD_IPv4_DST_IP;

    //ENGR00305912:
    fields["ipv6.ver"]            = NET_HEADER_FIELD_IPv6_VER | NET_HEADER_FIELD_IPv6_TC;
    fields["ipv6.tos"]            = NET_HEADER_FIELD_IPv6_VER | NET_HEADER_FIELD_IPv6_TC;
    fields["ipv6.flabel"]         = NET_HEADER_FIELD_IPv6_FL;
    //ENGR00303764:
    //fields["ipv6.ver"]            = NET_HEADER_FIELD_IPv6_VER | NET_HEADER_FIELD_IPv6_TC | NET_HEADER_FIELD_IPv6_FL;
    //fields["ipv6.tos"]            = NET_HEADER_FIELD_IPv6_VER | NET_HEADER_FIELD_IPv6_TC | NET_HEADER_FIELD_IPv6_FL;

    fields["ipv6.nexthdr"]        = NET_HEADER_FIELD_IPv6_NEXT_HDR;
    fields["ipv6.src"]            = NET_HEADER_FIELD_IPv6_SRC_IP;
    fields["ipv6.dst"]            = NET_HEADER_FIELD_IPv6_DST_IP;
    fields["ipv6.hop"]            = NET_HEADER_FIELD_IPv6_HOP_LIMIT;
    fields["ip.nextp"]            = NET_HEADER_FIELD_IP_PROTO;
    fields["ip.dscp"]             = NET_HEADER_FIELD_IP_DSCP;
    fields["tcp.sport"]           = NET_HEADER_FIELD_TCP_PORT_SRC;
    fields["tcp.dport"]           = NET_HEADER_FIELD_TCP_PORT_DST;
    fields["tcp.seq"]             = NET_HEADER_FIELD_TCP_SEQ;
    fields["tcp.ack"]             = NET_HEADER_FIELD_TCP_ACK;
    fields["tcp.flags"]           = NET_HEADER_FIELD_TCP_FLAGS;
    fields["tcp.win"]             = NET_HEADER_FIELD_TCP_WINDOW;
    fields["tcp.crc"]             = NET_HEADER_FIELD_TCP_CKSUM;
    fields["tcp.urg"]             = NET_HEADER_FIELD_TCP_URGPTR;
    fields["udp.sport"]           = NET_HEADER_FIELD_UDP_PORT_SRC;
    fields["udp.dport"]           = NET_HEADER_FIELD_UDP_PORT_DST;
    fields["udp.len"]             = NET_HEADER_FIELD_UDP_LEN;
    fields["udp.crc"]             = NET_HEADER_FIELD_UDP_CKSUM;
    fields["gre.type"]            = NET_HEADER_FIELD_GRE_TYPE;
    fields["pppoe.ver"]           = NET_HEADER_FIELD_PPPoE_VER;
    fields["pppoe.type"]          = NET_HEADER_FIELD_PPPoE_TYPE;
    fields["pppoe.code"]          = NET_HEADER_FIELD_PPPoE_CODE;
    fields["pppoe.session_ID"]    = NET_HEADER_FIELD_PPPoE_SID;
    fields["pppoe.hlen"]          = NET_HEADER_FIELD_PPPoE_LEN;
    fields["pppoe.nextp"]         = NET_HEADER_FIELD_PPPoE_PID;
    fields["minencap.dst"]        = NET_HEADER_FIELD_MINENCAP_DST_IP;
    fields["sctp.sport"]          = NET_HEADER_FIELD_SCTP_PORT_SRC;
    fields["sctp.dport"]          = NET_HEADER_FIELD_SCTP_PORT_DST;
    fields["sctp.ver_tag"]        = NET_HEADER_FIELD_SCTP_VER_TAG;
    fields["sctp.crc"]            = NET_HEADER_FIELD_SCTP_CKSUM;
    fields["dccp.sport"]          = NET_HEADER_FIELD_DCCP_PORT_SRC;
    fields["dccp.dport"]          = NET_HEADER_FIELD_DCCP_PORT_DST;
    fields["ipsec_ah.nexthdr"]    = NET_HEADER_FIELD_IPSEC_AH_NH;
    fields["ipsec_ah.spi"]        = NET_HEADER_FIELD_IPSEC_AH_SPI;
    fields["ipsec_esp.spi"]       = NET_HEADER_FIELD_IPSEC_ESP_SPI;

    if ( fields.find( fieldname ) != fields.end() ) {
        return fields[fieldname];
    }

    return UNKNOWN_NetCommField;
}


////////////////////////////////////////////////////////////////////////////////
/// Returns NetComm field type converted to string
////////////////////////////////////////////////////////////////////////////////
std::string
CFMCModel::getNetCommFieldTypeStr( std::string fieldname )
{
    std::map< std::string, std::string > fields;

    fields["ethernet.dst"]        = "NET_HEADER_FIELD_ETH_DA";
    fields["ethernet.src"]        = "NET_HEADER_FIELD_ETH_SA";
    fields["ethernet.type"]       = "NET_HEADER_FIELD_ETH_TYPE";
    fields["vlan.pri"]            = "NET_HEADER_FIELD_VLAN_VPRI";
    fields["vlan.cfi"]            = "NET_HEADER_FIELD_VLAN_CFI";
    fields["vlan.vlanid"]         = "NET_HEADER_FIELD_VLAN_VID";
    fields["vlan.type"]           = "NET_HEADER_FIELD_VLAN_TYPE";
    fields["vlan.tci"]            = "NET_HEADER_FIELD_VLAN_TCI";
    fields["llc_snap.OUI"]        = "NET_HEADER_FIELD_SNAP_OUI";
    fields["llc_snap.type"]       = "NET_HEADER_FIELD_LLC_SNAP_TYPE";
    fields["llc_snap.dsap"]       = "NET_HEADER_FIELD_LLC_DSAP";
    fields["llc_snap.ssap"]       = "NET_HEADER_FIELD_LLC_SSAP";
    fields["mpls.label"]          = "NET_HEADER_FIELD_MPLS_LABEL_STACK";
    fields["ipv4.ver"]            = "NET_HEADER_FIELD_IPv4_VER";
    fields["ipv4.hlen"]           = "NET_HEADER_FIELD_IPv4_HDR_LEN";
    fields["ipv4.tos"]            = "NET_HEADER_FIELD_IPv4_TOS";
    fields["ipv4.tlen"]           = "NET_HEADER_FIELD_IPv4_TOTAL_LEN";
    fields["ipv4.identification"] = "NET_HEADER_FIELD_IPv4_ID";
    fields["ipv4.df"]             = "NET_HEADER_FIELD_IPv4_FLAG_D";
    fields["ipv4.mf"]             = "NET_HEADER_FIELD_IPv4_FLAG_M";
    fields["ipv4.foffset"]        = "NET_HEADER_FIELD_IPv4_OFFSET";
    fields["ipv4.ttl"]            = "NET_HEADER_FIELD_IPv4_TTL";
    fields["ipv4.nextp"]          = "NET_HEADER_FIELD_IPv4_PROTO";
    fields["ipv4.hchecksum"]      = "NET_HEADER_FIELD_IPv4_CKSUM";
    fields["ipv4.src"]            = "NET_HEADER_FIELD_IPv4_SRC_IP";
    fields["ipv4.dst"]            = "NET_HEADER_FIELD_IPv4_DST_IP";
    
    //ENGR00305912:
    fields["ipv6.ver"]            = "NET_HEADER_FIELD_IPv6_VER | NET_HEADER_FIELD_IPv6_TC";
    fields["ipv6.tos"]            = "NET_HEADER_FIELD_IPv6_VER | NET_HEADER_FIELD_IPv6_TC";
    fields["ipv6.flabel"]         = "NET_HEADER_FIELD_IPv6_FL";
    //ENGR00303764:
    //fields["ipv6.ver"]            = "NET_HEADER_FIELD_IPv6_VER | NET_HEADER_FIELD_IPv6_TC | NET_HEADER_FIELD_IPv6_FL";
    //fields["ipv6.tos"]            = "NET_HEADER_FIELD_IPv6_VER | NET_HEADER_FIELD_IPv6_TC | NET_HEADER_FIELD_IPv6_FL";

    fields["ipv6.nexthdr"]        = "NET_HEADER_FIELD_IPv6_NEXT_HDR";
    fields["ipv6.src"]            = "NET_HEADER_FIELD_IPv6_SRC_IP";
    fields["ipv6.dst"]            = "NET_HEADER_FIELD_IPv6_DST_IP";
    fields["ipv6.hop"]            = "NET_HEADER_FIELD_IPv6_HOP_LIMIT";
    fields["ip.nextp"]            = "NET_HEADER_FIELD_IP_PROTO";
    fields["ip.dscp"]             = "NET_HEADER_FIELD_IP_DSCP";
    fields["tcp.sport"]           = "NET_HEADER_FIELD_TCP_PORT_SRC";
    fields["tcp.dport"]           = "NET_HEADER_FIELD_TCP_PORT_DST";
    fields["tcp.seq"]             = "NET_HEADER_FIELD_TCP_SEQ";
    fields["tcp.ack"]             = "NET_HEADER_FIELD_TCP_ACK";
    fields["tcp.flags"]           = "NET_HEADER_FIELD_TCP_FLAGS";
    fields["tcp.win"]             = "NET_HEADER_FIELD_TCP_WINDOW";
    fields["tcp.crc"]             = "NET_HEADER_FIELD_TCP_CKSUM";
    fields["tcp.urg"]             = "NET_HEADER_FIELD_TCP_URGPTR";
    fields["udp.sport"]           = "NET_HEADER_FIELD_UDP_PORT_SRC";
    fields["udp.dport"]           = "NET_HEADER_FIELD_UDP_PORT_DST";
    fields["udp.len"]             = "NET_HEADER_FIELD_UDP_LEN";
    fields["udp.crc"]             = "NET_HEADER_FIELD_UDP_CKSUM";
    fields["gre.type"]            = "NET_HEADER_FIELD_GRE_TYPE";
    fields["pppoe.ver"]           = "NET_HEADER_FIELD_PPPoE_VER";
    fields["pppoe.type"]          = "NET_HEADER_FIELD_PPPoE_TYPE";
    fields["pppoe.code"]          = "NET_HEADER_FIELD_PPPoE_CODE";
    fields["pppoe.session_ID"]    = "NET_HEADER_FIELD_PPPoE_SID";
    fields["pppoe.hlen"]          = "NET_HEADER_FIELD_PPPoE_LEN";
    fields["pppoe.nextp"]         = "NET_HEADER_FIELD_PPPoE_PID";
    fields["minencap.dst"]        = "NET_HEADER_FIELD_MINENCAP_DST_IP";
    fields["sctp.sport"]          = "NET_HEADER_FIELD_SCTP_PORT_SRC";
    fields["sctp.dport"]          = "NET_HEADER_FIELD_SCTP_PORT_DST";
    fields["sctp.ver_tag"]        = "NET_HEADER_FIELD_SCTP_VER_TAG";
    fields["sctp.crc"]            = "NET_HEADER_FIELD_SCTP_CKSUM";
    fields["dccp.sport"]          = "NET_HEADER_FIELD_DCCP_PORT_SRC";
    fields["dccp.dport"]          = "NET_HEADER_FIELD_DCCP_PORT_DST";
    fields["ipsec_ah.nexthdr"]    = "NET_HEADER_FIELD_IPSEC_AH_NH";
    fields["ipsec_ah.spi"]        = "NET_HEADER_FIELD_IPSEC_AH_SPI";
    fields["ipsec_esp.spi"]       = "NET_HEADER_FIELD_IPSEC_ESP_SPI";

    if ( fields.find( fieldname ) != fields.end() ) {
        return fields[fieldname];
    }

    return "UNKNOWN_FIELD";
}


////////////////////////////////////////////////////////////////////////////////
/// Returns true if a field can be extracted as a full field by coarse classific.
////////////////////////////////////////////////////////////////////////////////
bool
CFMCModel::isFullFieldForCC( std::string fieldName )
{
    const char* supported[] =
    {
        "ethernet.dst",
        "ethernet.src",
        "ethernet.type",
        "vlan.tci",
        "mpls.label",
        "ipv4.dst",
        "ipv4.tos",
        "ipv4.nextp",
        "ipv4.src",
        // "ipv4.dst" | "ipv4.src"
        "ipv4.ttl",
        "ipv6.ver",
        "ipv6.tos",
        "ipv6.flabel", //ENGR00305912: with "ipv6.flabel"  / ENGR00303764: without "ipv6.flabel"
        "ipv6.nexthdr",
        "ipv6.dst",
        "ipv6.src",
        "ipv6.hop",
        "ip.nextp",
        "ip.dscp",
        "gre.type",
        "minencap.dst",
        // NET_HEADER_FIELD_MINENCAP_TYPE
        // NET_HEADER_FIELD_MINENCAP_SRC_IP
        "tcp.sport",
        "tcp.dport",
        // "tcp.sport" | "tcp.dport"
        "pppoe.nextp",
        "udp.sport",
        "udp.dport",
        // "udp.sport" | "udp.dport"
    };

    const size_t supported_len = sizeof(supported)/sizeof(supported[0]);
    const char** find_result = std::find( &supported[0],
                                          &supported[supported_len],
                                          fieldName );

    return ( find_result != &supported[supported_len] );
}


////////////////////////////////////////////////////////////////////////////////
/// Returns NetComm header index as e_FmPcdHdrIndex
////////////////////////////////////////////////////////////////////////////////
e_FmPcdHdrIndex
CFMCModel::getNetCommHeaderIndex( std::string indexstr )
{
    if ( indexstr == "0" ) {
        return e_FM_PCD_HDR_INDEX_NONE;
    }
    if ( indexstr == "1" ) {
        return e_FM_PCD_HDR_INDEX_1;
    }
    if ( indexstr == "2" ) {
        return e_FM_PCD_HDR_INDEX_2;
    }
    if ( indexstr == "3" ) {
        return e_FM_PCD_HDR_INDEX_3;
    }
    if ( indexstr == "last" ) {
        return e_FM_PCD_HDR_INDEX_LAST;
    }

    return e_FM_PCD_HDR_INDEX_NONE;
}


////////////////////////////////////////////////////////////////////////////////
/// Returns NetComm header index as string
////////////////////////////////////////////////////////////////////////////////
std::string
CFMCModel::getNetCommHeaderIndexStr( std::string indexstr )
{
    if ( indexstr == "0" ) {
        return "e_FM_PCD_HDR_INDEX_NONE";
    }
    if ( indexstr == "1" ) {
        return "e_FM_PCD_HDR_INDEX_1";
    }
    if ( indexstr == "2" ) {
        return "e_FM_PCD_HDR_INDEX_2";
    }
    if ( indexstr == "3" ) {
        return "e_FM_PCD_HDR_INDEX_3";
    }
    if ( indexstr == "last" ) {
        return "e_FM_PCD_HDR_INDEX_LAST";
    }

    return "e_FM_PCD_HDR_INDEX_NONE";
}


e_FmPcdPlcrColor
CFMCModel::getPlcrColor( std::string color )
{
    if ( color == "yellow" ) {
        return e_FM_PCD_PLCR_YELLOW;
    }
    else if ( color == "red" ) {
        return e_FM_PCD_PLCR_RED;
    }
    else if ( color == "override" ) {
        return e_FM_PCD_PLCR_OVERRIDE;
    }

    // Default color
    return e_FM_PCD_PLCR_GREEN;
}


std::string
CFMCModel::getPlcrColorStr( std::string color )
{
    if ( color == "yellow" ) {
        return "e_FM_PCD_PLCR_YELLOW";
    }
    else if ( color == "red" ) {
        return "e_FM_PCD_PLCR_RED";
    }
    else if ( color == "override" ) {
        return "e_FM_PCD_PLCR_OVERRIDE";
    }

    // Default color
    return "e_FM_PCD_PLCR_GREEN";
}


e_FmPcdEngine
CFMCModel::getEngineByType( std::string enginename )
{
    if ( enginename == "distribution" ) {
        return e_FM_PCD_KG;
    }
    else if ( enginename == "classification" ) {
        return e_FM_PCD_CC;
    }
    else if ( enginename == "policer" ) {
        return e_FM_PCD_PLCR;
    }
    else if ( enginename == "parser" ) {
        return e_FM_PCD_PRS;
    }
#if (DPAA_VERSION >= 11)
    else if ( enginename == "replicator" ) {
        return e_FM_PCD_FR;
    }
#endif /* (DPAA_VERSION >= 11) */
    else if ( enginename == "hashtable" ) {
        return e_FM_PCD_HASH;
    }

    return e_FM_PCD_DONE;
}


std::string
CFMCModel::getEngineByTypeStr( std::string enginename )
{
    if ( enginename == "distribution" ) {
        return "e_FM_PCD_KG";
    }
    else if (enginename == "classification" ) {
        return "e_FM_PCD_CC";
    }
    else if (enginename == "policer" ) {
        return "e_FM_PCD_PLCR";
    }
    else if (enginename == "parser" ) {
        return "e_FM_PCD_PRS";
    }
    else if (enginename == "replicator" ) {
        return "e_FM_PCD_FR";
    }
    else if (enginename == "hashtable" ) {
        return "e_FM_PCD_CC";
    }

    return "e_FM_PCD_DONE";
}


std::string
CFMCModel::getExtractFromStr( e_FmPcdExtractFrom extract )
{
    std::string ret = "e_FM_PCD_EXTRACT_FROM_DFLT_VALUE";
    switch ( extract )
    {
    case e_FM_PCD_EXTRACT_FROM_FRAME_START:
        ret = "e_FM_PCD_EXTRACT_FROM_FRAME_START";
        break;
    case e_FM_PCD_EXTRACT_FROM_DFLT_VALUE:
        ret = "e_FM_PCD_EXTRACT_FROM_DFLT_VALUE";
        break;
    case e_FM_PCD_EXTRACT_FROM_KEY:
        ret = "e_FM_PCD_EXTRACT_FROM_KEY";
        break;
    case e_FM_PCD_EXTRACT_FROM_HASH:
        ret = "e_FM_PCD_EXTRACT_FROM_HASH";
        break;
    case e_FM_PCD_EXTRACT_FROM_PARSE_RESULT:
        ret = "e_FM_PCD_EXTRACT_FROM_PARSE_RESULT";
        break;
    case e_FM_PCD_EXTRACT_FROM_ENQ_FQID:
        ret = "e_FM_PCD_EXTRACT_FROM_ENQ_FQID";
        break;
    case e_FM_PCD_EXTRACT_FROM_FLOW_ID:
        ret = "e_FM_PCD_EXTRACT_FROM_FLOW_ID";
        break;
    case e_FM_PCD_EXTRACT_FROM_CURR_END_OF_PARSE:
        ret = "e_FM_PCD_EXTRACT_FROM_CURR_END_OF_PARSE";
        break;
    }

    return ret;
}


e_FmPcdCcStatsMode
CFMCModel::getStatistic( std::string statistic )
{
    if ( statistic == "frame" ) {
        return e_FM_PCD_CC_STATS_MODE_FRAME;
    }
    else if (statistic == "byteframe" ) {
        return e_FM_PCD_CC_STATS_MODE_BYTE_AND_FRAME;
    }

#ifndef P1023
#if (DPAA_VERSION >= 11)
    else if (statistic == "rmon" ) {
        return e_FM_PCD_CC_STATS_MODE_RMON;
    }
#endif /* (DPAA_VERSION >= 11) */
#endif /* P1023 */
    else if (statistic == "none" || statistic == ""){
        return e_FM_PCD_CC_STATS_MODE_NONE;
    }
    
    return e_FM_PCD_CC_STATS_MODE_NONE;
}

e_FmPcdManipHdrRmvSpecificL2
CFMCModel::getSpecificL2ByString( std::string l2 )
{
    if ( l2 == "eth" || l2 == "ethernet" ) {
        return e_FM_PCD_MANIP_HDR_RMV_ETHERNET;
    }
    else if ( l2 == "qtags" ) {
        return e_FM_PCD_MANIP_HDR_RMV_STACKED_QTAGS;
    }
    else if ( l2 == "ethmpls" || l2 == "ethernet_mpls" ) {
        return e_FM_PCD_MANIP_HDR_RMV_ETHERNET_AND_MPLS;
    }
    else if ( l2 == "mpls" ) {
        return e_FM_PCD_MANIP_HDR_RMV_MPLS;
    }
    
    return e_FM_PCD_MANIP_HDR_RMV_ETHERNET;
}

e_FmPcdManipHdrFieldUpdateType
CFMCModel::getFieldUpdateTypeByString( std::string type )
{
    if ( type == "vlan" ) {
        return e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN;
    }
    else if ( type == "ipv4" ) {
        return e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4;
    }
    else if ( type == "ipv6" ) {
        return e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6;
    }
    else if ( type == "tcpudp" ) {
        return e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP;
    }
    
    return e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN;
}


#ifndef P1023
unsigned int
Engine::getHeaderManipIndex(std::string name)
{
    for (unsigned int i = 0; i < headerManips_names.size(); i++) {
        if (headerManips_names[i] == name)
            return i;
    }

    throw CGenericError( ERR_NEXTMANIP_NOT_FOUND, name );

    return 0;
}
#endif // P1023


ApplyOrder::Entry::Entry( Type typePrm, unsigned int indexPrm ) :
    type( typePrm ), index( indexPrm )
{
}


void
ApplyOrder::add( Entry entry )
{
    entries.push_back( entry );
}


void
ApplyOrder::add_edge( Entry n1, Entry n2 )
{
    edges.push_back( std::pair< Entry, Entry >( n1, n2 ) );
}


class my_pred
{
  public:
    my_pred( const ApplyOrder::Entry c_ ) : c( c_ )
    {
    }

    bool operator()( const std::pair< ApplyOrder::Entry, ApplyOrder::Entry > e )
    {
        if ( e.second == c )
            return true;
        return false;
    }

    ApplyOrder::Entry c;
};


void
ApplyOrder::sort()
{
    // Find nodes with no children
    std::vector< Entry > result;

    // Count number of children
    std::map< Entry, int > all;
    for ( unsigned int i = 0; i < edges.size(); ++i ) {
        if ( all.find( edges[i].first ) == all.end() ) {
            all[edges[i].first] = 0;
        }
        if ( all.find( edges[i].second ) == all.end() ) {
            all[edges[i].second] = 0;
        }
        ++all[edges[i].first];
    }

    bool was_change = true;

    while ( was_change ) {
        was_change = false;
        // Move childless nodes to result list
        std::map< Entry, int >::iterator it;
        for ( it = all.begin(); it != all.end(); ++it ) {
            if ( it->second == 0 ) {
                was_change = true;

                std::vector< std::pair< Entry, Entry > >::iterator edge;
                for ( edge = edges.begin(); edge != edges.end(); ++edge ) {
                    if ( edge->second == it->first ) {
                        --all[edge->first];
                    }
                }

                std::vector< std::pair< Entry, Entry > >::iterator new_end;
                new_end = std::remove_if( edges.begin(), edges.end(),
                    my_pred( it->first ) );
                edges.erase( new_end, edges.end() );

                if ( it->first.type != None ) {
                    result.push_back( it->first );
                }
                all.erase( it );
                break;
            }
        }
    }

    if ( !all.empty() ) {
        throw CGenericError( ERR_LOOP_DEPENDENCY1 );
    }

    for ( unsigned int i = result.size(); i != 0; --i ) {
        // As some shared items might be already in the list,
        // add only those which were not added previously
        if ( find( entries.begin(), entries.end(), result[i - 1] ) == entries.end() ) {
            entries.push_back( result[i - 1] );
        }
    }
}


void
ApplyOrder::reverse_port_apply_order()
{
    std::vector< Entry >                engine_entries;
    std::vector< std::vector< Entry > > ports_of_engine;
    std::vector< Entry >                result_entries;

    bool   within_port = false;
    size_t port_index = 0;

    for ( size_t i = 0; i < entries.size(); ++i ) {
        switch( entries[i].type ) {
        case EngineEnd:
            engine_entries.clear();
            ports_of_engine.clear();
            within_port = false;
            port_index  = 0;
            result_entries.push_back( entries[i] );
            break;
        case EngineStart:
            for ( int j = ports_of_engine.size() - 1; j >= 0; --j ) {
                result_entries.insert( result_entries.end(),
                                       ports_of_engine[j].begin(),
                                       ports_of_engine[j].end() );
            }
            result_entries.insert( result_entries.end(),
                                   engine_entries.begin(),
                                   engine_entries.end() );
            result_entries.push_back( entries[i] );
            break;
        case PortEnd:
            within_port = true;
            ports_of_engine.push_back( std::vector< Entry >() );
            ports_of_engine[port_index].push_back( entries[i] );
            break;
        case PortStart:
            within_port = false;
            ports_of_engine[port_index].push_back( entries[i] );
            ++port_index;
            break;
        default:
            if ( within_port ) {
                ports_of_engine[port_index].push_back( entries[i] );
            }
            else {
                engine_entries.push_back( entries[i] );
            }
        }
    }

    entries = result_entries;
}


ApplyOrder::Entry
ApplyOrder::get( unsigned int index ) const
{
    return entries[index];
}


unsigned int
ApplyOrder::size() const
{
    return entries.size();
}
