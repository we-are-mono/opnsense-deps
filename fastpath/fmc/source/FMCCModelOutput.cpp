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
 * File Name : FMCCModelOutput.cpp
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#define _CRT_SECURE_NO_WARNINGS

#include <sstream>
#include <iomanip>
#include <string.h>

#include "FMCCModelOutput.h"
#include "FMCGenericError.h"


static std::string ind( size_t count )
{
    return std::string().append( count, ' ' );
}

#define QUOTE(x)    # x

#define EMIT1( A )              \
    oss << ind( indent ) << A << std::endl;

#define EMIT2( A, B )           \
    cmodel->A B;                \
    oss << ind( indent ) << "." << QUOTE( A ) << " " << B << "," << std::endl;

#define EMIT3( A, B, C )        \
    cmodel->A B C;              \
    oss << ind( indent ) << "." << QUOTE( A ) << B << QUOTE( C ) << "," << std::endl;

#define EMIT4( A, B, C, D )     \
    cmodel->A B C D;            \
    oss << ind( indent ) << "." << QUOTE( A ) << B << QUOTE( C ) << " " << D << "," << std::endl;

#define EMIT4STR( A, B, C, D )  \
    cmodel->A B C D;          \
    oss << ind( indent ) << "." << QUOTE( A ) << B << QUOTE( C ) << D ## Str << "," << std::endl;

#define EMIT5( A, B, C, D, E )   \
    cmodel->A B C D E;          \
    oss << ind( indent ) << "." << QUOTE( A ) << B << QUOTE( C ) << D << QUOTE( E ) << "," << std::endl;

#define EMIT5_2( A, B, C, D, E )  \
    cmodel->A B C D E;                  \
    oss << ind( indent ) << QUOTE( D ) << E << "," << std::endl;

#define EMIT5_2STR( A, B, C, D, E )  \
    cmodel->A B C D E;                  \
    oss << ind( indent ) << QUOTE( D ) << E ## Str << "," << std::endl;

#define EMIT6( A, B, C, D, E, F )   \
    cmodel->A B C D E F;          \
    oss << ind( indent ) << "." << QUOTE( A ) << B << QUOTE( C ) << D << QUOTE( E ) << F << "," << std::endl;

#if DPAA_VERSION >= 11
#define EMIT6_NEXTENG( A, B, C, D, E, F )   \
    cmodel->A B C D E F;          \
    oss << ind( indent ) << "." << QUOTE( A ) << B << QUOTE( C ) << D << QUOTE( E ) ;\
    if (F == e_FM_PCD_FR)\
        oss << QUOTE(e_FM_PCD_FR); \
    if (F == e_FM_PCD_CC)\
        oss << QUOTE(e_FM_PCD_CC); \
    if (F == e_FM_PCD_HASH)\
        oss << QUOTE(e_FM_PCD_HASH); \
    oss << "," << std::endl;
#else
#define EMIT6_NEXTENG( A, B, C, D, E, F )   \
    cmodel->A B C D E F;          \
    oss << ind( indent ) << "." << QUOTE( A ) << B << QUOTE( C ) << D << QUOTE( E ) ;\
    if (F == e_FM_PCD_CC)\
        oss << QUOTE(e_FM_PCD_CC); \
    if (F == e_FM_PCD_HASH)\
        oss << QUOTE(e_FM_PCD_HASH); \
    oss << "," << std::endl;
#endif

#define EMIT6STR( A, B, C, D, E, F )    \
    cmodel->A B C D E F;              \
    oss << ind( indent ) << "." << QUOTE( A ) << B << QUOTE( C ) << D << QUOTE( E ) << F ## Str << "," << std::endl;

#define EMIT7_2( A, B, C, D, E, F, G ) \
    cmodel->A B C D E F G;              \
    oss << ind( indent ) << QUOTE( F ) << G << "," << std::endl;

#define EMIT7_2A( A, B, C, D, E, F, G ) \
    cmodel->A B C D E F G;              \
    oss << ind( indent ) << "."                                         \
        << QUOTE( A ) << B << QUOTE( C ) << D                 \
        << QUOTE( E ) << QUOTE( F ) << G                                               \
        << "," << std::endl;

#define EMIT7_2A_HEX( A, B, C, D, E, F, G ) \
    cmodel->A B C D E F G;              \
    oss << ind( indent ) << "."                                         \
        << QUOTE( A ) << B << QUOTE( C ) << D                 \
        << QUOTE( E ) << QUOTE( F ) \
        << " 0x" << std::hex \
        << G                                               \
        << std::dec \
        << "," << std::endl;

#define EMIT7_2A_UPDTYPE( A, B, C, D, E, F, G ) \
    cmodel->A B C D E F G;              \
    oss << ind( indent ) << "."                                         \
        << QUOTE( A ) << B << QUOTE( C ) << D                 \
        << QUOTE( E ) << QUOTE( F ); \
    if (G == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN); \
    if (G == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4); \
    if (G == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6); \
    if (G == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP); \
    oss << "," << std::endl;

#define EMIT7_2A_VLANTYPE( A, B, C, D, E, F, G ) \
    cmodel->A B C D E F G;              \
    oss << ind( indent ) << "."                                         \
        << QUOTE( A ) << B << QUOTE( C ) << D                 \
        << QUOTE( E ) << QUOTE( F ); \
    if (G == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN_VPRI) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN_VPRI); \
    if (G == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_DSCP_TO_VLAN) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_FIELD_UPDATE_DSCP_TO_VLAN); \
    oss << "," << std::endl;

#define EMIT7_2A_CUSTOMTYPE( A, B, C, D, E, F, G ) \
    cmodel->A B C D E F G;              \
    oss << ind( indent ) << "."                                         \
        << QUOTE( A ) << B << QUOTE( C ) << D                 \
        << QUOTE( E ) << QUOTE( F ); \
    if (G == e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE); \
    oss << "," << std::endl;

#define EMIT7_2A_CUSTOMREPLACETYPE( A, B, C, D, E, F, G ) \
    cmodel->A B C D E F G;              \
    oss << ind( indent ) << "."                                         \
        << QUOTE( A ) << B << QUOTE( C ) << D                 \
        << QUOTE( E ) << QUOTE( F ); \
    if (G == e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV4_BY_IPV6) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV4_BY_IPV6); \
    if (G == e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4) \
       oss << QUOTE(e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4); \
    oss << "," << std::endl;


#define EMIT7_2STR( A, B, C, D, E, F, G )  \
    cmodel->A B C D E F G;                  \
    oss << ind( indent ) << QUOTE( F ) << G ## Str << "," << std::endl;

#define EMIT7SP( A, B, C, D, D1, E, F )                                 \
    cmodel->A B C D E F;                                                \
    oss << ind( indent ) << "."                                         \
        << QUOTE( A )  << B << QUOTE( C ) << QUOTE( D1 )                \
        << E << QUOTE( F )                                              \
        << "," << std::endl;

#define EMIT11SP( A, B, C, D, E, F, F1, G, H, I, J )                    \
    cmodel->A B C D E = F G H I J;                                      \
    oss << ind( indent ) << "."                                         \
        << QUOTE( A )  << B << QUOTE( C ) << D << QUOTE( E ) << " = "   \
        << QUOTE( F1 ) << G << QUOTE( H ) << I << QUOTE( J )            \
        << "," << std::endl;

#define OUT_EMPTY   \
    oss << std::endl;


void
CFMCCModelOutput::output( const CFMCModel& model, fmc_model_t* cmodel, std::ostream& oss,
                          size_t indent )
{
    if ( model.spEnable ) {
        oss << "#include \"softparse.h\"" << std::endl;
    }

    OUT_EMPTY;
    oss << ind( indent ) << "struct fmc_model_t cmodel = {" << std::endl;
    indent += 4;

    // Output format version
    EMIT2( format_version =, FMC_OUTPUT_FORMAT_VER );

    // Output Soft Parser
    EMIT2( sp_enable =, model.spEnable );
    if ( cmodel->sp_enable ) {
        cmodel->sp = model.swPrs;
        memcpy( cmodel->spCode, model.swPrs.p_Code, cmodel->sp.size );
        cmodel->sp.p_Code = (uint8_t*)&(cmodel->spCode);
        oss << ind( indent ) << "SOFT_PARSE_CODE," << std::endl;
    }
    else {
        oss << ind( indent ) << "{" << std::endl;
        oss << ind( indent ) << "}," << std::endl;
    }
    OUT_EMPTY;

    // Output all engines
    check_bounds( model.all_engines.size(), FMC_FMAN_NUM, "engines" );
    EMIT2( fman_count =, model.all_engines.size() );
    for ( unsigned int i = 0; i < cmodel->fman_count; ++i ) {
        output_fmc_fman( model, cmodel, i, oss, indent );
    }
    OUT_EMPTY;
    // Output all ports
    check_bounds( model.all_ports.size(),
                  FMC_PORTS_PER_FMAN * FMC_FMAN_NUM, "ports" );
    EMIT2( port_count =, model.all_ports.size() )
    for ( unsigned int i = 0; i < cmodel->port_count; ++i ) {
        output_fmc_port( model, cmodel, i, oss, indent );
    }
    OUT_EMPTY;
    // Output all schemes
    check_bounds( model.all_schemes.size(),
                  FMC_SCHEMES_NUM, "KeyGen schemes" );
    EMIT2( scheme_count =, model.all_schemes.size() )
    for ( unsigned int i = 0; i < cmodel->scheme_count; ++i ) {
        OUT_EMPTY;
        output_fmc_scheme( model, cmodel, i, oss, indent );
    }
    OUT_EMPTY;
    // Output CC nodes
    check_bounds( model.all_ccnodes.size(),
                  FMC_CC_NODES_NUM, "Coarse Classifications" );
    EMIT2( ccnode_count =, model.all_ccnodes.size() )
    for ( unsigned int i = 0; i < cmodel->ccnode_count; ++i ) {
        OUT_EMPTY;
        output_fmc_ccnode( model, cmodel, i, oss, indent );
    }
    OUT_EMPTY;
     // Output HT nodes
    check_bounds( model.all_htnodes.size(),
                  FMC_CC_NODES_NUM, "HT nodes" );
    EMIT2( htnode_count =, model.all_htnodes.size() )
    for ( unsigned int i = 0; i < cmodel->htnode_count; ++i ) {
        OUT_EMPTY;
        output_fmc_htnode( model, cmodel, i, oss, indent );
    }
    OUT_EMPTY;
#if (DPAA_VERSION >= 11)
    // Output Replicators
    check_bounds( model.all_replicators.size(),
                  FMC_REPLICATORS_NUM, "replicators" );
    EMIT2( replicator_count =, model.all_replicators.size() )
    for ( unsigned int i = 0; i < cmodel->replicator_count; ++i ) {
        OUT_EMPTY;
        output_fmc_replicator( model, cmodel, i, oss, indent );
    }
#endif /* (DPAA_VERSION >= 11) */
    OUT_EMPTY;
    // Output policers
    check_bounds( model.all_policers.size(),
                  FMC_PLC_NUM, "policers" );
    EMIT2( policer_count =, model.all_policers.size() )
    for ( unsigned int i = 0; i < cmodel->policer_count; ++i ) {
        OUT_EMPTY;
        output_fmc_policer( model, cmodel, i, oss, indent );
    }
    OUT_EMPTY;
    // Output apply order
    check_bounds( model.applier.size(),
                  FMC_FMAN_NUM*FMC_PORTS_PER_FMAN*(FMC_SCHEMES_NUM+FMC_CC_NODES_NUM),
                  "apply entries" );
    EMIT2( apply_order_count =, model.applier.size() )
    for ( int i = cmodel->apply_order_count - 1; i >= 0; --i ) {
        output_fmc_applier( model, cmodel, i, oss, indent );
    }

    indent -= 4;
    oss << ind( indent ) << "};" << std::endl;
}


void
CFMCCModelOutput::output_fmc_fman( const CFMCModel& model, fmc_model_t* cmodel,
                                   unsigned int index,
                                   std::ostream& oss, size_t indent )
{
    EMIT1( std::string( "/* FMan: " + model.all_engines[index].name + " */" ) );

    strncpy( cmodel->fman[index].name, model.all_engines[index].name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->fman[index].name[FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".fman[" << index << "].name = \"" << model.all_engines[index].name << "\"," << std::endl;
    EMIT4( fman[, index, ].number =, model.all_engines[index].number );

    strncpy( cmodel->fman[index].pcd_name, model.all_engines[index].pcd_name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->fman[index].pcd_name[FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".fman[" << index << "].pcd_name = \"" << model.all_engines[index].pcd_name << "\"," << std::endl;

    EMIT4( fman[, index, ].port_count =, model.all_engines[index].ports.size() );
    for ( unsigned int i = 0; i < cmodel->fman[index].port_count; ++i ) {
        EMIT6( fman[, index, ].ports[, i, ] =, model.all_engines[index].ports[i] )
    }

    OUT_EMPTY;

    if ( model.all_engines[index].kg_payload_offset != 0 ) {
        EMIT4( fman[, index, ].kg_payload_offset =, model.all_engines[index].kg_payload_offset );
        OUT_EMPTY;
    }

#ifndef P1023
    if ( model.all_engines[index].offload_support != 0 ) {
        EMIT4( fman[, index, ].offload_support =, model.all_engines[index].offload_support );
        OUT_EMPTY;
    }

    EMIT4( fman[, index, ].reasm_count =, model.all_engines[index].reasm.size() );
    for ( unsigned int i = 0; i < model.all_engines[index].reasm.size(); i++ ) {
        strncpy( cmodel->fman[index].reasm_name[i], model.all_engines[index].reasm_names[i].c_str(), FMC_NAME_LEN - 1 );
        cmodel->fman[index].reasm_name[i][FMC_NAME_LEN - 1] = 0;
        oss << ind( indent ) << ".fman[" << index << "].reasm_name[" << i << "] = \"" << model.all_engines[index].reasm_names[i] << "\"," << std::endl;

        EMIT5( fman[, index, ].reasm[, i, ].type = e_FM_PCD_MANIP_REASSEM );
        EMIT5( fman[, index, ].reasm[, i, ].h_NextManip = 0 );
        EMIT5( fman[, index, ].reasm[, i, ].u.reassem.hdr = HEADER_TYPE_IPv6 );

        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.maxNumFramesInProcess =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.maxNumFramesInProcess );
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.timeOutMode =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.timeOutMode );
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.numOfFramesPerHashEntry[0] =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.numOfFramesPerHashEntry[0] );
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.numOfFramesPerHashEntry[1] =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.numOfFramesPerHashEntry[1] );
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.timeoutThresholdForReassmProcess =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.timeoutThresholdForReassmProcess );
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.fqidForTimeOutFrames =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.fqidForTimeOutFrames );
//        EMIT7_2( fman[, index, ].reasm[, i, ].fragOrReasmParams, .ipReasmParams.relativeSchemeId[0] =, 0 );
//        EMIT7_2( fman[, index, ].reasm[, i, ].fragOrReasmParams, .ipReasmParams.relativeSchemeId[1] =, 1 );
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.minFragSize[0] =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.minFragSize[0] );
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.minFragSize[1] =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.minFragSize[1] );
#if (DPAA_VERSION >= 11)
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.nonConsistentSpFqid =,
            (int)model.all_engines[index].reasm[i].u.reassem.u.ipReassem.nonConsistentSpFqid );
#else
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.sgBpid =,
            (int)model.all_engines[index].reasm[i].u.reassem.u.ipReassem.sgBpid );
#endif /* (DPAA_VERSION >= 11) */
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.dataLiodnOffset =,
            model.all_engines[index].reasm[i].u.reassem.u.ipReassem.dataLiodnOffset );
        EMIT7_2A( fman[, index, ].reasm[, i, ].u.reassem.u, .ipReassem.dataMemId =,
            (int)model.all_engines[index].reasm[i].u.reassem.u.ipReassem.dataMemId );

        //indent -= 4;
        //EMIT1( "}," );
    }

    OUT_EMPTY;

    EMIT4( fman[, index, ].frag_count =, model.all_engines[index].frags.size() );
    for ( unsigned int i = 0; i < model.all_engines[index].frags.size(); i++ ) {
        strncpy( cmodel->fman[index].frag_name[i], model.all_engines[index].frag_names[i].c_str(), FMC_NAME_LEN - 1 );
        cmodel->fman[index].frag_name[i][FMC_NAME_LEN - 1] = 0;
        oss << ind( indent ) << ".fman[" << index << "].frag_name[" << i << "] = \"" << model.all_engines[index].frag_names[i] << "\"," << std::endl;

        EMIT5( fman[, index, ].frag[, i, ].type = e_FM_PCD_MANIP_FRAG );
        EMIT5( fman[, index, ].frag[, i, ].h_NextManip = 0 );
        EMIT5( fman[, index, ].frag[, i, ].u.frag.hdr = HEADER_TYPE_IPv6 );

        EMIT7_2A( fman[, index, ].frag[, i,].u.frag.u, .ipFrag.sizeForFragmentation =,
            model.all_engines[index].frags[i].u.frag.u.ipFrag.sizeForFragmentation );
#if (DPAA_VERSION == 10)
        EMIT7_2A( fman[, index, ].frag[, i,].u.frag.u, .ipFrag.scratchBpid =,
            (int)model.all_engines[index].frags[i].u.frag.u.ipFrag.scratchBpid );
#endif /* (DPAA_VERSION == 10) */
#ifdef FM_EXP_FEATURES
        EMIT7_2A( fman[, index, ].frag[, i,].u.frag.u, .ipFrag.optionsCounterEn =,
            (int)model.all_engines[index].frags[i].u.frag.u.ipFrag.optionsCounterEn );
#endif /* FM_EXP_FEATURES */
        EMIT7_2A( fman[, index, ].frag[, i,].u.frag.u, .ipFrag.dontFragAction =,
            model.all_engines[index].frags[i].u.frag.u.ipFrag.dontFragAction );
        EMIT7_2A( fman[, index, ].frag[, i,].u.frag.u, .ipFrag.sgBpidEn =,
            model.all_engines[index].frags[i].u.frag.u.ipFrag.sgBpidEn );
        EMIT7_2A( fman[, index, ].frag[, i,].u.frag.u, .ipFrag.sgBpid =,
            (int)model.all_engines[index].frags[i].u.frag.u.ipFrag.sgBpid );

        //indent -= 4;
        //EMIT1( "}," );
    }

    OUT_EMPTY;

    EMIT4( fman[, index, ].hdr_count =, model.all_engines[index].headerManips.size() );
    for ( unsigned int i = 0; i < model.all_engines[index].headerManips.size(); i++ ) {
        strncpy( cmodel->fman[index].hdr_name[i], model.all_engines[index].headerManips_names[i].c_str(), FMC_NAME_LEN - 1 );
        cmodel->fman[index].hdr_name[i][FMC_NAME_LEN - 1] = 0;
        oss << ind( indent ) << ".fman[" << index << "].hdr_name[" << i << "] = \"" << model.all_engines[index].headerManips_names[i] << "\"," << std::endl;

        EMIT5( fman[, index, ].hdr[, i, ].type = e_FM_PCD_MANIP_HDR );
        EMIT5( fman[, index, ].hdr[, i, ].h_NextManip = 0 );

        EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr, .insrt =,
            model.all_engines[index].headerManips[i].u.hdr.insrt );
        EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr, .rmv =,
            model.all_engines[index].headerManips[i].u.hdr.rmv );
        EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr, .fieldUpdate =,
            model.all_engines[index].headerManips[i].u.hdr.fieldUpdate );
        EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr, .custom =,
            model.all_engines[index].headerManips[i].u.hdr.custom );
        EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr, .dontParseAfterManip =,
            model.all_engines[index].headerManips[i].u.hdr.dontParseAfterManip );

        if ( model.all_engines[index].headerManips[i].u.hdr.insrt )
        {
            EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.insrtParams, .type =,
                model.all_engines[index].headerManips[i].u.hdr.insrtParams.type );
            if (model.all_engines[index].headerManips[i].u.hdr.insrtParams.type == e_FM_PCD_MANIP_INSRT_GENERIC)
            {
                EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.insrtParams.u.generic, .size =,
                    (int)model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.generic.size );
                EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.insrtParams.u.generic, .offset =,
                    (int)model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.generic.offset );
                EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.insrtParams.u.generic, .replace =,
                    model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.generic.replace );

                oss << ind( indent ) << ".fman[" << index << "].insertData[" << i << "] = {";
                for ( unsigned int j = 0; j < (int)model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.generic.size; ++j ) {
                        if ( j != 0 ) {
                            oss << ",";
                        }
                        oss << " 0x" << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (unsigned int)model.all_engines[index].insertDatas[i].data[j];
                        oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
                        cmodel->fman[index].insertData[i][j] = model.all_engines[index].insertDatas[i].data[j];
                }
                oss << " }," << std::endl;
            }

            if (model.all_engines[index].headerManips[i].u.hdr.insrtParams.type == e_FM_PCD_MANIP_INSRT_BY_HDR)
            {
                EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.insrtParams.u.byHdr, .type =,
                    model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.byHdr.type );
                EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.insrtParams.u.byHdr.u.specificL2Params, .specificL2 =,
                    (e_FmPcdManipHdrInsrtSpecificL2)model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.byHdr.u.specificL2Params.specificL2 );
                EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.insrtParams.u.byHdr.u.specificL2Params, .size =,
                    (int)model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.byHdr.u.specificL2Params.size );
                EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.insrtParams.u.byHdr.u.specificL2Params, .update =,
                    (int)model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.byHdr.u.specificL2Params.update );

                oss << ind( indent ) << ".fman[" << index << "].insertData[" << i << "] = {";
                for ( unsigned int j = 0; j < (int)model.all_engines[index].headerManips[i].u.hdr.insrtParams.u.byHdr.u.specificL2Params.size; ++j ) {
                        if ( j != 0 ) {
                            oss << ",";
                        }
                        oss << " 0x" << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (unsigned int)model.all_engines[index].insertDatas[i].data[j];
                        oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
                        cmodel->fman[index].insertData[i][j] = model.all_engines[index].insertDatas[i].data[j];
                }
                oss << " }," << std::endl;
            }
        }

        if ( model.all_engines[index].headerManips[i].u.hdr.rmv )
        {
            EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.rmvParams, .type =,
                model.all_engines[index].headerManips[i].u.hdr.rmvParams.type );

            if ( model.all_engines[index].headerManips[i].u.hdr.rmvParams.type == e_FM_PCD_MANIP_RMV_GENERIC)
            {
                 EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.rmvParams.u.generic, .size =,
                     (int)model.all_engines[index].headerManips[i].u.hdr.rmvParams.u.generic.size );
                 EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.rmvParams.u.generic, .offset =,
                     (int)model.all_engines[index].headerManips[i].u.hdr.rmvParams.u.generic.offset );
            }
            else {
                 EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.rmvParams.u.byHdr, .type =,
                     model.all_engines[index].headerManips[i].u.hdr.rmvParams.u.byHdr.type );
                 EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.rmvParams.u.byHdr.u, .specificL2 =,
                     model.all_engines[index].headerManips[i].u.hdr.rmvParams.u.byHdr.u.specificL2 );
            }
        }

        if ( model.all_engines[index].headerManips[i].u.hdr.fieldUpdate )
        {
            EMIT7_2A_UPDTYPE( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams, .type =,
                model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.type );

            if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.type == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN)
            {
                EMIT7_2A_VLANTYPE( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.vlan, .updateType =,
                    model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.vlan.updateType );

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.vlan.updateType == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN_VPRI)
                {
                    EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.vlan.u, .vpri =,
                        (unsigned int)model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.vlan.u.vpri );
                }

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.vlan.updateType == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_DSCP_TO_VLAN)
                {
                    oss << ind(indent) << "." << "fman[" << index << "].hdr[" << i 
                            << "].u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable = {";

                    for (unsigned int idx = 0; idx < FM_PCD_MANIP_DSCP_TO_VLAN_TRANS; idx++)
                    {
                        //Fill the cmodel dscpToVpri table
                        cmodel->fman[index].hdr[i].u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable[idx] = 
                            model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable[idx];

                        //Print the table
                        if ( idx != 0 ) {
                            oss << ",";
                        }

                        oss << " " << (unsigned int)model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable[idx];
                    }

                    oss << " }," << std::endl;

                    EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri, .vpriDefVal =,
                        (unsigned int)model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.vpriDefVal );
                }
            }

            if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.type == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4)
            {
                EMIT7_2A_HEX( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.ipv4, .validUpdates =,
                    model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.validUpdates );

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.validUpdates & HDR_MANIP_IPV4_TOS)
                {
                    EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.ipv4, .tos =,
                        (unsigned int)model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.tos );
                }

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.validUpdates & HDR_MANIP_IPV4_ID)
                {
                    EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.ipv4, .id =,
                        (uint32_t)model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.id );
                }

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.validUpdates & HDR_MANIP_IPV4_SRC)
                {
                    EMIT7_2A_HEX( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.ipv4, .src =,
                        model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.src );
                }

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.validUpdates & HDR_MANIP_IPV4_DST)
                {
                    EMIT7_2A_HEX( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.ipv4, .dst =,
                        model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv4.dst );
                }
            }

            if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.type == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6)
            {
                EMIT7_2A_HEX( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.ipv6, .validUpdates =,
                    model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.validUpdates );

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.validUpdates & HDR_MANIP_IPV6_TC)
                {
                    EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.ipv6, .trafficClass =,
                        model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.trafficClass );
                }

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.validUpdates & HDR_MANIP_IPV6_SRC)
                {
                    oss << ind(indent) << "." << "fman[" << index << "].hdr[" << i 
                            << "].u.hdr.fieldUpdateParams.u.ipv6.src = {";

                    for (unsigned int idx = 0; idx < NET_HEADER_FIELD_IPv6_ADDR_SIZE; idx++)
                    {
                        cmodel->fman[index].hdr[i].u.hdr.fieldUpdateParams.u.ipv6.src[idx] = 
                            model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.src[idx];

                        //Print the table
                        if ( idx != 0 ) {
                            oss << ",";
                        }

                        oss << " 0x" << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (unsigned int)model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.src[idx];
                    }

                     oss << " }," << std::endl;
                     oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
                }

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.validUpdates & HDR_MANIP_IPV6_DST)
                {
                    oss << ind(indent) << "." << "fman[" << index << "].hdr[" << i 
                            << "].u.hdr.fieldUpdateParams.u.ipv6.dst = {";

                    for (unsigned int idx = 0; idx < NET_HEADER_FIELD_IPv6_ADDR_SIZE; idx++)
                    {
                        cmodel->fman[index].hdr[i].u.hdr.fieldUpdateParams.u.ipv6.dst[idx] = 
                            model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.dst[idx];

                        //Print the table
                        if ( idx != 0 ) {
                            oss << ",";
                        }

                        oss << " 0x" << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (unsigned int)model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.ipv6.dst[idx];
                    }

                     oss << " }," << std::endl;
                     oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
                }
            }

            if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.type == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP)
            {
                EMIT7_2A_HEX( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.tcpUdp, .validUpdates =,
                    model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates );

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates & HDR_MANIP_TCP_UDP_SRC)
                {
                    EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.tcpUdp, .src =,
                        model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.tcpUdp.src );
                }

                if (model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates & HDR_MANIP_TCP_UDP_DST)
                {
                    EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.fieldUpdateParams.u.tcpUdp, .dst =,
                        model.all_engines[index].headerManips[i].u.hdr.fieldUpdateParams.u.tcpUdp.dst );
                }
            }
        }

        if ( model.all_engines[index].headerManips[i].u.hdr.custom )
        {
            EMIT7_2A_CUSTOMTYPE( fman[, index, ].hdr[, i,].u.hdr.customParams, .type =,
                e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE );
            EMIT7_2A_CUSTOMREPLACETYPE( fman[, index, ].hdr[, i,].u.hdr.customParams.u.ipHdrReplace, .replaceType =,
                model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.replaceType );
            if (model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.replaceType == e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4)
            {
                EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.customParams.u.ipHdrReplace, .updateIpv4Id =,
                    model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.updateIpv4Id );

                if (model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.updateIpv4Id)
                {
                    EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.customParams.u.ipHdrReplace, .id =,
                        (int)model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.id );
                }
            }

            EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.customParams.u.ipHdrReplace, .decTtlHl =,
                (int)model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.decTtlHl );

            EMIT7_2A( fman[, index, ].hdr[, i,].u.hdr.customParams.u.ipHdrReplace, .hdrSize =,
                (int)model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.hdrSize );

            oss << ind(indent) << "." << "fman[" << index << "].hdr[" << i 
                            << "].u.hdr.customParams.u.ipHdrReplace.hdr = {";

            for (unsigned int idx = 0; idx < model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.hdrSize; idx++)
            {
                cmodel->fman[index].hdr[i].u.hdr.customParams.u.ipHdrReplace.hdr[idx] = 
                    model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.hdr[idx];

                //Print the table
                if ( idx != 0 ) {
                    oss << ",";
                }

                oss << " 0x" << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (unsigned int)model.all_engines[index].headerManips[i].u.hdr.customParams.u.ipHdrReplace.hdr[idx];
            }

             oss << " }," << std::endl;
             oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
        }

        if ( model.all_engines[index].headerManips_hasNext[i] ) {
            EMIT5( fman[, index, ].hdr_hasNext[, i, ] = 1 );
            EMIT6( fman[, index, ].hdr_next[, i, ] = , model.all_engines[index].headerManips_nextNanip[i] );
        }
        else {
            EMIT5( fman[, index, ].hdr_hasNext[, i, ] = 0 );
        }
    }

    OUT_EMPTY;
#endif /* P1023 */
}


void
CFMCCModelOutput::output_fmc_port( const CFMCModel& model, fmc_model_t* cmodel,
                                   unsigned int index,
                                   std::ostream& oss, size_t indent )
{
    EMIT1( std::string( "/* FMan port: " + model.all_ports[index].name + " */" ) );

    strncpy( cmodel->port[index].name, model.all_ports[index].name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->port[index].name[FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".port[" << index << "].name = \"" << model.all_ports[index].name << "\"," << std::endl;

    std::string cctree_name =  model.all_ports[index].name + "/cctree";
    strncpy( cmodel->port[index].cctree_name, cctree_name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->port[index].cctree_name[FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".port[" << index << "].cctree_name = \"" << cctree_name << "\"," << std::endl;

    EMIT4STR( port[, index, ].type =, model.all_ports[index].type );
    EMIT4( port[, index, ].number  = ,  model.all_ports[index].number );
    EMIT4( port[, index, ].portid  = ,  model.all_ports[index].portid );

    EMIT4( port[, index, ].schemes_count =, model.all_ports[index].schemes.size() );
    for ( unsigned int i = 0; i < cmodel->port[index].schemes_count; ++i ) {
        EMIT6( port[, index, ].schemes[, i, ] =, model.all_ports[index].schemes[i] );
    }

#if (DPAA_VERSION >= 11)
    int numOfProfiles = 0;
    int dfltRelativeId = 0;
    std::vector<int> vProfileId;
    std::vector<int>::iterator itProfileId;
    bool bProfileIdFound = false;

    for ( unsigned int i = 0; i < cmodel->port[index].schemes_count; ++i ) {	
        int sch_idx = model.all_ports[index].schemes[i];
        const Scheme& sch = model.all_schemes[sch_idx];
        if (sch.overrideStorageProfile && sch.vspAlloc) {
            if (sch.storageProfile.direct) {
                bProfileIdFound = false;
                for (itProfileId = vProfileId.begin(); itProfileId != vProfileId.end(); itProfileId++) {
                    if (*itProfileId == sch.storageProfile.profileSelect.directRelativeProfileId) {
                        bProfileIdFound = true;
                        break;
                    }
                }
                if (!bProfileIdFound)
                    vProfileId.push_back(sch.storageProfile.profileSelect.directRelativeProfileId);
            } else {
                for (int profId = sch.storageProfile.profileSelect.indirectProfile.fqidOffsetRelativeProfileIdBase; 
                         profId < sch.storageProfile.profileSelect.indirectProfile.fqidOffsetRelativeProfileIdBase + sch.storageProfile.profileSelect.indirectProfile.numOfProfiles;
                         profId++) {
                    bProfileIdFound = false;
                    for (itProfileId = vProfileId.begin(); itProfileId != vProfileId.end(); itProfileId++) {
                        if (*itProfileId == profId) {
                            bProfileIdFound = true;
                            break;
                        }
                    }
                    if (!bProfileIdFound)
                        vProfileId.push_back(profId);
                }
            }
        }
    }
    numOfProfiles = vProfileId.size();
    EMIT4( port[, index, ].vspParam.numOfProfiles =, numOfProfiles );
    EMIT4( port[, index, ].vspParam.dfltRelativeId =, dfltRelativeId );
#endif /* (DPAA_VERSION >= 11) */

    EMIT4( port[, index, ].ccnodes_count =, model.all_ports[index].ccnodes.size() );
    for ( unsigned int i = 0; i < cmodel->port[index].ccnodes_count; ++i ) {
        EMIT6( port[, index, ].ccnodes[, i, ] =, model.all_ports[index].ccnodes[i] );
    }

    EMIT4( port[, index, ].htnodes_count =, model.all_ports[index].htnodes.size() );
    for ( unsigned int i = 0; i < cmodel->port[index].htnodes_count; ++i ) {
        EMIT6( port[, index, ].htnodes[, i, ] =, model.all_ports[index].htnodes[i] );
    }

#if (DPAA_VERSION >= 11)
    EMIT4( port[, index, ].replicators_count =, model.all_ports[index].replicators.size() );
    for ( unsigned int i = 0; i < cmodel->port[index].replicators_count; ++i ) {
        EMIT6( port[, index, ].replicators[, i, ] =, model.all_ports[index].replicators[i] );
    }
#endif /* (DPAA_VERSION >= 11) */

    EMIT4( port[, index, ].ccroot_count =, model.all_ports[index].cctrees.size() );
    for ( unsigned int i = 0; i < cmodel->port[index].ccroot_count; ++i ) {
        EMIT6( port[, index, ].ccroot[, i, ] =, model.all_ports[index].cctrees[i] );
        EMIT6_NEXTENG( port[, index, ].ccroot_type[, i, ] =, model.all_ports[index].cctrees_type[i] );
    }

#ifndef P1023
    for ( unsigned int i = 0; i < cmodel->port[index].ccroot_count; ++i ) {
        EMIT6( port[, index, ].ccroot_manip[, i, ] =, model.all_ports[index].hdrmanips[i] );
    }
#endif /* P1023 */

    // Distinction units
    unsigned int numOfDistUnits = model.all_ports[index].protocols.size();

    bool was_ipv4frag = false;
    bool was_ipv6frag = false;
    std::map< Protocol,
        std::pair< unsigned int, DistinctionUnitElement > >::const_iterator protoIt;
    for ( protoIt  = model.all_ports[index].protocols.begin();
          protoIt != model.all_ports[index].protocols.end();
          ++protoIt ) {
        EMIT6STR( port[, index, ].distinctionUnits.units[, protoIt->second.first, ].hdrs[0].hdr =, protoIt->second.second.hdr );
        if ( protoIt->second.second.opt != "" )
        {
            ipv4ProtocolOpt_t opt_ipv4;
            ipv6ProtocolOpt_t opt_ipv6;

            switch (cmodel->port[index].distinctionUnits.units[protoIt->second.first].hdrs[0].hdr)
            {
            case HEADER_TYPE_ETH:
                EMIT6( port[, index, ].distinctionUnits.units[, protoIt->second.first, ].hdrs[0].opt.ethOpt =, strtoul( protoIt->second.second.opt.c_str(), 0, 16 ) );
                break;
            case HEADER_TYPE_VLAN:
                EMIT6( port[, index, ].distinctionUnits.units[, protoIt->second.first, ].hdrs[0].opt.vlanOpt =, strtoul( protoIt->second.second.opt.c_str(), 0, 16 ) );
                break;
            case HEADER_TYPE_MPLS:
                EMIT6( port[, index, ].distinctionUnits.units[, protoIt->second.first, ].hdrs[0].opt.mplsOpt =, strtoul( protoIt->second.second.opt.c_str(), 0, 16 ) );
                break;
            case HEADER_TYPE_IPv4:
                opt_ipv4 = strtoul( protoIt->second.second.opt.c_str(), 0, 16 );
                EMIT6( port[, index, ].distinctionUnits.units[, protoIt->second.first, ].hdrs[0].opt.ipv4Opt =, opt_ipv4 );
                if ( opt_ipv4 == IPV4_FRAG_1 ) {
                    was_ipv4frag = true;
                }
                break;
            case HEADER_TYPE_IPv6:
                opt_ipv6 = strtoul( protoIt->second.second.opt.c_str(), 0, 16 );
                EMIT6( port[, index, ].distinctionUnits.units[, protoIt->second.first, ].hdrs[0].opt.ipv6Opt =, opt_ipv6 );
                if ( opt_ipv6 == IPV6_FRAG_1 ) {
                    was_ipv6frag = true;
                }
                break;
            }
        }
    }

#ifndef P1023
    if ( model.all_ports[index].reasm_index != 0 ) {
        if ( !was_ipv4frag ) {
            EMIT5( port[, index, ].distinctionUnits.units[, numOfDistUnits,].hdrs[0].hdr = HEADER_TYPE_IPv4 );
            EMIT5( port[, index, ].distinctionUnits.units[, numOfDistUnits,].hdrs[0].opt.ipv4Opt = IPV4_FRAG_1 );
            numOfDistUnits++;
        }
        if ( !was_ipv6frag ) {
            EMIT5( port[, index, ].distinctionUnits.units[, numOfDistUnits,].hdrs[0].hdr = HEADER_TYPE_IPv6 );
            EMIT5( port[, index, ].distinctionUnits.units[, numOfDistUnits,].hdrs[0].opt.ipv6Opt = IPV6_FRAG_1 );
            numOfDistUnits++;
        }
    }
#endif /* P1023 */

    EMIT4( port[, index, ].distinctionUnits.numOfDistinctionUnits =, numOfDistUnits );

    // Fill PCD params
    if ( ( !model.all_ports[index].cctrees.empty() || model.all_ports[index].reasm_index != 0 )
         && !model.all_ports[index].schemes.empty() && !model.all_policers.empty() ) {
        EMIT3( port[, index, ].pcdParam.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR );
    }
    else if ( ( !model.all_ports[index].cctrees.empty() || model.all_ports[index].reasm_index != 0 )
         && !model.all_ports[index].schemes.empty() ) {
        EMIT3( port[, index, ].pcdParam.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC );
    }
    else if ( !model.all_ports[index].schemes.empty() && !model.all_policers.empty() ) {
        EMIT3( port[, index, ].pcdParam.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR );
    }
    else if ( !model.all_ports[index].schemes.empty() ) {
        EMIT3( port[, index, ].pcdParam.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG );
    }
    else {
        EMIT3( port[, index, ].pcdParam.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_ONLY );
    }

    // Parser params
    EMIT3( port[, index, ].prsParam.parsingOffset = 0 );
    EMIT4( port[, index, ].prsParam.prsResultPrivateInfo =, model.all_ports[index].portid );
    EMIT3( port[, index, ].prsParam.firstPrsHdr = HEADER_TYPE_ETH );
    if ( model.spEnable ) {
        EMIT4( port[, index, ].prsParam.numOfHdrsWithAdditionalParams =, (unsigned int)model.swPrs.numOfLabels );
        for ( unsigned int i = 0; i < model.swPrs.numOfLabels; ++i ) {
            {
                // Special case - we don't have .hdr and corresponding .hdrStr fields in this structure
                cmodel->port[index].prsParam.additionalParams[i].hdr = model.swPrs.labelsTable[i].hdr;
                oss << ind( indent ) << ".port[" << index << "].prsParam.additionalParams[" << i << "].hdr =" <<
                    CFMCModel::getNetCommHeaderTypeStr( model.swPrs.labelsTable[i].hdr ) << "," <<std::endl;
            }
            EMIT5( port[, index, ].prsParam.additionalParams[, i, ].errDisable  = 0 );
            EMIT5( port[, index, ].prsParam.additionalParams[, i, ].swPrsEnable = 1 );
            EMIT5( port[, index, ].prsParam.additionalParams[, i, ].usePrsOpts  = 0 );
            EMIT5( port[, index, ].prsParam.additionalParams[, i, ].indexPerHdr = 0 );
            EMIT5( port[, index, ].prsParam.additionalParams[, i, ].usePrsOpts  = 0 );
        }
    }

    EMIT4( port[, index, ].reasm_index =, model.all_ports[index].reasm_index );

    OUT_EMPTY;
}


void
CFMCCModelOutput::output_fmc_scheme( const CFMCModel& model, fmc_model_t* cmodel,
                                     unsigned int index,
                                     std::ostream& oss, size_t indent )
{
    const Scheme& sch = model.all_schemes[index];

    EMIT1( std::string( "/* Distribution: " + sch.name + " */" ) );

    strncpy( cmodel->scheme_name[index], sch.name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->scheme_name[index][FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".scheme_name[" << index << "] = " << std::string( "\"" + sch.name + "\"" ) << "," << std::endl;

    EMIT4( scheme[, index, ].alwaysDirect        =, model.all_schemes[index].isDirect );
//    EMIT4( scheme[, index, ].id.relativeSchemeId =, (unsigned int)model.all_schemes[index].relativeSchemeId );
    EMIT4( scheme[, index, ].netEnvParams.numOfDistinctionUnits =, sch.used_protocols.size() );

    // Find port this scheme belongs to
    unsigned int port = 0;
    for ( unsigned int i = 0; i < model.all_ports.size(); i++ ) {
        for ( unsigned int j = 0; j < model.all_ports[i].schemes.size(); j++ ) {
            if ( model.all_ports[i].schemes[j] == index ) {
                port = i;
            }
        }
    }

    // Fill unitIds for used protocols
    int used_protocols_count = 0;
    std::set< Protocol >::const_iterator used_protocolsIt;
    for ( used_protocolsIt = sch.used_protocols.begin();
          used_protocolsIt != sch.used_protocols.end();
          ++used_protocolsIt, ++used_protocols_count ) {
        // Find index of this protocol
        unsigned int protoNum = model.all_ports[port].protocols.find( *used_protocolsIt )->second.first;
        EMIT6( scheme[, index, ].netEnvParams.unitIds[, used_protocols_count, ] =, protoNum );
    }

    unsigned int useHash = sch.key.empty() ? 0 : 1;
    EMIT4( scheme[, index, ].useHash =,  useHash );
    EMIT4( scheme[, index, ].baseFqid =, sch.qbase );
    EMIT4( scheme[, index, ].shared =, sch.shared );
    if (sch.bypass) {
        EMIT4( scheme[, index, ].bypassFqidGeneration =, sch.bypass );
    }

#if (DPAA_VERSION >= 11)
    EMIT4( scheme[, index, ].overrideStorageProfile =,  sch.overrideStorageProfile );
    if ( sch.overrideStorageProfile ) {
        EMIT4( scheme[, index, ].storageProfile.direct =,  sch.storageProfile.direct );
        if ( sch.storageProfile.direct ) {
            EMIT4( scheme[, index, ].storageProfile.profileSelect.directRelativeProfileId  =,  (unsigned int)sch.storageProfile.profileSelect.directRelativeProfileId );
        }
        else {
            EMIT4( scheme[, index, ].storageProfile.profileSelect.indirectProfile.fqidOffsetShift  =,  (unsigned int)sch.storageProfile.profileSelect.indirectProfile.fqidOffsetShift );
            EMIT4( scheme[, index, ].storageProfile.profileSelect.indirectProfile.fqidOffsetRelativeProfileIdBase  =,  (unsigned int)sch.storageProfile.profileSelect.indirectProfile.fqidOffsetRelativeProfileIdBase );
            EMIT4( scheme[, index, ].storageProfile.profileSelect.indirectProfile.numOfProfiles  =,  (unsigned int)sch.storageProfile.profileSelect.indirectProfile.numOfProfiles );
        }
    }
#endif /* (DPAA_VERSION >= 11) */

    EMIT4STR( scheme[, index, ].nextEngine =, sch.nextEngine );
    if ( sch.nextEngine == e_FM_PCD_DONE && sch.doneAction == e_FM_PCD_DROP_FRAME ) {
        EMIT4STR( scheme[, index, ].kgNextEngineParams.doneAction =, sch.doneAction );
    }
    if ( sch.nextEngine == e_FM_PCD_PLCR ) {
        EMIT4( scheme[, index, ].kgNextEngineParams.plcrProfile.sharedProfile =, 1 );
        EMIT4( scheme[, index, ].kgNextEngineParams.plcrProfile.direct =,        1 );
        EMIT4( scheme[, index, ].kgNextEngineParams.plcrProfile.profileSelect.
               directRelativeProfileId =, sch.actionHandleIndex );
    }
    else if ( sch.nextEngine == e_FM_PCD_CC || sch.nextEngine == e_FM_PCD_HASH) {
        EMIT4( scheme[, index, ].kgNextEngineParams.cc.grpId =, sch.actionHandleIndex );
    }

    EMIT3( scheme[, index, ].schemeCounter.update = 1 );
    EMIT3( scheme[, index, ].schemeCounter.value  = 0 );
    EMIT3( scheme[, index, ].keyExtractAndHashParams.numOfUsedMasks = 0 );
    EMIT4( scheme[, index, ].keyExtractAndHashParams.hashShift =,      sch.hashShift );
    EMIT4( scheme[, index, ].keyExtractAndHashParams.symmetricHash =,  sch.symmetricHash );
    EMIT4( scheme[, index, ].keyExtractAndHashParams.hashDistributionNumOfFqids =,
           sch.qcount );

    EMIT4( scheme[, index, ].keyExtractAndHashParams.numOfUsedExtracts =, sch.key.size() );
    if (sch.privateDflt0 > 0)
    {
        EMIT4( scheme[, index, ].keyExtractAndHashParams.privateDflt0 =, sch.privateDflt0 );
    }
    if (sch.privateDflt1 > 0)
    {
        EMIT4( scheme[, index, ].keyExtractAndHashParams.privateDflt1 =, sch.privateDflt1 );
    }
    if (sch.defaults.size() > 0)
    {
        EMIT4( scheme[, index, ].keyExtractAndHashParams.numOfUsedDflts =, sch.defaults.size() );
    }
    // Fill extract parameters
    indent += 4;
    unsigned int i = 0;
    std::vector< ExtractData >::const_iterator extractIt;
    for ( extractIt = sch.key.begin();
          extractIt != sch.key.end();
          ++extractIt, ++i ) {
        if (extractIt->type == e_FM_PCD_EXTRACT_BY_HDR)
        {
            EMIT1( std::string( "/* Extract field:" ) + extractIt->fieldName + " */" );
            if ( extractIt->hdr == HEADER_TYPE_USER_DEFINED_SHIM1 ||
    #ifdef FM_SHIM3_SUPPORT
                extractIt->hdr == HEADER_TYPE_USER_DEFINED_SHIM2 ||
                extractIt->hdr == HEADER_TYPE_USER_DEFINED_SHIM3 ) {
    #else  /* FM_SHIM3_SUPPORT */
                extractIt->hdr == HEADER_TYPE_USER_DEFINED_SHIM2 ) {
    #endif /* FM_SHIM3_SUPPORT */
                if (sch.defaults.empty())
                {
                    EMIT3( scheme[, index, ].keyExtractAndHashParams.numOfUsedDflts = 1 );
                    EMIT3( scheme[, index, ].keyExtractAndHashParams.dflts[0].type = e_FM_PCD_KG_GENERIC_FROM_DATA_NO_V );
                    EMIT3( scheme[, index, ].keyExtractAndHashParams.dflts[0].dfltSelect = e_FM_PCD_KG_DFLT_GBL_0 );
                }
            }
            EMIT6STR( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                                      ].type =, extractIt->type );

            // GCC does not compile designated init for unnamed units.
            // Put them into a block
            EMIT1( "{" );
            indent += 4;

            EMIT7_2STR( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                                         ], .extractByHdr.hdr =,
                                         extractIt->hdr );
            EMIT7_2STR( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                                         ], .extractByHdr.hdrIndex =,
                                         extractIt->hdrIndex );
            if ( extractIt->hdr == HEADER_TYPE_USER_DEFINED_SHIM1 ||
    #ifdef FM_SHIM3_SUPPORT
                 extractIt->hdr == HEADER_TYPE_USER_DEFINED_SHIM2 ||
                 extractIt->hdr == HEADER_TYPE_USER_DEFINED_SHIM3 ) {
    #else  /* FM_SHIM3_SUPPORT */
                extractIt->hdr == HEADER_TYPE_USER_DEFINED_SHIM2 ) {
    #endif /* FM_SHIM3_SUPPORT */
                EMIT7_2( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                                           ],
                                           .extractByHdr.ignoreProtocolValidation =, 1 );
            }
            else {
                EMIT7_2( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                                          ],
                                          .extractByHdr.ignoreProtocolValidation =, 0 );
            }
            EMIT7_2STR( scheme[, index, ].keyExtractAndHashParams.extractArray[, i, ],
                                          .extractByHdr.type =, extractIt->hdrtype );

            if ( extractIt->fieldType != 0xFFFFFFFF ) {
                switch( cmodel->scheme[index].keyExtractAndHashParams.extractArray[i].extractByHdr.hdr )
                {
                    case HEADER_TYPE_ETH:
                        EMIT7_2STR( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.eth =,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_VLAN:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.vlan =,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_LLC_SNAP:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.llcSnap =,
                            extractIt->fieldType );

                        break;
                    case HEADER_TYPE_PPPoE:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.pppoe=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_MPLS:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.mpls=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_IPv4:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.ipv4=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_IPv6:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.ipv6=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_TCP:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.tcp=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_UDP:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.udp=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_SCTP:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.sctp=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_DCCP:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.dccp=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_MINENCAP:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.minencap=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_IPSEC_AH:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.ipsecAh=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_IPSEC_ESP:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.ipsecEsp=,
                            extractIt->fieldType );
                        break;
                    case HEADER_TYPE_GRE:
                        EMIT7_2STR(
                            scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                            ], .extractByHdr.extractByHdrType.fullField.gre=,
                            extractIt->fieldType );
                        break;
                    default:
                        break;
                }
            }
            else {
                EMIT7_2( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                          ], .extractByHdr.extractByHdrType.fromHdr.size =,
                          extractIt->size );

                EMIT7_2( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                          ], .extractByHdr.extractByHdrType.fromHdr.offset =, extractIt->offset );

            }
        }//end of e_FM_PCD_EXTRACT_BY_HDR
        else
        {
            EMIT1( std::string( "/* Extract nonheader:" ) + extractIt->nhSourceStr + " */" );
            EMIT6STR( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                                      ].type =, extractIt->type );

            // GCC does not compile designated init for unnamed units.
            // Put them into a block
            EMIT1( "{" );
            indent += 4;

            EMIT7_2STR( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                                         ], .extractNonHdr.src =,
                                         extractIt->nhSource );
            EMIT7_2( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                          ], .extractNonHdr.offset =, extractIt->nhOffset );
            EMIT7_2( scheme[, index, ].keyExtractAndHashParams.extractArray[, i,
                          ], .extractNonHdr.size =,
                          extractIt->nhSize );
        }

        indent -= 4;
        EMIT1( "}," );
    }

    indent -= 4;
    for ( i = 0; i < sch.defaults.size(); ++i ) {
        EMIT6STR( scheme[, index, ].keyExtractAndHashParams.dflts[, i, ].type =, sch.defaults[i].type );
        EMIT6STR( scheme[, index, ].keyExtractAndHashParams.dflts[, i, ].dfltSelect =, sch.defaults[i].select );
    }
    indent += 4;

    indent -= 4;
    EMIT4( scheme[, index, ].numOfUsedExtractedOrs =, sch.combines.size() );
    indent += 4;

    for ( i = 0; i < sch.combines.size(); ++i ) {
        EMIT6STR( scheme[, index, ].extractedOrs[, i, ].type =, sch.combines[i].type );

        EMIT1( "{" );
        indent += 4;
        if ( sch.combines[i].type != e_FM_PCD_EXTRACT_BY_HDR ) {
            EMIT7_2STR( scheme[, index, ].extractedOrs[, i, ],
                         .src =, sch.combines[i].src );
        }
        else {
            EMIT7_2STR( scheme[, index, ].extractedOrs[, i, ],
                         .extractByHdr.hdr =, sch.combines[i].hdr );
            EMIT7_2( scheme[, index, ].extractedOrs[, i, ],
                      .extractByHdr.ignoreProtocolValidation =, 1 );
        }
        indent -= 4;
        EMIT1( "}," );

        EMIT6( scheme[, index, ].extractedOrs[, i, ].extractionOffset =, sch.combines[i].offset );
        EMIT6( scheme[, index, ].extractedOrs[, i, ].dfltValue =,
            (e_FmPcdKgExtractDfltSelect)sch.combines[i].default_ );
        EMIT6( scheme[, index, ].extractedOrs[, i, ].mask =, sch.combines[i].mask );
        EMIT6( scheme[, index, ].extractedOrs[, i, ].bitOffsetInFqid =, sch.combines[i].offsetInFqid );
    }
    indent -= 8;
}


void
CFMCCModelOutput::output_fmc_ccnode( const CFMCModel& model, fmc_model_t* cmodel,
                                     unsigned int index,
                                     std::ostream& oss, size_t indent )
{
    const CCNode& node = model.all_ccnodes[index];

    EMIT1( std::string( "/* Coarse classification node: " ) + node.name + " */" );

    strncpy( cmodel->ccnode_name[index], node.name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->ccnode_name[index][FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".ccnode_name[" << index << "] = " << std::string( "\"" + node.name + "\"" ) << "," << std::endl;

    // Fill extract parameters
    EMIT4STR( ccnode[, index, ].extractCcParams.type =, node.extract.type );

    EMIT1( "{" );
    indent += 4;

    if ( cmodel->ccnode[index].extractCcParams.type == e_FM_PCD_EXTRACT_BY_HDR )
    {
        EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.hdr =,
                     node.extract.hdr );
        EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.hdrIndex =,
                     node.extract.hdrIndex );
        EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.type =,
                     node.extract.hdrtype );

        if ( node.extract.hdrtype == e_FM_PCD_EXTRACT_FULL_FIELD ) {
            switch ( node.extract.hdr ) {
                case HEADER_TYPE_ETH:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.eth =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_VLAN:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.vlan =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_LLC_SNAP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.llcSnap =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_PPPoE:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.pppoe =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_MPLS:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.mpls =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IPv4:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.ipv4 =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IPv6:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.ipv6 =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.ip =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_UDP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.udp =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_TCP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.tcp =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_SCTP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.sctp =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_DCCP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.dccp =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_GRE:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.gre =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_MINENCAP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.minencap =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IPSEC_AH:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.ipsecAh =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IPSEC_ESP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fullField.ipsecEsp =,
                        node.extract.fieldType );
                    break;
                default:
                    break;

            }
        }
        else if ( node.extract.hdrtype == e_FM_PCD_EXTRACT_FROM_HDR ) {
            EMIT5_2( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromHdr.size =,
                node.extract.size );
            EMIT5_2( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromHdr.offset =,
                node.extract.offset );
        }
        else if ( node.extract.hdrtype == e_FM_PCD_EXTRACT_FROM_FIELD ) {
            switch ( node.extract.hdr ) {
                case HEADER_TYPE_ETH:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.eth =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_VLAN:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.vlan =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_LLC_SNAP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.llcSnap =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_PPPoE:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.pppoe =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_MPLS:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.mpls =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IPv4:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.ipv4 =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IPv6:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.ipv6 =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_UDP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.udp =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_TCP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.tcp =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_SCTP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.sctp =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_DCCP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.dccp =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_GRE:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.gre =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_MINENCAP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.minencap =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IPSEC_AH:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.ipsecAh =,
                        node.extract.fieldType );
                    break;
                case HEADER_TYPE_IPSEC_ESP:
                    EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.field.ipsecEsp =,
                        node.extract.fieldType );
                    break;
                default:
                    break;

            }
            EMIT5_2( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.size =,
                node.extract.size );
            EMIT5_2( ccnode[, index, ].extractCcParams, .extractByHdr.extractByHdrType.fromField.offset =,
                node.extract.offset );
        }
    }
    else
    {
        EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractNonHdr.src =,
            node.extract.nhSource );
        if (node.extract.nhAction != e_FM_PCD_ACTION_NONE)
        {
            EMIT5_2STR( ccnode[, index, ].extractCcParams, .extractNonHdr.action =,
                node.extract.nhAction );
        }

        EMIT5_2( ccnode[, index, ].extractCcParams, .extractNonHdr.offset =,
            node.extract.nhOffset );
        EMIT5_2( ccnode[, index, ].extractCcParams, .extractNonHdr.size =,
            node.extract.nhSize );

        if (node.extract.nhAction == e_FM_PCD_ACTION_INDEXED_LOOKUP)
        {
            EMIT5_2( ccnode[, index, ].extractCcParams, .extractNonHdr.icIndxMask =,
                node.extract.nhIcIndxMask );
        }
    }

    indent -= 4;
    EMIT1( "}," );

    if (node.maxNumOfKeys > 0)
    {
        EMIT4( ccnode[, index, ].keysParams.maxNumOfKeys =, node.maxNumOfKeys );
    }

    EMIT4( ccnode[, index, ].keysParams.maskSupport =, node.maskSupport );
    EMIT4( ccnode[, index, ].keysParams.statisticsMode =, node.statistics );

#ifndef P1023
#if (DPAA_VERSION >= 11)
    if (node.statistics == e_FM_PCD_CC_STATS_MODE_RMON)
    {
        //Print the frame length vector
        oss << ind(indent) << ".ccnode[" << index << "].keysParams.frameLengthRanges = {";

        for (unsigned int idx = 0; idx < FM_PCD_CC_STATS_MAX_NUM_OF_FLR && idx < node.frameLength.size(); idx++)
        {
            cmodel->ccnode[index].keysParams.frameLengthRanges[idx] = node.frameLength[idx];

            //Print the table
            if ( idx != 0 ) {
                oss << ",";
            }

            oss << " 0x" << std::hex << (unsigned int)node.frameLength[idx];
        }

        oss << " }," << std::endl;
        oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
    }
#endif /* (DPAA_VERSION >= 11) */
#endif /* P1023 */

    EMIT4( ccnode[, index, ].keysParams.numOfKeys =, node.keys.size() );
    EMIT4( ccnode[, index, ].keysParams.keySize =, node.keySize );

    if ( node.extract.nhAction != e_FM_PCD_ACTION_INDEXED_LOOKUP ) {
        EMIT4STR( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.nextEngine =, node.nextEngineOnMiss.nextEngine );
        EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.statisticsEn =, node.nextEngineOnMiss.statistics );
        if ( node.nextEngineOnMiss.nextEngine == e_FM_PCD_PLCR ) {
            EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.plcrParams.overrideParams =, 1 );
            EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.plcrParams.sharedProfile =, 1 );
            EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.plcrParams.newRelativeProfileId =, node.nextEngineOnMiss.actionHandleIndex );
            EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.plcrParams.newFqid =, node.nextEngineOnMiss.newFqid );
#if (DPAA_VERSION >= 11)
            EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.plcrParams.newRelativeStorageProfileId =, node.nextEngineOnMiss.newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
        }
        else if ( node.nextEngineOnMiss.nextEngine == e_FM_PCD_CC ) {
            EMIT4( ccmiss_action_index[, index, ] =, node.nextEngineOnMiss.actionHandleIndex );
            EMIT4( ccmiss_action_type[, index, ] =, node.nextEngineOnMiss.nextEngineTrueType );
        }
        else if ( node.nextEngineOnMiss.nextEngine == e_FM_PCD_KG ) {
            EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.kgParams.overrideFqid =, 1 );
            EMIT4( ccmiss_action_index[, index, ] =, node.nextEngineOnMiss.actionHandleIndex );
#if (DPAA_VERSION >= 11)
            EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.kgParams.newRelativeStorageProfileId =, node.nextEngineOnMiss.newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
        }
        else if ( node.nextEngineOnMiss.nextEngine == e_FM_PCD_DONE ) {
            if ( node.nextEngineOnMiss.doneAction == e_FM_PCD_DROP_FRAME ) {
                EMIT4STR( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.enqueueParams.action =, node.nextEngineOnMiss.doneAction );
            }
            else if ( node.nextEngineOnMiss.newFqid != 0 ) {
                EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.enqueueParams.overrideFqid =, 1 );
                EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.enqueueParams.newFqid =,
                        node.nextEngineOnMiss.newFqid );
#if (DPAA_VERSION >= 11)
                EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.enqueueParams.newRelativeStorageProfileId =,
                     node.nextEngineOnMiss.newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
            }
            else {
                EMIT4( ccnode[, index, ].keysParams.ccNextEngineParamsForMiss.params.enqueueParams.overrideFqid =, 0 );
            }
        }
    }

    oss << ind( indent ) << ".cckeydata[" << index << "] = {" << std::endl;
    for ( unsigned int i = 0; i < node.keys.size(); ++i ) {
        oss << ind( indent + 4 ) << "{";
        for ( unsigned int j = 0; j < node.keySize; ++j ) {
            if ( j != 0 ) {
                oss << ",";
            }
            oss << " 0x" << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (unsigned int)node.keys[i].data[j];
            oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
            cmodel->cckeydata[index][i][j] = node.keys[i].data[j];
        }
        oss << " }," << std::endl;
    }
    EMIT1( "}," );

    oss << ind( indent ) << ".ccmask[" << index << "] = {" << std::endl;
    for ( unsigned int i = 0; i < node.masks.size(); ++i ) {
        oss << ind( indent + 4 ) << "{";
        for ( unsigned int j = 0; j < node.keySize; ++j ) {
            if ( j != 0 ) {
                oss << ",";
            }
            oss << " 0x" << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (unsigned int)node.masks[i].data[j];
            oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
            cmodel->ccmask[index][i][j] = node.masks[i].data[j];
        }
        oss << " }," << std::endl;
    }
    EMIT1( "}," );

    for ( unsigned int i = 0; i < node.keys.size(); ++i ) {
        int node_num = node.indices[i];

        if ( node.frag[i] != 0 ) {
            EMIT6( ccentry_frag[, index, ][, node_num, ] =, node.frag[i] );
        }

        if ( node.header[i] != 0 ) {
            EMIT6( ccentry_manip[, index, ][, node_num, ] =, node.header[i] );
        }

        EMIT6STR( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.nextEngine =, node.nextEngines[i].nextEngine );
        EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.statisticsEn =, node.nextEngines[i].statistics );
        if ( node.nextEngines[i].nextEngine == e_FM_PCD_PLCR ) {
            EMIT5( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.plcrParams.overrideParams = 1 );
            EMIT5( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.plcrParams.sharedProfile = 1 );
            EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.plcrParams.newRelativeProfileId =, node.nextEngines[i].actionHandleIndex );
            EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.plcrParams.newFqid =, node.nextEngines[i].newFqid );
#if (DPAA_VERSION >= 11)
            EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.plcrParams.newRelativeStorageProfileId =, node.nextEngines[i].newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
        }
        else if ( node.nextEngines[i].nextEngine == e_FM_PCD_KG ) {
            if ( node.nextEngines[i].newFqid != 0 ) {
                EMIT5( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.kgParams.overrideFqid = 1 );
#if (DPAA_VERSION >= 11)
                EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.kgParams.newRelativeStorageProfileId =, node.nextEngines[i].newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
            }
            else {
                EMIT5( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.kgParams.overrideFqid = 0 );
            }
            EMIT6( ccentry_action_index[, index, ][, node_num, ] =, node.nextEngines[i].actionHandleIndex );
        }
        else if ( node.nextEngines[i].nextEngine == e_FM_PCD_CC ) {
            EMIT6( ccentry_action_type[, index, ][, node_num, ] =, node.nextEngines[i].nextEngineTrueType ); //We save the real type (CC of HT)
            EMIT6( ccentry_action_index[, index, ][, node_num, ] =, node.nextEngines[i].actionHandleIndex );
        }
#if (DPAA_VERSION >= 11)
        else if ( node.nextEngines[i].nextEngine == e_FM_PCD_FR ) {
            EMIT6( ccentry_action_index[, index, ][, node_num, ] =, node.nextEngines[i].actionHandleIndex );
        }
#endif /* (DPAA_VERSION >= 11) */
        else if ( node.nextEngines[i].nextEngine == e_FM_PCD_DONE ) {
            if ( node.nextEngines[i].doneAction == e_FM_PCD_DROP_FRAME ) {
                EMIT6STR( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.enqueueParams.action =, node.nextEngines[i].doneAction );
            }
            else if ( node.nextEngines[i].newFqid != 0 ) {
                EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.enqueueParams.overrideFqid =, 1 );
                EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.enqueueParams.newFqid =, node.nextEngines[i].newFqid );
#if (DPAA_VERSION >= 11)
                EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.enqueueParams.newRelativeStorageProfileId =, node.nextEngines[i].newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
            }
            else {
                EMIT6( ccnode[, index, ].keysParams.keyParams[, node_num, ].ccNextEngineParams.params.enqueueParams.overrideFqid =, 0 );
            }
        }
    }
}


void
CFMCCModelOutput::output_fmc_htnode( const CFMCModel& model, fmc_model_t* cmodel,
                                     unsigned int index,
                                     std::ostream& oss, size_t indent )
{
    const HTNode& node = model.all_htnodes[index];

    EMIT1( std::string( "/* Hash table node: " ) + node.name + " */" );

    strncpy( cmodel->htnode_name[index], node.name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->htnode_name[index][FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".htnode_name[" << index << "] = " << std::string( "\"" + node.name + "\"" ) << "," << std::endl;


    EMIT4( htnode[, index, ].maxNumOfKeys =, node.maxNumOfKeys );
    EMIT4( htnode[, index, ].statisticsMode =, node.statistics );
    EMIT4( htnode[, index, ].matchKeySize =, node.matchKeySize );
    EMIT4( htnode[, index, ].hashResMask =, node.hashResMask );
    EMIT4( htnode[, index, ].hashShift =, node.hashShift );
    EMIT4( htnode[, index, ].kgHashShift =, node.kgHashShift );
    EMIT4( htnode[, index, ].agingSupport =, node.agingSupport );
#if (DPAA_VERSION >= 11)
    EMIT4( htnode[, index, ].externalHash =, node.externalHash );
#endif /* (DPAA_VERSION >= 11) */

    EMIT4STR( htnode[, index, ].ccNextEngineParamsForMiss.nextEngine =, node.nextEngineOnMiss.nextEngine );
    EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.statisticsEn =, node.nextEngineOnMiss.statistics );
    if ( node.nextEngineOnMiss.nextEngine == e_FM_PCD_PLCR ) {
        EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.plcrParams.overrideParams =, 1 );
        EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.plcrParams.sharedProfile =, 1 );
        EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.plcrParams.newRelativeProfileId =, node.nextEngineOnMiss.actionHandleIndex );
        EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.plcrParams.newFqid =, node.nextEngineOnMiss.newFqid );
#if (DPAA_VERSION >= 11)
        EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.plcrParams.newRelativeStorageProfileId =, node.nextEngineOnMiss.newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
    }
    else if ( node.nextEngineOnMiss.nextEngine == e_FM_PCD_CC ) {
        EMIT4( htmiss_action_index[, index, ] =, node.nextEngineOnMiss.actionHandleIndex );
        EMIT4( htmiss_action_type[, index, ] =, node.nextEngineOnMiss.nextEngineTrueType );
    }
    else if ( node.nextEngineOnMiss.nextEngine == e_FM_PCD_KG ) {
        EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.kgParams.overrideFqid =, 1 );
        EMIT4( htmiss_action_index[, index, ] =, node.nextEngineOnMiss.actionHandleIndex );
#if (DPAA_VERSION >= 11)
        EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.kgParams.newRelativeStorageProfileId =, node.nextEngineOnMiss.newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
    }
    else if ( node.nextEngineOnMiss.nextEngine == e_FM_PCD_DONE ) {
        if ( node.nextEngineOnMiss.doneAction == e_FM_PCD_DROP_FRAME ) {
            EMIT4STR( htnode[, index, ].ccNextEngineParamsForMiss.params.enqueueParams.action =, node.nextEngineOnMiss.doneAction );
        }
        else if ( node.nextEngineOnMiss.newFqid != 0 ) {
            EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.enqueueParams.overrideFqid =, 1 );
            EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.enqueueParams.newFqid =,
                    node.nextEngineOnMiss.newFqid );
#if (DPAA_VERSION >= 11)
            EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.enqueueParams.newRelativeStorageProfileId =,
                 node.nextEngineOnMiss.newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
        }
        else {
            EMIT4( htnode[, index, ].ccNextEngineParamsForMiss.params.enqueueParams.overrideFqid =, 0 );
        }
    }

    oss << ind( indent ) << ".htkeydata[" << index << "] = {" << std::endl;
    for ( unsigned int i = 0; i < node.keys.size(); ++i ) {
        oss << ind( indent + 4 ) << "{";
        for ( unsigned int j = 0; j < node.matchKeySize; ++j ) {
            if ( j != 0 ) {
                oss << ",";
            }
            oss << " 0x" << std::hex << std::setw( 2 ) << std::setfill( '0' ) << (unsigned int)node.keys[i].data[j];
            oss << std::dec << std::resetiosflags(std::ios::basefield | std::ios::internal);
            cmodel->htkeydata[index][i][j] = node.keys[i].data[j];
        }
        oss << " }," << std::endl;
    }
    EMIT1( "}," );

    EMIT4( htentry_count[, index, ] =, (unsigned int)node.keys.size() );

    for ( unsigned int i = 0; i < node.keys.size(); ++i ) {
        int node_num = node.indices[i];

        if ( node.frag[i] != 0 ) {
            EMIT6( htentry_frag[, index, ][, node_num, ] =, node.frag[i] );
        }

        if ( node.header[i] != 0 ) {
            EMIT6( htentry_manip[, index, ][, node_num, ] =, node.header[i] );
        }

        EMIT6STR( htentry[, index, ][, node_num, ].ccNextEngineParams.nextEngine =, node.nextEngines[i].nextEngine );
        EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.statisticsEn =, node.nextEngines[i].statistics );
        if ( node.nextEngines[i].nextEngine == e_FM_PCD_PLCR ) {
            EMIT5( htentry[, index, ][, node_num, ].ccNextEngineParams.params.plcrParams.overrideParams = 1 );
            EMIT5( htentry[, index, ][, node_num, ].ccNextEngineParams.params.plcrParams.sharedProfile = 1 );
            EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.params.plcrParams.newRelativeProfileId =, node.nextEngines[i].actionHandleIndex );
            EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.params.plcrParams.newFqid =, node.nextEngines[i].newFqid );
#if (DPAA_VERSION >= 11)
            EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.params.plcrParams.newRelativeStorageProfileId =, node.nextEngines[i].newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
        }
        else if ( node.nextEngines[i].nextEngine == e_FM_PCD_KG ) {
            if ( node.nextEngines[i].newFqid != 0 ) {
                EMIT5( htentry[, index, ][, node_num, ].ccNextEngineParams.params.kgParams.overrideFqid = 1 );
#if (DPAA_VERSION >= 11)
                EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.params.kgParams.newRelativeStorageProfileId =, node.nextEngines[i].newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */
            }
            else {
                EMIT5( htentry[, index, ][, node_num, ].ccNextEngineParams.params.kgParams.overrideFqid = 0 );
            }
            EMIT6( htentry_action_index[, index, ][, node_num, ] =, node.nextEngines[i].actionHandleIndex );
        }
        else if ( node.nextEngines[i].nextEngine == e_FM_PCD_CC ) {
            EMIT6( htentry_action_type[, index, ][, node_num, ] =, node.nextEngines[i].nextEngineTrueType ); //We save the real type (CC of HT)
            EMIT6( htentry_action_index[, index, ][, node_num, ] =, node.nextEngines[i].actionHandleIndex );
        }
#if (DPAA_VERSION >= 11)
        else if ( node.nextEngines[i].nextEngine == e_FM_PCD_FR ) {
            EMIT6( htentry_action_index[, index, ][, node_num, ] =, node.nextEngines[i].actionHandleIndex );
        }
#endif /* (DPAA_VERSION >= 11) */
        else if ( node.nextEngines[i].nextEngine == e_FM_PCD_DONE ) {
            if ( node.nextEngines[i].doneAction == e_FM_PCD_DROP_FRAME ) {
                EMIT6STR( htentry[, index, ][, node_num, ].ccNextEngineParams.params.enqueueParams.action =, node.nextEngines[i].doneAction );
            }
            else if ( node.nextEngines[i].newFqid != 0 ) {
                EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.params.enqueueParams.overrideFqid =, 1 );
                EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.params.enqueueParams.newFqid =, node.nextEngines[i].newFqid );
#if (DPAA_VERSION >= 11)
                EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.params.enqueueParams.newRelativeStorageProfileId =, node.nextEngines[i].newRelativeStorageProfileId );
#endif /* (DPAA_VERSION >= 11) */

            }
            else {
                EMIT6( htentry[, index, ][, node_num, ].ccNextEngineParams.params.enqueueParams.overrideFqid =, 0 );
            }
        }
    }
}// End of HT node output


void
CFMCCModelOutput::output_fmc_policer( const CFMCModel& model, fmc_model_t* cmodel,
                                      unsigned int index,
                                      std::ostream& oss, size_t indent )
{
    const Policer& plc = model.all_policers[index];

    EMIT1( std::string( "/* Policer: " ) + plc.name + " */" );

    strncpy( cmodel->policer_name[index], plc.name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->policer_name[index][FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".policer_name[" << index << "] = " << std::string( "\"" + plc.name + "\"" ) << "," << std::endl;

    EMIT3( policer[, index, ].modify = 0 );
    EMIT3( policer[, index, ].id.newParams.profileType = e_FM_PCD_PLCR_SHARED );
    EMIT4( policer[, index, ].id.newParams.relativeProfileId =, plc.getIndex() );
    EMIT4STR( policer[, index, ].algSelection = , plc.algorithm );
    EMIT4STR( policer[, index, ].colorMode = , plc.colorMode );

    EMIT4( policer[, index, ].nonPassthroughAlgParams.committedInfoRate =, plc.committedInfoRate );
    EMIT4( policer[, index, ].nonPassthroughAlgParams.committedBurstSize =, plc.committedBurstSize );
    EMIT4( policer[, index, ].nonPassthroughAlgParams.peakOrExcessInfoRate =, plc.peakOrExcessInfoRate );
    EMIT4( policer[, index, ].nonPassthroughAlgParams.peakOrExcessBurstSize =, plc.peakOrExcessBurstSize );
    EMIT4STR( policer[, index, ].nonPassthroughAlgParams.rateMode =, plc.rateMode );
    EMIT3( policer[, index, ].nonPassthroughAlgParams.byteModeParams.frameLengthSelection = e_FM_PCD_PLCR_L2_FRM_LEN );
    EMIT3( policer[, index, ].nonPassthroughAlgParams.byteModeParams.rollBackFrameSelection = e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN );

    EMIT4STR( policer[, index, ].color.dfltColor =, plc.dfltColor );

    EMIT4STR( policer[, index, ].nextEngineOnGreen =, plc.nextEngineOnGreen );
    EMIT4STR( policer[, index, ].paramsOnGreen.action =, plc.onGreenAction );

    EMIT4STR( policer[, index, ].nextEngineOnYellow =, plc.nextEngineOnYellow );
    EMIT4STR( policer[, index, ].paramsOnYellow.action =, plc.onYellowAction );

    EMIT4STR( policer[, index, ].nextEngineOnRed =, plc.nextEngineOnRed );
    EMIT4STR( policer[, index, ].paramsOnRed.action =, plc.onRedAction );

    EMIT4( policer_action_index[, index, ][0] =, plc.onGreenActionHandleIndex );
    EMIT4( policer_action_index[, index, ][1] =, plc.onYellowActionHandleIndex );
    EMIT4( policer_action_index[, index, ][2] =, plc.onRedActionHandleIndex );
}

#if (DPAA_VERSION >= 11)
void
CFMCCModelOutput::output_fmc_replicator( const CFMCModel& model, fmc_model_t* cmodel,
                                      unsigned int index,
                                      std::ostream& oss, size_t indent )
{
    const CRepl& repl = model.all_replicators[index];

    EMIT1( std::string( "/* Replicator: " ) + repl.name + " */" );

    strncpy( cmodel->replicator_name[index], repl.name.c_str(), FMC_NAME_LEN - 1 );
    cmodel->replicator_name[index][FMC_NAME_LEN - 1] = 0;
    oss << ind( indent ) << ".replicator_name[" << index << "] = " << std::string( "\"" + repl.name + "\"" ) << "," << std::endl;

    EMIT4( replicator[, index, ].maxNumOfEntries =, repl.maxNumOfEntries );
    EMIT4( replicator[, index, ].numOfEntries =, repl.nextEngines.size() );

    for ( unsigned int i = 0; i < repl.nextEngines.size(); ++i ) {
        int entry_num = repl.indices[i];

        if ( repl.frag[i] != 0 ) {
            EMIT6( repentry_frag[, index, ][, entry_num, ] =, repl.frag[i] );
        }

        if ( repl.header[i] != 0 ) {
            EMIT6( repentry_manip[, index, ][, entry_num, ] =, repl.header[i] );
        }

        EMIT6STR( replicator[, index, ].nextEngineParams[, entry_num, ].nextEngine =, repl.nextEngines[i].nextEngine );
        if ( repl.nextEngines[i].nextEngine == e_FM_PCD_PLCR ) {
            if ( repl.nextEngines[i].newFqid != 0 ) {
                EMIT5( replicator[, index, ].nextEngineParams[, entry_num, ].params.plcrParams.overrideParams = 1 );
                EMIT5( replicator[, index, ].nextEngineParams[, entry_num, ].params.plcrParams.sharedProfile = 1 );
                EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.plcrParams.newRelativeProfileId =, repl.nextEngines[i].actionHandleIndex );
                EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.plcrParams.newFqid =, repl.nextEngines[i].newFqid );
            }
            else {
                EMIT5( replicator[, index, ].nextEngineParams[, entry_num, ].params.plcrParams.overrideParams = 0 );
            }
            EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.plcrParams.newRelativeStorageProfileId =, repl.nextEngines[i].newRelativeStorageProfileId );
        }
        else if ( repl.nextEngines[i].nextEngine == e_FM_PCD_KG ) {
            if ( repl.nextEngines[i].newFqid != 0 ) {
                EMIT5( replicator[, index, ].nextEngineParams[, entry_num, ].params.kgParams.overrideFqid = 1 );
                EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.kgParams.newFqid =, repl.nextEngines[i].newFqid );
                EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.kgParams.newRelativeStorageProfileId =, repl.nextEngines[i].newRelativeStorageProfileId );
            }
            else {
                EMIT5( replicator[, index, ].nextEngineParams[, entry_num, ].params.kgParams.overrideFqid = 0 );
            }
            EMIT6( repentry_action_index[, index, ][, entry_num, ] =, repl.nextEngines[i].actionHandleIndex );
        }
        else if ( repl.nextEngines[i].nextEngine == e_FM_PCD_CC ) {
            EMIT6( repentry_action_index[, index, ][, entry_num, ] =, repl.nextEngines[i].actionHandleIndex );
        }
        else if ( repl.nextEngines[i].nextEngine == e_FM_PCD_FR ) {
            EMIT6( repentry_action_index[, index, ][, entry_num, ] =, repl.nextEngines[i].actionHandleIndex );
        }
        else if ( repl.nextEngines[i].nextEngine == e_FM_PCD_DONE ) {
            if ( repl.nextEngines[i].newFqid != 0 ) {
                EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.enqueueParams.overrideFqid =, 1 );
                EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.enqueueParams.newFqid =, repl.nextEngines[i].newFqid );
                EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.enqueueParams.newRelativeStorageProfileId =, repl.nextEngines[i].newRelativeStorageProfileId );
            }

            else {
                EMIT6( replicator[, index, ].nextEngineParams[, entry_num, ].params.enqueueParams.overrideFqid =, 0 );
            }
        }
    }
}
#endif /* (DPAA_VERSION >= 11) */


std::string
CFMCCModelOutput::get_apply_item_name( fmc_model_t* cmodel,
                                       ApplyOrder::Entry e )
{
    switch ( get_fmc_type( e.type ) ) {
    case FMCEngineStart:
    case FMCEngineEnd:
        return std::string( " /* " ) +
            cmodel->fman[e.index].name + " */";
    case FMCPortStart:
    case FMCPortEnd:
    case FMCCCTree:
        return std::string( " /* " ) +
            cmodel->port[e.index].name + " */";
    case FMCScheme:
        return std::string( " /* " ) +
            cmodel->scheme_name[e.index] + " */";
    case FMCCCNode:
        return std::string( " /* " ) +
            cmodel->ccnode_name[e.index] + " */";
    case FMCHTNode:
        return std::string( " /* " ) +
            cmodel->htnode_name[e.index] + " */";
    case FMCPolicer:
        return std::string( " /* " ) +
            cmodel->policer_name[e.index] + " */";
#ifndef P1023
#if (DPAA_VERSION >= 11)
    case FMCReplicator:
        return std::string( " /* " ) +
            cmodel->replicator_name[e.index] + " */";
#endif /* (DPAA_VERSION >= 11) */
    case FMCManipulation:
        return std::string( " /* " ) +
            cmodel->fman[current_engine].hdr_name[e.index] + " */";
#endif // P1023
    default:
        return "";
    }
    return "";
}


void
CFMCCModelOutput::output_fmc_applier( const CFMCModel& model, fmc_model_t* cmodel,
                                      unsigned int index,
                                      std::ostream& oss, size_t indent )
{
    ApplyOrder::Entry e = model.applier.get( index );

    cmodel->apply_order[cmodel->apply_order_count - index - 1].type  = get_fmc_type( e.type );
    cmodel->apply_order[cmodel->apply_order_count - index - 1].index = e.index;

    if ( e.type == ApplyOrder::EngineStart ) {
        current_engine = e.index;
    }

    oss << ind( indent )
        << "FMC_APPLY_ORDER("
        << std::setfill(' ') << std::setw( 3 )
        << cmodel->apply_order_count - index - 1
        << ", "
        << get_fmc_type_str( e.type )
        << ","
        << std::setfill(' ') << std::setw( 3 )
        << e.index
        << " ),"
        << get_apply_item_name( cmodel, e )
        << std::endl;
}


fmc_apply_order_e
CFMCCModelOutput::get_fmc_type( ApplyOrder::Type t ) const
{
    switch ( t ) {
        case ApplyOrder::EngineStart:
            return FMCEngineStart;
        case ApplyOrder::EngineEnd:
            return FMCEngineEnd;
        case ApplyOrder::PortStart:
            return FMCPortStart;
        case ApplyOrder::PortEnd:
            return FMCPortEnd;
        case ApplyOrder::Scheme:
            return FMCScheme;
        case ApplyOrder::CCNode:
            return FMCCCNode;
        case ApplyOrder::HTNode:
            return FMCHTNode;
        case ApplyOrder::CCTree:
            return FMCCCTree;
        case ApplyOrder::Replicator:
            return FMCReplicator;
        case ApplyOrder::Policer:
            return FMCPolicer;
        case ApplyOrder::Manipulation:
            return FMCManipulation;
    }
    return FMCEngineStart;
}


std::string
CFMCCModelOutput::get_fmc_type_str( ApplyOrder::Type t ) const
{
    switch ( t ) {
        case ApplyOrder::EngineStart:
            return "FMCEngineStart ";
        case ApplyOrder::EngineEnd:
            return "FMCEngineEnd   ";
        case ApplyOrder::PortStart:
            return "FMCPortStart   ";
        case ApplyOrder::PortEnd:
            return "FMCPortEnd     ";
        case ApplyOrder::Scheme:
            return "FMCScheme      ";
        case ApplyOrder::CCNode:
            return "FMCCCNode      ";
        case ApplyOrder::HTNode:
            return "FMCHTNode      ";
        case ApplyOrder::CCTree:
            return "FMCCCTree      ";
        case ApplyOrder::Policer:
            return "FMCPolicer     ";
        case ApplyOrder::Replicator:
            return "FMCReplicator  ";
        case ApplyOrder::Manipulation:
            return "FMCManipulation";
    }
    return "";
}


void
CFMCCModelOutput::check_bounds( unsigned int used,
                                unsigned int available,
                                std::string  entity )
{
    if ( used > available ) {
        throw CGenericError( ERR_NOT_ENOUGH_RESOURCES,
                             entity, used, available );
    }
}
