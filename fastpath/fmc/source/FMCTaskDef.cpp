/* =====================================================================
 *
 * The MIT License (MIT)
 * Copyright 2009, 2010, Freescale Semiconductor, Inc.
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
 * File Name : FMCTaskDef.cpp
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#include <iomanip>
#include <cstdlib>
#include <cstring>
#include "FMCTaskDef.h"


bool
findConseqBits( uint64_t value, uint32_t& size, uint32_t& offset )
{
    if ( 0 == value ) return false;

    bool started = false;
    uint64_t mask = (uint64_t)1 << ( sizeof( value ) * 8 - 1 );
    for ( int i = 0; i < sizeof( value ) * 8; ++i ) {   // start from the left bit
        if ( ( !started ) && ( ( value & mask ) != 0 ) ) {
            offset = i;
            started = true;
        }
        if ( ( started ) && ( ( value & mask ) == 0 ) ) {
            size = i - offset;
            started = false;
            break;
        }
        mask >>= 1;
    }

    if ( started ) {
        size = sizeof( value ) * 8 - offset;
    }

    return true;
}

CTaskDef::CTaskDef(void)
{
}

CTaskDef::~CTaskDef(void)
{
}


bool
CTaskDef::checkSemantics()
{
    bool res = true;

    // Check distributions
    std::map< std::string, CDistribution >::iterator distIt;
    for ( distIt = distributions.begin(); res && distIt != distributions.end(); ++distIt ) {
        res &= checkSemanticsDistribution( distIt->second );
    }

    // Check classifictions
    std::map< std::string, CClassification >::iterator clsfIt;
    for ( clsfIt = classifications.begin(); res && clsfIt != classifications.end(); ++clsfIt ) {
        res &= checkSemanticsClassification( clsfIt->second );
    }

    // Check replicators
    std::map< std::string, CReplicator >::iterator replIt;
    for ( replIt = replicators.begin(); res && replIt != replicators.end(); ++replIt ) {
        res &= checkSemanticsReplicator( replIt->second );
    }

    // Check policers
    std::map< std::string, CPolicer >::iterator plcrIt;
    for ( plcrIt = policers.begin(); res && plcrIt != policers.end(); ++plcrIt ) {
        res &= checkSemanticsPolicer( plcrIt->second );
    }

    // Check reassemblies
    std::map< std::string, CReassembly >::iterator reasIt;
    for ( reasIt = reassemblies.begin(); res && reasIt != reassemblies.end(); ++reasIt ) {
        res &= checkSemanticsReassembly( reasIt->second );
    }

    // Check loop dependencies
    res &= checkLoopDependencies();

    return res;
}


bool
CTaskDef::checkSemanticsClassification( CClassification& clsf )
{
    // Check that actions' types and make sure that the actions have apropriate targets
    for ( unsigned int i = 0; i < clsf.entries.size(); ++i ) {
        checkActionTarget( clsf.entries[i].action, clsf.entries[i].actionName,
                           "classification", clsf.name );

         if (clsf.entries[i].statistics && (clsf.statistics == "" || clsf.statistics == "none"))
             throw CGenericError( ERR_CLSF_STAT_NONE, clsf.name );
    }
    
    if (clsf.statisticsOnMiss && (clsf.statistics == "" || clsf.statistics == "none"))
             throw CGenericError( ERR_CLSF_STAT_NONE, clsf.name );

    checkActionTarget( clsf.actionOnMiss, clsf.actionNameOnMiss,
                       "classification", clsf.name );

   

    if ( !clsf.key.header                                  &&
        clsf.key.nonHeaderEntry.source == ES_FROM_HASH     &&
        clsf.key.nonHeaderEntry.action == EA_INDEXED_LOOKUP ) {
        // Check that the last nible of IndxMask is zero
        if ( ( clsf.key.nonHeaderEntry.icIndxMask & 0x0F ) != 0 ) {
            throw CGenericError( ERR_CLSF_INDX_MASK, clsf.name );
        }

        //Adjust entries according to mask
        uint16_t glblMask = clsf.key.nonHeaderEntry.icIndxMask;
        uint16_t countMask = (uint16_t)(glblMask >> 4);
        unsigned int countOnes = 0;

        while (countMask)
        {
            countOnes++;
            countMask = (uint16_t)(countMask >> 1);
        }

        uint32_t numOfKeys = (uint32_t)1 << countOnes;

        if (clsf.max != 0)
            clsf.max = numOfKeys;

        for(unsigned int tmp = 0; tmp < numOfKeys; tmp++)
        {
            unsigned int i = 0;
            //Search the entry in the xml classif
            for (i = 0; i < clsf.entries.size(); i++)
            {
                if (clsf.entries[i].index == tmp)
                    break;
            }
            
            if((glblMask & (tmp * 16)) == (tmp * 16))
            {
                //Must be initialized
                if (i == clsf.entries.size())
                {
                    //It was not initialized, create a dummy entry
                    CClassEntry dummyEntry;
                    memset( dummyEntry.data, 0x00, sizeof( dummyEntry.data ) );
                    memset( dummyEntry.mask, 0xFF, sizeof( dummyEntry.mask ) );
                    dummyEntry.qbase = 0x00;
                    dummyEntry.fragmentationName = "";
                    dummyEntry.headerManipName   = "";
                    dummyEntry.action = "";
                    dummyEntry.actionName = "";
                    dummyEntry.statistics = false;
                    dummyEntry.index = tmp;
                    clsf.entries.push_back(dummyEntry);
                }
            }
            else
            {
                //Must be invalid
                if (i != clsf.entries.size())
                {
                    clsf.entries.erase(clsf.entries.begin() + i);
                }
            }
        }
        
    }

    if (clsf.key.field)
    {
        if (clsf.key.fields.size() != 1) {
            throw CGenericError( ERR_CLSF_FROMFIELD_NO, clsf.name );
        }

        if (clsf.key.fields[0].name != "ethernet.type" && clsf.key.fields[0].name != "vlan.tci" ) {
            throw CGenericError( ERR_CLSF_FROMFIELD_HEADER, clsf.name );
        }
    }

    if (clsf.key.header)
    {
        if (clsf.key.fields.size() > 3)
            throw CGenericError( ERR_CLSF_EXTRACTION, "you can not have more than 3 extracts", clsf.name );
    }

    return true;
}

bool
CTaskDef::checkSemanticsReplicator( CReplicator& repl )
{
    // Check that actions' types and make sure that the actions have apropriate targets
    for ( unsigned int i = 0; i < repl.entries.size(); ++i ) {
        checkActionTarget( repl.entries[i].action, repl.entries[i].actionName,
                           "replicator", repl.name );
    }
  
    return true;
}


bool
CTaskDef::checkSemanticsDistribution( CDistribution& dist )
{
    // Check the field's name and header_index validity
    for ( unsigned int i = 0; i < dist.key.size(); ++i ) {
        std::string name     = dist.key[i].name;
        std::string hdrindex = dist.key[i].header_index;

        if ( hdrindex == "0" ) {
            dist.key[i].header_index.clear();
            hdrindex.clear();
        }

        if ( !hdrindex.empty() && hdrindex != "1" && hdrindex != "2" &&
             hdrindex != "3" && hdrindex != "last" ) {
            CGenericError::printWarning( WARN_WRONG_HDR_INDEX, "Distribution", dist.name, dist.key[i].name );
            dist.key[i].header_index.clear();
            hdrindex.clear();
        }

        if ( !hdrindex.empty() ) {
            // Only the following combinations are permitted
            if ( ! ( ( name == "vlan.tci"     && hdrindex == "1" )    ||
                     ( name == "vlan.tci"     && hdrindex == "last" ) ||
                     ( name == "mpls.label"   && hdrindex == "1" )    ||
                     ( name == "mpls.label"   && hdrindex == "2" )    ||
                     ( name == "mpls.label"   && hdrindex == "last" ) ||
                     ( name == "ipv4.src"     && hdrindex == "1" )    ||
                     ( name == "ipv6.src"     && hdrindex == "1" )    ||
                     ( name == "ipv4.dst"     && hdrindex == "1" )    ||
                     ( name == "ipv6.dst"     && hdrindex == "1" )    ||
                     ( name == "ipv4.src"     && hdrindex == "last" ) ||
                     ( name == "ipv6.src"     && hdrindex == "last" ) ||
                     ( name == "ipv4.dst"     && hdrindex == "last" ) ||
                     ( name == "ipv6.dst"     && hdrindex == "last" ) ||
                     ( name == "ipv4.tos"     && hdrindex == "1" )    ||
                     ( name == "ipv4.nextp"   && hdrindex == "1" )    ||
                     ( name == "ipv6.nexthdr" && hdrindex == "1" )    ||
                     ( name == "ipv4.nextp"   && hdrindex == "last" ) ||
                     ( name == "ipv6.nexthdr" && hdrindex == "last" ) ||
                     ( name == "ipv4.tos"     && hdrindex == "1" )    ||
                     ( name == "ipv6.tos"     && hdrindex == "1" )    ||
                     ( name == "ipv4.tos"     && hdrindex == "last" ) ||
                     ( name == "ipv6.tos"     && hdrindex == "last" ) ||
                     ( name == "ipv6.flabel"  && hdrindex == "1" )    ||
                     ( name == "ipv6.flabel"  && hdrindex == "last" ) ) ) {
                CGenericError::printWarning( WARN_HDR_INDEX_NA, "Distribution", dist.name, dist.key[i].name );
                dist.key[i].header_index.clear();
                hdrindex.clear();
            }
        }

        // Check that it is a known field
        if ( !FieldExists( name ) ) {
            throw CGenericError( ERR_UNRECOGNIZED_FIELD, name );
        }
    }

    // Check that a 'distribution' is not a target of 'distribution' action
    if ( dist.action  == "distribution" ) {
        throw CGenericError( ERR_DIST_TRG_IS_DIST, dist.name );
    }

    // Check action types and make sure that the actions have apropriate targets
    checkActionTarget( dist.action, dist.actionName, "distribution", dist.name );

    // Make sure that queue count is 2^n
    if ( ( dist.qcount != 0 ) &&
        ( ( IntBits< unsigned int >( dist.qcount ).count1s() != 1 ) ||
          ( dist.qcount > 0x00FFFFFF ) ) ) {
        throw CGenericError( ERR_INCORRECT_QUEUE_SIZE, dist.name );
    }

    return true;
}


bool
CTaskDef::checkSemanticsPolicer( CPolicer& plcr )
{
    // Check that a 'classification' is not a target of 'policer' action
    if ( plcr.actionOnGreen  == "classification" ||
         plcr.actionOnYellow == "classification" ||
         plcr.actionOnRed    == "classification" ) {
        throw CGenericError( ERR_PLCR_TRG_IS_CLSF, plcr.name );
    }

    // Check that actions' types and make sure that the actions have apropriate targets
    checkActionTarget( plcr.actionOnGreen,  plcr.actionNameOnGreen,  "policer", plcr.name );
    checkActionTarget( plcr.actionOnYellow, plcr.actionNameOnYellow, "policer", plcr.name );
    checkActionTarget( plcr.actionOnRed,    plcr.actionNameOnRed,    "policer", plcr.name );

    return true;
}

bool
CTaskDef::checkSemanticsReassembly(CReassembly& reas)
{
    if ( ( reas.maxInProcess != 0 ) &&
       ( ( IntBits< unsigned int >( reas.maxInProcess ).count1s() != 1 )))
    {
        throw CGenericError( ERR_REAS_MAXINPROCESS, reas.name );
    }

    if ( reas.ipv6minFragSize < 256)
    {
        throw CGenericError( ERR_REAS_IPV6FRAGSIZE, reas.name );
    }

    if ( reas.numOfFramesPerHashEntry[0] < 1 || reas.numOfFramesPerHashEntry[0] > 8)
    {
        throw CGenericError( ERR_REAS_NUMFRAMESHASH, reas.name );
    }

    if ( reas.numOfFramesPerHashEntry[1] < 1 || reas.numOfFramesPerHashEntry[1] > 6)
    {
        throw CGenericError( ERR_REAS_NUMFRAMESHASH, reas.name );
    }

    return true;
}

class CNode {
public:
    CNode()                                                        {};
    CNode( std::string a, std::string n ) : action( a ), name( n ) {};
    bool operator<( const CNode& n ) const
    {
        if ( action < n.action )
            return true;
        else
            if ( action == n.action )
                return name < n.name;
        return false;
    }

    std::string action;
    std::string name;
};


class CEdge {
public:
    CEdge( std::string froma, std::string fromn,  std::string troma, std::string tromn ) :
      faction( froma ), fname( fromn ),  taction( troma ), tname( tromn ) {};
    std::string faction;
    std::string fname;
    std::string taction;
    std::string tname;
};


bool
CTaskDef::checkLoopDependencies()
{

    std::set< CNode > nodes;
    std::map< CNode, std::set< CNode > > edges;

    // For all distributions
    std::map< std::string, CDistribution >::iterator distIt;
    for ( distIt = distributions.begin(); distIt != distributions.end(); ++distIt ) {
        CNode from( "distribution", distIt->second.name );
        CNode to( distIt->second.action, distIt->second.actionName );
        nodes.insert( from ); nodes.insert( to );
        edges[to].insert( from );
    }

    // For all classifictions
    std::map< std::string, CClassification >::iterator clsfIt;
    for ( clsfIt = classifications.begin(); clsfIt != classifications.end(); ++clsfIt ) {
        // For all entries inside classification
        for ( unsigned int i = 0; i < clsfIt->second.entries.size(); ++i ) {
            CNode from( "classification", clsfIt->second.name );
            CNode to( clsfIt->second.entries[i].action, clsfIt->second.entries[i].actionName );
            nodes.insert( from ); nodes.insert( to );
            edges[to].insert( from );
        }
        CNode from( "classification", clsfIt->second.name );
        CNode to( clsfIt->second.actionOnMiss, clsfIt->second.actionNameOnMiss );
        nodes.insert( from ); nodes.insert( to );
        edges[to].insert( from );
    }

    // For all policers
    std::map< std::string, CPolicer >::iterator plcrIt;
    for ( plcrIt = policers.begin(); plcrIt != policers.end(); ++plcrIt ) {
        CNode from( "policer", plcrIt->second.name );
        nodes.insert( from );
        {
            CNode to( plcrIt->second.actionOnGreen, plcrIt->second.actionNameOnGreen );
            nodes.insert( to );
            edges[to].insert( from );
        }
        {
            CNode to( plcrIt->second.actionOnYellow, plcrIt->second.actionNameOnYellow );
            nodes.insert( to );
            edges[to].insert( from );
        }
        {
            CNode to( plcrIt->second.actionOnRed, plcrIt->second.actionNameOnRed );
            nodes.insert( to );
            edges[to].insert( from );
        }
    }

    bool found = true;
    while ( found && nodes.size() != 0 ) {
        // Find a node without parent and remove it
        found = false;
        std::set< CNode >::iterator nodeIt;
        for ( nodeIt = nodes.begin(); !found && nodeIt != nodes.end(); ++nodeIt ) {
            if ( edges.find( *nodeIt ) == edges.end() ) {
                found = true;
                break;
            }
        }
        if ( found ) {
            // Delete the node from parents' list
            std::map< CNode, std::set< CNode > >::iterator edgeIt;
            for ( edgeIt = edges.begin(); edgeIt != edges.end(); ++edgeIt ) {
                edgeIt->second.erase( *nodeIt );
            }

            // Delete orphan edges
            edgeIt = edges.begin();
            while ( edgeIt != edges.end() ) {
                // Is parents' list empty?
                if ( edgeIt->second.empty() ) {
                    edges.erase( edgeIt++ );
                }
                else {
                    ++edgeIt;
                }
            }

            // Delete the node
            nodes.erase( nodeIt );
        }
    }

    if ( !nodes.empty() ) {
        std::set< CNode > parents;

        std::map< CNode, std::set< CNode > >::iterator edgeIt;
        for ( edgeIt = edges.begin(); edgeIt != edges.end(); ++edgeIt ) {
            std::set< CNode >::iterator parentIt;
            for ( parentIt = edgeIt->second.begin();
                  parentIt != edgeIt->second.end();
                  ++parentIt ) {
                      parents.insert( *parentIt );
            }
        }

        std::string candidates;
        std::set< CNode >::iterator parentIt;
        for ( parentIt = parents.begin();
              parentIt != parents.end();
              ++parentIt ) {
                  candidates += parentIt->action + " '" +  parentIt->name + "'\n";
        }


        throw CGenericError( ERR_LOOP_DEPENDENCY, candidates );
    }
    return true;
}


bool
CTaskDef::checkActionTarget( const std::string action,
                             const std::string actionName,
                             const std::string fromType,
                             const std::string from )
{
    // Check that the action's type is known
    if ( !action.empty()             &&
          action != "classification" &&
          action != "distribution"   &&
          action != "drop"           &&
          action != "policer"        &&
          action != "hashtable"      &&
          action != "replicator") {
        throw CGenericError( ERR_UNREC_ACTION_TYPE, action, fromType, from );
    }

    // Check that appropriated target exists
    if ( action == "distribution" ) {
        std::map< std::string, CDistribution >::iterator distIt = distributions.find( actionName );
        if ( distIt == distributions.end() ) {
            throw CGenericError( ERR_DISTR_NOT_FOUND, actionName, from );
        }
    }
    else if ( action == "classification" ) {
        std::map< std::string, CClassification >::iterator clsfIt = classifications.find( actionName );
        if ( clsfIt == classifications.end() ) {
            throw CGenericError( ERR_CC_NOT_FOUND, actionName, from );
        }
    }
    else if ( action == "policer" ) {
        std::map< std::string, CPolicer >::iterator policerIt = policers.find( actionName );
        if ( policerIt == policers.end() ) {
            throw CGenericError( ERR_POLICER_NOT_FOUND, actionName, from );
        }
    }
    else if ( action == "replicator" ) {
        std::map< std::string, CReplicator >::iterator replIt = replicators.find( actionName );
        if ( replIt == replicators.end() ) {
            throw CGenericError( ERR_REP_NOT_FOUND, actionName, from );
        }
    }

    if (fromType == "replicator") {
        if ( action == "hashtable"      ||
             action == "classification" ||
             action == "replicator"     ||
             action == "drop" ) {
            throw CGenericError( ERR_TARGET_INVALID, action, from );
        }
    }

    // Check that it is not the same entity
    if ( ( action == fromType ) && ( actionName == from ) ) {
        throw CGenericError( ERR_TARGET_IS_ITSELF, fromType, from );
    }
    return true;
}


bool
CTaskDef::FieldExists( const std::string fullFieldName) const
{
    bool     bRet = false;
    uint32_t bitSize;
    uint32_t bitOffset;

    // Find the protocol
    std::string protocol_name = fullFieldName.substr( 0, fullFieldName.find_last_of( "." ) );
    for ( unsigned int j = 0; j < protocols.size(); ++j ) {
        if ( protocols[j].name == protocol_name ) {   // Found?
            if ( protocols[j].GetFieldProperties(
                    fullFieldName.substr( fullFieldName.find_last_of( "." ) + 1 ),
                    bitSize, bitOffset ) ) {
                bRet = true;
            }
            break;
        }
    }

    return bRet;
}


bool
CTaskDef::GetFieldProperties( const std::string fullFieldName,
                              uint32_t&         bitSize,
                              uint32_t&         bitOffset ) const
{
    bool bRet = false;

    if ( !FieldExists( fullFieldName ) ) {
        throw CGenericError( ERR_UNRECOGNIZED_FIELD, fullFieldName );
    }

    // Find the protocol and get the field's length
    std::string protocol_name = fullFieldName.substr( 0, fullFieldName.find_last_of( "." ) );
    for ( unsigned int j = 0; j < protocols.size(); ++j ) {
        if ( protocols[j].name == protocol_name ) {   // Found?
            if ( protocols[j].GetFieldProperties(
                    fullFieldName.substr( fullFieldName.find_last_of( "." ) + 1 ),
                    bitSize, bitOffset ) ) {
                bRet = true;
            }
            break;
        }
    }

    return bRet;
}


std::string
CTaskDef::getShimNoFromCustom( const std::string protocol_name ) const
{
    std::string result = "";
    unsigned int i;

    for ( i = 0; i < protocols.size(); ++i ) {
        if ( protocols[i].name == protocol_name ) {   // Found?
            break;
        }
    }
    if ( i >= protocols.size() ) {
        return result;
    }

    std::set< std::string > custom_confirms;
    protocols[i].executeCode.getConfirmCustom( custom_confirms );

    if ( custom_confirms.size() != 0 ) {
        result = *custom_confirms.begin();
    }

    return result;
}


/*Gets the size of the protocol's header according to its fields*/
bool
CProtocol::GetHeaderSize( uint32_t& size ) const
{
    uint32_t max=0;
    for (unsigned int i=0; i<fields.size(); i++)
    {
        uint32_t bitsize=0, bitOffset;
        if (!GetFieldProperties(fields[i].name, bitsize, bitOffset))
            return 0;
        if (bitsize+bitOffset > max)
            max = bitsize+bitOffset;
    }
    /*bits to bytes*/
    size = max/8;
    if (max%8 != 0)
        size++;
    return 1;
}

bool
CProtocol::FieldExists( const std::string fieldname) const
{
    std::vector< CField >::const_iterator fieldit;
    for ( fieldit = fields.begin();
          fieldit != fields.end();
          ++fieldit )
    {
        if ( fieldit->name == fieldname )
            return 1;
    }
    return 0;
}

bool
CProtocol::GetFieldProperties( const std::string fieldname,
                               uint32_t&         bitsize,
                               uint32_t&         bitoffset ) const
{
    bool bRet = true;

    bitsize   = 0;
    bitoffset = 0;

    bool     prev_was_bit           = false;
    bool     prev_last_bit_mask_one = false;
    uint32_t prev_size              = 0;

    std::vector< CField >::const_iterator fieldit;
    for ( fieldit = fields.begin();
          fieldit != fields.end();
          ++fieldit ) {

        // Only 'fixed' and 'bit' field definitions are supported
        uint32_t fsize   = std::strtoul( fieldit->size.c_str(), 0, 0 ) * 8;
        uint32_t foffset = 0;

        bool     offset_provided = !fieldit->offset.empty();
        uint32_t offset          = std::strtoul( fieldit->offset.c_str(), 0, 0 );

        if ( fieldit->type == "fixed" ) {
            if ( offset_provided ) {
                bitoffset = offset;
            }
            else {
                bitoffset  += prev_size;
            }
            bitsize     = fsize;
            prev_was_bit = false;
        }
        else if ( fieldit->type == "bit" ) {
            if ( offset_provided ) {
                bitoffset = offset;
            }
            else {
                if ( prev_last_bit_mask_one || !prev_was_bit ) {
                    bitoffset  += prev_size;
                }
            }

            bool isOK =
                findConseqBits( strtoull( fieldit->mask.c_str(), 0, 0 ),
                                bitsize, foffset );
            foffset -= sizeof(uint64_t)*8 - fsize;
            if ( !isOK ) {
                throw CGenericError( ERR_NO_BITS_FOUND );
            }
            prev_was_bit = true;

            /*If the last bit in the mask is one we move to the next byte range*/
            if ( strtoull( fieldit->mask.c_str(), 0, 0 ) & 0x1 )
                prev_last_bit_mask_one = true;
            else
                prev_last_bit_mask_one = false;
        }

        if ( fieldit->name == fieldname ) { // Is the field found?
            if ( prev_was_bit ) {           // Adjust the offset if it is the 'bit'
                bitoffset += foffset;
            }
            break;
        }
        prev_size = fsize;
    }

    if ( fieldit == fields.end() ) {    // Is it the end of the list?
        bRet = false;                   // The field was not found then
    }

    return bRet;
}

/*Return true if the previous protocol could be a layer 4 protocol*/
bool CProtocol::PossibleLayer4() const
{
    return PossibleLayer4(prevType[0]);
}

/*Return true if the specified protocol could be a layer 4 protocol*/
bool CProtocol::PossibleLayer4(ProtoType pt)
{
    if ((CProtocol::ProtocolLayer(pt) == 4) || (pt==PT_NEXT_IP))
        return true;
    return false;
}

/*Returns layer number (2/3/4) for previous protocol and 0 otherwise*/
short CProtocol::ProtocolLayer() const
{
    return ProtocolLayer(prevType[0]);
}

/*Returns layer number (2/3/4) for known protocols and 0 otherwise*/
short CProtocol::ProtocolLayer(ProtoType      pt)
{
    switch (pt) {
        case    PT_ETH:
        case    PT_LLC_SNAP:
        case    PT_VLAN:
        case    PT_PPPOE_PPP:
        case    PT_MPLS:
            return 2;
        case    PT_IPV4:
        case    PT_IPV6:
        case    PT_OTHER_L3:
        case    PT_GRE:
        case    PT_MINENCAP:
            return 3;
        case    PT_TCP:
        case    PT_UDP:
        case    PT_IPSEC_AH:
        case    PT_IPSEC_ESP:
        case    PT_SCTP:
        case    PT_DCCP:
        case    PT_OTHER_L4:
             return 4;
    }
    return 0;
}


CPolicer::CPolicer() : name(""), algorithm(0), color_mode(0),
                       CIR(0), EIR(0), CBS(0), EBS(0), unit(0)
{
}


void CExecuteSection::deleteSection()
{
    uint32_t i, j;
    for (i = 0; i < executeExpressions.size(); i++)
    {
        CExecuteExpression executeExpression = executeExpressions[i]; //executeCode.executeSections[j];
        if (executeExpression.ifInstr.ifTrueValid)
        {
            executeExpression.ifInstr.ifTrue.deleteSection();
            executeExpression.ifInstr.ifTrueValid = false;
        }
        if (executeExpression.ifInstr.ifFalseValid)
        {
            executeExpression.ifInstr.ifFalse.deleteSection();
            executeExpression.ifInstr.ifFalseValid = false;
        }
        if (!executeExpression.switchInstr.cases.empty())
        {
            for (j=0; j < executeExpression.switchInstr.cases.size(); j++)
            {
                if (executeExpression.switchInstr.cases[j].ifCaseValid)
                {
                    executeExpression.switchInstr.cases[j].ifCase.
                        deleteSection();
                    executeExpression.switchInstr.cases[j].ifCaseValid = false;
                }
            }
            if (executeExpression.switchInstr.defaultCaseValid)
            {
                executeExpression.switchInstr.defaultCase.deleteSection();
                executeExpression.switchInstr.defaultCaseValid = false;
            }
        }       /*finished switches*/
    }           /*finished expressions*/
                /*end of function*/
}


void CTaskDef::deleteExecute()
{
    uint32_t i, j;
    for (i = 0; i < protocols.size(); i++)
    {
        CExecuteCode executeCode  = protocols[i].executeCode;
        for (j = 0; j < executeCode.executeSections.size(); j++)
        {
            CExecuteSection executeSection =  executeCode.executeSections[j];
            executeSection.deleteSection();
        }
    }
}


void
CExecuteAction::getConfirmCustom( std::set< std::string >& custom_confirms ) const
{
    if ( !confirmCustom.empty() && ( confirmCustom != "no" ) ) {
        custom_confirms.insert( confirmCustom );
    }
}


void
CExecuteIf::getConfirmCustom( std::set< std::string >& custom_confirms ) const
{
    if ( ifTrueValid ) {
        ifTrue.getConfirmCustom( custom_confirms );
    }
    if ( ifFalseValid ) {
        ifFalse.getConfirmCustom( custom_confirms );
    }
}


void
CExecuteLoop::getConfirmCustom( std::set< std::string >& custom_confirms ) const
{
    loopBody.getConfirmCustom( custom_confirms );
}


void
CExecuteCase::getConfirmCustom( std::set< std::string >& custom_confirms ) const
{
    if ( ifCaseValid ) {
        ifCase.getConfirmCustom( custom_confirms );
    }
}


void
CExecuteSwitch::getConfirmCustom( std::set< std::string >& custom_confirms ) const
{
    for ( unsigned int i = 0; i < cases.size(); ++i ) {
        cases[i].getConfirmCustom( custom_confirms );
    }

    if ( defaultCaseValid ) {
        defaultCase.getConfirmCustom( custom_confirms );
    }
}


void
CExecuteSection::getConfirmCustom( std::set< std::string >& custom_confirms ) const
{
    if ( !confirmCustom.empty() && ( confirmCustom != "no" ) ) {
        custom_confirms.insert( confirmCustom );
    }

    for ( unsigned int i = 0; i < executeExpressions.size(); ++i ) {
        executeExpressions[i].getConfirmCustom( custom_confirms );
    }
}


void
CExecuteExpression::getConfirmCustom( std::set< std::string >& custom_confirms ) const
{
    switch ( type ) {
        case ACTION:
            actionInstr.getConfirmCustom( custom_confirms );
            break;
        case ASSIGN:
            assignInstr.getConfirmCustom( custom_confirms );
            break;
        case IF:
            ifInstr.getConfirmCustom( custom_confirms );
            break;
        case INLINE:
            inlineInstr.getConfirmCustom( custom_confirms );
            break;
        case SWITCH:
            switchInstr.getConfirmCustom( custom_confirms );
            break;
    }
}


void
CExecuteCode::getConfirmCustom( std::set< std::string >& custom_confirms ) const
{
    for ( unsigned int i = 0; i < executeSections.size(); ++i ) {
        executeSections[i].getConfirmCustom( custom_confirms );
    }
}
