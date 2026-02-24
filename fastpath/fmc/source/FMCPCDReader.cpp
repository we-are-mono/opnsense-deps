/* =====================================================================
 *
 * The MIT License (MIT)
 * Copyright 2009, 2012, Freescale Semiconductor, Inc.
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
 * File Name : FMCPCDReader.cpp
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#include <cstdlib>
#include <sstream>
#include <utility>
#include <string.h>
#include <libxml/parser.h>

#include "FMCTaskDef.h"
#include "FMCPCDReader.h"
#include "FMCGenericError.h"
#include "FMCUtils.h"

#include "logger.hpp"
using namespace logger;

#define FQID_BIT_SIZE 24
#define MAX_SIZE_OF_KEY 56


// Aid function to retrieve XML element's attribute
std::string
CPCDReader::getAttr( xmlNodePtr pNode, const char* attr )
{
   char* pAttr = (char*)xmlGetProp( pNode, (const xmlChar*)attr );
    std::string retStr;
    retStr.clear();

    if (pAttr != NULL)
    {
        char* pTmpAttr = pAttr;
        while (*pTmpAttr != '\0')
        {
            retStr.insert(retStr.end(), *pTmpAttr);
            pTmpAttr++;
        }
        xmlFree(pAttr);
    }

    return (retStr.size() != 0) ? retStr : "";

}


std::string
CPCDReader::getXMLElement( xmlNodePtr pNode )
{
    std::string ret;
    ret.clear();

    if ( pNode->children != 0 ) {
        if ( pNode->children->content != 0 ) {
            char* pAttr = (char*)pNode->children->content;
            if (pAttr != NULL)
            {
                while (*pAttr != '\0')
                {
                    ret.insert(ret.end(), *pAttr);
                    pAttr++;
                }
            }
        }
    }

    return ret;
}


void
CPCDReader::setTaskData( CTaskDef* pTaskData )
{
    task = pTaskData;
}


/////////////////////////////////////////////////////////////////////////////
// CPCDReader::parseNetPCD
// Process the root node of the NetPCD
/////////////////////////////////////////////////////////////////////////////
void
CPCDReader::parseNetPCD( std::string filename )
{
    // LibXML preparations
    xmlInitParser();
    LIBXML_TEST_VERSION;
    xmlSetStructuredErrorFunc( &error, errorFuncHandler );
    xmlKeepBlanksDefault(0);

    // Parse the XML file
    LOG( DBG1 ) << ind(2) << "Start XML parsing of PCD file: " << filename << std::endl;
    xmlDocPtr doc = xmlParseFile( filename.c_str() );

    // In case reader has stored something for reporting
    if ( !error.getErrorMsg().empty() ) {
        // Error message was formatted already
        throw CGenericError( ERR_XML_PARSE_ERROR1, error.getErrorMsg() );
    }

    if ( 0 == doc ) {   // Was the parsing successful?
        throw CGenericError( ERR_CANT_OPEN_FILE, filename );
    }

    // Get the root node
    xmlNodePtr cur = xmlDocGetRootElement( doc );
    if ( 0 == cur ) {   // Is the document empty?
        xmlFreeDoc( doc );
        throw CGenericError( ERR_EMPTY_DOCUMENT, filename );
    }

    // Is the document of the correct type?
    if ( xmlStrcmp( cur->name, (const xmlChar *)"netpcd" ) ) {
        xmlFreeDoc( doc );
        throw CGenericError( ERR_EMPTY_DOCUMENT, filename );
    }

    // Make sure we process the right node
    if ( xmlStrcmp( cur->name, (const xmlChar*)"netpcd" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)cur->name );
    }

    // Get known attributes
    task->pcdname    = getAttr( cur, "name" );
    task->pcdversion = getAttr( cur, "version" );
    task->pcdcreator = getAttr( cur, "creator" );
    task->pcddate    = getAttr( cur, "date" );

    checkUnknownAttr( cur, 6, "name", "version", "creator", "date", "description",
                      "noNamespaceSchemaLocation" );

    // Parse children nodes
    cur = cur->xmlChildrenNode;
    while ( 0 != cur ) {
        // distribution
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"distribution" ) ) {
            CDistribution distribution;
            parseDistribution( &distribution, cur );
            task->distributions[distribution.name] = distribution;
        }
        // classification
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"classification" ) ) {
            // classification
            CClassification classification;
            parseClassification( &classification, cur );
            task->classifications[classification.name] = classification;
        }
        // policer
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"policer" ) ) {
            CPolicer policer;
            parsePolicer( &policer, cur );
            task->policers[policer.name] = policer;
        }
        // policy
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"policy" ) ) {
            CPolicy policy;
            parsePolicy( &policy, cur );
            task->policies[policy.name] = policy;
        }
        // replicator
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"replicator" ) ) {
            CReplicator replicator;
            parseReplicator( &replicator, cur );
            task->replicators[replicator.name] = replicator;
        }
        // VSP
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"vsp" ) ) {
            CVsp vsp;
            parseVsp( &vsp, cur );
            task->vsps[vsp.name] = vsp;
        }
        // manipulations
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"manipulations" ) ) {
            parseManipulations( cur );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );
        }

        cur = cur->next;
    }

    xmlFreeDoc( doc );
    xmlCleanupParser();

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
    LOG( DBG1 ) << std::endl;
}


/////////////////////////////////////////////////////////////////////////////
// CPCDReader::parseAlias
// Process the "alias" node of the NetPCD
/////////////////////////////////////////////////////////////////////////////
void
CPCDReader::parseAlias( xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"alias" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'alias' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
    // Get known attributes
    std::string name     = getAttr( pNode, "name" );
    std::string protoref = getAttr( pNode, "protoref" );
    std::string fieldref = getAttr( pNode, "fieldref" );
    std::string mask     = getAttr( pNode, "mask" );

    checkUnknownAttr(pNode, 4, "name", "protoref", "fieldref", "mask" );

    // Some of the attributes are mandatory
    if ( name.empty() || protoref.empty() || fieldref.empty() ) {
        throw CGenericError( ERR_ALIAS_ATTR_EMPTY, name );
    }

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // comment
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}


/////////////////////////////////////////////////////////////////////////////
// CPCDReader::parseDistribution
// Process the 'distribution' node of the NetPCD
/////////////////////////////////////////////////////////////////////////////
void
CPCDReader::parseDistribution( CDistribution* distribution, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"distribution" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'distribution' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
    distribution->action     = "";
    distribution->actionName = "";

    // Get known attributes
    distribution->name          = getAttr( pNode, "name" );
    distribution->comment       = getAttr( pNode, "comment" );
    distribution->description   = getAttr( pNode, "description" );
	distribution->shared		= false;
    distribution->keyShift      = 0;
    distribution->symmetricHash = false;
    distribution->qcount        = 1;
    distribution->qbase         = 0;
    distribution->bypass        = false;
    distribution->dflt0         = 0;
    distribution->dflt1         = 0;
    distribution->vspbase       = 0;
    distribution->vspdirect     = true;
    distribution->vspshift      = 0;
    distribution->vspoffset     = 0;
    distribution->vspcount      = 0;
    distribution->vspoverride   = false;

    if ( getAttr( pNode, "shared" ) == "true" || getAttr( pNode, "shared" ) == "yes" ) {
        distribution->shared = true;
    }

    checkUnknownAttr( pNode, 4, "name", "comment", "description", "shared" );

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // key
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"key" ) ) {
            distribution->keyShift = std::strtol( getAttr( cur, "shift" ).c_str(), 0, 0 );
            if ( getAttr( cur, "symmetric" ) == "true" ) {
                distribution->symmetricHash = true;
            }
            checkUnknownAttr( cur, 2, "shift", "symmetric" );

            // Parse all fieldrefs inside the key
            xmlNodePtr fr = cur->xmlChildrenNode;
            while ( 0 != fr ) {
                if ( !xmlStrcmp( fr->name, (const xmlChar*)"fieldref" ) ) {
                    CFieldRef fieldref;
                    parseFieldRef( &fieldref, fr );
                    distribution->key.push_back( fieldref );
                }

                if ( !xmlStrcmp( fr->name, (const xmlChar*)"nonheader" ) ) {
                    CNonHeaderEntry nonHeaderEntry;
                    parseNonHeader( &nonHeaderEntry, fr );
                    distribution->nonHeader.push_back(nonHeaderEntry);
                }

                fr = fr->next;
            }
        }
        // protocols
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"protocols" ) ) {
            // Parse all protocolsrefs inside the key
            xmlNodePtr pr = cur->xmlChildrenNode;
            while ( 0 != pr ) {
                if ( !xmlStrcmp( pr->name, (const xmlChar*)"protocolref" ) ) {
                    CProtocolRef protocolref;
                    protocolref.name = getAttr( pr, "name" );
                    LOG( DBG1 ) << "'protocols' contains 'protocolref': '"
                                << protocolref.name
                                << "'" << std::endl;
                    protocolref.opt = getAttr( pr, "opt" );
                    checkUnknownAttr( pr, 2, "name", "opt");

                    // Check that such protocol exists
                    bool protoFound = false;
                    std::vector< CProtocol >::iterator protoIt;
                    for ( protoIt = task->protocols.begin();
                          protoIt != task->protocols.end();
                          ++protoIt ) {
                        if ( protocolref.name == protoIt->name ) {
                            protoFound = true;
                        }
                    }
                    if ( !protoFound ) {
                        throw CGenericError( ERR_PROTO_NOT_FOUND,
                            protocolref.name, distribution->name );
                    }

                    // Add the protocol to the protocols' list
                    // of this distribution
                    distribution->protocols.push_back( protocolref );
                }

                pr = pr->next;
            }
        }
        // queue
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"queue" ) ) {
            // Get the 'count' attribute
            distribution->qcount = std::strtol( getAttr( cur, "count" ).c_str(), 0, 0 );
            // Validate number of the desired queues
            if ( 0 == distribution->qcount ) {
                distribution->qcount = 1;
            }

            IntBits< int > ib( distribution->qcount );
            if ( ( ib.count1s() != 1 ) || ( ib.getFirstSet() > FQID_BIT_SIZE ) ) {
                throw CGenericError( ERR_INCORRECT_QUEUE_SIZE, distribution->name );
            }

            // Get the 'base' attribute
            distribution->qbase = std::strtol( getAttr( cur, "base" ).c_str(), 0, 0 );

            // Get the 'bypass' attribute
            if (getAttr( cur, "bypass" ) == "true" ) {
                distribution->bypass = true;
            }
            
            checkUnknownAttr( cur, 3, "base", "count", "bypass" );
        }
        // combine
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"combine" ) ) {
            checkUnknownAttr( cur, 10, "offset", "size", "default", "validate",
                              "extract_offset", "fieldref", "mask", "portid",
                              "frame", "parser" );

            CCombineEntry combine;
            combine.offsetInFqid = std::strtol(  getAttr( cur, "offset" )        .c_str(), 0, 0 );
            combine.size         = std::strtol(  getAttr( cur, "size" )          .c_str(), 0, 0 );
            combine.default_     = std::strtol(  getAttr( cur, "default" )       .c_str(), 0, 0 );
            combine.validate     = std::strtol(  getAttr( cur, "validate" )      .c_str(), 0, 0 );
            combine.offset       = std::strtoul( getAttr( cur, "extract_offset" ).c_str(), 0, 0 );
            combine.fieldref     = getAttr( cur, "fieldref" );
            combine.kind         = CCombineEntry::FIELD;
            std::string mask     = getAttr( cur, "mask" );
            combine.mask         = std::strtol( mask.c_str(), 0, 0 );
            if ( combine.mask == 0 ) {
                combine.mask = 0xFF;
            }

            if ( !getAttr( cur, "portid" ).empty() ) {
                combine.kind = CCombineEntry::PORTDATA;
                if ( combine.size == 0 ) {
                    combine.size = 1;
                }
            }

            std::string frame = getAttr(cur, "frame");
            if ( !frame.empty() ) {    // Does exist?
                combine.kind = CCombineEntry::FRAME;
                unsigned int offset = std::strtol( frame.c_str(), 0, 0 );
                combine.offset = std::max( offset, combine.offset );
                if ( combine.size == 0 ) {
                    combine.size = 1;
                }
            }

            std::string parser = getAttr(cur, "parser");
            if ( !parser.empty() ) {    // Does exist?
                combine.kind = CCombineEntry::PARSER;
                unsigned int offset = std::strtol( parser.c_str(), 0, 0 );
                combine.offset = std::max( offset, combine.offset );
                if ( combine.size == 0 ) {
                    combine.size = 1;
                }
            }

            distribution->combines.push_back( combine );
        }
        // defaults
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"defaults" ) ) {
            checkUnknownAttr( cur, 2, "private0", "private1" );
            distribution->dflt0     = std::strtoul( getAttr( cur, "private0" ).c_str(), 0, 0 );
            distribution->dflt1     = std::strtoul( getAttr( cur, "private1" ).c_str(), 0, 0 );

            xmlNodePtr pr = cur->xmlChildrenNode;
            while ( 0 != pr ) {
                if ( !xmlStrcmp( pr->name, (const xmlChar*)"default" ) ) {
                    checkUnknownAttr( pr, 2, "type", "select");
                    CDefaultGroup dflt;
                    dflt.type = getAttr( pr, "type" );
                    dflt.select = getAttr( pr, "select" );

                    distribution->defaults.push_back( dflt );
                }

                pr = pr->next;
            }
        }
        // action
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"action" ) ) {
            checkUnknownAttr( cur, 3, "type", "name", "header" );
            distribution->action     = stripBlanks( getAttr( cur, "type" ) );
            distribution->actionName = stripBlanks( getAttr( cur, "name" ) );
            distribution->headerManipName = stripBlanks( getAttr( cur, "header" ) );
            LOG( DBG1 ) << "'action' is: type - "
                        << distribution->action
                        << ", name - "
                        << distribution->actionName
                        << ", manip name - "
                        << distribution->headerManipName
                        << std::endl;
        }
         // vsp
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"vsp" ) ) {
            checkUnknownAttr( pNode, 6, "name", "type", "base", "fqshift", "vspoffset", "vspcount" );
            distribution->vspoverride = true;
            distribution->vspName = stripBlanks( getAttr( cur, "name" ) );

            if (distribution->vspName == "")
            {
                std::string type = getAttr( cur, "type" );
                if (type == "direct")
                {
                    distribution->vspdirect = true;
                }
                else
                {
                    distribution->vspdirect = false;
                }

                distribution->vspbase = std::strtoul( getAttr( cur, "base" ).c_str(), 0, 0 );
                distribution->vspshift = std::strtoul( getAttr( cur, "fqshift" ).c_str(), 0, 0 );
                distribution->vspoffset = std::strtoul( getAttr( cur, "vspoffset" ).c_str(), 0, 0 );
                distribution->vspcount = std::strtoul( getAttr( cur, "vspcount" ).c_str(), 0, 0 );
            }
        }
        // comment/text
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}


void
CPCDReader::parseClassification( CClassification* classification, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"classification" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'classification' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
                
    checkUnknownAttr( pNode, 5, "name", "max", "masks", "statistics", "shared" );

    classification->actionOnMiss            = "";
    classification->actionNameOnMiss        = "";
    classification->vspNameOnMiss           = "";
    classification->fragmentationNameOnMiss = "";
    classification->qbase                   = 0;
    classification->key.field               = false;
    classification->key.header              = false;
    classification->key.hashTable           = false;
    classification->max                     = 0;
    classification->masks                   = false;
    classification->statistics              = "none";
    classification->vspOverrideOnMiss       = false;
    classification->vspBaseOnMiss           = 0;
    classification->statisticsOnMiss        = false;
    classification->shared                  = false;

    for (unsigned int i = 0; i < 10; i++)
        classification->frameLength.push_back(i+1);
    classification->frameLength[9] = 0xFFFF;

    // Get known attributes
    classification->name = getAttr( pNode, "name" );

    classification->max = std::strtol( getAttr( pNode, "max" ).c_str(), 0, 0 );

    classification->statistics = getAttr( pNode, "statistics" );
    if ( classification->statistics == "" ) {
        classification->statistics = "none";
    }

    if ( getAttr( pNode, "masks" ) == "true" || getAttr( pNode, "masks" ) == "yes" ) {
        classification->masks = true;
    }

    if ( getAttr( pNode, "shared" ) == "true" || getAttr( pNode, "shared" ) == "yes" ) {
        classification->shared = true;
    }

    // 'Key presents' flags
    bool nonHeaderFound = false;
    bool fielrefFound   = false;
    bool hashTableFound = false;

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    int entry_index = 0;
    while ( 0 != cur ) {
        // key
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"key" ) ) {
            // Parse all fieldrefs inside the key
            xmlNodePtr fr = cur->xmlChildrenNode;

            while ( 0 != fr ) {
                if ( !xmlStrcmp( fr->name, (const xmlChar*)"fieldref" ) ) {
                    if ( nonHeaderFound )
                    {
                         throw CGenericError( ERR_NH_FIELDREF, classification->name );
                    }

                    if ( hashTableFound )
                    {
                         throw CGenericError( ERR_HT_FIELDREF, classification->name );
                    }

                    CFieldRef fieldref;
                    parseFieldRef( &fieldref, fr );
                    classification->key.fields.push_back( fieldref );
                    classification->key.header = true;
                    classification->key.hashTable = false;
                    if (fieldref.size > 0 || fieldref.offset > 0) {
                        classification->key.field = true;
                    }
                    fielrefFound = true;
                }

                if ( !xmlStrcmp( fr->name, (const xmlChar*)"nonheader" ) ) {
                    if ( fielrefFound )
                    {
                        throw CGenericError( ERR_NH_FIELDREF, classification->name );
                    }

                    if ( nonHeaderFound )
                    {
                        throw CGenericError( ERR_NH_ONE_ENTRY, classification->name );
                    }

                    if ( hashTableFound )
                    {
                        throw CGenericError( ERR_HT_NONHEADER, classification->name );
                    }

                    CNonHeaderEntry nonHeaderEntry;
                    parseNonHeader( &nonHeaderEntry, fr );
                    if (nonHeaderEntry.size > MAX_SIZE_OF_KEY)
                        throw CGenericError( ERR_NH_KEY_SIZE, MAX_SIZE_OF_KEY, classification->name);
                    classification->key.nonHeaderEntry = nonHeaderEntry;
                    classification->key.hashTable = false;
                    classification->key.header = false;
                    classification->key.field = false;
                    nonHeaderFound = true;
                }

                 if ( !xmlStrcmp( fr->name, (const xmlChar*)"hashtable" ) ) {
                    if (fielrefFound)
                    {
                        throw CGenericError( ERR_HT_FIELDREF, classification->name );
                    }

                    if (nonHeaderFound)
                    {
                        throw CGenericError( ERR_HT_NONHEADER, classification->name );
                    }

                     if (hashTableFound)
                    {
                        throw CGenericError( ERR_HT_ONE_ENTRY, classification->name );
                    }

                    CHashTable hashTableEntry;
                    parseHashTable( &hashTableEntry, fr );
                    classification->key.hashTableEntry = hashTableEntry;
                    classification->key.hashTable = true;
                    classification->key.header = false;
                    classification->key.field = false;
                    hashTableFound = true;
                    //Ajust max if hashtable
                    if (classification->max == 0){
                        uint16_t onesCount = 0;
                        uint16_t numOfSets = 0;
                        uint16_t countMask = (uint16_t)(hashTableEntry.mask >> 4);
                        while (countMask)
                        {
                            onesCount++;
                            countMask = (uint16_t)(countMask >> 1);
                        }

                        numOfSets = (uint16_t)(1 << onesCount);
                        classification->max = numOfSets;
                    }
                }

                fr = fr->next;
            }
        }
        // entry
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"entry" ) ) {
            CClassEntry ce;
            memset( ce.data, 0x00, sizeof( ce.data ) );
            memset( ce.mask, 0xFF, sizeof( ce.mask ) );
            ce.qbase = 0x00;
            ce.fragmentationName = "";
            ce.headerManipName   = "";
            ce.action = "";
            ce.actionName = "";
            ce.statistics = false;
            ce.vspBase = 0;
            ce.vspOverride = false;

            // Calculate entry index
            if ( !getAttr( cur, "index" ).empty() ) {
                entry_index = strtol( getAttr( cur, "index" ).c_str(), 0, 0 );
            }
            ce.index = entry_index++;

            xmlNodePtr pr = cur->xmlChildrenNode;
            while ( 0 != pr ) {
                // data
                if ( !xmlStrcmp( pr->name, (const xmlChar*)"data" ) ) {
                    std::string data = stripBlanks( (const char*)pr->children->content );
                    if ( data.length() < 3 || data.substr( 0, 2 ) != "0x" ) {
                        throw CGenericError( ERR_INVALID_ENTRY_DATA,
                                             classification->name );
                    }

                    // Convert data to numeric array
                    data = data.substr( 2 );
                    int index = sizeof( ce.data );
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
                        ce.data[--index] = (char)std::strtol( tmp.c_str(), 0, 0 );
                    }
                }
                // mask
                if ( !xmlStrcmp( pr->name, (const xmlChar*)"mask" ) ) {
                    std::string data = stripBlanks( (const char*)pr->children->content );
                    if ( data.length() < 3 || data.substr( 0, 2 ) != "0x" ) {
                        throw CGenericError( ERR_INVALID_ENTRY_DATA,
                                             classification->name );
                    }

                    // Convert data to numeric array
                    data = data.substr( 2 );
                    int index = sizeof( ce.mask );
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
                        ce.mask[--index] = (char)std::strtol( tmp.c_str(), 0, 0 );
                    }
                }
                // queue
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"queue" ) ) {
                    // Get the 'base' attribute
                    ce.qbase = std::strtol( getAttr( pr, "base" ).c_str(), 0, 0 );
                }
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"fragmentation" ) ) {
                    // Get the 'name' attribute of the fragmentation
                    ce.fragmentationName = stripBlanks( getAttr( pr, "name" ) );
                }
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"header" ) ) {
                    // Get the 'name' attribute of the header manipulation
                    ce.headerManipName = stripBlanks( getAttr( pr, "name" ) );
                }
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"vsp" ) ) {
                    // Get the 'name' attribute of the vsp
                    checkUnknownAttr( cur, 2, "name", "base" );

                    ce.vspOverride = true;
                    ce.vspBase = std::strtoul( getAttr( pr, "base" ).c_str(), 0, 0 );
                    ce.vspName = stripBlanks( getAttr( pr, "name" ) );
                }
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"action" ) ) {
                    ce.action     = stripBlanks( getAttr( pr, "type" ) );
                    ce.actionName = stripBlanks( getAttr( pr, "name" ) );
                    std::string text = stripBlanks( getAttr( pr, "statistics" ) );
                    if (text == "yes" || text == "true" || text == "enable")
                        ce.statistics = true;
                    else
                        ce.statistics = false;

                    LOG( DBG1 ) << "Entry's 'action' is: type - "
                                << ce.action
                                << ", name - "
                                << ce.actionName
                                << ", statistics - "
                                << ce.statistics
                                << std::endl;
                }

                pr = pr->next;
            }

            classification->entries.push_back( ce );
        }
        // action
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"action" ) ) {
            // The condition for this action is "on-miss",
            // but we permit it to be optional, so, no verification for this
            // attribute is done
            checkUnknownAttr( cur, 4, "type", "name", "condition", "statistics" );

            std::string condition = stripBlanks( getAttr( cur, "condition" ) );
            if ( condition != "on-miss" ) {
                CGenericErrorLine::printWarning( WARN_COND_ON_MISS,
                                                 xmlGetLineNo( cur ),
                                                 classification->name );
            }
            classification->actionOnMiss     = stripBlanks( getAttr( cur, "type" ) );
            classification->actionNameOnMiss = stripBlanks( getAttr( cur, "name" ) );

            std::string text = stripBlanks( getAttr( cur, "statistics" ) );
            if (text == "yes" || text == "true" || text == "enable")
                classification->statisticsOnMiss = true;
            else
                classification->statisticsOnMiss = false;

            LOG( DBG1 ) << "'action' on-miss is: type - "
                        << classification->actionOnMiss
                        << ", name - "
                        << classification->actionNameOnMiss
                        << ", statistics - "
                        << classification->statisticsOnMiss
                        << std::endl;
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"framelength" ) ) {
            //Read the frame lenghts
             checkUnknownAttr( cur, 2, "index", "value" );
             unsigned int index = std::strtoul( getAttr( cur, "index" ).c_str(), 0, 0 );
             if (index < 10)
                classification->frameLength[index] = std::strtoul( getAttr( cur, "value" ).c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"vsp" ) ) {
            //VSP for the on-miss case
            checkUnknownAttr( cur, 2, "name", "base" );

            classification->vspOverrideOnMiss = true;
            classification->vspNameOnMiss = getAttr( cur, "name" );
            classification->vspBaseOnMiss = std::strtoul( getAttr( cur, "base" ).c_str(), 0, 0 );
        }
        // fragmentation
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"fragmentation" ) ) {
            checkUnknownAttr( cur, 1, "name" );
            classification->fragmentationNameOnMiss = getAttr( cur, "name" );
        }
        // may-use
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"may-use" ) ) {
            checkUnknownAttr( cur, 0, "" );
            xmlNodePtr pr = cur->xmlChildrenNode;
            while ( 0 != pr ) {
                if ( !xmlStrcmp( pr->name, (const xmlChar*)"action" ) ) {
                    checkUnknownAttr( pr, 3, "type", "name", "condition" );

                    std::string action     = stripBlanks( getAttr( pr, "type" ) );
                    std::string actionName = stripBlanks( getAttr( pr, "name" ) );
                    classification->may_use_action.push_back( action );
                    classification->may_use_actionName.push_back( actionName );
                }

                pr = pr->next;
            }

        }
        // queue
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"queue" ) ) {
            checkUnknownAttr( cur, 1, "base" );
            classification->qbase = std::strtoul( getAttr( cur, "base" ).c_str(), 0, 0 );
        }
        // comment/text
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    // Don't permit classifications without 'key'
    if (!nonHeaderFound && !fielrefFound && !hashTableFound) {
        throw CGenericError( ERR_EMPTY_CLSF_KEY, classification->name );
    }
    
    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}


void
CPCDReader::parseFieldRef( CFieldRef* fieldref, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"fieldref" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'fieldref' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
    checkUnknownAttr( pNode, 4, "name", "header_index", "offset", "size" );

    fieldref->offset = 0;
    fieldref->size = 0;

    // Get known attributes
    fieldref->name            = getAttr( pNode, "name" );
    fieldref->header_index    = getAttr( pNode, "header_index" );
    fieldref->offset          = std::strtoul( getAttr( pNode, "offset" ).c_str(), 0, 0 );
    fieldref->size            = std::strtoul( getAttr( pNode, "size" ).c_str(), 0, 0 );

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // comment
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );
        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}

void
CPCDReader::parseNonHeader( CNonHeaderEntry* nonHeaderEntry, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"nonheader" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'nonheader' with source: '"
                << getAttr( pNode, "source" )
                << "' ... " << std::endl;
    
    checkUnknownAttr( pNode, 5, "source", "action", "offset", "size",
        "ic_index_mask" );

    std::string source = getAttr( pNode, "source" );

    if ( stripBlanks( source ) == "frame_start" ) {
        nonHeaderEntry->source = ES_FROM_FRAME_START;
    }
    else if ( stripBlanks( source ) == "key" ) {
        nonHeaderEntry->source = ES_FROM_KEY;
    }
    else if ( stripBlanks( source ) == "hash" ) {
        nonHeaderEntry->source = ES_FROM_HASH;
    }
    else if ( stripBlanks( source ) == "parser" ) {
        nonHeaderEntry->source = ES_FROM_PARSE_RESULT;
    }
    else if ( stripBlanks( source ) == "fqid" ) {
        nonHeaderEntry->source = ES_FROM_ENQ_FQID;
    }
    else if ( stripBlanks( source ) == "flowid" ) {
        nonHeaderEntry->source = ES_FROM_FLOW_ID;
    }
    else if ( stripBlanks( source ) == "default" ) {
        nonHeaderEntry->source = ES_FROM_DFLT_VALUE;
    }
    else if ( stripBlanks( source ) == "endofparse" ) {
        nonHeaderEntry->source = ES_FROM_CURR_END_OF_PARSE;
    }
    else
    {
        throw CGenericError( ERR_NH_INVALID_SOURCE, source );
    }

    std::string action = getAttr( pNode, "action" );

    if ( stripBlanks( action ) == "indexed_lookup" ) {
        nonHeaderEntry->action = EA_INDEXED_LOOKUP;
        if (nonHeaderEntry->source != ES_FROM_FLOW_ID && nonHeaderEntry->source != ES_FROM_HASH)
        {
            throw CGenericError( ERR_NH_COND_ACTION, action, source );
        }
    }
    else if ( stripBlanks( action ) == "exact_match" ) {
        nonHeaderEntry->action = EA_EXACT_MATCH;
        if (nonHeaderEntry->source != ES_FROM_KEY && nonHeaderEntry->source != ES_FROM_HASH)
        {
            throw CGenericError( ERR_NH_COND_ACTION, action, source );
        }
    }
    else if ( stripBlanks( action ) == "" ) {
        if (nonHeaderEntry->source == ES_FROM_KEY)
        {
            nonHeaderEntry->action = EA_EXACT_MATCH;
        } else if (nonHeaderEntry->source == ES_FROM_FLOW_ID)
        {
            nonHeaderEntry->action = EA_INDEXED_LOOKUP;
        } else if (nonHeaderEntry->source == ES_FROM_HASH)
        {
            throw CGenericError( ERR_NH_COND_ACTION, source );
        } else
        {
            nonHeaderEntry->action = EA_NONE;
        }
    }
    else
    {
        throw CGenericError( ERR_NH_INVALID_ACTION, action );
    }

    nonHeaderEntry->offset     = std::strtoul( getAttr( pNode, "offset" ).c_str(), 0, 0 );
    nonHeaderEntry->size       = std::strtoul( getAttr( pNode, "size" ).c_str(), 0, 0 );
    nonHeaderEntry->icIndxMask = std::strtoul( getAttr( pNode, "ic_index_mask" ).c_str(), 0, 0 );

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;

    return;
}


void
CPCDReader::parseHashTable( CHashTable* hashTable, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"hashtable" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'hashtable'"
                << " ... " << std::endl;
    
    checkUnknownAttr( pNode, 5, "mask", "hashshift", "keysize", "external", "aging" );

    hashTable->mask      = std::strtoul( getAttr( pNode, "mask" ).c_str(), 0, 0 );
    hashTable->hashShift = std::strtoul( getAttr( pNode, "hashshift" ).c_str(), 0, 0 );
    hashTable->keySize   = std::strtoul( getAttr( pNode, "keysize" ).c_str(), 0, 0 );

    std::string extStr   = getAttr( pNode, "external" );
    hashTable->external  = ( extStr == "yes" || extStr == "true" || extStr == "1" );

    std::string agingStr = getAttr( pNode, "aging" );
    hashTable->aging     = ( agingStr == "yes" || agingStr == "true" || agingStr == "1" );

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;

    return;
}


void
CPCDReader::parsePolicer( CPolicer* policer, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"policer" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'policer' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;

    // Set default parameters
    policer->name       = "";
    policer->shared     = false;
    policer->algorithm  = 0;
    policer->color_mode = 0;
    policer->CIR        = 0;
    policer->EIR        = 0;
    policer->CBS        = 0;
    policer->EBS        = 0;
    policer->unit       = 0;

    policer->actionOnRed        = "";
    policer->actionNameOnRed    = "";
    policer->actionOnYellow     = "";
    policer->actionNameOnYellow = "";
    policer->actionOnGreen      = "";
    policer->actionNameOnGreen  = "";

    // Get known attributes
    policer->name = getAttr( pNode, "name" );

    if ( getAttr( pNode, "shared" ) == "true" || getAttr( pNode, "shared" ) == "yes" ) {
        policer->shared = true;
    }

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // policer_algorithm
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"algorithm" ) ) {
            std::string text = getXMLElement( cur );

            if ( stripBlanks( text ) == "rfc2698" ) {
                policer->algorithm = 1;
            }
            else if ( stripBlanks( text ) == "rfc4115" ) {
                policer->algorithm = 2;
            }
            else {
                policer->algorithm = 0;
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"color_mode" ) ) {
            std::string text = getXMLElement( cur );

            if ( stripBlanks( text ) == "color_aware" ) {
                policer->color_mode = 1;
            }
            else {
                policer->color_mode = 0;
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"unit" ) ) {
            std::string text = getXMLElement( cur );

            if ( stripBlanks( text ) == "packet" ) {
                policer->unit = 1;
            }
            else {
                policer->unit = 0;
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"CIR" ) ) {
            std::string text = getXMLElement( cur );
            policer->CIR = std::strtol( text.c_str(), 0, 0 );
        }
        // PIR is a synonim for EIR
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"EIR" )  ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"PIR" ) ) {
            std::string text = getXMLElement( cur );
            policer->EIR = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"CBS" ) ) {
            std::string text = getXMLElement( cur );
            policer->CBS = std::strtol( text.c_str(), 0, 0 );
        }
        // PBS is a synonim for EBS
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"EBS" )  ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"PBS" ) ) {
            std::string text = getXMLElement( cur );
            policer->EBS = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"default_color" ) ) {
            std::string text = getXMLElement( cur );
            policer->dfltColor = text;
            if ( ( text != "red" ) && ( text != "yellow" ) && ( text != "green" ) && ( text != "override" ) ) {
                CGenericErrorLine::printWarning( WARN_UNEXPECTED_COLOR,
                                                 xmlGetLineNo( cur ),
                                                 text, policer->name );
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"action" ) ) {
            checkUnknownAttr( cur, 3, "type", "name", "condition" );

            std::string cond = stripBlanks( getAttr( cur, "condition" ) );
            std::string type = stripBlanks( getAttr( cur, "type" ) );
            std::string name = stripBlanks( getAttr( cur, "name" ) );
            if ( cond == "on-red" ) {
                policer->actionOnRed = type;
                policer->actionNameOnRed = name;
            }
            else if ( cond == "on-yellow" ) {
                policer->actionOnYellow = type;
                policer->actionNameOnYellow = name;
            }
            else  if ( cond == "on-green" ) {
                policer->actionOnGreen = type;
                policer->actionNameOnGreen = name;
            }
            else {
                throw CGenericError( ERR_COND_UNEXPECTED, cond, policer->name );
            }

            LOG( DBG1 ) << "'action' " << cond << " type - "
                        << type
                        << ", name - "
                        << name
                        << std::endl;
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }
    
    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}


void
CPCDReader::parsePolicy( CPolicy* policy, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"policy" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'policy' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
    checkUnknownAttr( pNode, 1, "name" );

    //Set defaults
    policy->name = "";
    policy->reassemblyName = "";

    // Get known attributes
    policy->name = getAttr( pNode, "name" );

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // dist_order
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"dist_order" ) ) {
            parseDistOrder( policy, cur );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"reassembly" ) ) {
            if (strcmp("", policy->reassemblyName.c_str()))
            {
                CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                                 xmlGetLineNo( cur ),
                                                 (char*)cur->name );
            }
            policy->reassemblyName = getAttr( cur, "name" );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}


void
CPCDReader::parseDistOrder( CPolicy* policy, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"dist_order" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'dist_order'"
                << " ... " << std::endl;
    
    checkUnknownAttr( pNode, 0 );

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // action
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"distributionref" ) ) {
            std::string name = getAttr( cur, "name" );
            LOG( DBG1 ) << "'distributionref' found: '"
                        << name << "'" << std::endl;
            policy->dist_order.push_back( name );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}

void
CPCDReader::parseReassembly( CReassembly* reassembly, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"reassembly" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'reassembly' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
    checkUnknownAttr( pNode, 1, "name" );

    // Set default parameters
    reassembly->name                       = "";
    reassembly->sgBpid                     = 0;
    reassembly->maxInProcess               = 0;
    reassembly->dataLiodnOffset            = 0;
    reassembly->dataMemId                  = 0;
    reassembly->ipv4minFragSize            = 0;
    reassembly->ipv6minFragSize            = 256;
    reassembly->timeOutMode                = 0;
    reassembly->fqidForTimeOutFrames       = 0;
    reassembly->numOfFramesPerHashEntry[0] = 1;
    reassembly->numOfFramesPerHashEntry[1] = 1;
    reassembly->timeoutThreshold           = 0;
    reassembly->nonConsistentSpFqid        = 0;

    // Get known attributes
    reassembly->name = getAttr( pNode, "name" );

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"sgBpid" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->sgBpid = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"nonConsistentSpFqid" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->nonConsistentSpFqid = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"maxInProcess" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->maxInProcess = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"dataLiodnOffset" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->dataLiodnOffset = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"dataMemId" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->dataMemId = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"ipv4minFragSize" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->ipv4minFragSize = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"ipv6minFragSize" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->ipv6minFragSize = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"timeOutMode" ) ) {
            std::string text = getXMLElement( cur );
            if ( stripBlanks( text ) == "fragment" ) {
                reassembly->timeOutMode = 1;
            }
            else {
                //frame
                reassembly->timeOutMode = 0;
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"fqidForTimeOutFrames" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->fqidForTimeOutFrames = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"numOfFramesPerHashEntry" ) || !xmlStrcmp( cur->name, (const xmlChar*)"numOfFramesPerHashEntry1" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->numOfFramesPerHashEntry[0] = std::strtol( text.c_str(), 0, 0 );
        }
         else if ( !xmlStrcmp( cur->name, (const xmlChar*)"numOfFramesPerHashEntry2" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->numOfFramesPerHashEntry[1] = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"timeoutThreshold" ) ) {
            std::string text = getXMLElement( cur );
            reassembly->timeoutThreshold = std::strtol( text.c_str(), 0, 0 );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( pNode ),
                                             (char*)cur->name);

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}

void
CPCDReader::parseFragmentation( CFragmentation* fragmentation, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"fragmentation" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'fragmentation' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
     // Set default parameters
    fragmentation->name             = "";
    fragmentation->size             = 0;
    fragmentation->dontFragAction   = 0;
    fragmentation->scratchBpid      = 0;
    fragmentation->sgBpidEn         = false;
    fragmentation->sgBpid           = 0;
    fragmentation->optionsCounterEn = false;

    checkUnknownAttr( pNode, 1, "name" );

    // Get known attributes
    fragmentation->name = getAttr( pNode, "name" );

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"size" ) ) {
            std::string text    = getXMLElement( cur );
            fragmentation->size = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"dontFragAction" ) ) {
            std::string text = getXMLElement( cur );
            if ( stripBlanks( text ) == "continue" ) {
                fragmentation->dontFragAction = 2;
            }
            else if ( stripBlanks( text ) == "fragment" ) {
                fragmentation->dontFragAction = 1;
            }
            else {
                //discard
                fragmentation->dontFragAction = 0;
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"scratchBpid" ) ) {
            std::string text           = getXMLElement( cur );
            fragmentation->scratchBpid = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"optionsCounterEn" ) ) {
            std::string text = getXMLElement( cur );
            if ( stripBlanks( text ) == "yes" || stripBlanks( text ) == "true" || stripBlanks( text ) == "enable") {
                fragmentation->optionsCounterEn = true;
            }
            else
            {
                fragmentation->optionsCounterEn = false;
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"sgBpid" ) ) {
            std::string text        = getXMLElement( cur );
            fragmentation->sgBpidEn = true;
            fragmentation->sgBpid   = std::strtol( text.c_str(), 0, 0 );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}

void
CPCDReader::parseInsert( CInsert* insert, xmlNodePtr pNode )
{
    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"size" ) ) {
            std::string text = getXMLElement( cur );
            insert->size = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"offset" ) ) {
            std::string text = getXMLElement( cur );
            insert->offset = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"replace" ) ) {
            std::string text = getXMLElement( cur );
            if (text == "yes" || text == "true" || text == "\"yes\"" || text == "\"true\"")
                insert->replace = true;
            else
                insert->replace = false;
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"data" ) ) {
                    std::string data = stripBlanks( (const char*)cur->children->content );
                    if ( data.length() < 3 || data.substr( 0, 2 ) != "0x" ) {
                        throw CGenericError( ERR_INVALID_ENTRY_DATA,
                                             "header manipulation insert" );
                    }

                    // Convert data to numeric array
                    data = data.substr( 2 );
                    int index = sizeof( insert->data );
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
                        insert->data[--index] = (char)std::strtol( tmp.c_str(), 0, 0 );
                    }
                }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }
}

void
CPCDReader::parseRemove( CRemove* remove, xmlNodePtr pNode )
{
    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"size" ) ) {
            std::string text = getXMLElement( cur );
            remove->size = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"offset" ) ) {
            std::string text = getXMLElement( cur );
            remove->offset = std::strtol( text.c_str(), 0, 0 );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }
}

void
CPCDReader::parseInsertHeader( CInsertHeader* headerInsert, xmlNodePtr pNode )
{
    checkUnknownAttr( pNode, 2, "type", "header_index" );

    //Update appears as replace in the driver structure but kept it like this to be consistent with the generic insert
    headerInsert->update = false;

    //Size is calculated according to the type of the inserted header, for mpls it is 4
    headerInsert->size = 0;

    //There can be 2 mpls header inserted at the same time but in the xml I have separated them to be easier to give them field by field
    headerInsert->header_index = 1;

    headerInsert->type = getAttr( pNode, "type" );

    if (headerInsert->type == "mpls")
    {
        headerInsert->size = 4;
    }

    headerInsert->header_index = std::strtoul( getAttr( pNode, "header_index" ).c_str(), 0, 0 );
    if (headerInsert->header_index == 0)
        headerInsert->header_index = 1;

    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        //Read the data of the header as raw data
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"data" ) ) {
            std::string data = stripBlanks( (const char*)cur->children->content );
            if ( data.length() < 3 || data.substr( 0, 2 ) != "0x" ) {
                throw CGenericError( ERR_INVALID_ENTRY_DATA,
                                     "header manipulation insert" );
            }

            // Convert data to numeric array
            data = data.substr( 2 );
            int index = sizeof( headerInsert->data );
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
                headerInsert->data[--index] = (char)std::strtol( tmp.c_str(), 0, 0 );
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"field" ) ) {
            CInsertField field;
            field.type = getAttr( cur, "type" );
            field.value = getAttr( cur, "value" );
            
            headerInsert->fields.push_back(field);
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"replace" ) ) {
            std::string text = getXMLElement( cur );
            if (text == "yes" || text == "true" || text == "\"yes\"" || text == "\"true\"")
                headerInsert->update = true;
            else
                headerInsert->update = false;
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );


        cur = cur->next;
    }
}

void
CPCDReader::parseRemoveHeader( CRemoveHeader* headerRemove, xmlNodePtr pNode )
{
    checkUnknownAttr( pNode, 1, "type" );

    headerRemove->type = getAttr( pNode, "type" );
}

void
CPCDReader::parseUpdate( CUpdate* update, xmlNodePtr pNode )
{
    checkUnknownAttr( pNode, 1, "type" );

    update->type = getAttr( pNode, "type" );

    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"field" ) ) {
            CUpdateField field;
            field.type = getAttr( cur, "type" );
            field.value = getAttr( cur, "value" );
            field.index = std::strtoul( getAttr( cur, "index" ).c_str(), 0, 0 );

            field.fill = false;
            field.fillValue = 0;
            field.defVal = false;
            field.vpriDefVal = 0;
            
            std::string text = getAttr( cur, "fill" );
            if (text != "")
            {
                field.fill = true;
                field.fillValue = std::strtoul( field.value.c_str(), 0, 0 );
            }

            text = getAttr( cur, "default" );
            if (text != "")
            {
                field.defVal = true;
                field.vpriDefVal = std::strtoul( field.value.c_str(), 0, 0 );
            }
            
            update->fields.push_back(field);
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );


        cur = cur->next;
    }
}

void
CPCDReader::parseCustom( CCustom* headerCustom, xmlNodePtr pNode )
{
    checkUnknownAttr( pNode, 1, "type" );

    headerCustom->type = getAttr( pNode, "type" );

    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"dechl" ) ) {
            std::string text = getXMLElement( cur );
            if (text == "yes" || text == "true" || text == "\"yes\"" || text == "\"true\"")
                headerCustom->decHl = true;
            else
                headerCustom->decHl = false;
        } else if ( !xmlStrcmp( cur->name, (const xmlChar*)"decttl" ) ) {
            std::string text = getXMLElement( cur );
            if (text == "yes" || text == "true" || text == "\"yes\"" || text == "\"true\"")
                headerCustom->decTtl = true;
            else
                headerCustom->decTtl = false;
        }else if ( !xmlStrcmp( cur->name, (const xmlChar*)"size" ) ) {
            std::string text = getXMLElement( cur );
            headerCustom->size = std::strtol( text.c_str(), 0, 0 );
        }else if ( !xmlStrcmp( cur->name, (const xmlChar*)"data" ) ) {
            std::string text = getXMLElement( cur );
            headerCustom->data = text;
        }else if ( !xmlStrcmp( cur->name, (const xmlChar*)"id" ) || !xmlStrcmp( cur->name, (const xmlChar*)"ipid" ) ) {
            std::string text = getXMLElement( cur );
            headerCustom->updateIpv4Id = true;
            headerCustom->id = std::strtol( text.c_str(), 0, 0 );
        }

        cur = cur->next;
    }
}

void
CPCDReader::parseHeaderManipulation( CHeaderManip* headerManip, xmlNodePtr pNode )
{
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"header" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'header' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
    //Fill the default values.
    headerManip->name              = "";
    headerManip->insert            = false;
    headerManip->remove            = false;
    headerManip->insertHeader      = false;
    headerManip->removeHeader      = false;
    headerManip->update            = false;
    headerManip->custom            = false;
    headerManip->hdrInsert.size    = 0;
    headerManip->hdrInsert.offset  = 0;
    headerManip->hdrInsert.replace = false;
    headerManip->hdrRemove.size    = 0;
    headerManip->hdrRemove.offset  = 0;
    headerManip->hdrInsertHeader[0].type = "";
    headerManip->hdrInsertHeader[0].header_index = 1;
    headerManip->hdrInsertHeader[0].size = 0;
    headerManip->hdrInsertHeader[0].update = false;
    headerManip->hdrInsertHeader[1].type = "";
    headerManip->hdrInsertHeader[1].header_index = 1;
    headerManip->hdrInsertHeader[1].size = 0;
    headerManip->hdrInsertHeader[1].update = false;
    headerManip->hdrRemoveHeader.type = "";
    headerManip->hdrUpdate.type = "";
    headerManip->hdrCustom.type = "ipv4";
    headerManip->hdrCustom.updateIpv4Id = false;
    headerManip->hdrCustom.id = 0;
    headerManip->hdrCustom.decHl = false;
    headerManip->hdrCustom.decTtl = false;
    headerManip->hdrCustom.data = "0x00";
    headerManip->hdrCustom.size = 0;
    headerManip->duplicate = 0;
    memset( headerManip->hdrInsert.data, 0x00, sizeof( headerManip->hdrInsert.data ) );
    memset( headerManip->hdrInsertHeader[0].data, 0x00, sizeof( headerManip->hdrInsertHeader[0].data ) );
    memset( headerManip->hdrInsertHeader[1].data, 0x00, sizeof( headerManip->hdrInsertHeader[1].data ) );

    checkUnknownAttr( pNode, 3, "name", "parse", "duplicate" );

    headerManip->name = getAttr( pNode, "name" );

    std::string parse = getAttr( pNode, "parse" );

    if (parse == "yes" || parse == "true")
        headerManip->parse = true;
    else
        headerManip->parse = false;

    headerManip->duplicate = std::strtoul( getAttr( pNode, "duplicate" ).c_str(), 0, 0 );

     // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // action
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"insert" ) ) {
            headerManip->insert = true;
            parseInsert( &headerManip->hdrInsert, cur );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"remove" ) ) {
            headerManip->remove = true;
            parseRemove( &headerManip->hdrRemove, cur );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"insert_header" ) ) {
            headerManip->insertHeader = true;
            CInsertHeader hdrForInsert;
            parseInsertHeader( &hdrForInsert, cur );

            if (hdrForInsert.header_index >= 1 && hdrForInsert.header_index <= 2)
            {
                headerManip->hdrInsertHeader[hdrForInsert.header_index - 1] = hdrForInsert;
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"remove_header" ) ) {
            headerManip->removeHeader = true;
            parseRemoveHeader( &headerManip->hdrRemoveHeader, cur );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"update" ) ) {
            headerManip->update = true;
            parseUpdate( &headerManip->hdrUpdate, cur );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"custom" ) ) {
            headerManip->custom = true;
            parseCustom( &headerManip->hdrCustom, cur );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"nextmanip" ) ) {
            headerManip->nextManip = stripBlanks( getAttr( cur, "name" ) );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}

void
CPCDReader::parseManipulations( xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"manipulations" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'manipulations'"
                << " ... " << std::endl;
    
    checkUnknownAttr( pNode, 0 );

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // action
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"fragmentation" ) ) {
            CFragmentation fragmentation;
            parseFragmentation( &fragmentation, cur );
            task->fragmentations[fragmentation.name] = fragmentation;
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"reassembly" ) ) {
            CReassembly reassembly;
            parseReassembly( &reassembly, cur );
            task->reassemblies[reassembly.name] = reassembly;
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"header" ) ) {
            CHeaderManip headerManip;
            parseHeaderManipulation( &headerManip, cur );

            if (headerManip.duplicate == 0)
            {
                task->headermanips[headerManip.name] = headerManip;
            }
            else
            {
                std::string origName = headerManip.name;
                for (unsigned int i = 0; i < headerManip.duplicate; i++)
                {
                    std::stringstream ss;
                    ss << origName << "_" << i + 1;
                    headerManip.name = ss.str();
                    task->headermanips[headerManip.name] = headerManip;
                }
            }
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}

void
CPCDReader::parseVsp( CVsp* vsp, xmlNodePtr pNode )
{
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"vsp" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }
    
    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'vsp' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
    checkUnknownAttr( pNode, 7, "name", "type", "base", "fqshift", "vspoffset", "vspcount", "alloc" );

    vsp->name = getAttr( pNode, "name" );

    std::string type = getAttr( pNode, "type" );
    if (type == "indirect")
    {
        vsp->direct = false;
    }
    else
    {
        vsp->direct = true;
    }

    vsp->base      = std::strtoul( getAttr( pNode, "base" ).c_str(),      0, 0 );
    vsp->fqshift   = std::strtoul( getAttr( pNode, "fqshift" ).c_str(),   0, 0 );
    vsp->vspoffset = std::strtoul( getAttr( pNode, "vspoffset" ).c_str(), 0, 0 );
    vsp->vspcount  = std::strtoul( getAttr( pNode, "vspcount" ).c_str(),  0, 0 );

	vsp->vspAlloc = false;
	if (getAttr( pNode, "alloc" ) == "yes")
		vsp->vspAlloc = true;

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}

void
CPCDReader::parseReplicator( CReplicator* replicator, xmlNodePtr pNode )
{
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"replicator" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'replicator' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;
    
    checkUnknownAttr( pNode, 2, "name", "max" );

    replicator->name = getAttr( pNode, "name" );
    replicator->max = std::strtoul( getAttr( pNode, "max" ).c_str(), 0, 0 );
    
    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    int entry_index = 0;
    while ( 0 != cur ) {
        // entry
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"entry" ) ) {
            CReplicatorEntry re;
            re.qbase = 0x00;
            re.fragmentationName = "";
            re.headerManipName   = "";
            re.vspName = "";
            re.action = "";
            re.actionName = "";
            re.vspOverride = false;
            re.vspBase = 0;

            // Calculate entry index
            if ( !getAttr( cur, "index" ).empty() ) {
                entry_index = strtol( getAttr( cur, "index" ).c_str(), 0, 0 );
            }
            re.index = entry_index++;

            xmlNodePtr pr = cur->xmlChildrenNode;
            while ( 0 != pr ) {
                // queue
                if ( !xmlStrcmp( pr->name, (const xmlChar*)"queue" ) ) {
                    // Get the 'base' attribute
                    re.qbase = std::strtol( getAttr( pr, "base" ).c_str(), 0, 0 );
                }
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"fragmentation" ) ) {
                    // Get the 'name' attribute of the fragmentation
                    re.fragmentationName = stripBlanks( getAttr( pr, "name" ) );
                }
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"header" ) ) {
                    // Get the 'name' attribute of the header manipulation
                    re.headerManipName = stripBlanks( getAttr( pr, "name" ) );
                }
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"vsp" ) ) {
                    // Get the 'name' attribute of the vsp
                    re.vspName = stripBlanks( getAttr( pr, "name" ) );
                    checkUnknownAttr( cur, 2, "name", "base" );

                    re.vspOverride = true;
                    re.vspBase = std::strtoul( getAttr( pr, "base" ).c_str(), 0, 0 );
                }
                else if ( !xmlStrcmp( pr->name, (const xmlChar*)"action" ) ) {
                    re.action     = stripBlanks( getAttr( pr, "type" ) );
                    re.actionName = stripBlanks( getAttr( pr, "name" ) );
                }

                pr = pr->next;
            }

            replicator->entries.push_back( re );
        }
        // may-use
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"may-use" ) ) {
            checkUnknownAttr( cur, 0, "" );
            xmlNodePtr pr = cur->xmlChildrenNode;
            while ( 0 != pr ) {
                if ( !xmlStrcmp( pr->name, (const xmlChar*)"action" ) ) {
                    checkUnknownAttr( pr, 3, "type", "name", "condition" );

                    std::string action     = stripBlanks( getAttr( pr, "type" ) );
                    std::string actionName = stripBlanks( getAttr( pr, "name" ) );
                    replicator->may_use_action.push_back( action );
                    replicator->may_use_actionName.push_back( actionName );
                }

                pr = pr->next;
            }

        }
         // comment/text
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo( cur ),
                                             (char*)cur->name );

        cur = cur->next;
    }

    if (replicator->entries.size() > replicator->max)
    {
        replicator->max = replicator->entries.size();
    }

    if (replicator->max < 2)
    {
        replicator->max = 2;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}

void CPCDReader::checkUnknownAttr ( xmlNodePtr pNode, int num, ...)
{
    va_list listPointer;
    _xmlAttr * attributes = pNode->properties;
    std::set <const xmlChar*, MyXMLCharComparator> allowedAttr;

    va_start(listPointer, num);
    for(signed int i = 0; i < num; i++ )
        allowedAttr.insert((const xmlChar*)va_arg(listPointer, const xmlChar*));
    va_end(listPointer);

    if (allowedAttr.empty())
        return;

    while (pNode->properties)
    {
        if (allowedAttr.find(pNode->properties->name) ==
            allowedAttr.end())
            CGenericErrorLine::printWarning( WARN_UNKNOWN_ATTRIBUTE,
                xmlGetLineNo(pNode), (char*)pNode->properties->name,
                (char*)pNode->name );
        pNode->properties=pNode->properties->next;
    }
    pNode->properties=attributes;
}
