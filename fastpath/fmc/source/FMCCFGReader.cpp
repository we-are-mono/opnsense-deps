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
 * File Name : FMCCFGReader.cpp
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#include <cstdlib>
#include <sstream>
#include <libxml/parser.h>

#include "FMCTaskDef.h"
#include "FMCCFGReader.h"
#include "FMCGenericError.h"
#include "FMCUtils.h"

#include "logger.hpp"
using namespace logger;


// Aid function to retrieve XML element's attribute
std::string
CCFGReader::getXMLAttr( xmlNodePtr pNode, const char* attr )
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
CCFGReader::getXMLElement( xmlNodePtr pNode )
{
    std::string ret = "";

    if ( pNode->children != 0 ) {
        if ( pNode->children->content != 0 ) {
            ret = (const char*)pNode->children->content;
        }
    }

    return ret;
}


void
CCFGReader::setTaskData( CTaskDef* pTaskData )
{
    task = pTaskData;
}


/////////////////////////////////////////////////////////////////////////////
// CCFGReader::parseNetPCD
// Process the root node of the NetPCD
/////////////////////////////////////////////////////////////////////////////
void
CCFGReader::parseCfgData( std::string filename )
{
    // LibXML preparations
    xmlInitParser();
    LIBXML_TEST_VERSION;
    xmlSetStructuredErrorFunc( &error, errorFuncHandler );
    xmlKeepBlanksDefault(0);

    // Parse the XML file
    LOG( DBG1 ) << ind(2) << "Start XML parsing of config file: " << filename << std::endl;
    xmlDocPtr doc = xmlParseFile( filename.c_str() );

    if ( !error.getErrorMsg().empty() ) {
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
    if ( xmlStrcmp( cur->name, (const xmlChar *)"cfgdata" ) ) {
        xmlFreeDoc( doc );
        throw CGenericError( ERR_EMPTY_DOCUMENT, filename );
    }

    // Make sure we process the right node
    if ( xmlStrcmp( cur->name, (const xmlChar*)"cfgdata" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)cur->name );
    }

    // Parse children nodes
    cur = cur->xmlChildrenNode;
    while ( 0 != cur ) {
        // config
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"config" ) ) {
            xmlNodePtr engineNode = cur->xmlChildrenNode;
            while ( engineNode ) {
                if ( !xmlStrcmp( engineNode->name, (const xmlChar*)"engine")) {
                    parseEngine( engineNode );
                }
                engineNode = engineNode->next;
            }
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // other
        else {
            CGenericError::printWarning(WARN_UNEXPECTED_NODE,(char*)cur->name);
        }

        cur = cur->next;
    }

    xmlFreeDoc( doc );
    xmlCleanupParser();

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
    LOG( DBG1 ) << std::endl;
}


void
CCFGReader::parseEngine( xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"engine" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'engine' named: '"
                << getXMLAttr( pNode, "name" )
                << "' ... " << std::endl;

    CEngine engine;
    engine.name = getXMLAttr( pNode, "name" );
    if ( engine.name != "fm0" && engine.name != "fm1" ) {
        throw CGenericError( ERR_INVALID_ENGINE_NAME, engine.name );
    }

    std::string offload = stripBlanks( getXMLAttr( pNode, "offload" ) );
    engine.offload_support = std::strtol( offload.c_str(), 0, 0 );

    std::string kg_payload_offset = stripBlanks( getXMLAttr( pNode, "kg_payload" ) );
    engine.kg_payload_offset = std::strtol( kg_payload_offset.c_str(), 0, 0 );

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // port
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"port" ) ) {
            CPort port;
            port.type   = stripBlanks( getXMLAttr( cur, "type" ) );
            port.number = std::strtol( getXMLAttr( cur, "number" ).c_str(),
                                       0, 0 );
            port.policy = stripBlanks( getXMLAttr( cur, "policy" ) );
            port.portid = std::strtol( getXMLAttr( cur, "portid" ).c_str(),
                                       0, 0 );

            LOG( DBG1 ) << "XML entity 'port' found: "
                        << "type: "     << port.type
                        << ", number: " << port.number
                        << ", policy: " << port.policy
                        << std::endl;

            // Find the policy entry
            if ( task->policies.find( port.policy ) == task->policies.end() ) {
                throw CGenericError( ERR_POLICY_NOT_FOUND, port.policy,
                                     port.type, port.number );
            }

            // Add the port to the engine
            if ( !port.type.empty() && !port.policy.empty() ) {
                engine.ports.push_back( port );
            }
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"default_queue1" ) ) {
            std::string text = getXMLElement( cur );
            engine.default_queue1 = std::strtol( text.c_str(), 0, 0 );
        }
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"default_queue2" ) ) {
            std::string text = getXMLElement( cur );
            engine.default_queue2 = std::strtol( text.c_str(), 0, 0 );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ) {
        }
        // text
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"text" ) ) {
        }
        // other
        else
            CGenericError::printWarning(WARN_UNEXPECTED_NODE,(char*)cur->name);


        cur = cur->next;
    }

    if ( !engine.name.empty() && ( 0 != engine.ports.size() ) ) {
        task->engines[engine.name] = engine;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}
