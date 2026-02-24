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
 * File Name : FMCPDLReader.cpp
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#include "FMCPDLReader.h"

#include "logger.hpp"
using namespace logger;


CPDLReader::CPDLReader ()
{
    softParse = false;
}

void CPDLReader::setSoftParse( bool newSoftParse )
{
    softParse = newSoftParse;
}

bool CPDLReader::getSoftParse() const
{
    return softParse;
}


// Aid function to retrieve XML element's attribute
std::string
CPDLReader::getAttr( xmlNodePtr pNode, const char* attr )
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


void CPDLReader::checkUnknownAttr ( xmlNodePtr pNode, int num, ...)
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
            CGenericErrorLine::printWarning(WARN_UNKNOWN_ATTRIBUTE,
                xmlGetLineNo(pNode), (char*)pNode->properties->name,
                (char*)pNode->name);
        pNode->properties=pNode->properties->next;
    }
    pNode->properties=attributes;
}


void
CPDLReader::setTaskData( CTaskDef* pTaskData )
{
    task = pTaskData;
}


/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseNetPDL
// Process the root node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseNetPDL( std::string filename )
{
    // LibXML preparations
    xmlInitParser();
    // init line numbers - critical for Linux
    xmlLineNumbersDefault(1);

    LIBXML_TEST_VERSION;
    xmlSetStructuredErrorFunc( &error, errorFuncHandler );
    xmlKeepBlanksDefault(0);

    // Parse the XML file
    LOG( DBG1 ) << ind(2) << "Start XML parsing of NetPDL file: " << filename << std::endl;
    xmlDocPtr doc = xmlParseFile( filename.c_str() );

    // In case reader has stored something for reporting
    if ( !error.getErrorMsg().empty() ) {
        throw CGenericError( ERR_XML_PARSE_ERROR1, error.getErrorMsg() );
    }

    if ( 0 == doc ) {   // Was the parsing successful?
        throw CGenericError(ERR_CANT_OPEN_FILE, filename );
    }

    // Get the root node
    xmlNodePtr cur = xmlDocGetRootElement( doc );
    if ( 0 == cur ) {   // Is the document empty?
        xmlFreeDoc( doc );
        throw CGenericError(ERR_EMPTY_DOCUMENT, filename );
    }

    // Is the document of the correct type?
    if ( xmlStrcmp( cur->name, (const xmlChar *)"netpdl" ) ) {
        xmlFreeDoc( doc );
        throw CGenericError( ERR_EMPTY_DOCUMENT, filename );
    }

    // Make sure we process the right node
    if ( xmlStrcmp( cur->name, (const xmlChar*)"netpdl" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)cur->name );
    }

    // Get known attributes
    task->name    = getAttr( cur, "name" );
    task->version = getAttr( cur, "version" );
    task->creator = getAttr( cur, "creator" );
    task->date    = getAttr( cur, "date" );

    checkUnknownAttr( cur, 5, "name", "version", "creator", "date", "description" );

    // Parse children nodes
    cur = cur->xmlChildrenNode;
    while ( 0 != cur ) {
        // protocol
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"protocol" ) ) {
            CProtocol protocol;
            parseProtocol( &protocol, cur );
            task->protocols.push_back( protocol );
        }
        // visualization
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"visualization" ) ) {
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }

        cur = cur->next;
    }

    xmlFreeDoc( doc );
    xmlCleanupParser();

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
    LOG( DBG1 ) << std::endl;
}


/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseProtocol
// Process the 'protocol' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseProtocol( CProtocol* protocol, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"protocol" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'protocol' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;

    // Get known attributes
    protocol->name            = getAttr( pNode, "name" );
    protocol->longname        = getAttr( pNode, "longname" );
    protocol->showsumtemplate = getAttr( pNode, "showsumtemplate" );
    protocol->comment         = getAttr( pNode, "comment" );
    protocol->description     = getAttr( pNode, "description" );
    protocol->line            = xmlGetLineNo(pNode);

    checkUnknownAttr(pNode, 6, "name", "longname", "showsumtemplate",
                               "comment", "description", "prevproto");

    // In softparse get prevproto
    if (getSoftParse())
    {
        std::string prevprotonames = getAttr( pNode, "prevproto" );
        if (prevprotonames == "")
            throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, xmlGetLineNo(pNode),
                                    "prevproto", "protocol", protocol->name);

        LOG( DBG1 ) << "The protocol is attached to 'prevproto': "
                    << prevprotonames
                    << std::endl;

        // If several protocols are given, split them
        std::basic_string <char>::size_type comma_place = prevprotonames.find( ',' );
        while ( comma_place != std::string::npos ) {
            std::string extracted_name = stripBlanks( prevprotonames.substr( 0, comma_place ) );
            if (extracted_name == "")
                throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, xmlGetLineNo(pNode),
                                        "prevproto", "protocol", protocol->name);

            protocol->prevproto.push_back( extracted_name );
            prevprotonames = prevprotonames.substr( comma_place + 1, std::string::npos );

            comma_place = prevprotonames.find( ',' );
        }
        protocol->prevproto.push_back( stripBlanks( prevprotonames ) );
    }

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // execute-code
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"execute-code" ) ) {
            if (getSoftParse())
                parseExecute (protocol, cur);
        }
        // format
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"format" ) ) {
            parseFormat( protocol, cur );
        }
        // encapsulation
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"encapsulation" ) ) {
        }
        // visualization
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"visualization" ) ) {
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning( WARN_UNEXPECTED_NODE,
                                             xmlGetLineNo(cur), (char*)cur->name );
        }

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}


/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseFormat
// Process the 'format' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseFormat( CProtocol* protocol, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"format" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    checkUnknownAttr(pNode, 0);

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // fields
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"fields" ) ) {
            parseFields( protocol, cur );
        }
        // block
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"block" ) ) {
            // Don't process 'block' outside of 'fields'
            // parseBlock( protocol, cur );
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" ) ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }

        cur = cur->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseBlock
// Process the 'block' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseBlock( CProtocol* protocol, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"block" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // field
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"field" ) ) {
            CField field;
            parseField( &field, cur );
            protocol->fields.push_back( field );
        }
        // block
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"block" ) ) {
            parseBlock( protocol, cur );
        }
        // loop
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"loop" ) ) {
        }
        // switch
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"switch" ) ) {
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text"    )){
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }

        cur = cur->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseFields
// Process the 'fields' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseFields( CProtocol* protocol, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"fields" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    checkUnknownAttr(pNode, 0);

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // field
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"field" ) ) {
            CField field;
            parseField( &field, cur );
            protocol->fields.push_back( field );
        }
        // block
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"block" ) ) {
            parseBlock( protocol, cur );
        }
        // switch
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"switch" ) ) {
        }
        // if
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"if" ) ) {
        }
        // loop
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"loop" ) ) {
        }
        // includeblk
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"includeblk" ) ) {
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }

        cur = cur->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseField
// Process the 'field' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseField( CField* field, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"field" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    LOG( DBG1 ) << ind(2) << "Parsing of XML node 'field' named: '"
                << getAttr( pNode, "name" )
                << "' ... " << std::endl;

    // Get known attributes
    field->type         = getAttr( pNode, "type" );
    field->name         = getAttr( pNode, "name" );
    field->size         = getAttr( pNode, "size" );
    field->longname     = getAttr( pNode, "longname" );
    field->showtemplate = getAttr( pNode, "showtemplate" );
    field->mask         = getAttr( pNode, "mask" );
    field->plugin       = getAttr( pNode, "plugin" );
    field->expr         = getAttr( pNode, "expr" );
    field->description  = getAttr( pNode, "description" );
    field->endtoken     = getAttr( pNode, "endtoken" );
    field->begintoken   = getAttr( pNode, "begintoken" );
    field->endregex     = getAttr( pNode, "endregex" );
    field->endoffset    = getAttr( pNode, "endoffset" );
    field->beginregex   = getAttr( pNode, "beginregex" );
    field->beginoffset  = getAttr( pNode, "beginoffset" );
    field->bigendian    = getAttr( pNode, "bigendian" );
    field->comment      = getAttr( pNode, "comment" );
    field->align        = getAttr( pNode, "align" );
    field->enddiscard   = getAttr( pNode, "enddiscard" );

    /*Check for errors*/
    if (field->type == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, xmlGetLineNo(pNode),
                                "type", "field", field->name);
    if (field->size == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, xmlGetLineNo(pNode),
                                "size", "field", field->name);
    if (field->name == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, xmlGetLineNo(pNode),
                                "name", "field");
    if (field->type != "bit" && field->type != "fixed")
        throw CGenericErrorLine( ERR_FIELD_NOT_BIT_FIXED, xmlGetLineNo(pNode),
                                  field->type);
    if (field->type == "bit" && field->mask== "" )
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, xmlGetLineNo(pNode),
                                "mask", "bit field", field->name);
    uint64_t fieldSize;
    stringToInt(field->size, fieldSize);
    if (field->type == "bit" &&  fieldSize> 8)
        throw CGenericErrorLine(ERR_BIT_FIELD_LARGER8, xmlGetLineNo(pNode),
                                field->name);

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // fields
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"field" ) ) {
        }
        // block
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"block" ) ) {
        }
        // switch
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"switch" ) ) {
        }
        // if
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"if" ) ) {
        }
        // loop
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"loop" ) ) {
        }
        // includeblk
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"includeblk" ) ) {
        }
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" ) ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }

        cur = cur->next;
    }

    LOG( DBG1 ) << ind(-2) << "Done" << std::endl;
}


/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecute
// Process the 'execute_code' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecute( CProtocol* protocol, xmlNodePtr pNode )
{
    // Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"execute-code" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    checkUnknownAttr(pNode, 0);

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // init
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"init" ) )
            CGenericError::printWarning(WARN_UNSUPPORTED, (char*)cur->name);
        // before
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"before" ) ) {
            CExecuteSection executeSection(BEFORE);
            parseExecuteSection (&executeSection, cur);
            protocol->executeCode.executeSections.push_back (executeSection);
        }
        // after
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"after" ) ) {
            CExecuteSection executeSection (AFTER);
            parseExecuteSection (&executeSection, cur);
            protocol->executeCode.executeSections.push_back (executeSection);
        }
        // verify
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"verify" ) )
            CGenericError::printWarning (WARN_UNSUPPORTED, (char*)cur->name);
        // comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }
        cur = cur->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecuteSection
// Process the 'before, after, verify, init' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecuteSection( CExecuteSection* executeSection, xmlNodePtr pNode, bool virtualSection)
{
    if (!virtualSection)
    {
        executeSection->line            = xmlGetLineNo(pNode);
        executeSection->when            = getAttr(pNode, "when" );
        executeSection->confirm         = getAttr(pNode, "confirm" );
        executeSection->confirmCustom   = getAttr(pNode, "confirmcustom" );

        checkUnknownAttr(pNode, 3, "when", "confirm", "confirmcustom");

    }

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // assign
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"assign-variable" ) ) {
            CExecuteExpression executeExpression(ASSIGN);
            parseExecuteAssign (&executeExpression.assignInstr, cur);
            executeSection->executeExpressions.push_back (executeExpression);
        }
        // action
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"action" ) ) {
            CExecuteExpression executeExpression(ACTION);
            parseExecuteAction (&executeExpression.actionInstr, cur);
            executeSection->executeExpressions.push_back (executeExpression);
        }
        // if
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"if" ) ) {
            CExecuteExpression executeExpression(IF);
            parseExecuteIf (&executeExpression.ifInstr, cur);
            executeSection->executeExpressions.push_back (executeExpression);
        }
        // loop
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"loop" ) ) {
            CExecuteExpression executeExpression(LOOP);
            parseExecuteLoop (&executeExpression.loopInstr, cur);
            executeSection->executeExpressions.push_back (executeExpression);
        }
        // inline
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"inline" ) ) {
            CExecuteExpression executeExpression(INLINE);
            parseExecuteInline (&executeExpression.inlineInstr, cur);
            executeSection->executeExpressions.push_back (executeExpression);
        }
        //switch
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"switch" ) ) {
            CExecuteExpression executeExpression(SWITCH);
            parseExecuteSwitch (&executeExpression.switchInstr, cur);
            executeSection->executeExpressions.push_back (executeExpression);
        }
        // comment/description/data/author
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" )     ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"description" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"data" )        ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"author" )      ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }
        cur = cur->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecuteAssign
// Process the 'assign-variable' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecuteAssign( CExecuteAssign* executeAssign, xmlNodePtr pNode )
{
//     Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"assign-variable" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    executeAssign->name     = getAttr(pNode, "name" );
    executeAssign->value    = getAttr(pNode, "value" );
    executeAssign->fwoffset = getAttr(pNode, "fwoffset" );
    executeAssign->line     = xmlGetLineNo(pNode);

    checkUnknownAttr(pNode, 3, "name", "value", "fwoffset");

    if (executeAssign->name == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeAssign->line,
                                "name", "assign-variable");
    if (executeAssign->value == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeAssign->line,
                                "value","assign-variable",executeAssign->name);
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecuteIf
// Process the 'if' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecuteIf( CExecuteIf* executeIf, xmlNodePtr pNode )
{
//     Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"if" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    executeIf->expr   = getAttr(pNode, "expr" );
    executeIf->line   = xmlGetLineNo(pNode);

    checkUnknownAttr(pNode, 1, "expr");

    if (executeIf->expr == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeIf->line,
                                "expr", "if");

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // false
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"if-false" ) ) {
            CExecuteSection executeSection(EMPTY);
            parseExecuteSection (&executeSection, cur, 1);
            executeIf->ifFalse      = executeSection;
            executeIf->ifFalseValid = true;
        }
        // true
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"if-true" ) ) {
            CExecuteSection executeSection(EMPTY);
            parseExecuteSection (&executeSection, cur, 1);
            executeIf->ifTrue      = executeSection;
            executeIf->ifTrueValid = true;
        }
        //comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }
        cur = cur->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecuteLoop
// Process the 'loop' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecuteLoop( CExecuteLoop* executeLoop, xmlNodePtr pNode )
{
//     Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"loop" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    executeLoop->type = getAttr(pNode, "type" );
    executeLoop->expr = getAttr(pNode, "expr" );
    executeLoop->line = xmlGetLineNo(pNode);

    checkUnknownAttr(pNode, 2, "expr", "type");

    if (executeLoop->type == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeLoop->line,
                                "type", "loop");

    if (executeLoop->type != "while")
        throw CGenericErrorLine(ERR_UNSUPPORTED_LOOP_TYPE, executeLoop->line,
                                executeLoop->type);

    if (executeLoop->expr == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeLoop->line,
                                "expr", "loop");

    // Parse children nodes
    CExecuteSection executeSection(EMPTY);
    parseExecuteSection (&executeSection, pNode, 1);
    executeLoop->loopBody = executeSection;
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecuteInline
// Process the 'inline' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecuteInline(CExecuteInline* executeInline, xmlNodePtr pNode )
{
//     Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"inline" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    executeInline->line   = xmlGetLineNo(pNode);
    executeInline->data   = getAttr(pNode, "data" );

    checkUnknownAttr(pNode, 1, "data");

    /* This code can be used if we decide that it's more convenient to
       read inline asm for the xml content instead of attribute
    if (executeInline->data == "")
    {
        if ((char*)xmlNodeGetContent(pNode))
                executeInline->data = ((char*)xmlNodeGetContent(pNode));
    }*/
    if (executeInline->data == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeInline->line,
                                "data", "inline");

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        //comment
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }
        cur = cur->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecuteSwitch
// Process the 'switch' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecuteSwitch( CExecuteSwitch* executeSwitch, xmlNodePtr pNode )
{
//     Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"switch" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    executeSwitch->expr   = getAttr(pNode, "expr" );
    executeSwitch->line   = xmlGetLineNo(pNode);

    checkUnknownAttr(pNode, 1, "expr");

    if (executeSwitch->expr == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeSwitch->line,
                                "expr", "switch");

    // Parse children nodes
    xmlNodePtr cur = pNode->xmlChildrenNode;
    while ( 0 != cur ) {
        // case
        if ( !xmlStrcmp( cur->name, (const xmlChar*)"case" ) ) {
            if (executeSwitch->defaultCaseValid)
                throw CGenericErrorLine(ERR_SWITCH_EARLY_DEFAULT,
                                    executeSwitch->line);
            CExecuteCase executeCase;
            parseExecuteCase (&executeCase, cur);
            executeSwitch->cases.push_back (executeCase);
        }
        //default
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"default" ) ) {
            CExecuteSection executeSection(EMPTY);
            parseExecuteSection (&executeSection, cur, 1);
            executeSwitch->defaultCase      = executeSection;
            executeSwitch->defaultCaseValid = true;
        }
        //comment
        else if ( !xmlStrcmp( cur->name, (const xmlChar*)"comment" ) ||
                  !xmlStrcmp( cur->name, (const xmlChar*)"text" )  ) {
        }
        // other
        else {
            CGenericErrorLine::printWarning(WARN_UNEXPECTED_NODE,
                                          xmlGetLineNo(cur), (char*)cur->name);
        }
        cur = cur->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecuteCase
// Process the 'case' node, inside 'switch' in NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecuteCase( CExecuteCase* executeCase, xmlNodePtr pNode )
{
//     Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"case" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    executeCase->value      = getAttr(pNode, "value" );
    executeCase->maxValue   = getAttr(pNode, "maxvalue" );
    executeCase->line       = xmlGetLineNo(pNode);

    checkUnknownAttr(pNode, 2, "value", "maxvalue");

    if (executeCase->value == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeCase->line,
                                "value", "case");

    /*Inside the case we have regular code just like any other section*/
    CExecuteSection executeSection(EMPTY);
    parseExecuteSection (&executeSection, pNode, 1);
    executeCase->ifCase      = executeSection;
    executeCase->ifCaseValid = true;
}


/////////////////////////////////////////////////////////////////////////////
// CPDLReader::parseExecuteAssign
// Process the 'action' node of the NetPDL
/////////////////////////////////////////////////////////////////////////////
void
CPDLReader::parseExecuteAction( CExecuteAction* executeAction, xmlNodePtr pNode )
{
//     Make sure we process the right node
    if ( xmlStrcmp( pNode->name, (const xmlChar*)"action" ) ) {
        throw CGenericError( ERR_WRONG_TYPE1, (char*)pNode->name );
    }

    executeAction->type             = getAttr(pNode, "type" );
    executeAction->advance          = getAttr(pNode, "advance" );
    executeAction->confirm          = getAttr(pNode, "confirm" );
    executeAction->confirmCustom    = getAttr(pNode, "confirmcustom" );
    executeAction->nextproto        = getAttr(pNode, "nextproto" );
    executeAction->line             = xmlGetLineNo(pNode);

    checkUnknownAttr(pNode, 5, "type", "advance", "confirm", "confirmcustom",
                               "nextproto");

    if (executeAction->type == "")
        throw CGenericErrorLine(ERR_MISSING_ATTRIBUTE, executeAction->line,
                                "type", "action");
}

