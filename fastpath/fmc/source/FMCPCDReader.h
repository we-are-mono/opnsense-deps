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
 * File Name : FMCPCDReader.h
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#ifndef PCDREADER_H
#define PCDREADER_H

#include <libxml/parser.h>
#include "FMCTaskDef.h"

class CPCDReader {
public:
    void setTaskData( CTaskDef* pTaskData );
    void parseNetPCD( std::string filename );

    void parseAlias( xmlNodePtr pNode );
    void parseDistribution( CDistribution* distribution, xmlNodePtr pNode );
    void parseClassification( CClassification* classification, xmlNodePtr pNode );
    void parseFieldRef( CFieldRef* fieldref, xmlNodePtr pNode );
    void parseNonHeader( CNonHeaderEntry* nonHeaderEntry, xmlNodePtr pNode );
    void parseHashTable( CHashTable* hashTable, xmlNodePtr pNode );
    void parsePolicy( CPolicy* policy, xmlNodePtr pNode );
    void parsePolicer( CPolicer* policer, xmlNodePtr pNode );
    void parseDistOrder( CPolicy* policy, xmlNodePtr pNode );
    void parseManipulations( xmlNodePtr pNode );
    void parseFragmentation( CFragmentation* fragmentation, xmlNodePtr pNode );
    void parseReassembly( CReassembly* reassembly, xmlNodePtr pNode );
    void parseHeaderManipulation( CHeaderManip* headerManip, xmlNodePtr pNode );
    void parseInsert( CInsert* insert, xmlNodePtr pNode );
    void parseRemove( CRemove* remove, xmlNodePtr pNode );

    void parseInsertHeader( CInsertHeader* headerInsert, xmlNodePtr pNode );
    void parseRemoveHeader( CRemoveHeader* headerRemove, xmlNodePtr pNode );
    void parseUpdate( CUpdate* update, xmlNodePtr pNode );
    void parseCustom( CCustom* update, xmlNodePtr pNode );

    void parseReplicator( CReplicator* replicator, xmlNodePtr pNode );
    void parseVsp( CVsp* vsp, xmlNodePtr pNode );

protected:
    static std::string getAttr( xmlNodePtr pNode, const char* attr );
    static std::string getXMLElement( xmlNodePtr pNode );
    static void checkUnknownAttr( xmlNodePtr pNode, int num, ... );

private:
    CTaskDef* task;
    CGenericError error;
};

#endif // PCDREADER_H
