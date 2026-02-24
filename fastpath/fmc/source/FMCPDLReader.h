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
 * File Name : FMCPDLReader.h
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#ifndef PDLREADER_H
#define PDLREADER_H

#include <libxml/parser.h>
#include "FMCTaskDef.h"


class CPDLReader {
public:
    CPDLReader();

    void setTaskData( CTaskDef* pTaskData );
    void parseNetPDL( std::string filename );
    void setSoftParse( bool newSoftParse );
    bool getSoftParse () const;

    void parseProtocol     (CProtocol* protocol, xmlNodePtr pNode );
    void parseExecute      (CProtocol* protocol, xmlNodePtr pNode );
    void parseExecuteSection(CExecuteSection* executeSection, xmlNodePtr pNode, bool virtualSection=0);
    void parseExecuteAction(CExecuteAction* executeAction, xmlNodePtr pNode );
    void parseExecuteAssign(CExecuteAssign* executeAssign, xmlNodePtr pNode );
    void parseExecuteCase  (CExecuteCase*   executeCase,   xmlNodePtr pNode );
    void parseExecuteIf    (CExecuteIf*     executeIf,     xmlNodePtr pNode );
    void parseExecuteLoop  (CExecuteLoop*   executeLoop,   xmlNodePtr pNode );
    void parseExecuteInline(CExecuteInline* executeInline, xmlNodePtr pNode );
    void parseExecuteSwitch(CExecuteSwitch* executeSwitch, xmlNodePtr pNode );
    void parseFormat       (CProtocol* protocol, xmlNodePtr pNode );
    void parseBlock        (CProtocol* protocol, xmlNodePtr pNode );
    void parseFields       (CProtocol* protocol, xmlNodePtr pNode );
    void parseField        (CField* field,       xmlNodePtr pNode );

protected:
    static std::string getAttr( xmlNodePtr pNode, const char* attr );
    static void checkUnknownAttr( xmlNodePtr pNode, int num, ... );

private:
    CTaskDef* task;
    bool      softParse;
    CGenericError error;
};

#endif // PDLREADER_H
