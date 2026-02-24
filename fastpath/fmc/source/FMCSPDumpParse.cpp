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
 *  File Name : FMCSPDumpParse.cpp
 *  Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#include "FMCTaskDef.h"


void CTaskDef::dumpSpParsed (std::string path)
{
    std::ofstream outFile;
    outFile.open(path.c_str(), std::ios::out);

    uint32_t i, j;
    for (i = 0; i < protocols.size(); i++)
    {
        CExecuteCode executeCode  = protocols[i].executeCode;
        if (executeCode.executeSections.size())
        {
            outFile << "PROTOCOL " << protocols[i].name << " - "
                    << protocols[i].longname << std::endl;
            for (j = 0; j < executeCode.executeSections.size(); j++)
                executeCode.executeSections[j].dumpSection(outFile, 1);
            outFile << "END PROTOCOL " << protocols[i].name << std::endl <<std::endl;
        }
    }
}

void CExecuteSection::dumpSection(std::ofstream &outFile, uint8_t spaces)
{
    switch(type) {
        case AFTER:   outFile << std::string(spaces, ' ') << "AFTER--" ; break;
        case BEFORE:  outFile << std::string(spaces, ' ') << "BEFORE--"; break;
        case INIT:    outFile << std::string(spaces, ' ') << "INIT--"  ; break;
        case VERIFY:  outFile << std::string(spaces, ' ') << "VERIFY--"; break;
    }
    if (when != "")
        outFile << "  (when - "       << when       << ")";
    if (type!=EMPTY)
        outFile << std::endl;

    for (unsigned int i=0; i < executeExpressions.size(); i++)
    {
        if (executeExpressions[i].type == ACTION)
            executeExpressions[i].actionInstr.dumpAction(outFile, spaces+2);
        else if (executeExpressions[i].type == ASSIGN)
            executeExpressions[i].assignInstr.dumpAssign(outFile, spaces+2);
        else if (executeExpressions[i].type == IF)
            executeExpressions[i].ifInstr.dumpIf        (outFile, spaces+2);
        else if (executeExpressions[i].type == LOOP)
            executeExpressions[i].loopInstr.dumpLoop    (outFile, spaces+2);
        else if (executeExpressions[i].type == INLINE)
            executeExpressions[i].inlineInstr.dumpInline(outFile, spaces+2);
        else if (executeExpressions[i].type == SWITCH)
            executeExpressions[i].switchInstr.dumpSwitch(outFile, spaces+2);
    }
}

void CExecuteAssign::dumpAssign (std::ofstream &outFile, uint8_t spaces)
{
    outFile << std::string(spaces, ' ') << "ASSIGN " << name
            << " " << value;
    if ( !fwoffset.empty() ) {
        outFile << " FWOFFSET " << fwoffset;
    }
    outFile << std::endl;
}

void CExecuteAction::dumpAction (std::ofstream &outFile, uint8_t spaces)
{
    outFile << std::string(spaces, ' ') << "ACTION " << type
            << " " << nextproto << std::endl;
}

void CExecuteSwitch::dumpSwitch (std::ofstream &outFile, uint8_t spaces)
{
    outFile << std::string(spaces, ' ') << "SWITCH " << expr << std::endl;
    for (unsigned int i = 0; i<cases.size(); i++)
        cases[i].dumpCase(outFile, spaces+2);
    if (defaultCaseValid)
    {
        outFile << std::string(spaces+2, ' ') << "DEFAULT " << std::endl;
        defaultCase.dumpSection(outFile, spaces+2);
    }
}

void CExecuteCase::dumpCase (std::ofstream &outFile, uint8_t spaces)
{
    std::string maxVal = "";
    if (maxValue != "" )
        maxVal = "-" + maxValue;
    outFile << std::string(spaces, ' ') << "CASE " << value
            << maxVal << std::endl;
    if (ifCaseValid)
        ifCase.dumpSection(outFile, spaces);
}

void CExecuteIf::dumpIf (std::ofstream &outFile, uint8_t spaces)
{
    outFile << std::string(spaces, ' ') << "IF " << expr << std::endl;
    if (ifTrueValid)
        ifTrue.dumpSection(outFile, spaces);
    if (ifFalseValid)
    {
        outFile << std::string(spaces, ' ') << "ELSE " << std::endl;
        ifFalse.dumpSection(outFile, spaces);
    }
}

void CExecuteLoop::dumpLoop (std::ofstream &outFile, uint8_t spaces)
{
    outFile << std::string(spaces, ' ') << "LOOP " << expr << std::endl;
    loopBody.dumpSection(outFile, spaces);
}

void CExecuteInline::dumpInline (std::ofstream &outFile, uint8_t spaces)
{
    outFile << std::string(spaces, ' ')   << "INLINE_ASM " << std::endl;
    outFile << std::string(spaces+2, ' ') << data << std::endl;
}

