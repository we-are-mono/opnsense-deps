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
 * File Name : FMCSPDumpIR.cpp
 * Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#include "FMCSPIR.h"

void CIR::setDumpIr (std::string path)
{
    if (outFile)
        delete outFile;
    outFile = new std::ofstream;
    outFile->open(path.c_str(), std::ios::out);
}

void CIR::deleteDumpPath ()
{
    if (outFile)
    {
        delete outFile;
        outFile = 0;
    }
}

void CIR::dumpEntireIR () const
{
    CExecuteCode executeCode;
    uint32_t i;
    if (!outFile)
        return;
    for (i = 0; i < protocolsIRs.size(); i++)
        protocolsIRs[i].dumpProtocol (*outFile, 0);
}

void CProtocolIR::dumpProtocol(std::ofstream &outFile, uint8_t spaces) const
{
    outFile << "PROTOCOL " << protocol.name << " - " << protocol.longname
             << std::endl;
    for (unsigned int i = 0; i < statements.size(); i++)
        statements[i].dumpStatement(outFile, spaces+2);
    outFile << "END PROTOCOL " << protocol.name << std::endl << std::endl;
}

void CStatement::dumpStatement (std::ofstream &outFile, uint8_t spaces) const
{
    uint32_t i;
    std::string labelName = "";
    switch(type) {
        case ST_EXPRESSION:
            outFile << std::string(spaces, ' ') << "EXPRESSION - " <<std::endl;
            expr->dumpExpression(outFile, spaces+2);
            break;
        case ST_IFGOTO:
            outFile << std::string(spaces, ' ') << "IFGOTO "
                    << label.name << std::endl;
            expr->dumpExpression(outFile, spaces+2);
            break;
        case ST_IFNGOTO:
            outFile << std::string(spaces, ' ') << "IFNGOTO " << label.name
                    << std::endl;
            expr->dumpExpression(outFile, spaces+2);
            break;
        case ST_INLINE:
            outFile << std::string(spaces, ' ') << "INLINE " << std::endl;
            outFile << std::string(spaces+2, ' ') << text    << std::endl;
            break;
        case ST_LABEL:
            outFile << std::endl << label.name << ":" << std::endl;
            break;
        case ST_GOTO:
            label.isProto? labelName = label.getProtocolOutputName() :
                           labelName = label.name;
            outFile << std::string(spaces, ' ') << "GOTO "
                    << labelName << std::endl;
            break;
        case ST_SWITCH:
            outFile <<  std::string(spaces, ' ');
            outFile << *(switchTable) << std::endl;
            expr->dumpExpression(outFile, spaces+2);
            for (i=0; i<switchTable->values.size(); i++)
            {
                if (i==switchTable->values.size()-1 &&
                    switchTable->lastDefault)
                    outFile << std::string(spaces+2, ' ') << "DEFAULT ";
                else
                    outFile << std::string(spaces+2, ' ') << "CASE ";
                outFile << switchTable->values[i] << ":  " <<
                           switchTable->labels[i].name << std::endl;
            }
            outFile << std::endl;
            break;
        case ST_SECTIONEND:
            outFile << std::string(spaces, ' ') << "END_SECTION" ;
            if (flags.afterSection)
                outFile << " (after)";
            else
                outFile << " (before)";
            outFile << std::endl << std::string(spaces+2, ' ')
                    << "headerSize:" << std::endl;
            expr->dumpExpression(outFile, spaces+2);
            outFile << std::endl;
            break;
    }
    /*if (section.when != "")
        outFile << "  (when) - " << section.when;
    if (section.type!=EMPTY)
        outFile << std::endl; */
}

void CENode::dumpExpression (std::ofstream &outFile, uint8_t spaces) const
{
    std::map< ENodeType, std::string > nodeString;
    std::map <ENodeType, std::string >::iterator iterator;
    nodeString[EASS]             = "EASS";
    nodeString[ESUB]             = "ESUB";
    nodeString[EADD]             = "EADD";
    nodeString[EADDCARRY]        = "EADDCARRY";
    nodeString[EBITAND]          = "EBITAND";
    nodeString[EBITOR]           = "EBITOR";
    nodeString[EBITNOT]          = "EBITNOT";
    nodeString[EXOR]             = "EXOR";
    nodeString[ESHL]             = "ESHL";
    nodeString[ESHLAND]          = "ESHLAND";
    nodeString[ESHR]             = "ESHR";
    nodeString[EEQU]             = "EEQU";
    nodeString[ENOTEQU]          = "ENOTEQU";
    nodeString[EGREATEREQU]      = "EGREATEREQU";
    nodeString[EGREATER]         = "EGREATER";
    nodeString[ELESSEQU]         = "ELESSEQU";
    nodeString[ELESS]            = "ELESS";
    nodeString[ENOTEQU]          = "ENOTEQU";
    nodeString[EOBJREF]          = "EOBJECT";
    nodeString[EINTCONST]        = "EINTCONST";
    nodeString[EREG]             = "EREG";
    nodeString[EOR]              = "EOR";
    nodeString[EAND]             = "EAND";
    nodeString[ENOT]             = "ENOT";
    nodeString[ECHECKSUM]        = "ECHECKSUM";
    nodeString[ECHECKSUM_LOC]    = "ECHECKSUM_LOC";

    iterator = nodeString.find (type);
    if (iterator == nodeString.end())
        outFile << std::string(spaces, ' ') << "UNKNOWN NAME" << std::endl;
    else
        outFile << std::string(spaces, ' ') << nodeString[type] << " (w-" <<
                   weight << ")";

    if (isDyadic())
    {
        outFile << std::endl;
        dumpDiadic(outFile, spaces+3);
    }
    else if (isMonadic())
    {
        outFile << std::endl;
        dumpMonadic(outFile, spaces+3);
    }
    else if (type==EINTCONST)
        dumpInt(outFile, 2);
    else if (type==EOBJREF)
        this->objref->dumpObject(outFile, 2);
    else if (type==EREG)
        dumpReg(outFile, 2);
}

void CENode::dumpInt (std::ofstream &outFile, uint8_t spaces) const
{
    outFile << std::string(spaces, ' ') << "[0x" << std::hex
            << intval << "]" << std::endl;
}

void CENode ::dumpReg (std::ofstream &outFile, uint8_t spaces) const
{
    outFile << std::string(spaces, ' ') << "[" << reg.getName()
                                        << "]" << std::endl;
}

void CENode::dumpDiadic (std::ofstream &outFile, uint8_t spaces) const
{
    dyadic.left->dumpExpression(outFile, spaces);
    dyadic.right->dumpExpression(outFile, spaces);
}

void CENode::dumpMonadic (std::ofstream &outFile, uint8_t spaces) const
{
    monadic->dumpExpression(outFile, spaces);
}

void CObject::dumpObject (std::ofstream &outFile, uint8_t spaces) const
{
    std::string objTypeName;
    std::string midChar;
    if (type == OB_FW)
    {
        objTypeName = "FW";
        midChar = "..";
    }
    else if (type == OB_RA)
    {
        objTypeName = "RA";
        midChar = ":";
    }
    else if (type == OB_WO)
    {
        objTypeName = "WO";
        midChar = ":";
    }
    std::string printName = name.empty() ? "" : name + " - ";
    outFile << std::string(spaces, ' ') << "(" << printName << objTypeName;
    if (type == OB_FW || type == OB_RA)
    {
        outFile << "[" << std::dec << location.start << "," << std::dec <<
                   location.end << "]";
    }
    outFile << ")" << std::endl;
}

std::ofstream & operator<<(std::ofstream &out, const CSwitchTable switchTable)
{
  out << "SWITCH ";
  return out;
}
