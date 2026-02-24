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
 * File Name : FMCSPDumpCode.cpp
 * Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#include "FMCSPCreateCode.h"

void CCode::prepareEntireCode ()
{
    uint32_t i, j;
    asmOutput = ""; codeOutput = "";

    for (i = 0; i < protocolsCode.size(); i++)
    {
        for (j = 0; j < protocolsCode[i].instructions.size(); j++)
        {
            if (j == 0) {
                protocolsCode[i].instructions[j].flags.ifFirstLabel = 1;
            }
            protocolsCode[i].instructions[j].prepareAsm(asmOutput);
            protocolsCode[i].instructions[j].prepareCode(codeOutput);
            asmOutput+= "\n";
            codeOutput += "\n";
        }
        codeOutput  += "\n";
        asmOutput   += "\n";
    }
}

void CInstruction::prepareAsm (std::string &asmOutput)
{
    if ((opcode == LABEL) && !flags.ifFirstLabel)
        asmOutput += "\n";

    switch (opcode)
    {
        case LOAD_BYTES_RA_TO_WR:
        case LOAD_BYTES_PA_TO_WR:
        case LOAD_BITS_FW_TO_WR:
            checkError(3, OT_REG, OT_SHIFT, OT_OBJ);
            asmOutput += operands[0]->getOperandName() + " "
                      +  operands[1]->getOperandName() + "= "
                      +  operands[2]->getOperandName();
            break;
        case LOAD_BITS_IV_TO_WR:
            checkError(4, OT_REG, OT_SHIFT, OT_VAL, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " "
                      +  operands[1]->getOperandName() + "= "
                      +  operands[2]->getOperandName();
            if (operands[3]->getValue())
            {
                std::string hexString = operands[3]->getOperandName();
                std::string decString = hexToDecString(hexString);
                asmOutput += ":" + decString;
            }
            break;
        case ZERO_WR:
            checkError(1, OT_REG);
            asmOutput += "CLR " + operands[0]->getOperandName();
            break;
        case STORE_WR_TO_RA:
            checkError(2, OT_OBJ, OT_REG);
            asmOutput += operands[0]->getOperandName() + " = "
                      +  operands[1]->getOperandName();
            break;
        case STORE_IV_TO_RA:
            checkError(2, OT_OBJ, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " = "
                      +  operands[1]->getOperandName();
            break;
        case ADD_WR_WR_TO_WR:
            checkError(3, OT_REG, OT_REG, OT_REG);
            asmOutput += operands[0]->getOperandName() + " = " +
                         operands[1]->getOperandName() + " + " +
                         operands[2]->getOperandName();
            break;
        case ADD_WR_IV_TO_WR:
            checkError(3, OT_REG, OT_REG, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " = " +
                         operands[1]->getOperandName() + " + " +
                         operands[2]->getOperandName();
            break;
        case SUB_WR_WR_TO_WR:
            checkError(3, OT_REG, OT_REG, OT_REG);
            asmOutput += operands[0]->getOperandName() + " = " +
                         operands[1]->getOperandName() + " - " +
                         operands[2]->getOperandName();
            break;
        case SUB_WR_IV_TO_WR:
            checkError(3, OT_REG, OT_REG, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " = " +
                         operands[1]->getOperandName() + " - " +
                         operands[2]->getOperandName();
            break;
        case SHIFT_LEFT_WR_BY_SV:
            checkError(2, OT_REG, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " << " +
                         operands[1]->getOperandName();
            break;
        case SHIFT_RIGHT_WR_BY_SV:
            checkError(2, OT_REG, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " >> " +
                         operands[1]->getOperandName();
            break;
        case BITWISE_WR_WR_TO_WR:
            checkError(4, OT_REG, OT_REG, OT_BITOP, OT_REG);
            asmOutput += operands[0]->getOperandName() + " = " +
                         operands[1]->getOperandName() + " " +
                         operands[2]->getOperandName() + " " +
                         operands[3]->getOperandName();
            break;
        case BITWISE_WR_IV_TO_WR:
            checkError(4, OT_REG, OT_REG, OT_BITOP, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " = " +
                         operands[1]->getOperandName() + " " +
                         operands[2]->getOperandName() + " " +
                         operands[3]->getOperandName();
            break;
        case CASE1_DJ_WR_TO_WR:
        case CASE2_DJ_WR_TO_WR:
        case CASE2_DC_WR_TO_WR:
        case CASE3_DC_WR_TO_WR:
        case CASE3_DJ_WR_TO_WR:
        case CASE4_DC_WR_TO_WR:
            if      (opcode==CASE1_DJ_WR_TO_WR ||
                     opcode==CASE2_DC_WR_TO_WR)
                checkError(5, OT_REG, OT_HXS, OT_LABEL, OT_HXS, OT_LABEL);
            else if (opcode==CASE2_DJ_WR_TO_WR ||
                     opcode==CASE3_DC_WR_TO_WR)
                checkError(7, OT_REG, OT_HXS, OT_LABEL, OT_HXS, OT_LABEL,
                              OT_HXS, OT_LABEL);
            else if (opcode==CASE3_DJ_WR_TO_WR ||
                     opcode==CASE4_DC_WR_TO_WR)
                checkError(9, OT_REG, OT_HXS, OT_LABEL, OT_HXS, OT_LABEL,
                              OT_HXS, OT_LABEL, OT_HXS, OT_LABEL);
            asmOutput += "JMP ? ";
            for (unsigned int i = 0; i <noperands/2; i++)
            {
                asmOutput += operands[i*2+1]->getOperandName()   + " "
                          +  operands[i*2+2]->getOperandName() + " ";
                if (i<noperands/2-1)
                {
                    if ((i==noperands/2-2) && (
                        opcode==CASE1_DJ_WR_TO_WR ||
                        opcode==CASE2_DJ_WR_TO_WR ||
                        opcode==CASE3_DJ_WR_TO_WR))
                        asmOutput += ":: ";
                    else
                        asmOutput += "| ";
                }
            }
            break;
        case LABEL:
            checkError(1, OT_LABEL);
            asmOutput += operands[0]->getOperandName() += ":";
            break;
        case JMP:
            checkError(2, OT_HXS, OT_LABEL);
            asmOutput += "JMP " + operands[0]->getOperandName()
                      +  " "    + operands[1]->getOperandName();
            break;
        case JMP_PROTOCOL_ETH:
            checkError(1, OT_HXS);
            asmOutput += "JMP NXT_ETH_TYPE";
            break;
        case JMP_PROTOCOL_IP:
            checkError(1, OT_HXS);
            asmOutput += "JMP NXT_IP_PROTO";
            break;
        case OR_IV_LCV:
            checkError(1, OT_VAL);
            asmOutput += "LCV |= " + operands[0]->getOperandName();
            break;
        case CLM:
            checkError(0);
            asmOutput += "CLM";
            break;
        case ADVANCE_HB_BY_WO:
            checkError(1, OT_REG);
            asmOutput += "HB += " + operands[0]->getOperandName();
            break;
        case LOAD_SV_TO_WO:
            checkError(2, OT_REG, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " = " +
                         operands[1]->getOperandName();
            break;
        case ADD_SV_TO_WO:
            checkError(2, OT_REG, OT_VAL);
            asmOutput += operands[0]->getOperandName() + " += " +
                         operands[1]->getOperandName();
            break;
        case ONES_COMP_WR1_TO_WR0:
            checkError(2, OT_REG, OT_REG);
            asmOutput += operands[0]->getOperandName() + " = ONESCOMP(" +
                         operands[0]->getOperandName() + ", " +
                         operands[1]->getOperandName() + ")";
            break;
        case COMPARE_WORKING_REGS:
            checkError(4, OT_LABEL, OT_REG, OT_CONDOP, OT_REG);
            asmOutput += "JMP " + operands[0]->getOperandName() + " IF "
                                + operands[1]->getOperandName() + " "
                                + operands[2]->getOperandName() + " "
                                + operands[3]->getOperandName();
            break;
        case COMPARE_WR0_TO_IV:
            checkError(4, OT_LABEL, OT_REG, OT_CONDOP, OT_VAL);
            asmOutput += "JMP " + operands[0]->getOperandName() + " IF "
                                + operands[1]->getOperandName() + " "
                                + operands[2]->getOperandName() + " "
                                + operands[3]->getOperandName();
            break;
        case ADD_WO_BY_WR:
            checkError(2, OT_REG, OT_REG);
            asmOutput += operands[0]->getOperandName() + " += " +
                         operands[1]->getOperandName();
            break;
        case SET_WO_BY_WR:
            checkError(2, OT_REG, OT_REG);
            asmOutput += operands[0]->getOperandName() + " = " +
                         operands[1]->getOperandName();
            break;
        case INLINE_INSTR:
            checkError(1, OT_TEXT);
            asmOutput += operands[0]->getOperandName();
            break;
        case NOP:
            checkError(0);
            asmOutput += "NOP";
            break;
    }
    /*Add space after 'before' section*/
    if (opcode == ADVANCE_HB_BY_WO)
        asmOutput += "\n";
}

void CInstruction::prepareCode (std::string &codeOutput)
{
    codeOutput += getOpcodeName() + ": "
               +  std::string(25 - getOpcodeName().length(), ' ');
    for (unsigned int i=0; i < noperands; i++)
    {
        std::string temp;
        temp = operands[i]->getOperandName();
        if (temp.length() < 15)
            codeOutput += temp + std::string(15 - temp.length(), ' ');
        else
            codeOutput += temp;
    }
}

void CCode::deletePaths()
{
    if (asmFile)
    {
        delete asmFile;
        asmFile = 0;
    }
    if (codeFile)
    {
        delete codeFile;
        codeFile = 0;
    }
}

void CCode::setDumpCode (std::string path)
{
    if (codeFile)
        delete codeFile;
    codeFile = new std::ofstream;
    codeFile->open(path.c_str(), std::ios::out);
}

void CCode::setDumpAsm (std::string path)
{
    if (asmFile)
        delete asmFile;
    asmFile = new std::ofstream;
    asmFile->open(path.c_str(), std::ios::out);
}

void CCode::dumpAsm ()
{
    if (asmFile)
        *asmFile << asmOutput;
    else throw CGenericError (ERR_INTERNAL_SP_ERROR,
                              "Can't dump assembly code");
}

/*If debugAsm is set we should dump the entire asm process (all the revisions
and not just the final .asm version*/
void CCode::setDebugAsm (bool bool1)
{
    debugAsm = bool1;
}

void CCode::dumpCode ()
{
    if (codeFile)
        *codeFile << codeOutput;
}

std::string CCode::getAsmOutput()
{
    return asmOutput;
}
