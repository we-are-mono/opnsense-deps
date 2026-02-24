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
 * File Name : FMCSPReviseCode.cpp
 * Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#include "FMCSPCreateCode.h"

void CCode::reviseEntireCode ()
{
    for (unsigned int i = 0; i < protocolsCode.size(); i++)
        protocolsCode[i].reviseProtocolCode();
}

void CProtocolCode::reviseProtocolCode()
{
    bool changed = 1;
    while (changed == 1)
    {
        changed = 0;
        changed = removeDoubleDefine();
        for (int i = (signed)instructions.size()-1; i >= 0; i--)
        {
            if (instructions[i].opcode == LOAD_BITS_IV_TO_WR &&
                instructions[i].operands[2]->getValue() == 0 &&
                instructions[i].operands[1]->getOperandName() == "")
                changed = reviseClear(i);
        }
    }
}

bool CProtocolCode::removeDoubleDefine()
{
    int defWR1=1;
    bool changed = 0;
    for (int i = (signed)instructions.size()-1; i >= 0; i--)
    {
        if (instructions[i].opcode == LABEL || instructions[i].canJump())
            defWR1 = 0;
        for (unsigned int j=0; j<instructions[i].noperands; j++)
        {
            COperand* op = instructions[i].operands[j];
            if (!op->hasReg() || op->getReg().type != R_WR1)
                continue;
            if      (op->flags.used)
                defWR1 = 0;
            else if (op->flags.defined)
            {
                if (defWR1)
                {
                    /* This optimization is currently disabled
                    std::cout << "kill instr number" << i
                              << instructions[i].getOpcodeName() << std::endl;
                    eraseInstruction (i);
                    changed = 1;*/
                }
                else
                    defWR1 = 1;
            }
            /*if (instructions[i].operands[j]->flags.used &&
                instructions[i].operands[j]->hasReg())
                std::cout << instructions[i].getOpcodeName() << " " <<
                             instructions[i].operands[j]->getReg().getName() <<
                             "used" << std::endl;*/
        }
    }
    return 0;
}

bool CProtocolCode::reviseClear(uint32_t i)
{
    CInstruction clearInstr = CCode::createZERO_WR(CCode::newRegOp(
                              instructions[i].operands[0]->getReg()));
    /*add new instruction and delete old one*/
    insertInstruction (i+1, clearInstr);
    eraseInstruction (i);
    return 1;
}

void CProtocolCode::insertInstruction(uint32_t i, CInstruction instruction)
{
    std::vector <CInstruction>::iterator instructionsI;
    instructionsI = instructions.begin()+i;
    instructions.insert(instructionsI, instruction);
}

void CProtocolCode::eraseInstruction(uint32_t i)
{
    instructions[i].deleteInstruction();
    std::vector <CInstruction>::iterator instructionsI;
    instructionsI = instructions.begin()+i;
    instructions.erase(instructionsI);
}
