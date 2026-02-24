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
 * File Name : FMCSPCreateCode.cpp
 * Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#include "FMCSPCreateCode.h"

void CCode::createCode (CIR IR)
{
    CExecuteCode executeCode;
    uint32_t i, j;
    /*grab current name in case more labels need to be added*/

    for (i = 0; i < IR.protocolsIRs.size(); i++)
    {
        CProtocolCode tempProtoCode;
        tempProtoCode.protocol = IR.protocolsIRs[i].protocol;
        tempProtoCode.label    = IR.protocolsIRs[i].label;
        for (j = 0; j < IR.protocolsIRs[i].statements.size(); j++)
             processStatement(IR.protocolsIRs[i].statements[j], tempProtoCode);
        protocolsCode.push_back(tempProtoCode);
    }
    prepareEntireCode();
    if (asmFile && debugAsm)
        dumpAsm();
    if (codeFile)
        dumpCode();

    /*revise*/
    std::string reviseMsg = std::string(50,'-') + "\n" + std::string(18,'-') +
     "After Revision" + std::string(18,'-') + "\n" + std::string(50,'-')+"\n";

    reviseEntireCode();
    prepareEntireCode();
    if (asmFile && debugAsm)
        *asmFile << reviseMsg;
    if (asmFile)
        dumpAsm();
    if (codeFile)
    {
        *codeFile << reviseMsg;
        dumpCode();
    }
}

void CCode::processStatement (CStatement statement, CProtocolCode& code)
{
    std::vector <CLabel> labels;
    CLabel returnLabel;
    bool foundChksum = 0;
    switch(statement.type) {
        case ST_EXPRESSION:
            /*chksum uses wr0 wr1 and some bytes in gpr2[0:7] therefore it must
              be processed first*/
            findAndProcessChecksum(statement.expr, code, foundChksum);
            processExpression (statement.expr,code);
            break;
        case ST_IFGOTO:
            if (statement.expr->dyadic.right->type==EINTCONST)
                statement.expr->dyadic.left->reg.type = R_WR0;
            findAndProcessChecksum(statement.expr, code, foundChksum);
            processExpression (statement.expr, code);
            processIf(statement.expr, statement.label, code);
            break;
        case ST_INLINE:
            processInline(statement.text, code);
            break;
        case ST_GOTO:
            processJump(statement, code);
            break;
        case ST_LABEL:
            addInstr (createLABEL(newLabelOp(statement.label)), code);
            break;
        case ST_SWITCH:
            processSwitch(statement.expr, statement.switchTable, code);
            break;
        case ST_SECTIONEND:
            processEndSection(statement, code);
            break;
    }
    chksumStored = 0;
}

/*Process the endSection Statement.
  If this is the end of the last section there is a need to execute CLM,
  advance HB and jump out of softparse.
  If we are between offsets we just need to advance the HB*/
void CCode::processEndSection (CStatement statement, CProtocolCode& code)
{
    /*Confirm custom protocol by modifying LCV*/
    if (!statement.flags.lastStatement)
        statement.flags.confirmLCV_DEFAULT = 0;
    processLCV(statement.flags, code);

    /*Confirm original protocol by modifying LCV*/
    if (statement.flags.confirm)
        addInstr(createCLM(), code);

    /*Move WO and advance HB between 'before' and 'after' sections*/
    if (!statement.flags.lastStatement)
    {
        processExpression (statement.expr, code);
        addInstr(createSET_WO_BY_WR(newRegOp(statement.expr->reg)), code);
        addInstr (createADVANCE_HB_BY_WO(),  code);
    }
    /* Jump after last section*/
    else
    {
        bool jmpHxs = 0;
        if (statement.label.protocol != PT_RETURN &&
            statement.label.protocol != PT_END_PARSE)
        {
            processExpression(statement.expr, code);
            addInstr(createSET_WO_BY_WR(newRegOp(statement.expr->reg)), code);
            jmpHxs = 1;
        }
        addInstr(createJMP(newHxsOp(jmpHxs),newLabelOp(statement.label)),code);
    }
}

void CCode::processLCV(CStatementFlags statementFlags, CProtocolCode& code)
{
    int val = 0;
    if (statementFlags.confirmLCV1)
        val = LCV_SHIM1;
    if (statementFlags.confirmLCV2)
        val = LCV_SHIM2;
#ifdef FM_SHIM3_SUPPORT
    else if (statementFlags.confirmLCV3)
        val = LCV_SHIM3;
#endif /* FM_SHIM3_SUPPORT */
    else if (statementFlags.confirmLCV_DEFAULT)
        val = LCV_DEFAULT;
    if (val!=0)
        addInstr(createOR_IV_LCV(newValueOp(val)), code);
}

void CCode::processJump (CStatement statement, CProtocolCode& code)
{
    bool jmpHxs = 0;
    CLabel label = statement.label;

    /*Confirm custom protocol by modifying LCV*/
    processLCV(statement.flags, code);

    /* If we're jumping to a outside this protocol*/
    if (statement.flags.externJump)
    {
        if (statement.flags.confirm)
            addInstr (createCLM(), code);
        if (statement.flags.advanceJump)
        {
            processExpression(statement.expr, code);
            addInstr(createSET_WO_BY_WR(newRegOp(statement.expr->reg)), code);
            jmpHxs = 1;
        }
    }

    if      (label.protocol == PT_NEXT_ETH)
        addInstr(createJMP_PROTOCOL_ETH(), code);
    else if (label.protocol == PT_NEXT_IP)
        addInstr(createJMP_PROTOCOL_IP(), code);
    else
        addInstr(createJMP(newHxsOp(jmpHxs), newLabelOp(label)), code);
}

void CCode::processIf (CENode* expression, CLabel label, CProtocolCode& code)
{
    bool compareInt = 0;
    uint64_t value  = 0;
    if (expression->dyadic.right->type==EINTCONST)
    {
        compareInt = 1;
        value      = expression->dyadic.right->intval;
    }

    /*Create a compare instruction according to the specific operator*/
    if (expression->type == EEQU)
    {
        if (compareInt)
            addInstr(createCOMPARE_WR0_TO_IV(newLabelOp(label),
                     newCondOp(CO_EQU), newValueOp(value)), code);
        else
            addInstr(createCOMPARE_WORKING_REGS(newLabelOp(label),
                     newCondOp(CO_EQU)), code);
    }
    else if (expression->type == ENOTEQU)
    {
        if (compareInt)
            addInstr (createCOMPARE_WR0_TO_IV(newLabelOp(label),
                      newCondOp(CO_NOTEQU), newValueOp(value)) ,code);
        else
            addInstr (createCOMPARE_WORKING_REGS(newLabelOp(label),
                      newCondOp(CO_NOTEQU)), code);
    }
    else if (expression->type == EGREATEREQU)
    {
        /*No assemble instruction exists for WR0 >= imm*/
        addInstr (createCOMPARE_WORKING_REGS(newLabelOp(label),
                  newCondOp(CO_GREATEREQU)), code);
    }
    else if (expression->type == ELESSEQU)
    {
        /*No assemble instruction exists for WR0 <= imm*/
        addInstr (createCOMPARE_WORKING_REGS(newLabelOp(label),
                  newCondOp(CO_LESSEQU)), code);
    }
    else if (expression->type == EGREATER)
    {
        if (compareInt)
            addInstr (createCOMPARE_WR0_TO_IV(newLabelOp(label),
                      newCondOp(CO_GREATER),newValueOp(value)), code);
        else
            addInstr (createCOMPARE_WORKING_REGS(newLabelOp(label),
                      newCondOp(CO_GREATER)),code);
    }
    else if (expression->type == ELESS)
    {
        if (compareInt)
            addInstr(createCOMPARE_WR0_TO_IV(newLabelOp(label),
                     newCondOp(CO_LESS), newValueOp(value)), code);
        else
            addInstr (createCOMPARE_WORKING_REGS(newLabelOp(label),
                      newCondOp(CO_LESS)), code);
    }
}

void CCode::processInline (std::string data, CProtocolCode& code)
{
    addInstr(createInlineInstr(newTextOp(data)), code);
}

void CCode::processSwitch (CENode* expression, CSwitchTable* switchTable, CProtocolCode& code)
{
    int valuesSize = switchTable->values.size();
    int labelsSize = switchTable->labels.size();

    /*The case instructions expects the switch expr in WR0*/
    expression->reg.type = R_WR0;
    processExpression (expression, code);

    /*Check for errors in table*/
    if ((valuesSize==0) || (labelsSize>4) || (valuesSize !=  labelsSize))
         throw CGenericError (ERR_INTERNAL_SP_ERROR, "switch error");

    /*Insert up to 4 case values into WR1 for the case instruction*/
    for (int i=valuesSize-1; i>=0; i--)
        /*pad with zero when inserting the value*/
        if (i==valuesSize-1)
            addInstr(createLOAD_BITS_IV_TO_WR (newRegOp(R_WR1), newShiftOp(0),
                    newValueOp(switchTable->values[i]), newValueOp(0)), code);
        else
            addInstr(createLOAD_BITS_IV_TO_WR (newRegOp(R_WR1), newShiftOp(1),
                    newValueOp(switchTable->values[i]), newValueOp(16)), code);

    /* Find the correct opcode*/
    Opcode op;
    switch (valuesSize)
    {
    case 1:
        if (switchTable->lastDefault)
            throw CGenericError(ERR_INTERNAL_SP_ERROR,"switch error");
        else
        {
            addInstr(createCOMPARE_WORKING_REGS(newLabelOp
                    (switchTable->labels[0]) ,newCondOp(CO_EQU)), code);
            return;
        }
        break;
    case 2:
        if (switchTable->lastDefault)
            op = CASE1_DJ_WR_TO_WR;
        else
            op = CASE2_DC_WR_TO_WR;
        break;
    case 3:
        if (switchTable->lastDefault)
            op = CASE2_DJ_WR_TO_WR;
        else
            op = CASE3_DC_WR_TO_WR;
        break;
    case 4:
        if (switchTable->lastDefault)
            op = CASE3_DJ_WR_TO_WR;
        else
            op = CASE4_DC_WR_TO_WR;
        break;
    }
    /*Create the instruction*/
    addInstr(createCaseInstr(op, 0, switchTable->labels) ,code);
}

void CCode::processExpression (CENode* expression, CProtocolCode& code)
{
    if (expression->type == EASS)
        processAssign (expression, code);
    else if (expression->type == ECHECKSUM)
        processChecksum(expression, code);
    else if (expression->isDyadic())
        processWROperation (expression, code);

    else if (expression->type == EOBJREF)
        processObject (expression, code);
    else if (expression->type == EINTCONST)
        processInt (expression, code);
    else
        throw CGenericError (ERR_INTERNAL_SP_ERROR,
                             "expression error");
}

void CCode::processChecksum (CENode* expression, CProtocolCode& code)
{
    /*Case 1, we already processed checksum (using the findAndProcessChecksum
      function), and we now only need to access the stored data*/
    if (chksumStored)
    {
        if (expression->reg.type == R_EMPTY)
            expression->reg.type = R_WR0;
        CObject obj = getAndFreeGPR2(6,7);
        addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(expression->reg),
                    newShiftOp(0),newObjOp(&obj)), code);
        chksumStored = 0;
        return;
    }

    /*Case 2: Checksum has not been calculated yet
      The checksum node is dyadic, the left node holds the initial checksum
      result (which can be the runningSum for example). The right node hold
      the FW section on which checksum should be calculated. The left node
      of the right node holds the offset of the FW, and the right node of
      the right node holds the FW section's size (both values are in bytes).*/
    CENode* initialResultNode = expression->dyadic.left;
    CENode* offsetNode  = expression->dyadic.right->dyadic.left;
    CENode* sizeNode    = expression->dyadic.right->dyadic.right;

    CObject size    = getAndAllocateGPR2 (5,5);
    CObject res     = getAndAllocateGPR2 (6,7);
    CObject fw      = CObject (OB_FW, CLocation(0,63));
    CObject shortFw = CObject (OB_FW, CLocation(0,7));
    CLabel label    = CLabel(CIR().createUniqueName()+"_LOOP");
    CLabel label2   = CLabel(CIR().createUniqueName()+"_LOOP_MINOR");
    CLabel label3   = CLabel(CIR().createUniqueName()+"_EVEN");
    CLabel label4   = CLabel(CIR().createUniqueName());
    CLabel label5   = CLabel(CIR().createUniqueName());

    /*Initialize checksum*/
    if (offsetNode->type != EINTCONST ||
        offsetNode->intval != 0)
    {
        processExpression(offsetNode, code);
        addInstr(createADD_WO_BY_WR(newRegOp(offsetNode->reg)), code);
    }
    processExpression(sizeNode, code);
    addInstr(createSTORE_WR_TO_RA(newObjOp(&size), newRegOp(sizeNode->reg)),
                                  code);
    processExpression(initialResultNode, code);
    addInstr(createSTORE_WR_TO_RA(newObjOp(&res), newRegOp(
                                  initialResultNode->reg)), code);

    /*Start the main loop*/
    addInstr(createLABEL(newLabelOp(label)), code);
    /*OPTION 1: Check if less than 8 bytes are left to load from the FW*/
    addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(R_WR0), newShiftOp(0),
                                       newObjOp(&size)), code);
    addInstr(createCOMPARE_WR0_TO_IV(newLabelOp(label4), newCondOp(CO_GREATER),
                                     newValueOp(7)), code);
    addInstr(createZERO_WR(newRegOp(R_WR1)), code);
    /*Minor loop, load final bytes from FW one at a time*/
    addInstr(createLABEL(newLabelOp(label2)), code);
    // We should place NOPs  before each Load_Bits_FW_to_WR to
    // ensure that the effects of stale instructions are cleaned
    addInstr(createNOP(), code);
    addInstr(createLOAD_BITS_FW_TO_WR (newRegOp(R_WR1), newShiftOp(1),
                                       newObjOp(&shortFw)), code);
    addInstr(createSUB_WR_IV_TO_WR(newRegOp(R_WR0), newRegOp(R_WR0),
                                   newValueOp(1)), code);
    addInstr(createADD_SV_TO_WO(newValueOp(1)), code);
    addInstr(createCOMPARE_WR0_TO_IV(newLabelOp(label2), newCondOp(CO_GREATER),
                                     newValueOp(0)), code);
    /*If we are loading an odd number of final bytes we need to shift them
    to the left (in order to remain aligned with the previous bytes)*/
    addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(R_WR0), newShiftOp(0),
                                       newObjOp(&size)), code);
    addInstr(createBITWISE_WR_IV_TO_WR(newRegOp(R_WR0), newRegOp(R_WR0),
                                       newBitOp(BO_AND), newValueOp(1)), code);
    addInstr(createCOMPARE_WR0_TO_IV(newLabelOp(label3), newCondOp(CO_EQU),
                                     newValueOp(0)), code);
    addInstr(createLOAD_BITS_IV_TO_WR(newRegOp(R_WR1), newShiftOp(1),
                                       newValueOp(0), newValueOp(8)), code);
    /*Process the final check sum*/
    addInstr(createLABEL(newLabelOp(label3)), code);
    addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(R_WR0), newShiftOp(0),
                                       newObjOp(&res)), code);
    addInstr(createONES_COMP_WR1_TO_WR0(), code);
    addInstr(createJMP(newHxsOp(0), newLabelOp(label5)), code);

    /*OPTION 2: We still have 8 or more bytes left*/
    addInstr(createLABEL(newLabelOp(label4)), code);
    /*check sum process*/
    // We should place NOPs  before each Load_Bits_FW_to_WR to
    // ensure that the effects of stale instructions are cleaned
    addInstr(createNOP(), code);
    addInstr(createLOAD_BITS_FW_TO_WR (newRegOp(R_WR1), newShiftOp(0),
                                       newObjOp(&fw)), code);
    addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(R_WR0), newShiftOp(0),
                                       newObjOp(&res)), code);
    addInstr(createONES_COMP_WR1_TO_WR0(), code);
    /*store check sum result and move to the next frame*/
    addInstr(createSTORE_WR_TO_RA(newObjOp(&res), newRegOp(R_WR0)), code);
    addInstr(createADD_SV_TO_WO(newValueOp(8)), code);
    /*check if we finished running on requested size
      if not return to beginning of main loop*/
    addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(R_WR0), newShiftOp(0),
                                       newObjOp(&size)), code);
    addInstr(createSUB_WR_IV_TO_WR(newRegOp(R_WR0), newRegOp(R_WR0),
                                   newValueOp(8)), code);
    addInstr(createSTORE_WR_TO_RA(newObjOp(&size), newRegOp(R_WR0)), code);
    addInstr(createCOMPARE_WR0_TO_IV(newLabelOp(label), newCondOp(CO_GREATER),
                                     newValueOp(0)), code);
    /*After loop load checksum result*/
    addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(R_WR0), newShiftOp(0),
                                       newObjOp(&res)), code);
    addInstr(createJMP(newHxsOp(0), newLabelOp(label5)), code);

    /*After checksum process init WO */
    addInstr(createLABEL(newLabelOp(label5)), code);
    addInstr(createLOAD_SV_TO_WO(newValueOp(0)), code);

    expression->reg.type = R_WR0;
    freeGPR2(5,7);
}

/*Find checksum in expression and process it before the rest of the expression
  while there are still three free registers*/
void CCode::findAndProcessChecksum(CENode* expr, CProtocolCode& code, bool &found)
{
    if (expr->type == ECHECKSUM)
    {
        if (found)
            throw CGenericErrorLine (ERR_COMPLEX_EXPR, expr->line,
                 " - can't calculate checksum twice in the same expression");
        else
        {
            processChecksum(expr, code);
            CObject ob = getAndAllocateGPR2(6,7);
            addInstr(createSTORE_WR_TO_RA(newObjOp(&ob),
                                          newRegOp(expr->reg)), code);
            found           = 1;
            chksumStored    = 1;
        }
    }
    if (expr->isDyadic())
    {
        findAndProcessChecksum(expr->dyadic.left,  code, found);
        findAndProcessChecksum(expr->dyadic.right, code, found);
    }
    if (expr->isMonadic())
        findAndProcessChecksum(expr->monadic, code, found);
}

void CCode::processInt (CENode* expression, CProtocolCode& code)
{
    if (expression->reg.type == R_EMPTY)
        expression->reg.type = R_WR1;
    addInstr(createLOAD_BITS_IV_TO_WR (newRegOp(expression->reg),
            newShiftOp(expression->flags.concat),
            newValueOp(expression->intval), newValueOp(0)), code);
}

void CCode::processObject (CENode* expression, CProtocolCode& code)
{
    if (expression->reg.type == R_EMPTY)
        expression->reg.type = R_WR1;
    bool concat = expression->flags.concat;
    CReg reg = expression->reg;

    /*Find the object and load it to a register*/
    if (expression->objref->type == OB_RA)
    {
        addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(reg), newShiftOp(concat),
                 newObjOp(expression->objref)), code);
    }
    else if (expression->objref->type == OB_PA)
    {
        addInstr(createLOAD_BYTES_PA_TO_WR(newRegOp(reg), newShiftOp(concat),
                 newObjOp(expression->objref)), code);
    }
    else if (expression->objref->type == OB_FW)
    {
        int addWO = 0;
        if (expression->objref->location.end >= 128)
        {
            addWO = (expression->objref->location.end - 128)/8 + 1;
            expression->objref->location -= CLocation(addWO*8, addWO*8);
            addInstr(createADD_SV_TO_WO(newValueOp(addWO)), code);
        }
        // We should place NOPs  before each Load_Bits_FW_to_WR to
        // ensure that the effects of stale instructions are cleaned
        addInstr(createNOP(), code);
        addInstr(createLOAD_BITS_FW_TO_WR(newRegOp(reg), newShiftOp(concat),
                 newObjOp(expression->objref)), code);
        if (addWO)
        {
            expression->objref->location += CLocation(addWO*8, addWO*8);
            addInstr(createLOAD_SV_TO_WO(newValueOp(0)), code);
        }
    }
}

void CCode::processAssign (CENode* expression, CProtocolCode& code)
{
    bool rightInt = 0;
    if (expression->dyadic.right->type == EINTCONST)
        rightInt = 1;
    else
        processExpression (expression->dyadic.right, code);

    CENode* left   = expression->dyadic.left;
    CENode* right  = expression->dyadic.right;

    if (left->type == EOBJREF && left->objref->type == OB_RA)
    {
        if (rightInt)
            addInstr(createSTORE_IV_TO_RA(newObjOp(left->objref),
                     newValueOp(right->intval)), code);
        else
            addInstr(createSTORE_WR_TO_RA(newObjOp(left->objref),
                     newRegOp(right->reg)), code);
    }
    if (left->type == EOBJREF && left->objref->type == OB_WO)
    {
        if (rightInt)
            addInstr(createLOAD_SV_TO_WO(newValueOp(right->intval)), code);
        else
            addInstr(createSET_WO_BY_WR(newRegOp(right->reg)), code);
    }
    else if (left->type == EREG)
        addInstr(createSET_WO_BY_WR(newRegOp(right->reg)), code);
}

void CCode::processConcat(CENode* expr, CProtocolCode& code)
{
    /*Right side is int or object
    For this option, we don't need to perform any special operation, only
    to set a specific bit when we load the object/int in the right node.
    Therefore we only process the left node and turn on the the
    concat flag before processing the right node*/
    processExpression (expr->dyadic.left, code);
    expr->dyadic.right->reg = expr->dyadic.left->reg;
    expr->reg = expr->dyadic.left->reg;
    expr->dyadic.right->flags.concat = 1;
    processExpression (expr->dyadic.right, code);
    return;
}

void CCode::processWROperation (CENode* expr, CProtocolCode& code)
{
    CReg leftReg, reg, rightReg;
    bool stored       = 0;   /*first value is spilled*/
    uint64_t rightVal = 0;   /*right reg value*/
    CObject obj;

    /*If there is a condition, R_WR0 must come second in assembler and only WR0 can
      be compared to IV.
      ADDCARRY uses the ONES_COMP_WR1_TO_WR0 which forces us
      to store the result in WR0*/
    if (expr->isCond() || expr->type==EADDCARRY)
    {
        expr->reg.type               = R_WR0;
        expr->dyadic.right->reg.type = R_WR1;
    }
    expr->dyadic.left->reg = expr->reg;

    if (expr->type == ESHLAND)
    {
        processConcat(expr, code);
        return;
    }

    /* In some cases, if the right node is int, we do not need to copy it
    to a register, and can use an addi/subi/comparei...
    assembly instruction instead. */
    if (expr->flags.rightInt)
    {
        rightVal  = expr->dyadic.right->intval;
        processExpression (expr->dyadic.left, code);
    }
    else
    {
        processExpression(expr->first(),code);
        if (expr->second()->weight > 1)
        {
            /*Spill*/
            obj = getAndAllocateGPR2(0,7);
            addInstr(createSTORE_WR_TO_RA(newObjOp(&obj),
                        newRegOp(expr->first()->reg)), code);
            stored   = 1;
        }
        expr->second()->reg = expr->first()->reg.other();
        processExpression(expr->second(),code);
        if (stored)
        {
            /*Load spilled data*/
            addInstr(createLOAD_BYTES_RA_TO_WR(newRegOp(expr->first()->reg),
                     newShiftOp(0), newObjOp(&obj)), code);
            freeGPR2(0,7);
        }
    }

    if (expr->reg.type == R_EMPTY)
        expr->reg = expr->dyadic.left->reg;

    /* In case of cond processIf will take it from here*/
    if (expr->isCond())
        return;

    /*Create the insturctions according to the specific operation*/
    rightReg = expr->dyadic.right->reg;
    leftReg  = expr->dyadic.left->reg;
    reg      = expr->reg;
    switch (expr->type)
    {
        case EADD:
            /*This code can be used to pad with zeros the left 32 bits before
            add/sub operations
            addInstr(createBITWISE_WR_IV_TO_WR(newRegOp(reg), newRegOp(reg),
                     newBitOp(BO_AND), newValueOp(0x00000000ffffffff)), code);*/
            if (expr->flags.rightInt)
                addInstr(createADD_WR_IV_TO_WR(newRegOp(reg),
                         newRegOp(leftReg), newValueOp(rightVal)), code);
            else
                addInstr(createADD_WR_WR_TO_WR(newRegOp(reg),
                         newRegOp(leftReg), newRegOp(rightReg)), code);
            break;
        case ESUB:
            if (expr->flags.rightInt)
                addInstr(createSUB_WR_IV_TO_WR(newRegOp(reg),
                         newRegOp(leftReg), newValueOp(rightVal)), code);
            else
                addInstr(createSUB_WR_WR_TO_WR(newRegOp(reg),
                         newRegOp(leftReg), newRegOp(rightReg)), code);
            break;
        case EADDCARRY:
                addInstr(createONES_COMP_WR1_TO_WR0(),code);
            break;
        case EBITAND:
            if (expr->flags.rightInt)
                addInstr(createBITWISE_WR_IV_TO_WR(newRegOp(reg),
                         newRegOp(leftReg), newBitOp(BO_AND),
                         newValueOp(rightVal)), code);
            else
                addInstr(createBITWISE_WR_WR_TO_WR(newRegOp(reg),
                         newBitOp(BO_AND)), code);
            break;
        case EBITOR:
            if (expr->flags.rightInt)
                addInstr(createBITWISE_WR_IV_TO_WR(newRegOp(reg),
                         newRegOp(leftReg) ,newBitOp(BO_OR),
                         newValueOp(rightVal)), code);
            else
                addInstr(createBITWISE_WR_WR_TO_WR (newRegOp(reg),
                            newBitOp(BO_OR)), code);
            break;
        case EXOR:
            if (expr->flags.rightInt)
                addInstr(createBITWISE_WR_IV_TO_WR(newRegOp(reg),
                         newRegOp(leftReg), newBitOp(BO_XOR),
                         newValueOp(rightVal)), code);
            else
                addInstr(createBITWISE_WR_WR_TO_WR(newRegOp(reg),
                         newBitOp(BO_XOR)), code);
            break;
        case ESHL:
            addInstr(createSHIFT_LEFT_WR_BY_SV(newRegOp(reg),
                     newValueOp(rightVal)), code);
            break;
        case ESHR:
            addInstr(createSHIFT_RIGHT_WR_BY_SV(newRegOp(reg),
                     newValueOp(rightVal)), code);
            break;
        default:
            throw CGenericError (ERR_INTERNAL_SP_ERROR, "wrong enode type");
    }
}

void CCode::addInstr(CInstruction instr, CProtocolCode& code)
{
    code.instructions.push_back(instr);
}

/*----------------------------GPR2 functions----------------------------*/
CObject CCode::getAndFreeGPR2(uint8_t start, uint8_t end)
{
    CObject obj = CObject(OB_RA, CLocation(start+8,end+8));
    freeGPR2(start, end);
    return obj;
}

CObject CCode::getAndAllocateGPR2(uint8_t start, uint8_t end, int line)
{
    if (GPR2Used(start,end))
        throw CGenericErrorLine (ERR_COMPLEX_EXPR, line);
    for (uint8_t i=start; i<= end; i++)
        gpr2Used |= (1<<i);
    CObject obj = CObject(OB_RA, CLocation(start+8,end+8));
    return obj;
}

void CCode::freeGPR2(uint8_t start, uint8_t end)
{
    for (uint8_t i=start; i<= end; i++)
        gpr2Used &= ~(1<<i);
}

bool CCode::GPR2Used(uint8_t start, uint8_t end)
{
    for (uint8_t i=start; i<= end; i++)
    {
        if ((gpr2Used >> i) &  1)
            return 1;
    }
    return 0;
}

/* ---------------------------- create instructions---------------*/
/*  See note regarding these functions in the .h file*/

CInstruction CCode::createCOMPARE_WR0_TO_IV     (CLabelOperand* opA, CCondOperand*  opB,    CValueOperand* opC)
{
    CInstruction instr(COMPARE_WR0_TO_IV,    opA, newRegOp(R_WR0), opB, opC);
    instr.operands[1]->flags.used = 1;
    return instr;
}

CInstruction CCode::createCOMPARE_WORKING_REGS  (CLabelOperand* opA, CCondOperand*  opB)
{
    CInstruction instr(COMPARE_WORKING_REGS, opA, newRegOp(R_WR0),
                                             opB, newRegOp(R_WR1));
    instr.operands[1]->flags.used = 1;
    instr.operands[3]->flags.used = 1;
    return instr;
}


CInstruction CCode::createLABEL                 (CLabelOperand* opA)
    { return CInstruction(LABEL,                opA); }

CInstruction CCode::createJMP                   (CHxsOperand*   opA, CLabelOperand* opB)
{
    CInstruction instr(JMP, opA, opB);
    instr.operands[0]->flags.used = opA->hxsOp;
    return instr;
}

CInstruction CCode::createJMP_PROTOCOL_ETH      ()
{
    CInstruction instr(JMP_PROTOCOL_ETH, newHxsOp(1));
    instr.operands[0]->flags.used= 1;
    return instr;
}


CInstruction CCode::createJMP_PROTOCOL_IP       ()
{
    CInstruction instr(JMP_PROTOCOL_IP, newHxsOp(1));
    instr.operands[0]->flags.used= 1;
    return instr;
}

CInstruction CCode::createOR_IV_LCV             (CValueOperand* opA)
    { return CInstruction(OR_IV_LCV,            opA); }

CInstruction CCode::createSTORE_IV_TO_RA        (CObjOperand*   opA, CValueOperand* opB)
{
    CInstruction instr(STORE_IV_TO_RA,       opA, opB);
    instr.operands[0]->flags.defined= 1;
    return instr;
}

CInstruction CCode::createSTORE_WR_TO_RA        (CObjOperand*   opA, CRegOperand*   opB)
{
    CInstruction instr(STORE_WR_TO_RA,       opA, opB);
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createLOAD_BYTES_RA_TO_WR   (CRegOperand* opA, CShiftOperand* opB,      CObjOperand*    opC)
{
    CInstruction instr(LOAD_BYTES_RA_TO_WR, opA, opB, opC);
    instr.operands[0]->flags.defined= 1;
    instr.operands[0]->flags.used   = opB->shiftOp;
    instr.operands[2]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createLOAD_BYTES_PA_TO_WR   (CRegOperand*   opA, CShiftOperand* opB,    CObjOperand*    opC)
{
    CInstruction instr(LOAD_BYTES_PA_TO_WR, opA, opB, opC);
    instr.operands[0]->flags.defined= 1;
    instr.operands[0]->flags.used   = opB->shiftOp;
    instr.operands[2]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createLOAD_BITS_FW_TO_WR    (CRegOperand*   opA, CShiftOperand* opB,    CObjOperand*    opC)
{
    CInstruction instr(LOAD_BITS_FW_TO_WR, opA, opB, opC);
    instr.operands[0]->flags.defined= 1;
    instr.operands[0]->flags.used  = opB->shiftOp;
    instr.operands[2]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createLOAD_BITS_IV_TO_WR    (CRegOperand* opA, CShiftOperand*   opB,    CValueOperand*  opC, CValueOperand* opD)
{
    CInstruction instr(LOAD_BITS_IV_TO_WR, opA, opB, opC, opD);
    instr.operands[0]->flags.defined= 1;
    instr.operands[0]->flags.used   = opB->shiftOp;
    return instr;
}

CInstruction CCode::createZERO_WR               (CRegOperand* opA)
{
    CInstruction instr(ZERO_WR, opA);
    instr.operands[0]->flags.defined= 1;
    return instr;
}

CInstruction CCode::createADD_WR_WR_TO_WR       (CRegOperand*   opA, CRegOperand*   opB,    CRegOperand*    opC)
{
    CInstruction instr(ADD_WR_WR_TO_WR,      opA, opB, opC);
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    instr.operands[2]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createSUB_WR_WR_TO_WR       (CRegOperand*   opA, CRegOperand*   opB,    CRegOperand*    opC)
{
    CInstruction instr(SUB_WR_WR_TO_WR,      opA, opB, opC);
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    instr.operands[2]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createADD_WR_IV_TO_WR       (CRegOperand*   opA, CRegOperand*   opB,    CValueOperand*  opC)
{
    CInstruction instr(ADD_WR_IV_TO_WR,      opA, opB, opC);
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createSUB_WR_IV_TO_WR       (CRegOperand*   opA, CRegOperand*   opB,    CValueOperand*  opC)
{
    CInstruction instr(SUB_WR_IV_TO_WR,      opA, opB, opC);
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createSHIFT_LEFT_WR_BY_SV   (CRegOperand*   opA, CValueOperand* opB)
{
    CInstruction instr(SHIFT_LEFT_WR_BY_SV, opA, opB);
    instr.operands[0]->flags.defined = 1;
    instr.operands[0]->flags.used    = 1;
    return instr;
}

CInstruction CCode::createSHIFT_RIGHT_WR_BY_SV  (CRegOperand*   opA, CValueOperand* opB)
{
    CInstruction instr(SHIFT_RIGHT_WR_BY_SV, opA, opB);
    instr.operands[0]->flags.defined = 1;
    instr.operands[0]->flags.used    = 1;
    return instr;
}

CInstruction CCode::createBITWISE_WR_WR_TO_WR   (CRegOperand*   opA, CBitOperand*   opB)
{
    CInstruction instr(BITWISE_WR_WR_TO_WR, opA, newRegOp(R_WR0),
                                            opB, newRegOp(R_WR1));
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    instr.operands[3]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createBITWISE_WR_IV_TO_WR   (CRegOperand*   opA, CRegOperand*   opB,    CBitOperand*    opC,    CValueOperand* opD)
{
    CInstruction instr(BITWISE_WR_IV_TO_WR, opA, opB, opC, opD);
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createLOAD_SV_TO_WO         (CValueOperand* opA)
{
    CInstruction instr(LOAD_SV_TO_WO, newRegOp(R_WO),  opA);
    instr.operands[0]->flags.defined= 1;
    return instr;
}

CInstruction CCode::createADD_SV_TO_WO          (CValueOperand* opA)
{
    CInstruction instr(ADD_SV_TO_WO, newRegOp(R_WO),  opA);
    instr.operands[0]->flags.defined= 1;
    instr.operands[0]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createSET_WO_BY_WR          (CRegOperand*   opA)
{
    CInstruction instr(SET_WO_BY_WR, newRegOp(R_WO),  opA);
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createADD_WO_BY_WR          (CRegOperand*   opA)
{
    CInstruction instr(ADD_WO_BY_WR, newRegOp(R_WO),  opA);
    instr.operands[0]->flags.defined= 1;
    instr.operands[0]->flags.used   = 1;
    instr.operands[1]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createCLM                   ()
    { return CInstruction(CLM); }

CInstruction CCode::createADVANCE_HB_BY_WO      ()
{
    CInstruction instr(ADVANCE_HB_BY_WO, newRegOp(R_WO));
    instr.operands[0]->flags.used = 1;
    return instr;
}

CInstruction CCode::createONES_COMP_WR1_TO_WR0  ()
{
    CInstruction instr(ONES_COMP_WR1_TO_WR0, newRegOp(R_WR0), newRegOp(R_WR1));
    instr.operands[0]->flags.used   = 1;
    instr.operands[0]->flags.defined= 1;
    instr.operands[1]->flags.used   = 1;
    return instr;
}

CInstruction CCode::createNOP                   ()
    { return CInstruction(NOP); }

CInstruction CCode::createInlineInstr           (CTextOperand*  opA)
    { return CInstruction(INLINE_INSTR, opA); }


/*A special function for the case instr since it can hold up to 8 operands.
  The four hxs operands are calculated according to the second argument in
  the function (according to specific bits), and the labels are taken from the
  third argument*/
CInstruction CCode::createCaseInstr (Opcode op, uint8_t hxses, std::vector <CLabel> labels)
{
    CInstruction instruction (op);
    instruction.operands.push_back(newRegOp(R_WR0));
    instruction.operands[0]->flags.used = 1;
    if (op==CASE1_DJ_WR_TO_WR || op==CASE2_DC_WR_TO_WR)
        instruction.noperands = 5;
    else if (op==CASE2_DJ_WR_TO_WR || op==CASE3_DC_WR_TO_WR)
        instruction.noperands = 7;
    else if (op==CASE3_DJ_WR_TO_WR || op==CASE4_DC_WR_TO_WR)
        instruction.noperands = 9;
    for (unsigned int i=0; i<instruction.noperands/2; i++)
    {
        CHxsOperand     *hxsOperand;
        CLabelOperand   *labelOperand;
        if ((i==0 && ((hxses & HXS0) != 0)) ||
            (i==1 && ((hxses & HXS1) != 0)) ||
            (i==2 && ((hxses & HXS2) != 0)) ||
            (i==3 && ((hxses & HXS3) != 0)))
            hxsOperand = newHxsOp(1);
        else
            hxsOperand = newHxsOp(0);
        hxsOperand->flags.used = 1;
        labelOperand = newLabelOp(labels[i]);
        instruction.operands.push_back(hxsOperand);
        instruction.operands.push_back(labelOperand);
    }
    return instruction;
}

/* ---------------------------- create operands ---------------*/
CLabelOperand* CCode::newLabelOp (CLabel label1)
{
    CLabelOperand* labelOp  = new CLabelOperand();
    labelOp->label          = label1;
    labelOp->kind           = OT_LABEL;
    return labelOp;
}

CObjOperand* CCode::newObjOp (CObject *object1)
{
    CObjOperand* objOp  = new CObjOperand();
    objOp->object       = *object1;
    objOp->kind         = OT_OBJ;
    return objOp;
}

CRegOperand* CCode::newRegOp (RegType type1)
{
    CRegOperand*  regOp     = new CRegOperand();
    regOp->reg              = CReg(type1);
    regOp->kind             = OT_REG;
    return regOp;
}

CRegOperand* CCode::newRegOp (CReg reg1)
{
    return newRegOp(reg1.type);
}

CCondOperand* CCode::newCondOp (CondOperator condOp1)
{
    CCondOperand*  condOp   = new CCondOperand();
    condOp->condOperator    = condOp1;
    condOp->kind            = OT_CONDOP;
    return condOp;
}

CBitOperand* CCode::newBitOp (BitOperator bitOp1)
{
    CBitOperand*  bitOp     = new CBitOperand();
    bitOp->bitOperator      = bitOp1;
    bitOp->kind             = OT_BITOP;
    return bitOp;
}

CHxsOperand* CCode::newHxsOp    (bool hxsOp1)
{
    CHxsOperand* hxsOp      = new CHxsOperand();
    hxsOp->hxsOp            = hxsOp1;
    hxsOp->kind             = OT_HXS;
    return hxsOp;
}

CShiftOperand* CCode::newShiftOp    (bool shiftOp1)
{
    CShiftOperand* shiftOp  = new CShiftOperand();
    shiftOp->shiftOp        = shiftOp1;
    shiftOp->kind           = OT_SHIFT;
    return shiftOp;
}

CTextOperand*  CCode::newTextOp      (std::string text1)
{
    CTextOperand* textOp    = new CTextOperand();
    textOp->text            = text1;
    textOp->kind            = OT_TEXT;
    return textOp;
}

CValueOperand* CCode::newValueOp     (uint64_t valueOp1)
{
    CValueOperand* valueOp  = new CValueOperand();
    valueOp->value          = valueOp1;
    valueOp->kind           = OT_VAL;
    return valueOp;
}

/* --------------------------- CInstruction -------------------*/
CInstruction::CInstruction(Opcode op, COperand* operandA, COperand* operandB, COperand* operandC, COperand* operandD)
{
    opcode      = op;
    noperands   = 1;

    operands.push_back(operandA);
    if (operandB)
    {
        operands.push_back(operandB);
        noperands++;
    }
    if (operandC)
    {
        operands.push_back(operandC);
        noperands++;
    }
    if (operandD)
    {
        operands.push_back(operandD);
        noperands++;
    }
}

std::string CInstruction::getOpcodeName()
{
    std::map <Opcode, std::string>::iterator iterator;
    std::map <Opcode, std::string> opcodeNames;

    opcodeNames[LOAD_BYTES_RA_TO_WR]    = "LOAD_BYTES_RA_TO_WR";
    opcodeNames[LOAD_BITS_FW_TO_WR]     = "LOAD_BITS_FW_TO_WR";
    opcodeNames[LOAD_BITS_IV_TO_WR]     = "LOAD_BITS_IV_TO_WR";
    opcodeNames[ZERO_WR]                = "ZERO_WR";
    opcodeNames[STORE_IV_TO_RA]         = "STORE_IV_TO_RA";
    opcodeNames[STORE_WR_TO_RA]         = "STORE_WR_TO_RA";
    opcodeNames[ADD_WR_WR_TO_WR]        = "ADD_WR_WR_TO_WR";
    opcodeNames[ADD_WR_IV_TO_WR]        = "ADD_WR_IV_TO_WR";
    opcodeNames[SUB_WR_WR_TO_WR]        = "SUB_WR_WR_TO_WR";
    opcodeNames[SUB_WR_IV_TO_WR]        = "SUB_WR_IV_TO_WR";
    opcodeNames[SHIFT_LEFT_WR_BY_SV]    = "SHIFT_LEFT_WR_BY_SV";
    opcodeNames[SHIFT_RIGHT_WR_BY_SV]   = "SHIFT_RIGHT_WR_BY_SV";
    opcodeNames[BITWISE_WR_WR_TO_WR]    = "BITWISE_WR_WR_TO_WR";
    opcodeNames[BITWISE_WR_IV_TO_WR]    = "BITWISE_WR_IV_TO_WR";
    opcodeNames[CASE1_DJ_WR_TO_WR]      = "CASE1_DJ_WR_TO_WR";
    opcodeNames[CASE2_DJ_WR_TO_WR]      = "CASE2_DJ_WR_TO_WR";
    opcodeNames[CASE2_DC_WR_TO_WR]      = "CASE2_DC_WR_TO_WR";
    opcodeNames[CASE3_DC_WR_TO_WR]      = "CASE3_DC_WR_TO_WR";
    opcodeNames[CASE3_DJ_WR_TO_WR]      = "CASE3_DJ_WR_TO_WR";
    opcodeNames[CASE4_DC_WR_TO_WR]      = "CASE4_DC_WR_TO_WR";
    opcodeNames[LABEL]                  = "LABEL";
    opcodeNames[JMP]                    = "JMP";
    opcodeNames[JMP_PROTOCOL_ETH]       = "JMP_PROTOCOL_ETH";
    opcodeNames[JMP_PROTOCOL_IP]        = "JMP_PROTOCOL_IP";
    opcodeNames[OR_IV_LCV]              = "OR_IV_LCV";
    opcodeNames[ONES_COMP_WR1_TO_WR0]   = "ONES_COMP_WR1_TO_WR0";
    opcodeNames[COMPARE_WORKING_REGS]   = "COMPARE_WORKING_REGS";
    opcodeNames[COMPARE_WR0_TO_IV]      = "COMPARE_WR0_TO_IV";
    opcodeNames[CLM]                    = "CLM";
    opcodeNames[ADVANCE_HB_BY_WO]       = "ADVANCE_HB_BY_WO";
    opcodeNames[LOAD_SV_TO_WO]          = "LOAD_SV_TO_WO";
    opcodeNames[ADD_SV_TO_WO]           = "ADD_SV_TO_WO";
    opcodeNames[SET_WO_BY_WR]           = "SET_WO_BY_WR";
    opcodeNames[ADD_WO_BY_WR]           = "ADD_WO_BY_WR";
    opcodeNames[INLINE_INSTR]           = "INLINE_INSTR";
    opcodeNames[NOP]                    = "NOP";

    iterator = opcodeNames.find(opcode);
    if (iterator == opcodeNames.end())
        return "";
    else
        return opcodeNames[opcode];
}

void CInstruction::checkError(int num...)
{
    OpType type;
    if (num != noperands)
        throw CGenericError (ERR_INTERNAL_SP_ERROR,"wrong number of operands");
    va_list listPointer;
    va_start(listPointer, num);
    for(signed int i = 0; i < num; i++ )
    {
        type = (OpType)va_arg(listPointer, int);
        if (type != operands[i]->kind)
            throw CGenericError (ERR_INTERNAL_SP_ERROR, "wrong argument type");
    }
    va_end( listPointer );
}

bool CInstruction::canJump() const
{
    return (opcode==CASE1_DJ_WR_TO_WR || opcode==CASE1_DJ_WR_TO_WR      ||
            opcode==CASE2_DJ_WR_TO_WR || opcode==CASE3_DC_WR_TO_WR      ||
            opcode==CASE3_DJ_WR_TO_WR || opcode==CASE4_DC_WR_TO_WR      ||
            opcode==COMPARE_WR0_TO_IV || opcode==COMPARE_WORKING_REGS   ||
            opcode==JMP               || opcode==JMP_PROTOCOL_ETH       ||
            opcode==JMP_PROTOCOL_IP);
}


/* --------------------------- COperand ------------------------*/
uint64_t COperand::getValue() const
{
    const CValueOperand* vo = dynamic_cast <const CValueOperand*> (this);
    if (vo)
        return vo->value;
    else
        throw CGenericError (ERR_INTERNAL_SP_ERROR);
}

CReg COperand::getReg() const
{
    if (kind==OT_REG)
    {
        const CRegOperand* ro = dynamic_cast<const CRegOperand*>(this);
        if (ro)
            return ro->reg;
        else
            throw CGenericError(ERR_INTERNAL_SP_ERROR);
    }
    else if (kind==OT_HXS)
        return CHxsOperand::reg;
    else
        throw CGenericError(ERR_INTERNAL_SP_ERROR);
}

CRegOperand* COperand::getRegOp() const
{
    const CRegOperand* ro = dynamic_cast<const CRegOperand*>(this);
    return const_cast <CRegOperand*> (ro);
}

bool COperand::hasReg() const
{
    return (kind==OT_REG || kind==OT_HXS);
}

void   COperand::setDef(const bool val)
{
    flags.defined = val;
}

void   COperand::setUsed(const bool val)
{
    flags.used = val;
}

std::string CBitOperand::getOperandName () const
{
    switch (bitOperator) {
        case BO_AND:        return "&";
        case BO_OR:         return "|";
        case BO_XOR:        return "XOR";
    }
    return "R_ERROR";
}

std::string CCondOperand::getOperandName () const
{
    switch (condOperator) {
        case CO_EQU:        return "==";
        case CO_NOTEQU:     return "!=";
        case CO_GREATER:    return ">";
        case CO_LESS:       return "<";
        case CO_GREATEREQU: return ">=";
        case CO_LESSEQU:    return "<=";
    }
    return "R_ERROR";
}

CReg CHxsOperand::reg = CReg(R_WO);

std::string CHxsOperand::getOperandName () const
{
    if (hxsOp)
        return "HXS";
    else
        return "";
}

std::string CLabelOperand::getOperandName () const
{
    if (!label.isProto)
        return label.name;
    else
        return label.getProtocolOutputName();
}

std::string CLabel::getProtocolOutputName ()  const
{
    switch (protocol) {
        case PT_ETH:        return "ETH_HXS";
        case PT_LLC_SNAP:   return "LLC_SNAP_HXS";
        case PT_VLAN:       return "VLAN_HXS";
        case PT_PPPOE_PPP:  return "PPPOE_PPP_HXS";
        case PT_MPLS:       return "MPLS_HXS";
        case PT_IPV4:       return "IPV4_HXS";
        case PT_IPV6:       return "IPV6_HXS";
        case PT_GRE:        return "GRE_HXS";
        case PT_MINENCAP:   return "MINENCAP_HXS";
        case PT_OTHER_L3:   return "OTH_L3_HXS";
        case PT_TCP:        return "TCP_HXS";
        case PT_UDP:        return "UDP_HXS";
        case PT_IPSEC_AH:   return "IPSEC_HXS";
        case PT_IPSEC_ESP:  return "IPSEC_HXS";
        case PT_SCTP:       return "SCTP_HXS";
        case PT_DCCP:       return "DCCP_HXS";
        case PT_OTHER_L4:   return "OTH_L4_HXS";
        case PT_NEXT_ETH:   return "PT_NEXT_ETH";
        case PT_NEXT_IP:    return "PT_NEXT_IP";
        case PT_RETURN:     return "RETURN_HXS";
        case PT_END_PARSE:  return "END_PARSE";
        default:    throw CGenericError
                    (ERR_INTERNAL_SP_ERROR,"Wrong protocol type");
    }
}

std::string CObjOperand::getOperandName () const
{
    return object.getName();
}

std::string CRegOperand::getOperandName () const
{
    return reg.getName();
}

std::string CShiftOperand::getOperandName () const
{
    if (shiftOp)
        return "<<";
    else
        return "";
}

std::string CTextOperand::getOperandName () const
{
    return text;
}

std::string CValueOperand::getOperandName () const
{
    std::string ret;
    std::stringstream ss;
    ss << "0x" << std::hex << value;
    ss >> ret;
    return ret;
}


/* ------------------------------ delete ---------------------------------*/

void CCode::deleteCode()
{
    deletePaths();
    for (unsigned int i = 0; i < protocolsCode.size(); i++)
        for (unsigned int j = 0; j < protocolsCode[i].instructions.size(); j++)
            protocolsCode[i].instructions[j].deleteInstruction();
}

void CInstruction::deleteInstruction()
{
    for (unsigned int i=0; i < noperands; i++)
        delete operands[i];
}
