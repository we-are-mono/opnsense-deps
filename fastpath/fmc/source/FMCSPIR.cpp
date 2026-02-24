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
 * File Name : FMCSPIR.cpp
 * Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#include "FMCSPIR.h"

uint32_t CIR::currentUniqueName = 0;

/* ------------------------- CreateIR functions ---------------------------*/
void CIR::createIR(CTaskDef* newTask)
{
    this->task = newTask;
    this->createIR();
}

/*Creates IR. This function analyzes the taskDef structure, and creates an
IR instruction. The function is the second stage in the compilation process
(after parsing, and before creating pcode and dumping the assembly code*/
void CIR::createIR ()
{
    uint32_t i, j, count = 0;
    /*Create IR for each protocol*/
    for (i = 0; i < task->protocols.size(); i++)
    {
        CExecuteCode executeCode  = task->protocols[i].executeCode;
        if (executeCode.executeSections.size())
        {
            status.currentProtoIndex = count;

            /*Insert initial label*/
            CLabel labelP("START_"+task->protocols[i].name);
            CProtocolIR protoIR(labelP, task->protocols[i]);
            protoIR.ir = this;
            CStatement statement;
            statement.createLabelStatement(labelP);
            protoIR.statements.push_back(statement);

            // For each protocol name, find corresponding ProtoType
            for ( uint32_t k = 0; k < protoIR.protocol.prevproto.size(); k++ )
            {
                protoIR.protocol.prevType.push_back( findSpecificProtocol
                    (protoIR.protocol.prevproto[k], protoIR.protocol.line) );
            }

            protocolsIRs.push_back(protoIR);

            /*Add any special code before user sections if needed*/
            initIRProto(protocolsIRs[count].statements);

            /*Organize sections before parsing them*/
            uniteSections (executeCode.executeSections);

            /*Create IR instruction for each section in the protocol*/
            std::vector< CExecuteSection> sections=executeCode.executeSections;
            for (j = 0; j < sections.size(); j++)
                createIRSection(sections[j], protocolsIRs[count]);
            /*Mark endsection statement of last statement.
              Needed for final jump and to decide on hb advancement*/
            protocolsIRs[count].statements.back().flags.lastStatement = 1;
            /*Last statement should confirm by default*/
            if (sections[sections.size()-1].confirm != "no")
                protocolsIRs[count].statements.back().flags.confirm = 1;
            count++;
        }
    }

    /*dump IR*/
    if (outFile)
        dumpEntireIR();

    /*revise*/
    reviseEntireIR();
    if (outFile)
    {
        *outFile << "-------------------------------" << std::endl
                 << "--------After revision---------" << std::endl
                 << "-------------------------------" << std::endl;
        dumpEntireIR();
    }
}

/*Add code that should appear before the 'before' and 'after' sections*/
void CIR::initIRProto(std::vector <CStatement> &statements)
{
    ProtoType pt = protocolsIRs[status.currentProtoIndex].protocol.prevType[0];

    /*  Workaround for HW issue 19895
     The last label of an MPLS stack can direct the parser to begin a soft HXS.
     If MPLS parsing encountered an error, parsing should be terminated and
     not jump to the soft HXS. Currently, the parser does not check the error
     status before going to the soft parser.*/
    /*Currently disabled*/
    if (pt == PT_MPLS)
    {
        CStatement ifStatement, jumpStatement, labelStatement;
        labelStatement.createLabelStatement("NO_MPLS_ERROR");
        ifStatement.newIfGotoStatement(labelStatement.label);
        ifStatement.expr->newDyadicENode(EEQU);
        ifStatement.expr->dyadic.left->newDyadicENode(EBITAND);
        ifStatement.expr->dyadic.left->dyadic.left->newObjectENode(RA_L2R);
        ifStatement.expr->dyadic.left->dyadic.right->createIntENode(31);
        ifStatement.expr->dyadic.right->createIntENode(0);
        jumpStatement.createGotoStatement(PT_END_PARSE);
        jumpStatement.flags.advanceJump         = 0;
        jumpStatement.flags.confirm             = 0;
        jumpStatement.flags.confirmLCV_DEFAULT  = 0;
        /*If there are no errors skip the next statement*/
        statements.push_back(ifStatement);
        /*Endparse if an error was encountered*/
        statements.push_back(jumpStatement);
        /*Finish workaround and continue normal code*/
        statements.push_back(labelStatement);
    }
}

/*Check if there are multiple 'before' or 'after' sections. Currently
 multiple sections are not supported, in the future they might be united
 in this function into one section (see commented code below)
 If no before action exists create a before section*/
void CIR::uniteSections (std::vector< CExecuteSection> &executeSections)
{
    bool foundBefore = 0, foundAfter = 0;
    uint32_t i       = 0;
    CExecuteSection *firstBefore;
    ProtoType pt = protocolsIRs[status.currentProtoIndex].protocol.prevType[0];
    while (i < executeSections.size())
    {
        if (executeSections[i].type == BEFORE)
        {
            /*Before not allowed when prevproto is otherl3/otherl4*/
            if (pt == PT_OTHER_L3 || pt == PT_OTHER_L4)
                throw CGenericErrorLine(ERR_BEFORE_OTHER_PREV,
                    executeSections[i].line,
                    protocolsIRs[status.currentProtoIndex].protocol.prevproto[0]);

            /*'before' not allowed after the 'after' element*/
            if (foundAfter)
                  throw CGenericErrorLine (ERR_AFTER_BEFORE_BEFORE,
                                           executeSections[i].line);
            /*Multiple before elements*/
            if (foundBefore)
            {
                throw CGenericErrorLine (ERR_MULTIPLE_BEFORE,
                                         executeSections[i].line);
                 /* This code unites all befores to one section
                 (with only one CLM) - disabled for the time being
                 std::vector<CExecuteExpression>::iterator dEnd =
                    firstBefore->executeExpressions.end();
                std::vector<CExecuteExpression>::iterator sBegin =
                    executeSections[i].executeExpressions.begin();
                std::vector<CExecuteExpression>::iterator sEnd =
                    executeSections[i].executeExpressions.end();

                firstBefore->executeExpressions.insert (dEnd, sBegin, sEnd);
                executeSections.erase(executeSections.begin()+i);
                i--;    */
            }
            foundBefore = 1;
            firstBefore = &(executeSections[i]);
        }
        else if (executeSections[i].type == AFTER)
        {
            /*Insert dummy before section unless the previous protocol is
              otherl3 or otherl4*/
            if (!foundBefore)
            {
                if (pt != PT_OTHER_L3 && pt != PT_OTHER_L4)
                {
                    executeSections.insert(executeSections.begin(),
                                           CExecuteSection(BEFORE));
                    i++;
                }
                foundBefore = 1;
                continue;
            }
            /*Multiple after elements*/
            if (foundAfter)
                throw CGenericErrorLine (ERR_MULTIPLE_AFTER,
                                         executeSections[i].line);
            foundAfter = 1;
        }
        i++;
    }
}

void CIR::createLCV (std::string confirmCustom, CStatement &stmt, int line)
{
    stmt.flags.confirmLCV_DEFAULT = 0;
    if (confirmCustom == "")
        stmt.flags.confirmLCV_DEFAULT = 1;
    else if (confirmCustom == "shim1")
        stmt.flags.confirmLCV1 = 1;
    else if (confirmCustom == "shim2")
        stmt.flags.confirmLCV2 = 1;
#ifdef FM_SHIM3_SUPPORT
    else if (confirmCustom == "shim3")
        stmt.flags.confirmLCV3 = 1;
#endif /* FM_SHIM3_SUPPORT */
    else if (confirmCustom == "no")
    {
        stmt.flags.confirmLCV_DEFAULT = 0;
        stmt.flags.confirmLCV1 = 0;
        stmt.flags.confirmLCV2 = 0;
#ifdef FM_SHIM3_SUPPORT
        stmt.flags.confirmLCV3 = 0;
#endif /* FM_SHIM3_SUPPORT */
    }
    else
        throw CGenericErrorLine (ERR_UNKNOWN_CCUSTOM_OPTION,
                                 line, confirmCustom);
}

void CIR::createIRSection (CExecuteSection section, CProtocolIR& pIR)
{
    /*Find name of current protocol and headerSize*/
    switch(section.type)
    {
        case BEFORE:
            status.currentAfter = 0;
            /*The prevHeaderSize in set the defaultHeaderSize which
              is interperted in yacc differently in the before/after sections*/
            createIRExprValue("$defaultHeaderSize", pIR.prevHeaderSize,
                              section.line, 0);
            break;
        case AFTER:
            status.currentAfter = 1;
            createIRExprValue("$defaultHeaderSize", pIR.headerSize,
                              section.line, 0);

            break;
    }

    /*Create IR for each expression*/
    createIRExpressions(section, pIR.statements);

    /*Insert final section statement after 'before' and 'after' sections
      - needed for CLM, to update WO and HB*/
    CStatement sStatement;
    sStatement.createSectionEndStatement();
    switch(section.type) {
          /*After the 'before' section we move to the next protocol,
          by modifying W0 and adding the EFBEFORE instruction*/
        case BEFORE:
            sStatement.expr     = pIR.prevHeaderSize->newDeepCopy();
            sStatement.label    = CLabel(PT_RETURN);
            break;
        /*Goto end parse or return hxs after the 'after' section*/
        case AFTER:
            sStatement.flags.afterSection   = 1;
            sStatement.expr                 = pIR.headerSize->newDeepCopy();
            sStatement.label                = CLabel(PT_END_PARSE);
            break;
    }

    /*Update LCV*/
    createLCV(section.confirmCustom, sStatement, section.line);

    /*Update confirm option, turned off by default for all sections
      besides the last (last section flag modified in createIR func) */
    if (section.confirm == "yes")
        sStatement.flags.confirm = 1;
    else
        sStatement.flags.confirm = 0;

    pIR.statements.push_back(sStatement);
}

/*This functions creates statements for a section and inserts them in the
  end of the 'statements' vector. Note: this function should only be used
  for the expression inside the sections and not to analyze the section
  type itself (before, after, etc.)*/
void CIR::createIRExpressions (CExecuteSection section, std::vector <CStatement> &statements)
{
    for (unsigned int i=0; i < section.executeExpressions.size(); i++)
    {
        CExecuteExpression ee = section.executeExpressions[i];
        if      (ee.type == ACTION)
            createIRAction (ee.actionInstr, statements);
        else if (ee.type == ASSIGN)
            createIRAssign (ee.assignInstr, statements);
        else if (ee.type == IF)
            createIRIf     (ee.ifInstr,     statements);
        else if (ee.type == LOOP)
            createIRLoop     (ee.loopInstr, statements);
        else if (ee.type == INLINE)
            createIRInline (ee.inlineInstr, statements);
        else if (ee.type == SWITCH)
            createIRSwitch (ee.switchInstr, statements);
    }
}

/*Create IR instructions for the switch element*/
void CIR::createIRSwitch (CExecuteSwitch switchElem, std::vector<CStatement> &statements)
{
    std::vector <CStatement>      executeStatments;
    std::vector <CExecuteSection> sections;
    uint8_t countInTable = 0;
    /*Switch with no case*/
    if (switchElem.cases.size() == 0)
        throw CGenericErrorLine(ERR_SWITCH_NO_CASE, switchElem.line,
                                switchElem.expr);
    /*finalLStatement is the last label related to the switch,
    we'll use finalGStatement to jump there either when we finished checking
    all cases (+default) or when we found a case and executed the
    elements inside it*/
    CStatement switchStatement,trueLStatement,finalGStatement,finalLStatement;
    finalLStatement.createLabelStatement(createUniqueName());
    finalGStatement.createGotoStatement(finalLStatement.label);

    for (unsigned int i=0; i<switchElem.cases.size(); i++)
    {
        uint64_t intValue;
        /*We currently support only int in cases*/
        if (!stringToInt(switchElem.cases[i].value, intValue,
                         switchElem.cases[i].line))
            throw CGenericErrorLine(ERR_CASE_NO_INT, switchElem.cases[i].line,
                                    switchElem.cases[i].value);
        /*We will jump to the trueLStatement label only if the value
        is in the correct range, the label will appear after all cases*/
        trueLStatement.createLabelStatement(createUniqueName());

        /*OPTION1: If value is larger than 16 bit we turn this specific
                   case into an ifInstr*/
        if ((intValue & 0xFFFFFFFFFFFF0000ull) != 0)
        {
            /*If switch table exists add it to statements and initialize it*/
            if (countInTable)
            {
                statements.push_back(switchStatement);
                countInTable = 0;
            }
            CStatement statement1;
            statement1.createIfGotoStatement(trueLStatement.label,
                                             switchElem.line);
            CExecuteIf ifInstr1(switchElem.cases[i].value + "== (" +
                                switchElem.expr +  ")");
            createIRExprValue(ifInstr1.expr, statement1.expr,
                              switchElem.cases[i].line);
            statements.push_back(statement1);
        }

        /*OPTION 2: If we have a max value we turn this
                    specific case into two ifs */
        else if (!switchElem.cases[i].maxValue.empty())
        {
            /*If switch table exists add it to statements and initialize it*/
            if (countInTable)
            {
                statements.push_back(switchStatement);
                countInTable = 0;
            }
            CStatement statement1, statement2, falseLStatement, trueGStatement;
            CExecuteIf ifInstr1("(" + switchElem.cases[i].value + ") gt ("
                                    + switchElem.expr +  ")");
            CExecuteIf ifInstr2("(" + switchElem.cases[i].maxValue + ") lt ("
                                    + switchElem.expr +  ")");
            /*This falseLStatement label will take us back to the switch to
            check more cases.*/
            falseLStatement.createLabelStatement(createUniqueName());
            trueGStatement.createGotoStatement  (trueLStatement.label);
            /*check if expr value is smaller than allowed value*/
            createIRExprValue(ifInstr1.expr, statement1.expr,
                              switchElem.cases[i].line);
            statement1.createIfGotoStatement(falseLStatement.label, NO_LINE);
            /*check if expr value is larger than max value*/
            createIRExprValue(ifInstr2.expr, statement2.expr,
                               switchElem.cases[i].line);
            statement2.createIfGotoStatement(falseLStatement.label, NO_LINE);
            /*Insert both ifs, if we failed in any of them we will jmp
              to falseLStatement, otherwise we will reach trueLStatement*/
            statements.push_back(statement1);
            statements.push_back(statement2);
            statements.push_back(trueGStatement);
            statements.push_back(falseLStatement);
        }
        else /*OPTION3: Create a switch table*/
        {
            countInTable++;
            if (countInTable == 1) /*new table*/
            {
                switchStatement.newSwitchStatement(switchElem.line);
                createIRExprValue (switchElem.expr,
                        switchStatement.expr, switchElem.line);
                if (switchStatement.expr->isCond())
                    throw CGenericErrorLine(ERR_UNEXPECTED_COND_SWITCH,
                                            switchElem.line, switchElem.expr);
            }
            /*insert values and labels to table*/
            switchStatement.switchTable->values.push_back((uint16_t)intValue);
            switchStatement.switchTable->labels.push_back(trueLStatement.label);
            /*Max table size is four (according to assembly case instruction*/
            if (countInTable == 4 || i+1 == switchElem.cases.size())
            {
                statements.push_back(switchStatement);
                countInTable = 0;
            }
        }

        /*If this case is true we will reach this label and execute
        the case's instructions*/
        executeStatments.push_back(trueLStatement);
        createIRExpressions(switchElem.cases[i].ifCase, executeStatments);
        /* After the case skip the rest of the statements related to
           the switch (as if there was a 'break' in c, or 'last' in perl*/
        executeStatments.push_back(finalGStatement);
    }   /*Finished checking cases*/

    /*If we'll reach the end of the switch without jumping we should execute
      the default case, and skip the following statements for 'true' cases*/
    if (switchElem.defaultCaseValid)
        createIRExpressions(switchElem.defaultCase, statements);
    statements.push_back(finalGStatement);
    /*Insert all the labels, and statements which should be executed
    if one of the cases was true. */
    for (unsigned int i=0; i<executeStatments.size(); i++)
        statements.push_back(executeStatments[i]);
    /*Last label related to switch, jump here when done*/
    statements.push_back(finalLStatement);
}

void CIR::createIRInline (CExecuteInline inInstr, std::vector<CStatement> &statements)
{
    CStatement  inlineStatement;
    inlineStatement.createInlineStatement(inInstr.data, inInstr.line);
    statements.push_back(inlineStatement);
}

void CIR::createIRIf (CExecuteIf ifInstr, std::vector<CStatement> &statements)
{
    CStatement  statement, gStatement, lstatement1, lstatement2, lstatement3;
    CObject     object;
    std::string newName, label1Name, label2Name, label3Name, temp;

    /*No if true*/
    if (!ifInstr.ifTrueValid)
        throw CGenericErrorLine(ERR_IF_NO_TRUE, ifInstr.line, ifInstr.expr);
    createIRExprValue (ifInstr.expr, statement.expr, ifInstr.line);
    if (!statement.expr->isCond())
        throw CGenericErrorLine(ERR_EXPECTED_COND, ifInstr.line, ifInstr.expr);

    /*Only an ifTrue label*/
    if (!ifInstr.ifFalseValid)
    {
        lstatement1.createLabelStatement(createUniqueName());
        statement.createIfNGotoStatement(lstatement1.label, ifInstr.line);
        statements.push_back(statement);
        createIRExpressions(ifInstr.ifTrue, statements);
        statements.push_back(lstatement1);
    }

    /*An ifTrue and ifFalse*/
    else if (ifInstr.ifFalseValid)
    {
        lstatement1.createLabelStatement(createUniqueName());
        statement.createIfGotoStatement(lstatement1.label, ifInstr.line);
        statements.push_back(statement);
        createIRExpressions(ifInstr.ifFalse, statements);
        lstatement2.createLabelStatement(createUniqueName());
        gStatement.createGotoStatement(lstatement2.label);
        statements.push_back(gStatement);
        statements.push_back(lstatement1);
        createIRExpressions(ifInstr.ifTrue, statements);
        statements.push_back(lstatement2);
    }
}

void CIR::createIRLoop (CExecuteLoop loopInstr, std::vector<CStatement> &statements)
{
    CStatement  statement, gStatement, lstatement1, lstatement2;
    std::string newName, label1Name, label2Name, label3Name, temp;

    lstatement1.createLabelStatement(createUniqueName());
    statements.push_back(lstatement1);
    createIRExprValue (loopInstr.expr, statement.expr, loopInstr.line);
    if (!statement.expr->isCond())
        throw CGenericErrorLine(ERR_EXPECTED_COND, loopInstr.line, loopInstr.expr);
    lstatement2.createLabelStatement(createUniqueName());
    statement.createIfNGotoStatement(lstatement2.label, loopInstr.line);
    statements.push_back(statement);
    createIRExpressions(loopInstr.loopBody, statements);
    gStatement.createGotoStatement(lstatement1.label);
    statements.push_back(gStatement);
    statements.push_back(lstatement2);
}

void CIR::createIRAction (CExecuteAction action, std::vector<CStatement> &statements)
{
    CStatement gStatement, eStatement;
    std::string actionTypeName = action.type;
    ProtoType pt;

    if (action.type == "exit")
    {
        std::string labelName;
        /*either exit to a specific protocol or return to HXS*/
        if (action.nextproto.length() != 0)
            pt = findProtoLabel(action.nextproto, action.line);
        else
            pt = PT_RETURN;
        gStatement.createGotoStatement(pt);

        /* we should update HB and WO before exiting and therefore we
           add the flag and header size*/
        gStatement.flags.hasENode = 1;
        if (status.currentAfter)
            gStatement.expr = protocolsIRs[status.currentProtoIndex].
                                headerSize->newDeepCopy();
        else
            gStatement.expr = protocolsIRs[status.currentProtoIndex].
                                prevHeaderSize->newDeepCopy();

        /*Update confirm option*/
        if ((action.confirm == "yes") || action.confirm == "")
            gStatement.flags.confirm = 1;
        else if (action.confirm == "no")
            gStatement.flags.confirm = 0;
        else throw CGenericErrorLine (ERR_UNKNOWN_CONFIRM_OPTION, action.line,
                                      action.confirm);

        /*Update advance option*/
        if (action.advance == "")
        {
            if (pt == PT_RETURN || pt == PT_END_PARSE)
                action.advance = "no";
            else
                action.advance = "yes";
        }

        if (action.advance == "yes")
            gStatement.flags.advanceJump = 1;
        else if (action.advance == "no")
            gStatement.flags.advanceJump = 0;
        else
            throw CGenericErrorLine (ERR_UNKNOWN_ADVANCE_OPTION,
                                     action.line, action.advance);

        /*Update LCV option*/
        createLCV(action.confirmCustom, gStatement, action.line);

        /*Check for errors*/
        if (!gStatement.flags.advanceJump && (pt == PT_NEXT_ETH ||
                                              pt == PT_NEXT_IP))
            throw CGenericErrorLine(ERR_ADVANCE_REQUIRED, action.line,
                                    action.advance);
        if (gStatement.flags.advanceJump && (pt == PT_RETURN))
            throw CGenericErrorLine(ERR_ADVANCE_NOT_ALLOWED,
                                    action.line, action.advance);

        /*Workaround for HW bug 19894
        The Parser maintains the outcome of its parsing activities in a
        Parse Result array. Specifically, the layer 4 header fields is captured
        in the Layer 4 results (L4R). Upon re-entry to layer 4 parsing,
        the L4R need to be cleared in order to reflect the new results
        properly. The parser does not clear the L4R upon re-entry.
        Note that re-entry is only possible via soft parser, not part of
        hard parser attachment.
        Currently we workaround the bug by initializing the l4r field when
        jumping from a layer4 extension or to a layer4 protocol.
        This covers almost all realistic scenarios and has a relativly minor
        effect on performance*/
        if ((pt != PT_END_PARSE && pt != PT_RETURN &&
             protocolsIRs[status.currentProtoIndex].protocol.PossibleLayer4())
                ||
            (CProtocol::PossibleLayer4(pt)))
        {
            CStatement assignStatement;
            assignStatement.newAssignStatement(gStatement.line);
            assignStatement.expr->newDyadicENode();
            assignStatement.expr->dyadic.left->newObjectENode(RA_L4R);
            assignStatement.expr->dyadic.right->createIntENode(0);
            statements.push_back(assignStatement);
        }

        statements.push_back(gStatement);
    }
    else
        throw CGenericErrorLine (ERR_UNSUPPORTED_ACTION,
                                 action.line, actionTypeName);
}

void CIR::createIRAssign (CExecuteAssign assign, std::vector <CStatement> &statements)
{
    CStatement  statement;

    /*Special treatment for headerSize, no statements are executed,
      only the internal value is modified*/
    if (insensitiveCompare(assign.name, "$headerSize"))
    {
        if (status.currentAfter)
            createIRExprValue(assign.value,
                protocolsIRs[status.currentProtoIndex].headerSize,
                assign.line, 1);
        else
            createIRExprValue(assign.value,
                protocolsIRs[status.currentProtoIndex].prevHeaderSize,
                assign.line, 1);
        return;
    }

    // In presence of fwoffset, create a new assignment statement
    // that sets $WO to fwoffset expression
    if ( !assign.fwoffset.empty() ) {
        CExecuteAssign assignWO( assign );
        assignWO.name     = "$WO";
        assignWO.value    = assignWO.fwoffset;
        assignWO.fwoffset = "";

        createIRAssign( assignWO, statements );
    }

    statement.newAssignStatement(assign.line);
    /*Create left side*/
    createIRExprValue(assign.name, statement.expr->dyadic.left, assign.line);
    /*Check that this is a valid assign statement*/
    if (statement.expr->dyadic.left->type != EOBJREF ||
        (statement.expr->dyadic.left->objref->type != OB_RA &&
         statement.expr->dyadic.left->objref->type != OB_WO))
        throw CGenericErrorLine (ERR_UNALLOWED_LVALUE_ASSIGN,
                                 assign.line, assign.name);

    /*Create right side*/
    createIRExprValue(assign.value, statement.expr->dyadic.right, assign.line);
    if (statement.expr->dyadic.right->isCond())
        throw CGenericErrorLine(ERR_UNEXPECTED_COND_ASSIGN, assign.line,
                                assign.value);
    statements.push_back(statement);

    // In presence of fwoffset, create a new assignment statement
    // that restores $WO to be zero
    if ( !assign.fwoffset.empty() ) {
        CExecuteAssign assignWO( assign );
        assignWO.name     = "$WO";
        assignWO.value    = "0";
        assignWO.fwoffset = "";

        createIRAssign( assignWO, statements );
    }
}

void CIR::createIRVariable (std::string name, CObject *object, int line)
{
    std::string newName = stripDollar (name);

    /*First check predefined variable(s)*/
    if (insensitiveCompare(newName, "prevprotoOffset"))
        findPrevprotoOffset(object, line);
    /*Then check parse array*/
    else if (RA::Instance().findNameInRA(newName, object->typeRA,
                                         object->location, line))
    {
        object->type = OB_RA;
    }
    else if (insensitiveCompare(newName, "WO"))
    {
        object->type = OB_WO;
    }
    else
        throw CGenericErrorLine (ERR_UNRECOGNIZED_OBJECT, line, name);

    /*check for errors*/
    if (object->location.end - object->location.start > 7)
        throw CGenericErrorLine (ERR_VAR_TOO_LARGE, line, name);
}

void CIR::createIRVariableAccess (std::string name, CObject *object, int line)
{
    std::string newName = stripDollar (name);
    uint32_t start, size;
    getBufferInfo (newName, start, size, line, 0);
    if (insensitiveCompare(newName, "PA"))
    {
        if (size==0)
            throw CGenericErrorLine (ERR_PA_SIZE_MISSING, line, name);
        if (start+size > 63)
            throw CGenericErrorLine (ERR_PA_SIZE_LARGE, line, name);
        object->type = OB_PA;
    }
    else if (RA::Instance().findNameInRA(newName, object->typeRA,
                                         object->location, line))
    {
        object->type = OB_RA;
        /*Make sure not to access outside the variable*/
        if (object->location.start + start + size - 1 > object->location.end)
            throw CGenericErrorLine (ERR_VAR_ACCESS_TOO_LARGE, line, newName,
                    object->location.end-object->location.start+1, name);
    }
    else
        throw CGenericErrorLine (ERR_UNRECOGNIZED_OBJECT, line, name);

    object->location.start += start;
    /*In case size==0 we return the entire buffer*/
    if (size!=0)
        object->location.end    = object->location.start + size - 1;

    if (object->location.end - object->location.start > 7)
        throw CGenericErrorLine (ERR_BUFFER_ACCESS_TOO_LARGE, line, name);
}

void CIR::createIRFWAccess (std::string name, CObject *object, int line)
{
    uint32_t size, start;
    std::string newName = name;
    getBufferInfo (newName, start, size, line, 1);
    object->location.start = start;
    if (size!=0)
        object->location.end  = start+size-1;
    else
        throw CGenericErrorLine (ERR_FW_SIZE_MISSING, line, name);
    if (start+size > 2040)
        throw CGenericErrorLine (ERR_FW_SIZE_LARGE, line, name);
    object->type = OB_FW;
}

void CIR::createIRField (std::string name, CObject *object, int line)
{
    findInFW(getCurrentProtoName(), name, object->location, line);
    object->type = OB_FW;
}

void CIR::createIRProtocolField (std::string name, CObject *object, int line)
{
    std::string protocolName, newName = name;

    int dotLoc = newName.find(".", 0);
    if (dotLoc == std::string::npos)
        protocolName = getCurrentProtoName();
    else
        protocolName = newName.substr(0, dotLoc);
    newName = newName.substr(dotLoc+1,newName.length());
    if (!insensitiveCompare (protocolName,getCurrentProtoName()))
        throw CGenericErrorLine(ERR_CANT_ACCESS_PROTOCOL, line, protocolName +
            " currently working in protocol " + getCurrentProtoName());

    findInFW(protocolName, newName, object->location, line);
    object->type = OB_FW;
}

/*create an expression based on lex/yacc files*/
void CIR::createIRExprValue (std::string name, CENode*& eNode, int line, int replace)
{
    setIRYacc (this);
    setLineYacc(&line);
    FMCSPExpr_scan_string (name.c_str());
    FMCSPExprparse();
    FMCSPExprlex_destroy ();
    if (replace && eNode)
    {
        eNode->deleteENode();
        deleteEnode (eNode);
    }
    eNode  = getExpressionYacc();
    checkExprValue (eNode, line);
}

/* ---------------------------------- Useful IR functions-------------------*/

uint32_t CIR::calculateFormatSize (int line)
{
    uint32_t ret;
    if (!status.currentAfter)
        throw CGenericErrorLine (ERR_INTERNAL_SP_ERROR, line);
    if (!protocolsIRs[status.currentProtoIndex].protocol.GetHeaderSize(ret))
        throw CGenericErrorLine (ERR_HEADER_SIZE_MISSING, line);
    else
        return ret;
}

void CIR::getBufferInfo (std::string &name, uint32_t &startByte, uint32_t &sizeByte, int line, bool bits)
{
    std::string oName   = name;
    int indexLoc        = name.find("[",0);
    int midIndexLoc     = name.find(":", 0);
    int endLoc          = name.find("]",0);
    if (midIndexLoc<=indexLoc || endLoc<=midIndexLoc)
        throw CGenericErrorLine (ERR_INVALID_INDEX, line, name);
    std::istringstream stringS1(name.substr(indexLoc + 1,
                                midIndexLoc - indexLoc - 1));
    stringS1 >> startByte;
    std::istringstream stringS2(name.substr(midIndexLoc + 1,
                                endLoc - midIndexLoc - 1));
    stringS2 >> sizeByte;
    name=name.substr(0,indexLoc);
    if (!bits && sizeByte > 8)
        throw CGenericErrorLine (ERR_BUFFER_ACCESS_TOO_LARGE, line, oName);
    else if (bits && sizeByte > 64)
        throw CGenericErrorLine (ERR_BUFFER_ACCESS_TOO_LARGE, line, oName);
}

void CIR::setTask (CTaskDef *task1)
{
    task = task1;
}


/*Find errors in expressions*/
void CIR::checkExprValue (CENode* eNode, int line) const
{
    eNode->line = line;
    if (eNode->type == ESHL || eNode->type == ESHR)
    {
        if (eNode->dyadic.right->type != EINTCONST)
            throw CGenericErrorLine (ERR_SHIFT_BY_IMM, line);
        if (eNode->dyadic.right->type == EINTCONST &&
            (eNode->dyadic.right->intval < 1 ||
             eNode->dyadic.right->intval > 64))
            throw CGenericErrorLine (ERR_SHIFT_BY_VALUE, line);
    }
    else if (eNode->type == ESHLAND)
    {
        if (eNode->dyadic.right->type != EINTCONST &&
            eNode->dyadic.right->type != EOBJREF)
            throw CGenericErrorLine (ERR_CONCAT_VALUE, line);
    }
    else if (eNode->type == EADD || eNode->type == ESUB)
    {
        if (eNode->dyadic.left->isMoreThan32() ||
            eNode->dyadic.right->isMoreThan32())
            CGenericErrorLine::printWarning(WARN_MORE_THAN32, line);
    }
    else if (eNode->type == EADDCARRY)
    {
        if (eNode->dyadic.left->isMoreThan16() ||
            eNode->dyadic.right->isMoreThan16())
                throw CGenericErrorLine (ERR_ADDC_SIZE, line);
    }
    else if (eNode->type == ECHECKSUM_LOC)
    {
        if (eNode->dyadic.left->type   == EINTCONST &&
            eNode->dyadic.right->type  == EINTCONST &&
            eNode->dyadic.left->intval  > 256 ||
            eNode->dyadic.right->intval > 256)
               throw CGenericErrorLine(ERR_CHECKSUM_SECOND_THIRD, line);
    }
    else if (eNode->type == ECHECKSUM)
    {
        if (eNode->dyadic.left->type   == EINTCONST &&
            eNode->dyadic.left->intval  > 0xffff)
                throw CGenericErrorLine (ERR_CHECKSUM_FIRST, line);
    }

    /*Check for errors related to mix of arithmetic/logical operators*/
    if (eNode->isMonadic() || eNode->isDyadic())
    {
        if (eNode->type == ENOT)
        {
            if (!eNode->monadic->isCond())
                throw CGenericErrorLine (ERR_EXPECTED_COND_NOT, line);
        }
        else if (eNode->type == EAND || eNode->type == EOR)
        {
            if((!eNode->dyadic.left->isCond()) ||
               (!eNode->dyadic.right->isCond()))
                throw CGenericErrorLine (ERR_EXPECTED_COND_AND, line);
        }
        else
        {
            if ((eNode->isMonadic() && eNode->monadic->isCond())    ||
                (eNode->isDyadic()  && eNode->dyadic.left->isCond()) ||
                (eNode->isDyadic()  && eNode->dyadic.right->isCond()))
                throw CGenericErrorLine (ERR_UNEXPECTED_COND, line);
        }
    }
    if (eNode->isDyadic())
    {
        checkExprValue (eNode->dyadic.left, line);
        checkExprValue (eNode->dyadic.right, line);
    }
    if (eNode->isMonadic())
        checkExprValue (eNode->monadic, line);
}

void CIR::findInFW(std::string protocolName, std::string fieldName, CLocation &location, int line) const
{
    for (unsigned int i = 0; i < task->protocols.size(); i++)
    {
        uint32_t     bitsize;
        uint32_t     bitoffset;
        /*Find the correct protocol*/
        if (insensitiveCompare (task->protocols[i].name, protocolName))
        {
            /*Check if field exists*/
            if (!task->protocols[i].FieldExists(fieldName))
                throw CGenericErrorLine (ERR_UNRECOGNIZED_FIELD,
                                         line, fieldName);
            else
            {
                task->protocols[i].GetFieldProperties( fieldName,
                                                       bitsize, bitoffset );
                location.start = bitoffset;
                location.end = bitoffset+bitsize-1;
                if (location.end - location.start > 63)
                    throw CGenericErrorLine (ERR_FIELD_TOO_LARGE,
                                             line, fieldName);
                return;
            }
        }
    }
    throw CGenericErrorLine (ERR_UNRECOGNIZED_OBJECT, line, fieldName);
}

std::string CIR::getCurrentProtoName() const
{
    if (status.currentAfter)
        return protocolsIRs[status.currentProtoIndex].protocol.name;
    else
        return protocolsIRs[status.currentProtoIndex].protocol.prevproto[0];
}

void CIR::findPrevprotoOffset (CObject *object, int line) const
{
    ProtoType pt = protocolsIRs[status.currentProtoIndex].
                                        protocol.prevType[0];
    int eCode = 0;
    object->type = OB_RA;
    RAType lookForRAType;

    switch (pt)
    {
        case PT_ETH:        lookForRAType = RA_ETHOFFSET;       break;
        case PT_VLAN:       lookForRAType = RA_VLANTCIOFFSET_N; break;
        case PT_LLC_SNAP:   lookForRAType = RA_LLC_SNAPOFFSET;  break;
        case PT_MPLS:       lookForRAType = RA_MPLSOFFSET_N;    break;
        case PT_IPV4:       lookForRAType = RA_IPOFFSET_N;      break;
        case PT_IPV6:       lookForRAType = RA_IPOFFSET_N;      break;
        case PT_TCP:        lookForRAType = RA_L4OFFSET;        break;
        case PT_UDP:        lookForRAType = RA_L4OFFSET;        break;
        case PT_GRE:        lookForRAType = RA_GREOFFSET;       break;
        case PT_PPPOE_PPP:  lookForRAType = RA_PPPOEOFFSET;     break;
        case PT_MINENCAP:   lookForRAType = RA_MINENCAPOFFSET;  break;
        case PT_SCTP:       lookForRAType = RA_L4OFFSET;        break;
        case PT_DCCP:       lookForRAType = RA_L4OFFSET;        break;
        case PT_IPSEC_AH:   lookForRAType = RA_L4OFFSET;        break;
        case PT_IPSEC_ESP:  lookForRAType = RA_L4OFFSET;        break;
        case PT_OTHER_L3:   lookForRAType = RA_NXTHDROFFSET;    break;
        case PT_OTHER_L4:   lookForRAType = RA_NXTHDROFFSET;    break;
        default: throw CGenericErrorLine (ERR_INTERNAL_SP_ERROR, line);
    }

    eCode = RA::Instance().findTypeInRA(lookForRAType, object->location);
    if (!eCode)
        throw CGenericError (ERR_INTERNAL_SP_ERROR);
}

/*Find a protocol*/
ProtoType CIR::findProtoLabel (std::string nextproto, int line) const
{
    int i = 0;

    std::string newName = stripBlanks (nextproto);
    if (insensitiveCompare(newName, "end_parse") ||
        insensitiveCompare(newName, "none"))
        return PT_END_PARSE;
    else if (insensitiveCompare(newName, "return"))
        return PT_RETURN;
    else if (insensitiveCompare(newName, "after_ethernet"))
        return PT_NEXT_ETH;
    else if (insensitiveCompare(newName, "after_ip"))
        return PT_NEXT_IP;
    else
        return findSpecificProtocol(newName, line);
}

ProtoType CIR::findSpecificProtocol(std::string name, int line) const
{
    std::map< std::string, ProtoType >::iterator protocolsLabelsIterator;
    std::map< std::string, ProtoType> protocolsLabels;
    std::string newName = name;
    std::transform(newName.begin(), newName.end(), newName.begin(), mytolower);

    protocolsLabels["ethernet"]     = PT_ETH;
    protocolsLabels["llc_snap"]     = PT_LLC_SNAP;
    protocolsLabels["vlan"]         = PT_VLAN;
    protocolsLabels["pppoe"]        = PT_PPPOE_PPP;
    protocolsLabels["mpls"]         = PT_MPLS;
    protocolsLabels["ipv4"]         = PT_IPV4;
    protocolsLabels["ipv6"]         = PT_IPV6;
    protocolsLabels["gre"]          = PT_GRE;
    protocolsLabels["minencap"]     = PT_MINENCAP;
    protocolsLabels["otherl3"]      = PT_OTHER_L3;
    protocolsLabels["tcp"]          = PT_TCP;
    protocolsLabels["udp"]          = PT_UDP;
    protocolsLabels["ipsec_ah"]     = PT_IPSEC_AH;
    protocolsLabels["ipsec_esp"]    = PT_IPSEC_ESP;
    protocolsLabels["sctp"]         = PT_SCTP;
    protocolsLabels["dccp"]         = PT_DCCP;
    protocolsLabels["otherl4"]      = PT_OTHER_L4;

    protocolsLabelsIterator = protocolsLabels.find(newName);
    if (protocolsLabelsIterator == protocolsLabels.end())
        throw CGenericErrorLine (ERR_UNSUPPORTED_PROTOCOL, line, name);
    else
        return protocolsLabels[newName];
}

std::string CIR::createUniqueName()
{
    return std::string("LABEL_" + intToString(++currentUniqueName));
}

CENode* CIR::createENode()
{
    return new CENode;
}

/* ------------------------ CReg---------------------------------*/

/*Return the other working register or R_WR1 by default*/
CReg CReg::other()
{
    if      (type == R_WR0)
        return CReg(R_WR1);
    else if (type == R_WR1)
        return CReg(R_WR0);
    else if (type == R_EMPTY)
        return CReg(R_WR1);
    else
        throw CGenericError (ERR_INTERNAL_SP_ERROR);
}

std::string CReg::getName() const
{
    switch (type)
    {
        case R_WR1:  return "WR1";
        case R_WR0:  return "WR0";
        case R_WO:   return "WO";
        default:
            throw CGenericError (ERR_INTERNAL_SP_ERROR, "wrong register type");
    }
}

/* ------------------------ CObject -----------------------------*/

/*Returns string with object name (type and location)*/
std::string CObject::getName() const
{
    std::string objTypeName;
    std::string midChar;
    std::stringstream ss;
    std::string ret;
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
    else if (type == OB_PA)
    {
        objTypeName = "PA";
        midChar = ":";
    }
    ss << objTypeName << "[" << std::dec << location.start
       << midChar << std::dec << location.end << "]";
    ss >> ret;
    return ret;
}

bool CObject::isMoreThan32 () const
{
    if ((type == OB_PA || type == OB_RA) &&
        location.end-location.start>3)
        return 1;
    else if (type == OB_FW &&
             location.end-location.start>31)
         return 1;
    else
        return 0;
}

bool CObject::isMoreThan16 () const
{
    if ((type == OB_PA || type == OB_RA) &&
        location.end-location.start>1)
        return 1;
    else if (type == OB_FW &&
             location.end-location.start>15)
         return 1;
    else
        return 0;
}

/*------------------------ CENode Section--------------------------------*/

CENode::CENode (ENodeType newType, CENode* unary)
{
    *this = CENode();
    type       = newType;
    monadic    = unary;
}

CENode::CENode (ENodeType newType, CENode* left, CENode* right)
{
    *this = CENode();
    type           = newType;
    dyadic.left    = left;
    dyadic.right   = right;
    dyadic.dir     = 0;
}

void CENode::createIntENode(uint64_t intval1)
{
    this->type      = EINTCONST;
    this->intval    = intval1;
}

void CENode::newMonadicENode (ENodeType newType)
{
    this->type      = newType;
    this->monadic   = new CENode;
}

void CENode::newDyadicENode ()
{
    this->dyadic.left   = new CENode;
    this->dyadic.right  = new CENode;
    this->dyadic.dir    = 0;
}

void CENode::newDyadicENode (ENodeType newType)
{
    this->newDyadicENode();
    this->type          = newType;
}

void CENode::newObjectENode ()
{
    this->type      = EOBJREF;
    this->objref    = new CObject;
}

void CENode::newObjectENode (CLocation loc)
{
    this->type      = EOBJREF;
    this->objref    = new CObject(loc);
}

void CENode::newObjectENode (CObject obj)
{
    this->type      = EOBJREF;
    this->objref    = new CObject(obj);
}

void CENode::newObjectENode (RAType rat)
{
    this->type      = EOBJREF;
    this->objref    = new CObject(rat);
    RA::Instance().findTypeInRA(rat, this->objref->location);
}

/*Create a new copy of this ENode*/
CENode* CENode::newDeepCopy()
{
    CENode* retNode = newENode(type);
    retNode->line   = this->line;
    retNode->flags  = this->flags;
    retNode->reg    = this->reg;
    retNode->intval = this->intval;
    if (type == EOBJREF)
        retNode->newObjectENode(*(this->objref));
    else if (isDyadic())
    {
        retNode->dyadic.left  = this->dyadic.left->newDeepCopy();
        retNode->dyadic.right = this->dyadic.right->newDeepCopy();
    }
    else if (isMonadic())
        retNode->monadic = this->monadic->newDeepCopy();
    return retNode;
}

bool CENode::isMonadic () const
{
    if (type == ENOT    || type == EBITNOT)
        return 1;
    else
        return 0;
}

bool CENode::isDyadic () const
{
    if (this->isCondi()     || this->isCondNoti()
     || type == EAND        || type == EOR          || type == EXOR
     || type == ESHL        || type == ESHR         || type == ESHLAND
     || type == EADD        || type == EADDCARRY    || type == ESUB
     || type == ECHECKSUM   || type == ECHECKSUM_LOC
     || type == EBITOR      || type == EBITAND
     || type == EASS        )
        return 1;
    else
        return 0;
}

bool CENode::isCond () const
{
    if (this->isCondi() || this->isCondNoti() ||
        type == EAND    || type == EOR        || type == ENOT)
        return 1;
    else
        return 0;
}

bool CENode::isCondi () const
{
    if (type == ELESS || type == EGREATER || type == EEQU || type == ENOTEQU)
        return 1;
    else
        return 0;
}

bool CENode::isCondNoti () const
{
    if (type == ELESSEQU || type == EGREATEREQU)
        return 1;
    else
        return 0;
}

bool CENode::isMoreThan16 () const
{
    if (type == EINTCONST && ((intval & 0xffffffffffff0000ull) != 0))
        return 1;
    else if (type == EOBJREF && objref->isMoreThan16())
         return 1;
    else
        return 0;
}

bool CENode::isMoreThan32 () const
{
    if (type == EINTCONST &&
        ((intval & 0xffffffff00000000ull) != 0))
        return 1;
    else if (type == EOBJREF && objref->isMoreThan32())
         return 1;
    else
        return 0;
}

CENode* CENode::first() const
{
    if (!isDyadic())
        throw CGenericErrorLine (ERR_INTERNAL_SP_ERROR, line);
    if (dyadic.dir)
        return dyadic.right;
    else
        return dyadic.left;
}

CENode* CENode::second() const
{
    if (!isDyadic())
        throw CGenericErrorLine (ERR_INTERNAL_SP_ERROR, line);
    if (dyadic.dir)
        return dyadic.left;
    else
        return dyadic.right;
}


/*------------------------ Global function--------------------------------*/

CENode* newObjectENode()
{
    CENode* node = new CENode;
    node->newObjectENode();
    return node;
}

CENode* newENode(ENodeType type)
{
    CENode* node = new CENode;
    node->type = type;
    return node;
}

void    deleteEnode(CENode* expr)
{
    delete expr;
    expr = 0;
}


/*--------------------CStatement Section ---------------------------*/

void CStatement::newIfGotoStatement ()
{
    this->type              = ST_IFGOTO;
    this->expr              = new CENode;
    this->flags.hasENode    = 1;
}

void CStatement::newIfGotoStatement (CLabel label1, int line1)
{
    createIfGotoStatement(label1, line1);
    this->expr              = new CENode;
}

void CStatement::newExpressionStatement (int line1)
{
    this->type              = ST_EXPRESSION;
    this->expr              = new CENode;
    this->line              = line1;
    this->expr->line        = line1;
    this->flags.hasENode    = 1;
}

void CStatement::newAssignStatement (int line1)
{
    newExpressionStatement (line1);
    this->expr->type = EASS;
}

void CStatement::newSwitchStatement (int line1)
{
    this->type              = ST_SWITCH;
    this->switchTable       = new CSwitchTable;
    this->line              = line1;
    this->flags.hasENode    = 1;
}

void CStatement::createIfGotoStatement (CLabel label1, int line1)
{
    this->type              = ST_IFGOTO;
    this->label             = label1;
    this->line              = line1;
    this->flags.hasENode    = 1;
}

void CStatement::createIfNGotoStatement (CLabel label1, int line1)
{
    this->type              = ST_IFNGOTO;
    this->label             = label1;
    this->line              = line1;
    this->flags.hasENode    = 1;
}

void CStatement::createInlineStatement (std::string data, int line1)
{
    this->type  = ST_INLINE;
    this->text  = data;
    this->line  = line1;
}


void CStatement::createExpressionStatement (CENode *enode)
{
    this->type              = ST_EXPRESSION;
    this->expr              = enode;
    this->flags.hasENode    = 1;
}

void CStatement::createLabelStatement ()
{
    this->type = ST_LABEL;
}

void CStatement::createLabelStatement (std::string labelName)
{
    this->type = ST_LABEL;
    this->label.name = labelName;
}

void CStatement::createLabelStatement (CLabel label)
{
    this->type = ST_LABEL;
    this->label = label;
}

void CStatement::createGotoStatement (CLabel newLabel)
{
    this->type  = ST_GOTO;
    this->label = newLabel;
}

void CStatement::createGotoStatement (std::string labelName)
{
    this->type  = ST_GOTO;
    this->label = CLabel (labelName);
}

void CStatement::createGotoStatement (ProtoType type)
{
    this->type              = ST_GOTO;
    this->label             = CLabel (type);
    this->flags.externJump  = 1;
}

void CStatement::createSectionEndStatement ()
{
    this->type              = ST_SECTIONEND;
    this->flags.hasENode    = 1;
}

bool CStatement::isGeneralExprStatement () const
{
    if (this->flags.hasENode)
        return 1;
    else
        return 0;
}


/* ------------------- delete  --------------------------------------*/

void CENode::deleteObjectENode ()
{
    if (objref)
    {
        delete objref;
        objref = 0;
    }
}

void CENode::deleteMonadicENode ()
{
    if (monadic)
    {
        monadic->deleteENode();
        delete monadic;
        monadic = 0;
    }
}

void CENode::deleteDyadicENode ()
{
    if (dyadic.left)
    {
        dyadic.left->deleteENode();
        delete dyadic.left;
        dyadic.left = 0;
    }
    if (dyadic.right)
    {
        dyadic.right->deleteENode();
        delete dyadic.right;
        dyadic.right = 0;
    }
}

void CENode::deleteENode ()
{
    if (this->isDyadic())
        this->deleteDyadicENode();
    if (this->isMonadic())
        this->deleteMonadicENode();
    else if (type==EOBJREF)
        this->deleteObjectENode();
}

void CStatement::deleteStatementNonRecursive ()
{
    if (isGeneralExprStatement() && expr)
    {
        delete expr;
        expr = 0;
    }
    if (type == ST_SWITCH && switchTable)
    {
        delete switchTable;
        switchTable = 0;
    }
}


CStatement::CStatement()
    : type(ST_EMPTY), text(""), line(NO_LINE)
{
};


void CStatement::deleteStatement ()
{
    if (isGeneralExprStatement() && expr)
    {
        expr->deleteENode();
        delete expr;
        expr = 0;
    }
    if (type == ST_SWITCH && switchTable)
    {
        delete switchTable;
        switchTable = 0;
    }
}

void CIR::deleteIR ()
{
    uint32_t i=0, j=0;
    for (i = 0; i < protocolsIRs.size(); i++)
    {
        if (protocolsIRs[i].prevHeaderSize)
        {
            protocolsIRs[i].prevHeaderSize->deleteENode();
            delete protocolsIRs[i].prevHeaderSize;
            protocolsIRs[i].prevHeaderSize = 0;
        }
        if (protocolsIRs[i].headerSize)
        {
            protocolsIRs[i].headerSize->deleteENode();
            delete protocolsIRs[i].headerSize;
            protocolsIRs[i].headerSize = 0;
        }
        for (j = 0; j < protocolsIRs[i].statements.size(); j++)
            protocolsIRs[i].statements[j].deleteStatement();
    }
    deleteDumpPath();
}

/*-------------------- RA section------------------------------------*/

void RA::initRA()
{
    RAInInfo["gpr1"]                  = RA_GPR1;
    RAInInfo["gpr2"]                  = RA_GPR2;
    RAInInfo["logicalportid"]         = RA_LOGICALPORTID;
    RAInInfo["shimr"]                 = RA_SHIMR;
    RAInInfo["l2r"]                   = RA_L2R;
    RAInInfo["l3r"]                   = RA_L3R;
    RAInInfo["l4r"]                   = RA_L4R;
    RAInInfo["classificationplanid"]  = RA_CLASSIFICATIONPLANID;
    RAInInfo["nxthdr"]                = RA_NXTHDR;
    RAInInfo["runningsum"]            = RA_RUNNINGSUM;
    RAInInfo["flags"]                 = RA_FLAGS;
    RAInInfo["fragoffset"]            = RA_FRAGOFFSET;
    RAInInfo["routtype"]              = RA_ROUTTYPE;
    RAInInfo["rhp"]                   = RA_RHP;
    RAInInfo["ipvalid"]               = RA_IPVALID;
    RAInInfo["shimoffset_1"]          = RA_SHIMOFFSET_1;
    RAInInfo["shimoffset_2"]          = RA_SHIMOFFSET_2;
#ifdef FM_SHIM3_SUPPORT
    RAInInfo["shimoffset_3"]          = RA_SHIMOFFSET_3;
#else  /* FM_SHIM3_SUPPORT */
    RAInInfo["ip_pidoffset"]          = RA_IP_PIDOFFSET;
#endif /* FM_SHIM3_SUPPORT */
    RAInInfo["ethoffset"]             = RA_ETHOFFSET;
    RAInInfo["llc_snapoffset"]        = RA_LLC_SNAPOFFSET;
    RAInInfo["vlantcioffset_1"]       = RA_VLANTCIOFFSET_1;
    RAInInfo["vlantcioffset_n"]       = RA_VLANTCIOFFSET_N;
    RAInInfo["lastetypeoffset"]       = RA_LASTETYPEOFFSET;
    RAInInfo["pppoeoffset"]           = RA_PPPOEOFFSET;
    RAInInfo["mplsoffset_1"]          = RA_MPLSOFFSET_1;
    RAInInfo["mplsoffset_n"]          = RA_MPLSOFFSET_N;
    RAInInfo["ipoffset_1"]            = RA_IPOFFSET_1;
    RAInInfo["ipoffset_n"]            = RA_IPOFFSET_N;
    RAInInfo["minencapo"]             = RA_MINENCAPOFFSET;
    RAInInfo["minencapoffset"]        = RA_MINENCAPOFFSET;
    RAInInfo["greoffset"]             = RA_GREOFFSET;
    RAInInfo["l4offset"]              = RA_L4OFFSET;
    RAInInfo["nxthdroffset"]          = RA_NXTHDROFFSET;
    RAInInfo["framedescriptor1"]      = RA_FRAMEDESCRIPTOR1;
    RAInInfo["framedescriptor2"]      = RA_FRAMEDESCRIPTOR2;
    RAInInfo["framedescriptor2_low"]  = RA_FRAMEDESCRIPTOR2_LOW;
    RAInInfo["actiondescriptor"]      = RA_ACTIONDESCRIPTOR;
    RAInInfo["ccbase"]                = RA_CCBASE;
    RAInInfo["ks"]                    = RA_KS;
    RAInInfo["hpnia"]                 = RA_HPNIA;
    RAInInfo["sperc"]                 = RA_SPERC;
    RAInInfo["ipver"]                 = RA_IPVER;
    RAInInfo["iplength"]              = RA_IPLENGTH;
    RAInInfo["icp"]                   = RA_ICP;
    RAInInfo["attr"]                  = RA_ATTR;
    RAInInfo["nia"]                   = RA_NIA;
    RAInInfo["ipv4sa"]                = RA_IPV4SA;
    RAInInfo["ipv4da"]                = RA_IPV4DA;
    RAInInfo["ipv6sa1"]               = RA_IPV6SA1;
    RAInInfo["ipv6sa2"]               = RA_IPV6SA2;
    RAInInfo["ipv6da1"]               = RA_IPV6DA1;
    RAInInfo["ipv6da2"]               = RA_IPV6DA2;

    RATypeInfo[RA_GPR1]                  = CLocation(0,7);
    RATypeInfo[RA_GPR2]                  = CLocation(8,15);
    RATypeInfo[RA_LOGICALPORTID]         = CLocation(16,16);
    RATypeInfo[RA_SHIMR]                 = CLocation(17,17);
    RATypeInfo[RA_L2R]                   = CLocation(18,19);
    RATypeInfo[RA_L3R]                   = CLocation(20,21);
    RATypeInfo[RA_L4R]                   = CLocation(22,22);
    RATypeInfo[RA_CLASSIFICATIONPLANID]  = CLocation(23,23);
    RATypeInfo[RA_NXTHDR]                = CLocation(24,25);
    RATypeInfo[RA_RUNNINGSUM]            = CLocation(26,27);
    RATypeInfo[RA_FLAGS]                 = CLocation(28,28);
    RATypeInfo[RA_FRAGOFFSET]            = CLocation(28,29);
    RATypeInfo[RA_ROUTTYPE]              = CLocation(30,30);
    RATypeInfo[RA_RHP]                   = CLocation(31,31);
    RATypeInfo[RA_IPVALID]               = CLocation(31,31);
    RATypeInfo[RA_SHIMOFFSET_1]          = CLocation(32,32);
    RATypeInfo[RA_SHIMOFFSET_2]          = CLocation(33,33);
#ifdef FM_SHIM3_SUPPORT
    RATypeInfo[RA_SHIMOFFSET_3]          = CLocation(34,34);
#else  /* FM_SHIM3_SUPPORT */
    RATypeInfo[RA_IP_PIDOFFSET]          = CLocation(34,34);
#endif /* FM_SHIM3_SUPPORT */
    RATypeInfo[RA_ETHOFFSET]             = CLocation(35,35);
    RATypeInfo[RA_LLC_SNAPOFFSET]        = CLocation(36,36);
    RATypeInfo[RA_VLANTCIOFFSET_1]       = CLocation(37,37);
    RATypeInfo[RA_VLANTCIOFFSET_N]       = CLocation(38,38);
    RATypeInfo[RA_LASTETYPEOFFSET]       = CLocation(39,39);
    RATypeInfo[RA_PPPOEOFFSET]           = CLocation(40,40);
    RATypeInfo[RA_MPLSOFFSET_1]          = CLocation(41,41);
    RATypeInfo[RA_MPLSOFFSET_N]          = CLocation(42,42);
    RATypeInfo[RA_IPOFFSET_1]            = CLocation(43,43);
    RATypeInfo[RA_IPOFFSET_N]            = CLocation(44,44);
    RATypeInfo[RA_MINENCAPOFFSET]        = CLocation(44,44);
    RATypeInfo[RA_GREOFFSET]             = CLocation(45,45);
    RATypeInfo[RA_L4OFFSET]              = CLocation(46,46);
    RATypeInfo[RA_NXTHDROFFSET]          = CLocation(47,47);
    RATypeInfo[RA_FRAMEDESCRIPTOR1]      = CLocation(48,55);
    RATypeInfo[RA_FRAMEDESCRIPTOR2]      = CLocation(56,63);
    RATypeInfo[RA_FRAMEDESCRIPTOR2_LOW]  = CLocation(60,63);
    RATypeInfo[RA_ACTIONDESCRIPTOR]      = CLocation(64,71);
    RATypeInfo[RA_CCBASE]                = CLocation(72,75);
    RATypeInfo[RA_KS]                    = CLocation(76,76);
    RATypeInfo[RA_HPNIA]                 = CLocation(77,79);
    RATypeInfo[RA_SPERC]                 = CLocation(80,80);
    RATypeInfo[RA_IPVER]                 = CLocation(85,85);
    RATypeInfo[RA_IPLENGTH]              = CLocation(86,87);
    RATypeInfo[RA_ICP]                   = CLocation(90,91);
    RATypeInfo[RA_ATTR]                  = CLocation(92,92);
    RATypeInfo[RA_NIA]                   = CLocation(93,95);
    RATypeInfo[RA_IPV4SA]                = CLocation(96,99);
    RATypeInfo[RA_IPV4DA]                = CLocation(100,103);
    RATypeInfo[RA_IPV6SA1]               = CLocation(96,103);
    RATypeInfo[RA_IPV6SA2]               = CLocation(104,111);
    RATypeInfo[RA_IPV6DA1]               = CLocation(112,119);
    RATypeInfo[RA_IPV6DA2]               = CLocation(120,127);
}

RA::RA () {}
RA::~RA () {}

bool RA::findTypeInRA (const RAType type, CLocation &location, int line)
{
    if (type == RA_GPR2)
        CGenericErrorLine::printWarning(WARN_GPR2, line);

    RATypeIterator = RATypeInfo.find (type);
    if (RATypeIterator == RATypeInfo.end())
        throw CGenericError(ERR_INTERNAL_SP_ERROR);
    else
    {
        location.start  = RATypeInfo[type].start;
        location.end    = RATypeInfo[type].end;
        return 1;
    }
}

bool RA::findNameInRA (const std::string name, RAType &type, CLocation &location, int line)
{
    std::string newName = name;
    std::transform(newName.begin(), newName.end(), newName.begin(), mytolower);
    RAInIterator = RAInInfo.find (newName);
    if (RAInIterator == RAInInfo.end())
        return 0;
    else
        type = RAInInfo[newName];

    findTypeInRA (type, location, line);
    return 1;
}


/* -----------------------------General functions (no class)-----------*/
CLocation CLocation::operator+ (const CLocation location) const
{
    CLocation returnLoc;
    returnLoc.start = this->start + location.start;
    returnLoc.end = this->end + location.end;
    return returnLoc;
}

CLocation & CLocation::operator+= (const CLocation location)
{
    start += location.start;
    end   += location.end;
    return *this;
}

CLocation & CLocation::operator-= (const CLocation location)
{
    start -= location.start;
    end   -= location.end;
    return *this;
}


/* ------------------------------------- Lex/Yacc ---------------------*/
CENode*      exprYacc;
CIR*         irYacc;
int*         lineYacc;

void setExpressionYacc(CENode* expr1)
{
    exprYacc = expr1;
}

CENode* getExpressionYacc()
{
    return exprYacc;
}

void setIRYacc(CIR* ir)
{
    irYacc = ir;
}

CIR *getIRYacc()
{
    return irYacc;
}

void setLineYacc(int* line)
{
    lineYacc = line;
}

int *getLineYacc()
{
    return lineYacc;
}
