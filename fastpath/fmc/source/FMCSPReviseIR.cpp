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
 * File Name : FMCSPReviseIR.cpp
 * Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#include "FMCSPIR.h"

void CIR::reviseEntireIR ()
{
    uint32_t i;
    for (i = 0; i < protocolsIRs.size(); i++)
        protocolsIRs[i].reviseProtocolIR(this);
}

void CProtocolIR::reviseProtocolIR(CIR *ir)
{
    uint32_t i;
    bool revised = 1;
    while (revised)
    {
        revised = 0;
        for (i = 0; i < statements.size(); i++)
        {
            if (statements[i].type == ST_IFGOTO &&
                statements[i].expr->type == EAND)
                    reviseAnd(i, ir, revised);
            if (statements[i].type == ST_IFGOTO &&
                statements[i].expr->type == EOR)
                    reviseOr(i, revised);
            if (statements[i].type == ST_IFNGOTO)
                    reviseIfngoto(i, revised);
            if (statements[i].isGeneralExprStatement())
                    statements[i].reviseStatement(statements[i].expr, revised);
        }
        /*if (revised)
        {
            *(ir->outFile) << "\n\n\n-----------TEMP----------\n\n\n";
            dumpProtocol(*(ir->outFile), 0);
        }*/
    }

    /*After we have a final IR version we are ready to prepare
      for register assignment by assigning weight*/
    for (i = 0; i < statements.size(); i++)
    {
        if (statements[i].isGeneralExprStatement())
            statements[i].expr->assignWeight();
    }
}

/* Check for too complex expressions, assign weight (how many registers)
       are needed for this node and its children) and decide if the left or
       right node should be calculated first*/
void CENode::assignWeight ()
{
    if (type == ECHECKSUM)
    {
        dyadic.left->assignWeight();
        dyadic.right->assignWeight();
        weight = 3;
    }
    else if (isDyadic())
    {
        dyadic.left->assignWeight();
        dyadic.right->assignWeight();

        /*In these case we can use only one register
          for example WR0=WR0+1*/
        if (dyadic.right->type == EINTCONST && !isCondNoti() &&
           !dyadic.right->isMoreThan32()    && type!=EADDCARRY)
        {
            weight = dyadic.left->weight;
            flags.rightInt = 1;
        }
        else if (dyadic.left->weight == dyadic.right->weight)
            weight = dyadic.left->weight+1;
        else if (dyadic.left->weight > dyadic.right->weight)
            weight = dyadic.left->weight;
        else
            weight = dyadic.right->weight;

        /*If dir==1 we should start by calculating the right node*/
        if (dyadic.right->weight > dyadic.left->weight)
            dyadic.dir = 1;
    }
    else if (isMonadic())
    {
        monadic->assignWeight();
        weight = monadic->weight;
    }
    else
        weight = 1;

    if (weight == 4)
        throw CGenericErrorLine (ERR_COMPLEX_EXPR, line);
}

void CStatement::reviseStatement(CENode*& expr, bool  &revised)
{
    if (expr->type == ENOT)
    {
        reviseNot(expr->monadic, revised);
        CENode* temp = expr;
        expr = expr->monadic;
        deleteEnode (temp);
    }
    if (expr->type == EBITNOT)
        reviseBitnot(expr, revised);

    if (expr->isDyadic())
    {
        reviseStatement(expr->dyadic.left,  revised);
        reviseStatement(expr->dyadic.right, revised);
    }
    if (expr->isMonadic())
        reviseStatement(expr->monadic,      revised);
}

/*Replace 'and' with two seperate expressions
IFGOTO LABEL_1               IFNGOTO LABEL_2
    EAND                         COND_A
        COND_A      =>       IFNGOTO LABEL_2
        COND_B                   COND_B
                             GOTO LABEL_1
                             LABEL_2:        */
void CProtocolIR::reviseAnd(uint32_t i, CIR *ir, bool &revised)
{
    std::vector <CStatement>::iterator statementsI;
    CStatement falseLStatement, gStatement, newStatement1, newStatement2;
    falseLStatement.createLabelStatement(ir->createUniqueName());
    int line = statements[i].line;

    newStatement1.createIfNGotoStatement(falseLStatement.label, line);
    newStatement2.createIfNGotoStatement(falseLStatement.label, line);
    newStatement1.expr  = statements[i].expr->dyadic.left;
    newStatement2.expr  = statements[i].expr->dyadic.right;
    statements[i].deleteStatementNonRecursive();
    gStatement.createGotoStatement(statements[i].label);

    /*insert new statements*/
    insertStatement(i+1, newStatement1);
    insertStatement(i+2, newStatement2);
    insertStatement(i+3, gStatement);
    insertStatement(i+4, falseLStatement);
    eraseStatement (i);
    revised = 1;
}

/*Replace 'or' with two seperate expressions
IFGOTO LABEL_1               IFGOTO LABEL1
    EOR                         COND_A
        COND_A      =>       IFGOTO LABEL1
        COND_B                  COND_B      */
void CProtocolIR::reviseOr(uint32_t i, bool& revised)
{
    std::vector <CStatement>::iterator statementsI;
    CStatement newStatement1, newStatement2;

    newStatement1.createIfGotoStatement(statements[i].label, statements[i].line);
    newStatement2.createIfGotoStatement(statements[i].label, statements[i].line);
    newStatement1.expr = statements[i].expr->dyadic.left;
    newStatement2.expr = statements[i].expr->dyadic.right;
    statements[i].deleteStatementNonRecursive();

    /*insert new statements*/
    insertStatement (i+1, newStatement1);
    insertStatement (i+2, newStatement2);
    eraseStatement  (i);
    revised = 1;
}

/*Replace 'ifngoto' with ifgoto (which is recognized in the
create code process)
IFNGOTO LABEL_1              IFGOTO LABEL1
    ECOND           =>           NOT ECOND */
void CProtocolIR::reviseIfngoto(uint32_t i, bool &revised)
{
    statements[i].type = ST_IFGOTO;
    statements[i].reviseNot (statements[i].expr, revised);
    revised = 1;
}

void CStatement::reviseBitnot (CENode*& expr, bool  &revised)
{
    CENode* origExpr            = expr;
    expr->type                  = EXOR;
    expr->dyadic.left           = origExpr->monadic;
    expr->dyadic.right          = newENode(EINTCONST);
    expr->dyadic.right->intval  = 0xFFFFFFFFFFFFFFFFull;
    revised = 1;
}

void CStatement::reviseNot (CENode*& expr, bool  &revised)
{
    CENode* temp = expr;
    switch (expr->type) {
    case ELESS:       expr->type=EGREATEREQU; break;
    case EGREATEREQU: expr->type=ELESS;       break;
    case ELESSEQU:    expr->type=EGREATER;    break;
    case EGREATER:    expr->type=ELESSEQU;    break;
    case EEQU:        expr->type=ENOTEQU;     break;
    case ENOTEQU:     expr->type=EEQU;        break;
    case EAND:
       expr->type=EOR;
       reviseNot(expr->dyadic.left,  revised);
       reviseNot(expr->dyadic.right, revised);
       break;
    case EOR:
       expr->type=EAND;
       reviseNot(expr->dyadic.left,  revised);
       reviseNot(expr->dyadic.right, revised);
       break;
    case ENOT:
       expr = expr->monadic;
       deleteEnode (temp);
       break;
    default:
       throw CGenericErrorLine (ERR_EXPECTED_COND_NOT, expr->line);
    }
    revised = 1;
}

/*---------------------insert / delete statement ------------*/

void CProtocolIR::insertStatement(uint32_t i, CStatement statement)
{
    std::vector <CStatement>::iterator statementsI;
    statementsI = statements.begin()+i;
    statements.insert(statementsI, statement);
}

void CProtocolIR::eraseStatement(uint32_t i)
{
    std::vector <CStatement>::iterator statementsI;
    statementsI = statements.begin()+i;
    statements.erase(statementsI);
}

