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
 * File Name : FMCSPIR.h
 * Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#ifndef IR_H
#define IR_H

#include <iostream>
#include <algorithm>
#include "FMCTaskDef.h"
#include "FMCUtils.h"

extern int FMCSPExprparse();
typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern YY_BUFFER_STATE FMCSPExpr_scan_string(const char *yy_str);
extern int FMCSPExprlex_destroy (void );

class CENode;
class CStatement;
class CIR;

typedef enum RegType {
    R_WR0,
    R_WR1,
    R_WO,
    R_EMPTY
} RegType;

typedef enum ENodeType {                // Expression node types
    /*dyadic*/
    ELESS,EGREATER,ELESSEQU,EGREATEREQU,//  lt, gt, le, ge
    EEQU, ENOTEQU,                      //  == , !=
    EADD, EADDCARRY, ESUB,              //  +, addcarry, -
    EBITAND, EXOR, EBITOR,              //    bitwand, bitwxor, bitwor
    ESHL, ESHR,    ESHLAND,             //    <<, >>,
    EASS,                               //  =
    ECHECKSUM, ECHECKSUM_LOC,           //  checksum,
    /*Monadic*/
    EOBJREF,                            //  objects
    EINTCONST,                          //  numbers
    EEMPTY,                             //  no value set yet
    EREG,                               //  register, used in createCode process
    /*The following statements must be replaced in the reviseIR process
      since they are not recognized in the createCode process*/
    /*Dyadic*/
    EAND, EOR,                          //  &&, ||
    /*Monadic*/
    ENOT, EBITNOT                       //    not, bitwnot
}ENodeType;

typedef enum ObjectType {
    OB_FW,
    OB_RA,
    OB_PA,
    OB_WO,
    OBJ_LOCAL
}ObjectType;

typedef enum RAType {
    RA_EMPTY,  //Not an RA object
    RA_GPR1,
    RA_GPR2,
    RA_LOGICALPORTID,
    RA_SHIMR,
    RA_L2R,
    RA_L3R,
    RA_L4R,
    RA_CLASSIFICATIONPLANID,
    RA_NXTHDR,
    RA_RUNNINGSUM,
    RA_FLAGS,
    RA_FRAGOFFSET,
    RA_ROUTTYPE,
    RA_RHP,
    RA_IPVALID,
    RA_SHIMOFFSET_1,
    RA_SHIMOFFSET_2,
#ifdef FM_SHIM3_SUPPORT
    RA_SHIMOFFSET_3,
#else  /* FM_SHIM3_SUPPORT */
    RA_IP_PIDOFFSET,
#endif /* FM_SHIM3_SUPPORT */
    RA_ETHOFFSET,
    RA_LLC_SNAPOFFSET,
    RA_VLANTCIOFFSET_1,
    RA_VLANTCIOFFSET_N,
    RA_LASTETYPEOFFSET,
    RA_PPPOEOFFSET,
    RA_MPLSOFFSET_1,
    RA_MPLSOFFSET_N,
    RA_IPOFFSET_1,
    RA_IPOFFSET_N,
    RA_MINENCAPOFFSET,
    RA_GREOFFSET,
    RA_L4OFFSET,
    RA_NXTHDROFFSET,
    RA_FRAMEDESCRIPTOR1,
    RA_FRAMEDESCRIPTOR2,
    RA_FRAMEDESCRIPTOR2_LOW,
    RA_ACTIONDESCRIPTOR,
    RA_CCBASE,
    RA_KS,
    RA_HPNIA,
    RA_SPERC,
    RA_IPVER,
    RA_IPLENGTH,
    RA_ICP,
    RA_ATTR,
    RA_NIA,
    RA_IPV4SA,
    RA_IPV4DA,
    RA_IPV6SA1,
    RA_IPV6SA2,
    RA_IPV6DA1,
    RA_IPV6DA2
}RAType;

typedef enum TokenType {
    TVARIABLE,
    TNUMBER,
    THEXA,
    TOPERATION,
    TERROR
}TokenType;

/* Start with TO to signify a Token Operator*/
typedef enum TokenOperatorType {
    TO_UNKNOWN,
    TO_ADD,  TO_SUB,
    TO_AND,  TO_OR,         TO_XOR,
    TO_SHL,  TO_SHR,
    TO_EQU,  TO_NOTEQU,
    TO_LESS, TO_GREATER,    TO_LESSEQU,      TO_GREATEREQU
}TokenOperatorType;

typedef enum StatementType {
    ST_NOP=1,           //  no operation
    ST_SECTIONEND,      //  end of section (header base stored in expr)
    ST_LABEL,           //  label statement
    ST_GOTO,            //  goto
    ST_EXPRESSION,      //  expression statement
    ST_EMPTY,           //  statement still has no value
    ST_SWITCH,          //  switch statement
    ST_INLINE,          //  inline assembly
    ST_IFGOTO,          //  if expression is true goto 'label'
    ST_IFNGOTO          //  if expression is NOT true goto 'label
                        //  the statement must be replaced in reviseIR process
                        //  since it's not recognized in the createCode process
} StatementType;

class CReg {
  public:
    RegType type;

    CReg()              : type(R_EMPTY) {}
    CReg(RegType type1) : type(type1) {}

    CReg        other();
    std::string getName() const;
};

class CLocation
{
  public:
    uint32_t start;
    uint32_t end;
    CLocation (uint32_t a=0, uint32_t b=0) : start(a), end(b) {}
    CLocation operator+     (const CLocation location) const;
    CLocation &  operator+= (const CLocation location);
    CLocation &  operator-= (const CLocation location);
};

class CObjectFlags
{
public:
    bool dummyFlag;                     //just an example

    CObjectFlags() : dummyFlag(0) {}
};

class CObject
{
  public:
    std::string             name;       //  object name
    ObjectType              type;       //  the type of the object
    RAType                  typeRA;     //  specific RA object
    CObjectFlags            flags;      //  object flags
    CLocation               location;   //  index in buffer

    CObject (): typeRA (RA_EMPTY) {}
    CObject (CLocation loc):   typeRA (RA_EMPTY), location(loc) {}
    CObject (ObjectType type1): type(type1), typeRA(RA_EMPTY)  {}
    CObject (RAType typeRA1):   type(OB_RA), typeRA(typeRA1)   {}
    CObject (ObjectType type1, CLocation loc): type(type1), typeRA (RA_EMPTY),
                                               location(loc) {}

    bool        isMoreThan32    () const;
    bool        isMoreThan16    () const;
    std::string getName         () const;
    void        dumpObject      (std::ofstream &outFile, uint8_t spaces) const;
};

class CDyadic
{
  public:
      CENode *left;
      CENode *right;
      bool    dir;
};

class CSwitchTable
{
  public:
    std::vector  <uint16_t>          values;
    std::vector  <CLabel>            labels;
    bool                             lastDefault;
    CSwitchTable (): lastDefault(0) {};
};

class CENodeFlags
{
  public:
    bool    rightInt;
    bool    concat;

    CENodeFlags() : rightInt(0), concat(0) {}
}
;

class CENode
{
  public:
    ENodeType       type;           //  type of node operation
    CENodeFlags     flags;          //  expression flags
    CReg            reg;            //  Register attached to node
    int             line;           //  source file line number
    int             weight;         //  weight, for register allocation
    uint64_t        intval;         //  integral value
    CObject*        objref;         //  pointer to referenced object
    CDyadic         dyadic;         //  points to next two nodes in tree
    CENode*         monadic;        //  points to next node

    /*constructors*/
    CENode (): type(EEMPTY), line(NO_LINE), weight(0), intval(0),
               objref(0), monadic(0)  {}
    CENode (ENodeType newType, CENode* unary) ;
    CENode (ENodeType newType, CENode* left, CENode* right);

    bool isMonadic      () const;
    bool isDyadic       () const;
    bool isCond         () const;
    bool isCondi        () const;
    bool isCondNoti     () const;
    bool isMoreThan32   () const;
    bool isMoreThan16   () const;

    /* revise/dump functions */
    void dumpExpression (std::ofstream &outFile, uint8_t spaces) const;
    void dumpMonadic    (std::ofstream &outFile, uint8_t spaces) const;
    void dumpDiadic     (std::ofstream &outFile, uint8_t spaces) const;
    void dumpInt        (std::ofstream &outFile, uint8_t spaces) const;
    void dumpReg        (std::ofstream &outFile, uint8_t spaces) const;
    void assignWeight   ();
    CENode* first       () const;
    CENode* second      () const;

    /* create/new/delete functions */
    CENode* newDeepCopy();
    void createIntENode (uint64_t intval);
    void newDyadicENode ();
    void newDyadicENode (ENodeType newType);
    void newMonadicENode(ENodeType newType = EEMPTY);
    void newObjectENode ();
    void newObjectENode (RAType rat);
    void newObjectENode (CLocation loc);
    void newObjectENode (CObject   obj);
    void deleteENode        ();
    void deleteMonadicENode ();
    void deleteDyadicENode  ();
    void deleteObjectENode  ();
};

class CStatementFlags
{
  public:
    bool hasENode;          // this statement has an ENode
    bool externJump;        // jump out of softparser
    bool confirm;           // confirm prev protocol (using CLM)
    bool advanceJump;       // jump and advance HB
    bool afterSection;      // statement refers to after section
    bool lastStatement;     // last statement (end after or before section)
    bool confirmLCV_DEFAULT;// or LCV by default value
    bool confirmLCV1;       // or LCV by shim1   value
    bool confirmLCV2;       // or LCV by shim2   value
#ifdef FM_SHIM3_SUPPORT
    bool confirmLCV3;       // or LCV by shim3   value
#endif /* FM_SHIM3_SUPPORT */

    CStatementFlags():hasENode(0), externJump(0), confirm(1), advanceJump(1),
                      afterSection(0), lastStatement(0), confirmLCV_DEFAULT(1),
                      confirmLCV1(0), confirmLCV2(0)
#ifdef FM_SHIM3_SUPPORT
                      , confirmLCV3(0)
#endif /* FM_SHIM3_SUPPORT */
    {}
};

class CStatement
{
 public:
    StatementType       type;           //    statement type
    CStatementFlags     flags;          //    statement flags
    CENode              *expr;          //  statement expression
    CSwitchTable        *switchTable;   //  cases and labels for ST_SWITCH
    CLabel              label;          //  Either current label or where to jump
    std::string         text;           //  Needed for inline asm
    int                 line;

    void newExpressionStatement (int line1 = NO_LINE);
    void newAssignStatement     (int line1);
    void newSwitchStatement     (int line1 = NO_LINE);
    void newIfGotoStatement     ();
    void newIfGotoStatement     (CLabel label1, int line1 = NO_LINE);
    void newChecksumStatement   (int line1);
    void createExpressionStatement (CENode *enode);
    void createIfGotoStatement  (CLabel label1,    int line1);
    void createIfNGotoStatement (CLabel label1,    int line1);
    void createInlineStatement  (std::string data, int line1);
    void createGotoStatement    (CLabel newLabel);
    void createGotoStatement    (std::string labelName);
    void createGotoStatement    (ProtoType type);
    void createLabelStatement   ();
    void createLabelStatement   (std::string labelName);
    void createLabelStatement   (CLabel label);
    void createSectionEndStatement ();

    bool isGeneralExprStatement () const;
    void reviseStatement        (CENode*& expr, bool  &revised);
    void reviseNot              (CENode*& expr, bool  &revised);
    void reviseBitnot           (CENode*& expr, bool  &revised);
    void dumpStatement          (std::ofstream &outFile, uint8_t spaces) const;

    CStatement();
    void deleteStatement            ();
    void deleteStatementNonRecursive();
};

class CProtocolIR {
  public:
    CLabel                   label;
    CProtocol                protocol;
    std::vector <CStatement> statements;
    CIR*                     ir;
    CENode*                  headerSize;
    CENode*                  prevHeaderSize;

    CProtocolIR() :                     headerSize(0), prevHeaderSize(0) {}
    CProtocolIR(CLabel label1, CProtocol proto) :
        label(label1), protocol(proto), headerSize(0), prevHeaderSize(0) {}

    void reviseProtocolIR   (CIR *ir);
    void reviseAnd          (uint32_t i,  CIR *ir, bool &revised);
    void reviseOr           (uint32_t i, bool &revised);
    void reviseIfngoto      (uint32_t i, bool &revised);
    void insertStatement    (uint32_t i, CStatement statement);
    void eraseStatement     (uint32_t i);

    void dumpProtocol(std::ofstream &outFile, uint8_t spaces) const;
};

class CIRStatus
{
  public:
    int                       currentProtoIndex;
    bool                      currentAfter; //currently working on 'after'

    CIRStatus() : currentProtoIndex(0), currentAfter(0) {}
};

class CIR
{
  public:
    std::vector <CProtocolIR> protocolsIRs;
    CTaskDef                   *task;
    CIRStatus                 status;
    static uint32_t           currentUniqueName;
    std::ofstream             *outFile;

    CIR() : outFile(0) {}

    void setTask (CTaskDef *task1);
    void createIR ();
    void initIRProto(std::vector <CStatement> &statements);
    void createIR (CTaskDef *newTask);
    void createIRSection     (CExecuteSection    section,    CProtocolIR& pIR);
    void createIRExpressions (CExecuteSection    section,    std::vector<CStatement> &statements);
    void createIRAction      (CExecuteAction     action,     std::vector<CStatement> &statements);
    void createIRAssign      (CExecuteAssign     assign,     std::vector<CStatement> &statements);
    void createIRIf          (CExecuteIf         instr,      std::vector<CStatement> &statements);
    void createIRLoop        (CExecuteLoop       instr,      std::vector<CStatement> &statements);
    void createIRInline      (CExecuteInline     instr,      std::vector<CStatement> &statements);
    void createIRSwitch      (CExecuteSwitch     switchElem, std::vector<CStatement> &statements);
    void createLCV           (std::string confirmCustom, CStatement &stmt, int line);

    /*expressions and objects*/
    void createIRExprValue          (std::string name, CENode*& eNode,  int line, int replace=0);
    void createIRVariable           (std::string name, CObject *object, int line);
    void createIRVariableAccess     (std::string name, CObject *object, int line);
    void createIRFWAccess           (std::string name, CObject *object, int line);
    void createIRProtocolField      (std::string name, CObject *object, int line);
    void createIRField              (std::string name, CObject *object, int line);
    ProtoType findProtoLabel        (std::string nextproto, int line) const;
    ProtoType findSpecificProtocol  (std::string newName,   int line) const;
    void getBufferInfo              (std::string &name,     uint32_t &startByte, uint32_t &sizeByte, int line, bool bits);
    void checkExprValue             (CENode* eNode,         int line) const;
    void findInFW                   (std::string protocolName, std::string fieldName, CLocation &location, int line) const;
    void findPrevprotoOffset        (CObject *object,       int line) const;
    std::string getCurrentProtoName () const;

    /*more general functions*/
    void        uniteSections   (std::vector< CExecuteSection> &executeSections);
    std::string createUniqueName();
    CENode*     createENode     ();
    uint32_t    calculateFormatSize (int line);

    /*dump*/
    void setDumpIr      (std::string path);
    void dumpEntireIR   () const;
    void deleteDumpPath ();

    /*revise*/
    void reviseEntireIR();

    /*delete*/
    void deleteIR ();
};

//Singleton
class RA
{
  public:
    std::map <std::string, RAType>::iterator RAInIterator;
    std::map <std::string, RAType> RAInInfo;

    std::map <RAType, CLocation >::iterator RATypeIterator;
    std::map <RAType, CLocation > RATypeInfo;

    static   RA& Instance()
    {
        static   RA  instance;
        return   instance;
    }
    bool findNameInRA (const std::string name, RAType &type, CLocation &location, int line=NO_LINE);
    bool findTypeInRA (const RAType type, CLocation &location, int line=NO_LINE);

    void initRA();
  private:
    RA();
    ~RA ();
};

/*General function (no class)*/
std::ofstream & operator<<(std::ofstream & , const CSwitchTable switchTable);
CENode* newObjectENode();

CENode* newENode(ENodeType type = EEMPTY);
void    deleteEnode(CENode* expr);

/* Functions for Yacc*/
void setExpressionYacc(CENode* expr1);
CENode* getExpressionYacc();
void setIRYacc(CIR *ir);
CIR *getIRYacc();
void setLineYacc(int* line);
int *getLineYacc();

#endif //IR_H
