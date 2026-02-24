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
 * File Name : FMCTaskDef.h
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#ifndef TASKDEF_H
#define TASKDEF_H

#include <vector>
#include <string>
#include <map>
#include <set>
#include <ostream>
#include <fstream>

/* For strtoull */
#include <stdlib.h>
#ifdef _MSC_VER
#define snprintf _snprintf
#define strtoull _strtoui64
#define strtoll _strtoi64
#endif

#include "FMCGenericError.h"
#include "FMCUtils.h"

#define MAX_CC_KEY 56
#define MAX_INSERT_SIZE 56 //TODO check max size with driver team
#define MAX_IPREPLACE_SIZE 256

class CExecuteExpression;
class CExecuteSection;
class CProtocol;
class CLabel;

/// A set of named numbers with fixed values
typedef std::map< std::string, unsigned int >           CConstants;
/// Iterator class for constant values container
typedef std::map< std::string, unsigned int >::iterator CConstantsIter;


typedef enum ExecuteInstructionType {
    IF,
    LOOP,
    ACTION,
    ASSIGN,
    INLINE,
    SWITCH
} ExecuteInstructionType;

typedef enum ExecuteSectionType {
    INIT,
    BEFORE,
    AFTER,
    VERIFY,
    EMPTY /* EMPTY is used when the ExecuteSection class is accessed because
             of IN statement and not due to a new section*/
} ExecuteSectionType;


typedef enum ProtoType {
    PT_ETH,
    PT_LLC_SNAP,
    PT_VLAN,
    PT_PPPOE_PPP,
    PT_MPLS,
    PT_IPV4,
    PT_IPV6,
    PT_OTHER_L3,
    PT_GRE,
    PT_MINENCAP,
    PT_TCP,
    PT_UDP,
    PT_IPSEC_AH,
    PT_IPSEC_ESP,
    PT_SCTP,
    PT_DCCP,
    PT_OTHER_L4,
    PT_NEXT_ETH,
    PT_NEXT_IP,
    PT_RETURN,
    PT_END_PARSE
} ProtoType;

class CField
{
  public:
    std::string type;
    std::string name;
    std::string size;
    std::string longname;
    std::string showtemplate;
    std::string mask;
    std::string plugin;
    std::string expr;
    std::string description;
    std::string endtoken;
    std::string begintoken;
    std::string endregex;
    std::string endoffset;
    std::string beginregex;
    std::string beginoffset;
    std::string bigendian;
    std::string comment;
    std::string align;
    std::string enddiscard;
    std::string offset;
};

typedef enum e_FmPcdExtractSource {
    ES_FROM_FRAME_START,          /**< KG & CC: Extract from beginning of frame */
    ES_FROM_DFLT_VALUE,           /**< KG only: Extract from a default value */
    ES_FROM_CURR_END_OF_PARSE,    /**< KG only: Extract from the point where parsing had finished */
    ES_FROM_KEY,                  /**< CC only: Field where saved KEY */
    ES_FROM_HASH,                 /**< CC only: Field where saved HASH */
    ES_FROM_PARSE_RESULT,         /**< KG & CC: Extract from the parser result */
    ES_FROM_ENQ_FQID,             /**< KG & CC: Extract from enqueue FQID */
    ES_FROM_FLOW_ID               /**< CC only: Field where saved Dequeue FQID */
} e_FmPcdExtractSource;

typedef enum e_FmPcdExtractAction {
    EA_NONE,                           /**< NONE  */
    EA_EXACT_MATCH,                    /**< Exact match on the selected extraction*/
    EA_INDEXED_LOOKUP                  /**< Indexed lookup on the selected extraction*/
} e_FmPcdExtractAction;

class CConfirmCustomExtractor
{
  public:
    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const = 0;
};


class CExecuteSection : public CConfirmCustomExtractor
{
  public:
    std::vector< CExecuteExpression> executeExpressions;
    ExecuteSectionType               type;
    std::string                      when;
    std::string                      confirm;
    std::string                      confirmCustom;
    int                              line;

    CExecuteSection     () : line(NO_LINE) {};
    CExecuteSection     (ExecuteSectionType type1) : type(type1), line(NO_LINE) {};
    void dumpSection    (std::ofstream &outFile, uint8_t spaces);
    void deleteSection  ();

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const;
};


class CExecuteAssign : public CConfirmCustomExtractor
{
  public:
    std::string     name;
    std::string     value;
    std::string     fwoffset;
    int             line;

    CExecuteAssign  () : line(NO_LINE) {};
    void dumpAssign (std::ofstream &outFile, uint8_t spaces);

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const {};
};

class CExecuteAction : public CConfirmCustomExtractor
{
  public:
    std::string     type;
    std::string     value;
    std::string     nextproto;
    std::string     advance;
    std::string     confirm;
    std::string     confirmCustom;
    int             line;

    CExecuteAction  () : line(NO_LINE) {};
    void dumpAction (std::ofstream &outFile, uint8_t spaces);

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const;
};

class CExecuteLoop : public CConfirmCustomExtractor
{
  public:
    std::string      type;
    std::string      expr;
    CExecuteSection  loopBody;
    int              line;

    CExecuteLoop  () :                  line(NO_LINE) {}
    CExecuteLoop  (std::string expr1) : expr(expr1), line(NO_LINE) {}
    void dumpLoop (std::ofstream &outFile, uint8_t spaces);

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const;
};

class CExecuteIf : public CConfirmCustomExtractor
{
  public:
    std::string      expr;
    CExecuteSection  ifTrue;
    CExecuteSection  ifFalse;
    int              line;
    bool             ifTrueValid;
    bool             ifFalseValid;

    CExecuteIf  () :                  ifTrueValid( false ), ifFalseValid( false ), line(NO_LINE) {}
    CExecuteIf  (std::string expr1) : ifTrueValid( false ), ifFalseValid( false ), expr(expr1), line(NO_LINE) {}
    void dumpIf (std::ofstream &outFile, uint8_t spaces);

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const;
};

class CExecuteInline : public CConfirmCustomExtractor
{
  public:
    std::string      data;
    int              line;

    CExecuteInline  () :                  data(""),    line(NO_LINE) {}
    CExecuteInline  (std::string data1) : data(data1), line(NO_LINE) {}
    void dumpInline (std::ofstream &outFile, uint8_t spaces);

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const {}
};

class CExecuteCase : public CConfirmCustomExtractor
{
  public:
    std::string     value;
    std::string     maxValue;
    CExecuteSection ifCase;
    int             line;
    bool            ifCaseValid;

    CExecuteCase     () : ifCaseValid( false ),value (""), maxValue(""), line(NO_LINE) {};
    void dumpCase    (std::ofstream &outFile, uint8_t spaces);

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const;
};

class CExecuteSwitch : public CConfirmCustomExtractor
{
  public:
    std::string                     expr;
    std::vector <CExecuteCase>      cases;
    CExecuteSection                 defaultCase;
    int                             line;
    bool                            defaultCaseValid;

    CExecuteSwitch     () : defaultCaseValid( false ), line(NO_LINE) {};
    void dumpSwitch    (std::ofstream &outFile, uint8_t spaces);

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const;
};

class CExecuteExpression : public CConfirmCustomExtractor
{
  public:
    ExecuteInstructionType type;
    CExecuteAction         actionInstr;
    CExecuteAssign         assignInstr;
    CExecuteIf             ifInstr;
    CExecuteLoop           loopInstr;
    CExecuteInline         inlineInstr;
    CExecuteSwitch         switchInstr;

    CExecuteExpression() {}
    CExecuteExpression(ExecuteInstructionType type1): type(type1) {}

    virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const;
};


class CExecuteCode : public CConfirmCustomExtractor
{
  public:
     std::vector< CExecuteSection> executeSections;

     virtual void getConfirmCustom( std::set< std::string >& custom_confirms ) const;
};


class CBlock
{
  public:
};


class CProtocol
{
  public:
    CProtocol () : line(NO_LINE) {};
    bool         FieldExists( const std::string fieldname) const;
    bool         GetFieldProperties( const std::string fieldname,
                                     uint32_t&         bitsize,
                                     uint32_t&         bitoffset ) const;
    bool         GetHeaderSize( uint32_t &size) const;
    bool         PossibleLayer4() const;
    static bool  PossibleLayer4( ProtoType pt );
    short        ProtocolLayer() const;
    static short ProtocolLayer( ProtoType pt );

  public:
    ProtoType                  type;
    std::string                name;
    std::string                longname;
    std::string                showsumtemplate;
    std::string                comment;
    std::string                description;
    std::vector< std::string > prevproto;
    std::vector< ProtoType >   prevType;
    int                        line;
    std::vector< CField >      fields;
    CExecuteCode               executeCode;
};

class CLabel
{
  public:
    bool            isProto;    //  label is a protocol
    std::string     name;       //  label name
    ProtoType       protocol;   //  protocol type

    CLabel() :                  isProto(0)                 {}
    CLabel(std::string name1) : isProto(0), name(name1)    {}
    CLabel(ProtoType type)    : isProto(1), protocol(type) {}

    std::string getProtocolOutputName () const;
};

class CExtension
{
public:
    std::vector< ProtoType >   prevType;
    std::vector< std::string > prevNames;
    uint32_t position;
    uint8_t  indexPerHdr;

    CExtension() : position(0), indexPerHdr(0) {}
    CExtension(std::vector< ProtoType >& types, std::vector< std::string >& names, uint32_t pos) :
        prevType(types), prevNames(names), position(pos), indexPerHdr(0) {}
};

const int ASSEMBLER_BASE = 0x20;
const int CODE_SIZE      = 0x7C0;

class CSoftParseResult
{
public:
    bool                     softParseEnabled;
    bool                     override1;                   /**< FALSE to invoke a check that nothing else
                                                             was loaded to this address, including
                                                             internal patched.
                                                             TRUE to override any existing code.*/
    uint32_t                 size;                       /**< SW parser code size */
    uint16_t                 base;                       /**< SW parser base (in instruction counts!
                                                             muat be larger than 0x20)*/
    uint8_t                  p_Code[CODE_SIZE];          /**< SW parser code */
    uint32_t                 swPrsDataParams[16];
                                                         /**< SW parser data (parameters) */
    uint8_t                  numOfLabels;                /**< Number of labels for SW parser. */
    std::vector <CExtension> labelsTable;                /**< SW parser labels table, containing n
                                                             umOfLabels entries */

    CSoftParseResult() : softParseEnabled(0), override1(0) {}
    void setEnable      (const bool val);
    void setSize        (const uint32_t baseAddress1);
    void setBinary      (const uint8_t binary1[], const uint32_t size);
    void setBaseAddresss(const uint16_t baseAddress1);
    void setExtensions  (const std::vector <CExtension> extns);
    void dumpHeader     (std::string path) const;
    static std::string externProtoName (const ProtoType type);
};

class CFieldRef
{
  public:
    std::string name;
    std::string header_index;
    unsigned int offset;
    unsigned int size;
};

class CNonHeaderEntry
{
public:
    e_FmPcdExtractSource  source;
    e_FmPcdExtractAction  action;
    unsigned int offset;
    unsigned int size;
    unsigned int icIndxMask;
};

class CHashTable
{
public:
    unsigned int mask;
    unsigned int hashShift;
    unsigned int keySize;
    bool         external;
    bool         aging;

    CHashTable() : mask(0), hashShift(0), keySize(0), external(false), aging(false) {}
};

class CAction
{
  public:
    std::string type;
    std::string ref;
};


class CCombineEntry
{
  public:
    enum ExtractFrom { NONE, FIELD, PORTDATA, FRAME, PARSER };

    ExtractFrom kind;

    std::string fieldref;

    unsigned int offset;
    unsigned int offsetInFqid;
    unsigned int size;
    unsigned int mask;
    unsigned int default_;
    unsigned int validate;
};


class CProtocolRef
{
  public:
    std::string name;
    std::string opt;
};

class CDefaultGroup
{
  public:
    std::string type;
    std::string select;
};


class CDistribution
{
  public:
    std::string name;
    std::string comment;
    std::string description;

    unsigned int  qbase;
    unsigned int  qcount;
    bool          bypass;
	bool          shared;
    unsigned int  keyShift;
    bool          symmetricHash;
    unsigned long dflt0;
    unsigned long dflt1;

    bool         vspoverride;
    unsigned int vspbase;
    bool         vspdirect;
    unsigned int vspshift;
    unsigned int vspoffset;
    unsigned int vspcount;


    std::vector< CFieldRef >     key;
    std::vector< CCombineEntry > combines;
    std::vector< CProtocolRef >  protocols;
    std::vector< CNonHeaderEntry > nonHeader;
    std::vector< CDefaultGroup > defaults;

    std::string action;
    std::string actionName;
    std::string headerManipName;
    std::string vspName;
};


class CPolicer
{
  public:
    CPolicer();

  public:
    std::string  name;
    unsigned int algorithm;
    unsigned int color_mode;
    unsigned int CIR;
    unsigned int EIR;
    unsigned int CBS;
    unsigned int EBS;
    unsigned int unit;

    bool shared;

    std::string dfltColor;

    std::string actionOnRed;
    std::string actionNameOnRed;
    std::string actionOnYellow;
    std::string actionNameOnYellow;
    std::string actionOnGreen;
    std::string actionNameOnGreen;
};

class CFragmentation
{
  public:
    std::string  name;
    unsigned int size;
    unsigned int dontFragAction;
    unsigned int scratchBpid;
    unsigned int sgBpid;
    bool         sgBpidEn;
    bool         optionsCounterEn;
};

class CReassembly
{
  public:
    std::string  name;
    unsigned int sgBpid;
    unsigned int maxInProcess;
    unsigned int dataLiodnOffset;
    unsigned int dataMemId;
    unsigned int ipv4minFragSize;
    unsigned int ipv6minFragSize;
    unsigned int timeOutMode;
    unsigned int fqidForTimeOutFrames;
    unsigned int numOfFramesPerHashEntry[2];
    unsigned int timeoutThreshold;
    unsigned int nonConsistentSpFqid;
};

class CInsert
{
 public:
    unsigned int size;
    unsigned int offset;
    bool replace;
    char data[MAX_INSERT_SIZE];
};

class CRemove
{
 public:
   unsigned int size;
   unsigned int offset;
};

class CInsertField
{
public:
   std::string type;
   std::string value;
};

class CInsertHeader
{
 public:
   std::string type;
   unsigned int header_index;
   char data[MAX_INSERT_SIZE];
   bool update;
   unsigned int size;
   std::vector < CInsertField > fields;
};

class CRemoveHeader
{
 public:
   std::string type;
};

class CUpdateField
{
public:
   std::string type;
   std::string value;
   bool fill;
   bool defVal;
   unsigned int fillValue;
   unsigned int index;
   unsigned int vpriDefVal;
};

class CUpdate
{
 public:
   std::string type;
   std::vector < CUpdateField > fields;
};

class CCustom
{
 public:
   std::string type;
   unsigned int size;
   std::string data;
   bool decTtl;   
   bool decHl;
   bool updateIpv4Id;
   unsigned int id;
};

class CHeaderManip
{
 public:
    std::string  name;
    bool parse;
    bool insert;
    bool remove;
    bool insertHeader;
    bool removeHeader;
    bool update;
    bool custom;
    CInsert hdrInsert;
    CRemove hdrRemove;
    CInsertHeader hdrInsertHeader[2];
    CRemoveHeader hdrRemoveHeader;
    CUpdate hdrUpdate;
    CCustom hdrCustom;
    std::string   nextManip;
    unsigned int duplicate;
};

class CClassEntry
{
  public:
    char         data[MAX_CC_KEY];
    char         mask[MAX_CC_KEY];
    std::string  action;
    std::string  actionName;
    bool         statistics;
    std::string  vspName;
    bool         vspOverride;
    unsigned int vspBase;
    std::string  fragmentationName;
    std::string  headerManipName;
    unsigned int qbase;
    unsigned int index;
};

class CClassKey
{
public:
    bool                     header;
    bool                     field;
    bool                     hashTable;
    std::vector< CFieldRef > fields;
    CNonHeaderEntry          nonHeaderEntry;
    CHashTable               hashTableEntry;
};

class CClassification
{
  public:
    std::string                 name;
    CClassKey                   key;
    std::vector< CClassEntry >  entries;
    std::string                 actionOnMiss;
    std::string                 actionNameOnMiss;
    std::string                 fragmentationNameOnMiss;
    std::string                 vspNameOnMiss;
    bool                        vspOverrideOnMiss;
    bool                        statisticsOnMiss;
    bool                        shared;
    unsigned int                vspBaseOnMiss;
    unsigned int                qbase;
    //Pre-allocation
    unsigned int                max;
    bool                        masks;
    std::string                 statistics;
    std::vector< std::string >  may_use_action;
    std::vector< std::string >  may_use_actionName;
    std::vector< unsigned int > frameLength;
};


class CPolicy
{
  public:
    std::string                name;
    std::vector< std::string > dist_order;
    std::string                reassemblyName;
};

class CVsp
{
  public:
    std::string  name;
    bool         direct;
    unsigned int base;
    unsigned int fqshift;
    unsigned int vspoffset;
    unsigned int vspcount;
	bool         vspAlloc;
};

class CReplicatorEntry
{
  public:
    std::string  action;
    std::string  actionName;
    std::string  fragmentationName;
    std::string  headerManipName;
    std::string  vspName;
    bool         vspOverride;
    unsigned int vspBase;
    unsigned int qbase;
    unsigned int index;
};

class CReplicator
{
  public:
    std::string                name;
    std::vector< CReplicatorEntry > entries;
    unsigned int               max;
    std::vector< std::string > may_use_action;
    std::vector< std::string > may_use_actionName;
};


class CPort
{
  public:
    std::string  type;
    unsigned int number;
    std::string  policy;
    unsigned int portid;
};


class CEngine
{
  public:
    std::string          name;
    std::vector< CPort > ports;
    unsigned int default_queue1;
    unsigned int default_queue2;
    unsigned int offload_support;
	unsigned int kg_payload_offset;
};


class CTaskDef
{
  public:
    std::string name;
    std::string version;
    std::string creator;
    std::string date;

    std::string pcdname;
    std::string pcdversion;
    std::string pcdcreator;
    std::string pcddate;

    std::vector< CProtocol >                 protocols;
    CSoftParseResult                         spr;
    std::map< std::string, CDistribution >   distributions;
    std::map< std::string, CClassification > classifications;
    std::map< std::string, CReplicator >     replicators;
    std::map< std::string, CVsp >            vsps;
    std::map< std::string, CPolicer >        policers;
    std::map< std::string, CPolicy >         policies;
    std::map< std::string, CFragmentation >  fragmentations;
    std::map< std::string, CReassembly >     reassemblies;
    std::map< std::string, CHeaderManip >    headermanips;

    std::map< std::string, CEngine > engines;

  public:
    CTaskDef();
    ~CTaskDef();
    bool checkSemantics();

    bool FieldExists       ( const std::string fullFieldName) const;
    bool GetFieldProperties( const std::string fullFieldName,
                             uint32_t&         bitSize,
                             uint32_t&         bitOffset ) const;
    std::string getShimNoFromCustom( const std::string protocol_name ) const;

    void deleteExecute  ();
    void dumpSpParsed   (std::string path);

  private:
    bool checkLoopDependencies();
    bool checkSemanticsClassification( CClassification& clsf );
    bool checkSemanticsReplicator( CReplicator& repl );
    bool checkSemanticsDistribution( CDistribution& dist );
    bool checkSemanticsPolicer( CPolicer& plcr );
    bool checkSemanticsReassembly( CReassembly& reas );
    bool checkActionTarget( const std::string action,
                            const std::string actionName,
                            const std::string fromType,
                            const std::string from );

};

#endif // TASKDEF_H
