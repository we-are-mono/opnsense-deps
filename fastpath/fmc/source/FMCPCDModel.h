/* =====================================================================
 *
 * The MIT License (MIT)
 * Copyright 2009-2012, Freescale Semiconductor, Inc.
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
 * File Name : FMCPCDModel.h
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#ifndef FMCMODEL_H
#define FMCMODEL_H

#include <string>
#include <vector>
#include <set>
#include <map>

extern "C" {
#include <std_ext.h>
#include <error_ext.h>
#include <part_ext.h>
#include <fm_ext.h>
#include <Peripherals/fm_pcd_ext.h>
#include <Peripherals/fm_port_ext.h>
}


const unsigned int MAX_ENGINES   = 2;
const unsigned int MAX_PORTS     = 16;
const unsigned int MAX_SCHEMES   = 32;
const unsigned int MAX_POLICERS  = 256;
const unsigned int MAX_CCNODES   = 256;
const unsigned int MAX_REPLICATORS = 256;
const unsigned int MAX_CODE_SIZE = 0x7C0;


// Forward declarations
class CTaskDef;
class FMBlock;
class CEngine;
class CPort;
class CDistribution;
class CClassification;
class CReplicator;
class CPolicer;
class Engine;
class Port;
class Scheme;
class CCNode;
class HTNode;
class CRepl;
class Policer;
class CSoftParseResult;

////////////////////////////////////////////////////////////////////////////////
/// Unified handle's index for FM entities
////////////////////////////////////////////////////////////////////////////////
class FMBlock
{
public:
    unsigned int getIndex() const { return index; };
    static unsigned int assignIndex( std::vector< Engine >&  engines );
    static unsigned int assignIndex( std::vector< Port >&    ports );
    static unsigned int assignIndex( std::vector< Scheme >&  schemes );
    static unsigned int assignIndex( std::vector< CCNode >&  ccnodes );
    static unsigned int assignIndex( std::vector< HTNode >&  htnodes );
    static unsigned int assignIndex( std::vector< CRepl >&   repls );
    static unsigned int assignIndex( std::vector< Policer >& policers );

private:
    unsigned int index; // Handle index
};


class DefaultGroup
{
public:
    e_FmPcdKgKnownFieldsDfltTypes type;
    std::string                   typeStr;

    e_FmPcdKgExtractDfltSelect    select;
    std::string                      selectStr;
};

class ExtractData
{
public:
    e_FmPcdExtractType type;
    std::string        typeStr;

    e_FmPcdExtractFrom src;
    std::string        srcStr;

    unsigned int offset;
    unsigned int size;
    unsigned int mask;
    unsigned int default_;
    unsigned int validate;
    unsigned int offsetInFqid;

    e_FmPcdExtractByHdrType hdrtype;
    std::string             hdrtypeStr;

    e_NetHeaderType hdr;
    std::string     hdrStr;

    e_FmPcdHdrIndex hdrIndex;
    std::string     hdrIndexStr;

    std::string  fieldName;
    unsigned int fieldType;
    std::string  fieldTypeStr;

    e_FmPcdExtractFrom nhSource;
    std::string        nhSourceStr;
    e_FmPcdAction      nhAction;
    std::string        nhActionStr;
    unsigned int       nhOffset;
    unsigned int       nhSize;
    unsigned int       nhIcIndxMask;
};

class Protocol : public FMBlock
{
public:
  std::string name;         ///< Protocol name
  std::string opt;          ///< Protocol option

  inline bool operator < (const Protocol &b) const
  {
    if (name == b.name)
    {
      return ( opt < b.opt );
    }

    return ( name < b.name );
  }
};

////////////////////////////////////////////////////////////////////////////////
/// Storage class for FM Scheme properties
////////////////////////////////////////////////////////////////////////////////
class Scheme : public FMBlock
{
public:
    std::string name;                   ///< Scheme name

	bool shared;
    std::vector < ExtractData > key;   ///< Extracted fields forming the key
    std::vector < ExtractData > combines; ///<
                                        ///< 'extracted Or' fields

    std::vector < DefaultGroup > defaults; ///< Default groups

    unsigned int qbase;                 ///< Queue base
    unsigned int qcount;                ///< Number of queues
    bool bypass;                        ///< Bypass fqid generation

    uint32_t privateDflt0;              ///< Scheme default register 0
    uint32_t privateDflt1;              ///< Scheme default register 1

    uint8_t      relativeSchemeId;      ///< Scheme index for the containing port
    unsigned int hashShift;             ///< Hash value shift
    bool         symmetricHash;         ///< Symmetric hash
    unsigned int isDirect;              ///< Is the scheme always direct?

    std::set< Protocol > used_protocols; ///<
                                        ///< List of protocols which permit
                                        ///< extraction of the fields referenced in
                                        ///< 'key'
    unsigned int indexNetEnv;           ///< NetEnv index

    e_FmPcdEngine     nextEngine;
    std::string       nextEngineStr;
    std::string       nextActionName;
    e_FmPcdDoneAction doneAction;
    std::string       doneActionStr;
    unsigned int      actionHandleIndex;

#if (DPAA_VERSION >= 11)
    bool                    overrideStorageProfile; 
	bool                    vspAlloc;
    t_FmPcdKgStorageProfile storageProfile; 
#endif /* (DPAA_VERSION >= 11) */

    std::string port_signature;
    int         scheme_index_per_port;  // Scheme index for t_Fmc type
};


////////////////////////////////////////////////////////////////////////////////
/// Storage class for a Distinction Unit
////////////////////////////////////////////////////////////////////////////////
class DistinctionUnitElement
{
public:
    e_NetHeaderType hdr;
    std::string    opt;
    std::string     hdrStr;
};


////////////////////////////////////////////////////////////////////////////////
/// Storage class for CC node
////////////////////////////////////////////////////////////////////////////////
class CCNode : public FMBlock
{
public:
    class CCNextEngine
    {
    public:
        e_FmPcdEngine     nextEngine;
        std::string       nextEngineStr;
        unsigned int      newFqid;
        e_FmPcdDoneAction doneAction;
        std::string       doneActionStr;
        unsigned int      actionHandleIndex;
#if (DPAA_VERSION >= 11)
        unsigned int      newRelativeStorageProfileId;
#endif /* (DPAA_VERSION >= 11) */
        bool statistics;
        e_FmPcdEngine     nextEngineTrueType; //Drivers are using CC for both hash and match table so we cant deferientiate in the final structures between them. We must propagate this.
    };
    class CCData
    {
    public:
        unsigned char data[FM_PCD_MAX_SIZE_OF_KEY];
    };

    std::string name;                   ///< Node name

    unsigned int maxNumOfKeys;          ///< Max number of keys

    e_FmPcdCcStatsMode statistics;      ///< Statistics mode (none/frame)

    bool maskSupport;                   ///< Reservation of memory for key masks
    bool shared;

    ExtractData extract;                ///< Extract parameters

    unsigned int keySize;               ///< The key data size in bits

    std::set< std::string > used_protocols; ///<
                                        ///< List of protocols which permit
                                        ///< extraction of the fields referenced in
                                        ///< 'key'

    std::vector< CCData >       keys;   ///< The list of data entries
    std::vector< CCData >       masks;  ///< The list of masks corresponding to data entries
    std::vector< CCNextEngine > nextEngines;
    std::vector< unsigned int > frag;
    std::vector< unsigned int > header;
    std::vector< unsigned int > indices;
    std::vector <unsigned int > frameLength;

    CCNextEngine nextEngineOnMiss;
    unsigned int fragOnMiss;
    unsigned int headerOnMiss;

    std::string   port_signature;
};

////////////////////////////////////////////////////////////////////////////////
/// Storage class for CC node
////////////////////////////////////////////////////////////////////////////////
class HTNode : public FMBlock
{
public:
    class CCNextEngine
    {
    public:
        e_FmPcdEngine     nextEngine;
        std::string       nextEngineStr;
        unsigned int      newFqid;
        e_FmPcdDoneAction doneAction;
        std::string       doneActionStr;
        unsigned int      actionHandleIndex;
#if (DPAA_VERSION >= 11)
        unsigned int      newRelativeStorageProfileId;
#endif /* (DPAA_VERSION >= 11) */
        bool statistics;
        e_FmPcdEngine     nextEngineTrueType;
    };
    class CCData
    {
    public:
        unsigned char data[FM_PCD_MAX_SIZE_OF_KEY];
    };

    std::string name;                   ///< Node name

    unsigned int maxNumOfKeys;          ///< Max number of keys

    e_FmPcdCcStatsMode statistics;      ///< Statistics mode (none/frame)

    unsigned int hashResMask;           ///< Mask that will be used on the hash-result
    unsigned int matchKeySize;          ///< The key data size in bits
    unsigned int hashShift;             ///< Byte offset from the beginning of the KeyGen hash result to the 2-bytes to be used as hash index.
    unsigned int kgHashShift;           ///< KG-Hash-shift as it was configured in the KG-scheme that leads to this hash-table.
    bool         externalHash;          ///< TRUE for external hash tables (CDX manages buckets)
    bool         agingSupport;          ///< TRUE to enable aging support for keys

    std::vector< CCData >       keys;   ///< The list of data entries
    std::vector< CCData >       masks;  ///< The list of masks corresponding to data entries
    std::vector< CCNextEngine > nextEngines;
    std::vector< unsigned int > frag;
    std::vector< unsigned int > header;
    std::vector< unsigned int > indices;

    CCNextEngine nextEngineOnMiss;
    unsigned int fragOnMiss;
    unsigned int headerOnMiss;

    std::string   port_signature;
};

////////////////////////////////////////////////////////////////////////////////
/// Storage class for Replicator node
////////////////////////////////////////////////////////////////////////////////
class CRepl : public FMBlock
{
public:
    class CCNextEngine
    {
    public:
        e_FmPcdEngine     nextEngine;
        std::string       nextEngineStr;
        unsigned int      newFqid;
        e_FmPcdDoneAction doneAction;
        std::string       doneActionStr;
        unsigned int      actionHandleIndex;
#if (DPAA_VERSION >= 11)
        unsigned int      newRelativeStorageProfileId;
#endif /* (DPAA_VERSION >= 11) */
    };
 
public:
    std::string name;                   ///< Replicator name

    unsigned int maxNumOfEntries;          ///< Max number of keys

    std::vector< CCNextEngine > nextEngines;
    std::vector< unsigned int > frag;
    std::vector< unsigned int > header;
    std::vector< unsigned int > indices;

    std::string   port_signature;
};

////////////////////////////////////////////////////////////////////////////////
/// Storage class for FM Policer entry
////////////////////////////////////////////////////////////////////////////////
class Policer : public FMBlock
{
public:
    std::string name;

    bool shared;

    e_FmPcdPlcrAlgorithmSelection algorithm;
    std::string                   algorithmStr;
    e_FmPcdPlcrColorMode          colorMode;
    std::string                   colorModeStr;

    e_FmPcdPlcrColor dfltColor;
    std::string      dfltColorStr;

    t_FmPcdPlcrByteRateModeParams  byteModeParams;

    e_FmPcdPlcrRateMode rateMode;
    std::string         rateModeStr;

    unsigned int committedInfoRate;
    unsigned int committedBurstSize;
    unsigned int peakOrExcessInfoRate;
    unsigned int peakOrExcessBurstSize;

    e_FmPcdEngine     nextEngineOnGreen;
    std::string       nextEngineOnGreenStr;
    e_FmPcdDoneAction onGreenAction;
    std::string       onGreenActionStr;
    unsigned int      onGreenActionHandleIndex;

    e_FmPcdEngine     nextEngineOnYellow;
    std::string       nextEngineOnYellowStr;
    e_FmPcdDoneAction onYellowAction;
    std::string       onYellowActionStr;
    unsigned int      onYellowActionHandleIndex;

    e_FmPcdEngine     nextEngineOnRed;
    std::string       nextEngineOnRedStr;
    e_FmPcdDoneAction onRedAction;
    std::string       onRedActionStr;
    unsigned int      onRedActionHandleIndex;

    std::string   port_signature;
};


////////////////////////////////////////////////////////////////////////////////
/// Storage class for FM Port properties
////////////////////////////////////////////////////////////////////////////////
class Port : public FMBlock
{
public:
    std::string  name;

    e_FmPortType type;                  ///< Port type
    std::string  typeStr;               ///< Port type in string form
    unsigned int number;                ///< Port number

    unsigned int portid;                ///< Port assigned ID

    std::vector< unsigned int > schemes; ///<
                                        ///< Schemes used by this port
    std::vector< unsigned int > ccnodes; ///<
                                        ///< Class. nodes used by this port
    std::vector< unsigned int > htnodes; ///<
                                        ///< Hash table used by this port
    std::vector< unsigned int > replicators; ///<
                                        ///< Class. nodes used by this port
    std::vector< unsigned int > cctrees; ///<
                                        ///< Root CC nodes
    std::vector< e_FmPcdEngine > cctrees_type; ///<
                                        ///< Root CC nodes type
    std::vector< unsigned int > hdrmanips; ///<
                                        ///< Header manip for CC nodes
    std::map< Protocol,
        std::pair< unsigned int, DistinctionUnitElement > > protocols; ///<
                                        ///< Protocols used by this port
    unsigned int reasm_index;
};

////////////////////////////////////////////////////////////////////////////////
/// Storage class for FM Engine properties
////////////////////////////////////////////////////////////////////////////////
class Engine : public FMBlock
{
public:
    std::string  name;                  ///< Engine's name
    unsigned int number;                ///< Engine's number
    std::string  pcd_name;              ///< PCD name == 'policy' name
    unsigned int offload_support;       ///< Advanced offload support number
	unsigned int kg_payload_offset;		/// FM_PCD_KgSetAdditionalDataAfterParsing

    std::vector< unsigned int > ports;  ///< Ports of the engine

#ifndef P1023

    class CInsertData
    {
    public:
        unsigned char data[FM_PCD_MAX_SIZE_OF_KEY];
    };

    std::vector< t_FmPcdManipParams > reasm;
    std::vector< std::string >        reasm_names;

    std::vector< t_FmPcdManipParams > frags;
    std::vector< std::string >        frag_names;

    std::vector< t_FmPcdManipParams > headerManips;
    std::vector< CInsertData >        insertDatas;
    std::vector< std::string >        headerManips_names;
    std::vector< bool >               headerManips_hasNext;
    std::vector< unsigned int >       headerManips_nextNanip;

public:
    unsigned int getHeaderManipIndex(std::string name);
#endif /* P1023 */
};


////////////////////////////////////////////////////////////////////////////////
/// Creating and referencing the order of entities creation
////////////////////////////////////////////////////////////////////////////////
class ApplyOrder
{
public:
    enum Type { None, EngineStart, EngineEnd, PortStart, PortEnd, Scheme, HTNode,
                CCNode, CCTree, Policer, Replicator, Manipulation };

    class Entry {
    public:
        Entry( Type type, unsigned int index ); ///< Entry's constructor

        bool operator<( const Entry& rh ) const {
            if ( type < rh.type )                      return true;
            if ( type == rh.type && index < rh.index ) return true;
            return false;
        };

        bool operator==( const Entry& rh ) const {
            if ( type == rh.type && index == rh.index ) return true;
            return false;
        };

    public:
        Type         type;              ///< The type of the entry to apply
        unsigned int index;             ///< The referenced entry's index
    };

public:
    void  add( Entry entry );                     ///< Add new entry
    void  add_edge( Entry n1, Entry n2 );         ///< Add edge between entries
    void  sort();                                 ///< Topological sort of entries
    void  reverse_port_apply_order();

    unsigned int size() const;                    ///< Return number of entries
    Entry get( unsigned int index ) const;        ///< Return entry at position
    std::string get_type_str( Type t ) const;     ///< Return type name as string

private:
    std::vector< Entry > entries;                   ///< The entries' storage
    std::vector< std::pair< Entry, Entry > > edges; ///< The edges' storage
};


////////////////////////////////////////////////////////////////////////////////
/// FMC PCD model and database class
////////////////////////////////////////////////////////////////////////////////
class CFMCModel
{
public:
    /// Default constructor
    CFMCModel();

    /// Create model by building the internal database
    bool createModel( CTaskDef* m_pTaskDef );

    // Service functions
    static e_FmPortType     getPortType( std::string type );
    static std::string      getPortTypeStr( e_FmPortType type );
    static e_NetHeaderType  getNetCommHeaderType( std::string protoname );
    static std::string      getNetCommHeaderTypeStr( std::string protoname );
    static std::string      getNetCommHeaderTypeStr( e_NetHeaderType proto );
    static unsigned int     getNetCommFieldType( std::string fieldname );
    static std::string      getNetCommFieldTypeStr( std::string fieldname );
    static e_FmPcdHdrIndex  getNetCommHeaderIndex( std::string indexstr );
    static std::string      getNetCommHeaderIndexStr( std::string indexstr );
    static e_FmPcdEngine    getEngineByType( std::string enginename );
    static std::string      getEngineByTypeStr( std::string enginename );
    static std::string      getExtractFromStr( e_FmPcdExtractFrom extract );
    static e_FmPcdCcStatsMode             getStatistic( std::string statstic );
    static e_FmPcdManipHdrRmvSpecificL2   getSpecificL2ByString( std::string l2 );
    static e_FmPcdManipHdrFieldUpdateType getFieldUpdateTypeByString( std::string type );
    static e_FmPcdPlcrColor getPlcrColor( std::string color );
    static std::string      getPlcrColorStr( std::string color );
    static bool             isFullFieldForCC( std::string fieldName );


public:
    std::vector< Engine >  all_engines;     ///< Engines defined by this configuration
    std::vector< Port >    all_ports;       ///< Ports defined by this configuration
    std::vector< Scheme >  all_schemes;     ///< Schemes participating in this config
    std::vector< CCNode >  all_ccnodes;     ///< Class. nodes participating in this config
    std::vector< HTNode >  all_htnodes;     ///< Hash table nodes participating in this config
    std::vector< CRepl >   all_replicators; ///< Replicator nodes participating in this config
    std::vector< Policer > all_policers;    ///<
                                            ///< Policers participating in this config
    t_FmPcdPrsSwParams swPrs;
    bool               spEnable;
    unsigned char      spCode[MAX_CODE_SIZE];

    ApplyOrder applier;

private:
    Engine&  createEngine( const CEngine& xmlEngine, const CTaskDef* pTaskDef );
    Port&    createPort( Engine& engine, const CPort& xmlPort, const CTaskDef* pTaskDef );
    Scheme&  createScheme( const CTaskDef* pTaskDef, Port& port, const CDistribution& xmlDist,
                           bool isDirect );
    CCNode&  createCCNode( const CTaskDef* pTaskDef, Port& port, const CClassification& xmlCCNode, unsigned int kgHashShift);
    HTNode&  createHTNode( const CTaskDef* pTaskDef, Port& port, const CClassification& xmlCCNode, unsigned int kgHashShift);
    CRepl&   createReplicator( const CTaskDef* pTaskDef, Port& port, const CReplicator& xmlRepl );
    Policer& createPolicer( const CTaskDef* pTaskDef, Port& port, const CPolicer& xmlPolicer );
    void     createSoftParse( const CTaskDef* pTaskDef );

    unsigned int get_scheme_index( const CTaskDef* pTaskDef, std::string name,
                                   std::string from, Port& port, bool isDirect );
    unsigned int get_ccnode_index( const CTaskDef* pTaskDef, std::string name,
                                   std::string from, Port& port, bool isRoot, unsigned int kgHashShift, unsigned int manip = 0);
    unsigned int get_htnode_index( const CTaskDef* pTaskDef, std::string name,
                                   std::string from, Port& port, bool isRoot, unsigned int kgHashShift, unsigned int manip = 0);
#if (DPAA_VERSION >= 11)
    unsigned int get_replicator_index( const CTaskDef* pTaskDef, std::string name,
                                   std::string from, Port& port, bool isRoot, unsigned int manip = 0 );
#endif /* (DPAA_VERSION >= 11) */
    unsigned int get_policer_index( const CTaskDef* pTaskDef, std::string name,
                                    std::string from, Port& port );
    CCNode&  replicateCCNodes(const CTaskDef* pTaskDef, Port& port, CCNode& refnode);
    HTNode&  replicateHtNodes(const CTaskDef* pTaskDef, Port& port, HTNode& refnode);
};

#endif // FMCMODEL_H
