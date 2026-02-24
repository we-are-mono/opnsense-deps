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
 * File Name : FMCSP.cpp
 * Author    : Serge Lamikhov-Center, Levy Ro'ee
 *
 * ===================================================================*/

#include "FMCSP.h"

#ifdef _DEBUG
const bool DEBUG_SP= 0;
#else
const bool DEBUG_SP = 0;
#endif

using namespace std;



void softparser (CTaskDef *task, std::string filePath, unsigned int baseAddress)
{
    CIR               newIR;
    CCode             newCode;
    std::string       currentPath, fileNoExt, fileName, parsePath, dumpPath;
    std::string       headerPath;
    unsigned char     binary1[CODE_SIZE] = {0};
    fmsp_label_list_t *labels, *labelsIter;

    /*init tables*/
    RA::Instance().initRA();

    /* set paths*/
    int m       = filePath.find(".xml");
    fileNoExt   = filePath.substr(0,m);
    dumpPath    = fileNoExt+".dump";
    parsePath   = fileNoExt+".parsed";
    headerPath  = "softparse.h";

    if (DEBUG_SP)
    {
        newIR.  setDumpIr  (fileNoExt+".ir");
        newCode.setDumpCode(fileNoExt+".code");
        newCode.setDumpAsm (fileNoExt+".asm");
        newCode.setDebugAsm(1);
        task->dumpSpParsed (parsePath);
    }

    /*Parse, create IR and create asm*/
    newIR.createIR          (task);
    newCode.createCode      (newIR);

    /*assemble*/
    unsigned int actualCodeSize = assemble((char*)newCode.getAsmOutput().c_str(), binary1, &labels, DEBUG_SP, baseAddress);

    /*return result*/
    std::vector <CExtension> extns;
    createExtensions(extns, newCode, labels);
    task->spr.setEnable(1);
    task->spr.setBaseAddresss(baseAddress);
    task->spr.setBinary(binary1, sizeof(binary1));
    task->spr.setExtensions(extns);
    task->spr.setSize(actualCodeSize);

    task->spr.dumpHeader(headerPath);

    /* Free memory*/
    while (labels)
    {
        labelsIter  = labels->next_p;
        free (labels->name);
        free (labels);
        labels      = labelsIter;
    }
    newIR.deleteIR();
    task->deleteExecute();
    newCode.deleteCode();
}

unsigned int assemble (char* asmResult, unsigned char* binary, fmsp_label_list_t **labels, bool debug, int baseAddress)
{
    fmsp_label_list_t *localLabels = NULL;
    fmsp_assembler_options_t asmOptions;
    asmOptions.debug_level = fmsp_debug_none_e;
    asmOptions.program_space_base_address = baseAddress;
    asmOptions.suppress_warnings = 0;
    asmOptions.warnings_are_errors = 0;

    fmsp_error_code_t errorS =
        fmsp_assemble(asmResult, binary, &localLabels, &asmOptions, NULL);
    *labels = localLabels;
    if (errorS != fmsp_ok_e)
    {
        if (errorS == fmsp_max_instructions_exceeded_e)
            throw CGenericError (ERR_TOO_MANY_INSTR);
        else
        {
            std::string temp = "Code didn't assemble correctly. ";
            if (debug)
                temp += fmsp_get_error_string(errorS);
            throw CGenericError (ERR_INTERNAL_SP_ERROR, temp);
        }
    }
    /*Last 4 instructions must be zero*/
    else if(binary[CODE_SIZE-1] || binary[CODE_SIZE-2] ||
            binary[CODE_SIZE-3] || binary[CODE_SIZE-4] ||
            binary[CODE_SIZE-5] || binary[CODE_SIZE-6] ||
            binary[CODE_SIZE-7] || binary[CODE_SIZE-8])
        throw CGenericError (ERR_TOO_MANY_INSTR,
                     "Generated code should be 1-4 instructions shorter. ");

    return asmOptions.result_code_size;
}

void createExtensions (std::vector<CExtension> &extns, CCode code, fmsp_label_list_t *labels)
{
    fmsp_label_list_t *labelsIter;
    for (unsigned int i=0; i<code.protocolsCode.size(); i++)
    {
        labelsIter = labels;
        while (labelsIter) {
            if (labelsIter->name == code.protocolsCode[i].label.name)
            {
                CExtension extension (code.protocolsCode[i].protocol.prevType,
                                      code.protocolsCode[i].protocol.prevproto,
                                      labelsIter->byte_position);
                extns.push_back(extension);
                break;
            }
            labelsIter = labelsIter->next_p;
        }
        if (!labelsIter)
            throw CGenericError(ERR_INTERNAL_SP_ERROR, "Missing label");
    }
}

void CSoftParseResult::setBinary(const uint8_t binary1[], const uint32_t size)
{
    for (unsigned int i=0; i<size; i++)
        this->p_Code[i] = binary1[i];

}

void CSoftParseResult::setBaseAddresss(const uint16_t baseAddress1)
{
    this->base = baseAddress1;
}

void CSoftParseResult::setEnable(const bool val)
{
    this->softParseEnabled = 1;
}

void CSoftParseResult::setSize(const uint32_t size1)
{
    this->size = size1;
}

void CSoftParseResult::setExtensions(const std::vector <CExtension> extns)
{
    this->numOfLabels = 0;
    for (unsigned int i=0; i<extns.size(); i++)
    {
        for ( unsigned int j = 0; j < extns[i].prevType.size(); j++ )
        {
            CExtension ext = extns[i];
            ext.prevType.clear();
            ext.prevType.push_back( extns[i].prevType[j] );
            ext.prevNames.clear();
            ext.prevNames.push_back( extns[i].prevNames[j] );
            this->labelsTable.push_back( ext );
            this->numOfLabels++;
        }
    }
//    this->numOfLabels = extns.size();
}

void CSoftParseResult::dumpHeader(std::string path) const
{
    std::ofstream dumpFile;
    dumpFile.open(path.c_str(), std::ios::out);
    dumpFile.setf(std::ios::uppercase);
    unsigned int i,j;

    dumpFile << "#define SOFT_PARSE_CODE                                    \\"
    << endl  << "{                                                          \\"
    << endl  << "    TRUE,                               /*Override*/       \\"
    << endl  << "    " << size
             << ",                               /*Size*/           \\"
    << endl  << "    " << "0x" << std::hex << base
             << ",                               /*Base*/           \\"
    << endl  << "    (uint8_t *)&(uint8_t[]){            /*Code*/           \\"
    << endl;

    for (j=0, i=2*(base-ASSEMBLER_BASE); ( i < CODE_SIZE-4 ) && ( j < size ); i++, j++)
    {
        if (j%10 == 0 || i==2*(base-ASSEMBLER_BASE))
            dumpFile << "        ";
        dumpFile << "0x";
        if (p_Code[i]<0x10)
            dumpFile << "0";
        dumpFile << std::hex << (int)p_Code[i];
        if (i+1!=CODE_SIZE)
            dumpFile << ",";
        if ( ( (j+1)%10==0 ) || ( i+1==CODE_SIZE ) || ( j+1 >= size ) )
            dumpFile << " \\" << std::endl;
    }

    dumpFile << "    },                                                     \\"
    << endl  << "    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},  /*swPrsParams*/    \\"
    << endl  << "    " << (int)numOfLabels
             <<      ",                                  /*numOfLabels*/    \\"
    << endl  << "    {                                                      \\"
    << endl;

    for (i = 0; i < numOfLabels; i++)
    {
        dumpFile << "        {                                                  \\"
        << endl  << "            " << "0x" << hex << labelsTable[i].position
                 <<              ",                       /*offset*/         \\"
        << endl  << "            " << externProtoName(labelsTable[i].prevType[0])
                 <<              ",           /*prevProto*/      \\"
        << endl  << "            " << (int)labelsTable[i].indexPerHdr
                 <<              ",                           /*index*/          \\"
        << endl  << "        },                                                 \\"
        << endl;
    }

    dumpFile << "    },                                                     \\"
    << endl  << "}" << endl;
}

/*Find the protocol name which should be used in the softpare.h file*/
std::string CSoftParseResult::externProtoName(const ProtoType type)
{
    std::map< ProtoType, std::string >::iterator protocolsLabelsIterator;
    std::map< ProtoType, std::string> protocolsLabels;

    protocolsLabels[PT_ETH]       = "HEADER_TYPE_ETH";
    protocolsLabels[PT_LLC_SNAP]  = "HEADER_TYPE_SNAP";
    protocolsLabels[PT_VLAN]      = "HEADER_TYPE_VLAN";
    protocolsLabels[PT_PPPOE_PPP] = "HEADER_TYPE_PPPoE";
    protocolsLabels[PT_MPLS]      = "HEADER_TYPE_MPLS";
    protocolsLabels[PT_IPV4]      = "HEADER_TYPE_IPv4";
    protocolsLabels[PT_IPV6]      = "HEADER_TYPE_IPv6";
    protocolsLabels[PT_GRE]       = "HEADER_TYPE_GRE";
    protocolsLabels[PT_MINENCAP]  = "HEADER_TYPE_MINENCAP";
    protocolsLabels[PT_TCP]       = "HEADER_TYPE_TCP";
    protocolsLabels[PT_UDP]       = "HEADER_TYPE_UDP";
    protocolsLabels[PT_IPSEC_AH]  = "HEADER_TYPE_IPSEC_AH";
    protocolsLabels[PT_IPSEC_ESP] = "HEADER_TYPE_IPSEC_ESP";
    protocolsLabels[PT_SCTP]      = "HEADER_TYPE_SCTP";
    protocolsLabels[PT_DCCP]      = "HEADER_TYPE_DCCP";
    protocolsLabels[PT_OTHER_L3]  = "HEADER_TYPE_USER_DEFINED_L3";
    protocolsLabels[PT_OTHER_L4]  = "HEADER_TYPE_USER_DEFINED_L4";

    protocolsLabelsIterator = protocolsLabels.find(type);
    if (protocolsLabelsIterator == protocolsLabels.end())
        throw CGenericError (ERR_INTERNAL_SP_ERROR, "Unrecognized Protocol");
    else
        return protocolsLabels[type];
}
