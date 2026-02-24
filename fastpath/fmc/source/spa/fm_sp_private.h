/* =====================================================================
 *
 * The MIT License (MIT)
 * Copyright (c) 2009, 2010, Freescale Semiconductor, Inc.
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
 *  Author    : Hendricks Vince
 *
 * ===================================================================*/

#ifndef __FMSP_PRIVATE_H__
#define __FMSP_PRIVATE_H__

/* --------------------------------------------------------------------------
 *
 * Private header file for soft parse assembler.
 *
 * --------------------------------------------------------------------------*/
#include "fm_sp.h"
#include "dll.h"
#include "htbl.h"

#ifdef _MSC_VER
#define snprintf _snprintf
#define strtoull _strtoui64
#define strtoll _strtoi64
#endif

#define _FMSP_LABEL_TABLE_SIZE 100

#define _FMSP_DISPLAY_LINE_SIZE  92
#define _FMSP_DISPLAY_DESCR_SIZE 52

/* 
 * Instruction code strings
 */
#define _FMSP_INSTR_CODE_NOP_STR                     "0x0000"
#define _FMSP_INSTR_CODE_CLM_STR                     "0x0001"
#define _FMSP_INSTR_CODE_ADVANCE_HB_BY_WO_STR        "0x0002"
#define _FMSP_INSTR_CODE_OR_IV_LCV_STR               "0x0003"
#define _FMSP_INSTR_CODE_ZERO_WR_STR                 "0x0004"
#define _FMSP_INSTR_CODE_ONES_COMP_WR1_TO_WR0_STR    "0x0006"
#define _FMSP_INSTR_CODE_CASE1_DJ_WR_TO_WR_STR       "0x0008"
#define _FMSP_INSTR_CODE_CASE2_DC_WR_TO_WR_STR       "0x000c"
#define _FMSP_INSTR_CODE_CASE2_DJ_WR_TO_WR_STR       "0x0010"
#define _FMSP_INSTR_CODE_CASE3_DC_WR_TO_WR_STR       "0x0018"
#define _FMSP_INSTR_CODE_CASE3_DJ_WR_TO_WR_STR       "0x0020"
#define _FMSP_INSTR_CODE_CASE4_DC_WR_TO_WR_STR       "0x0030"
#define _FMSP_INSTR_CODE_LOAD_LCV_TO_WR_STR          "0x0040"
#define _FMSP_INSTR_CODE_STORE_WR_TO_LCV_STR         "0x0042"
#define _FMSP_INSTR_CODE_ADDSUB_WR_WR_TO_WR_STR      "0x0048"
#define _FMSP_INSTR_CODE_ADDSUB_WR_IV_TO_WR_STR      "0x0050"
#define _FMSP_INSTR_CODE_BITWISE_WR_WR_TO_WR_STR     "0x0070"
#define _FMSP_INSTR_CODE_COMPARE_WORKING_REGS_STR    "0x0078"
#define _FMSP_INSTR_CODE_MODIFY_WO_BY_WR_STR         "0x0080"
#define _FMSP_INSTR_CODE_BITWISE_WR_IV_TO_WR_STR     "0x00c0"
#define _FMSP_INSTR_CODE_SHIFT_LEFT_WR_BY_SV_STR     "0x0100"
#define _FMSP_INSTR_CODE_SHIFT_RIGHT_WR_BY_SV_STR    "0x0180"
#define _FMSP_INSTR_CODE_LOAD_BITS_IV_TO_WR_STR      "0x0200"
#define _FMSP_INSTR_CODE_LOAD_SV_TO_WO_STR           "0x0600"
#define _FMSP_INSTR_CODE_ADD_SV_TO_WO_STR            "0x0700"
#define _FMSP_INSTR_CODE_STORE_IV_TO_RA_STR          "0x0800"
#define _FMSP_INSTR_CODE_LOAD_BYTES_PA_TO_WR_STR     "0x1000"
#define _FMSP_INSTR_CODE_JUMP_STR                    "0x1800"
#define _FMSP_INSTR_CODE_STORE_WR_TO_RA_STR          "0x2800"
#define _FMSP_INSTR_CODE_LOAD_BYTES_RA_TO_WR_STR     "0x3000"
#define _FMSP_INSTR_CODE_COMPARE_WR0_TO_IV_STR       "0x4000"
#define _FMSP_INSTR_CODE_LOAD_BITS_FW_TO_WR_STR      "0x8000"

#define _FMSP_INSTR_CODE_JMP_PROTOCOL_STR            "0x0044"
/* For convenience further define the only two possible types of "JMP PROTOCOL" */
#define _FMSP_INSTR_CODE_JMP_NXT_ETH_TYPE_STR        "0x0044"
#define _FMSP_INSTR_CODE_JMP_NXT_IP_PROTO_STR        "0x0045"

/* 
 * Instruction codes
 */
#define _FMSP_INSTR_CODE_NOP                  0x0000
#define _FMSP_INSTR_CODE_CLM                  0x0001
#define _FMSP_INSTR_CODE_ADVANCE_HB_BY_WO     0x0002
#define _FMSP_INSTR_CODE_OR_IV_LCV            0x0003
#define _FMSP_INSTR_CODE_ZERO_WR              0x0004
#define _FMSP_INSTR_CODE_ONES_COMP_WR1_TO_WR0 0x0006
#define _FMSP_INSTR_CODE_CASE1_DJ_WR_TO_WR    0x0008
#define _FMSP_INSTR_CODE_CASE2_DC_WR_TO_WR    0x000c
#define _FMSP_INSTR_CODE_CASE2_DJ_WR_TO_WR    0x0010
#define _FMSP_INSTR_CODE_CASE3_DC_WR_TO_WR    0x0018
#define _FMSP_INSTR_CODE_CASE3_DJ_WR_TO_WR    0x0020
#define _FMSP_INSTR_CODE_CASE4_DC_WR_TO_WR    0x0030
#define _FMSP_INSTR_CODE_LOAD_LCV_TO_WR       0x0040
#define _FMSP_INSTR_CODE_STORE_WR_TO_LCV      0x0042
#define _FMSP_INSTR_CODE_ADDSUB_WR_WR_TO_WR   0x0048
#define _FMSP_INSTR_CODE_ADDSUB_WR_IV_TO_WR   0x0050
#define _FMSP_INSTR_CODE_BITWISE_WR_WR_TO_WR  0x0070
#define _FMSP_INSTR_CODE_COMPARE_WORKING_REGS 0x0078
#define _FMSP_INSTR_CODE_MODIFY_WO_BY_WR      0x0080
#define _FMSP_INSTR_CODE_BITWISE_WR_IV_TO_WR  0x00c0
#define _FMSP_INSTR_CODE_SHIFT_LEFT_WR_BY_SV  0x0100
#define _FMSP_INSTR_CODE_SHIFT_RIGHT_WR_BY_SV 0x0180
#define _FMSP_INSTR_CODE_LOAD_BITS_IV_TO_WR   0x0200
#define _FMSP_INSTR_CODE_LOAD_SV_TO_WO        0x0600
#define _FMSP_INSTR_CODE_ADD_SV_TO_WO         0x0700
#define _FMSP_INSTR_CODE_STORE_IV_TO_RA       0x0800
#define _FMSP_INSTR_CODE_LOAD_BYTES_PA_TO_WR  0x1000
#define _FMSP_INSTR_CODE_JUMP                 0x1800
#define _FMSP_INSTR_CODE_STORE_WR_TO_RA       0x2800
#define _FMSP_INSTR_CODE_LOAD_BYTES_RA_TO_WR  0x3000
#define _FMSP_INSTR_CODE_COMPARE_WR0_TO_IV    0x4000
#define _FMSP_INSTR_CODE_LOAD_BITS_FW_TO_WR   0x8000

#define _FMSP_INSTR_CODE_JMP_PROTOCOL         0x0044
/* For convenience further define the only two possible types of "JMP PROTOCOL" */
#define _FMSP_INSTR_CODE_JMP_NXT_ETH_TYPE     0x0044
#define _FMSP_INSTR_CODE_JMP_NXT_IP_PROTO     0x0045

/*
 * Instruction modification values
 */
#define _FMSP_INSTR_MOD_JMP_HXS               0x0400

/*
 * Operator values
 */
#define _FMSP_OPERATOR_OR  0
#define _FMSP_OPERATOR_AND 1
#define _FMSP_OPERATOR_XOR 2

#define _FMSP_OPERATOR_EQUAL              0
#define _FMSP_OPERATOR_NOT_EQUAL          1
#define _FMSP_OPERATOR_GREATER_THAN       2
#define _FMSP_OPERATOR_LESS_THAN          3
#define _FMSP_OPERATOR_GREATER_THAN_EQUAL 4
#define _FMSP_OPERATOR_LESS_THAN_EQUAL    5

#define _FMSP_OPERATOR_PLUS  0
#define _FMSP_OPERATOR_MINUS 1

#define _FMSP_ETH_HXS_LABEL           "ETH_HXS"
#define _FMSP_LLC_SNAP_HXS_LABEL      "LLC_SNAP_HXS"
#define _FMSP_VLAN_HXS_LABEL          "VLAN_HXS"
#define _FMSP_PPPOE_PPP_HXS_LABEL     "PPPOE_PPP_HXS"
#define _FMSP_MPLS_HXS_LABEL          "MPLS_HXS"
#define _FMSP_IPV4_HXS_LABEL          "IPV4_HXS"
#define _FMSP_IPV6_HXS_LABEL          "IPV6_HXS"
#define _FMSP_GRE_HXS_LABEL           "GRE_HXS"
#define _FMSP_MINENCAP_HXS_LABEL      "MINENCAP_HXS"
#define _FMSP_OTH_L3_HXS_LABEL        "OTH_L3_HXS"
#define _FMSP_TCP_HXS_LABEL           "TCP_HXS"
#define _FMSP_UDP_HXS_LABEL           "UDP_HXS"
#define _FMSP_IPSEC_HXS_LABEL         "IPSEC_HXS"
#define _FMSP_SCTP_HXS_LABEL          "SCTP_HXS"
#define _FMSP_DCCP_HXS_LABEL          "DCCP_HXS"
#define _FMSP_OTH_L4_HXS_LABEL        "OTH_L4"
#define _FMSP_RETURN_HXS_LABEL        "RETURN_HXS"
#define _FMSP_END_PARSE_LABEL         "END_PARSE"

#define _FMSP_ETH_HXS           0x000
#define _FMSP_LLC_SNAP_HXS      0x001
#define _FMSP_VLAN_HXS          0x002
#define _FMSP_PPPOE_PPP_HXS     0x003
#define _FMSP_MPLS_HXS          0x004
#define _FMSP_IPV4_HXS          0x005
#define _FMSP_IPV6_HXS          0x006
#define _FMSP_GRE_HXS           0x007
#define _FMSP_MINENCAP_HXS      0x008
#define _FMSP_OTH_L3_HXS        0x009
#define _FMSP_TCP_HXS           0x00a
#define _FMSP_UDP_HXS           0x00b
#define _FMSP_IPSEC_HXS         0x00c
#define _FMSP_SCTP_HXS          0x00d
#define _FMSP_DCCP_HXS          0x00e
#define _FMSP_OTH_L4_HXS        0x00f
#define _FMSP_RETURN_HXS        0x3fe
#define _FMSP_END_PARSE         0x3ff

#define _FMSP_MAX_INSTR_WORDS 992

/* ------------------------------------------------------------------------
 * Assembler parser context object.
 * ------------------------------------------------------------------------ */
typedef struct _fmsp_assembler_parser_context
{
   bool                       assemble_failed;
   fmsp_assembler_options_t   options;
   fmsp_error_code_t          assemble_msg_composition_error;
   char                     **assemble_msg_p;
   char                      *current_file_name_p;
   char                      *output_file_name_p;
   uint32_t                   line_number;
   dll_list_t                 instruction_list;
   uint32_t                   next_program_counter;
   htbl_table_t              *label_table_p;
   char                      *raw_str_p[5];
   uint16_t                   immediate_value[4];
   uint8_t                    num_immediate_values;
   uint32_t                   total_data_bytes;
   uint8_t                    range_start;
   uint8_t                    range_end;
   uint32_t                   ethernet_hxs;
   uint32_t                   ipv4_hxs;
   uint32_t                   ipv6_hxs;
   uint32_t                   other_l3_hxs;
   uint32_t                   tcp_hxs;
   uint32_t                   udp_hxs;
   uint32_t                   ipsec_hxs;
   uint32_t                   other_l4_hxs;
   uint32_t                   l5_hxs;
   /* String to hold values for LCV |= command */
   char                      *value_str_p;
} _fmsp_assembler_parser_context_t;

/* ------------------------------------------------------------------------
 * Instruction type
 * ------------------------------------------------------------------------ */
typedef enum
{
   _fmsp_assembler_raw_e = 0,
   _fmsp_assembler_label_e,
   _fmsp_assembler_nop_e,
   _fmsp_assembler_clm_e,
   _fmsp_assembler_advance_hb_by_wo_e,
   _fmsp_assembler_or_iv_lcv_e,
   _fmsp_assembler_zero_wr_e,
   _fmsp_assembler_ones_comp_wr1_to_wr0_e,
   _fmsp_assembler_case1_dj_wr_to_wr_e,
   _fmsp_assembler_case2_dc_wr_to_wr_e,
   _fmsp_assembler_case2_dj_wr_to_wr_e,
   _fmsp_assembler_case3_dc_wr_to_wr_e,
   _fmsp_assembler_case3_dj_wr_to_wr_e,
   _fmsp_assembler_case4_dc_wr_to_wr_e,
   _fmsp_assembler_bitwise_wr_wr_to_wr_e,
   _fmsp_assembler_compare_working_regs_e,
   _fmsp_assembler_bitwise_wr_iv_to_wr_e,
   _fmsp_assembler_shift_left_wr_by_sv_e,
   _fmsp_assembler_shift_right_wr_by_sv_e,
   _fmsp_assembler_load_bits_iv_to_wr_e,
   _fmsp_assembler_load_sv_to_wo_e,
   _fmsp_assembler_add_sv_to_wo_e,
   _fmsp_assembler_store_iv_to_ra_e,
   _fmsp_assembler_load_bytes_pa_to_wr_e,
   _fmsp_assembler_jump_e,
   _fmsp_assembler_store_wr_to_ra_e,
   _fmsp_assembler_load_bytes_ra_to_wr_e,
   _fmsp_assembler_compare_wr0_to_iv_e,
   _fmsp_assembler_load_bits_fw_to_wr_e,
   _fmsp_assembler_modify_wo_by_wr_e,
   _fmsp_assembler_load_lcv_to_wr_e,
   _fmsp_assembler_store_wr_to_lcv_e,
   _fmsp_assembler_addsub_wr_wr_to_wr_e,
   _fmsp_assembler_addsub_wr_iv_to_wr_e,
   _fmsp_assembler_jmp_nxt_eth_type_e,
   _fmsp_assembler_jmp_nxt_ip_proto_e

} _fmsp_assembler_instruction_type_t;

/* ------------------------------------------------------------------------
 * Variable type
 * ------------------------------------------------------------------------ */
typedef enum _fmsp_variable
{
   _fmsp_uint6_type_e,
   _fmsp_uint7_type_e,
   _fmsp_uint8_type_e,
   _fmsp_uint16_type_e,
   _fmsp_uint32_type_e,
   _fmsp_uint48_type_e,
   _fmsp_uint64_type_e

} _fmsp_assembler_variable_type_t;

/* ------------------------------------------------------------------------
 * Label type
 * ------------------------------------------------------------------------ */
typedef struct _fmsp_label
{
   htbl_entry_t htbl_entry;
   int32_t      program_counter;
} _fmsp_label_t;

/* ------------------------------------------------------------------------
 * Assembler instruction object
 * ------------------------------------------------------------------------ */
typedef struct _fmsp_assembler_instruction
{
   /* Double linked list node */
   dll_node_t                         dll_node;

   /* Instruction type */
   _fmsp_assembler_instruction_type_t type;

   /* Souce file line number for this instruction */
   uint32_t                           line_number;

   /* Hardware program counter for this instruction */
   uint32_t                           program_counter;

   /* Operands, if any */
   uint16_t                           operand[4];
   uint32_t                           operand_size; /* 0, 1, 2, 3, or 4 */

   /* Jump labels */
   char                              *jump_label1_p;
   char                              *jump_label2_p;
   char                              *jump_label3_p;
   char                              *jump_label4_p;

   /* Working register */
   uint8_t                            working_register;

   /* Target working register */
   uint8_t                            target_working_register;

   /* Source working register */
   uint8_t                            source_working_register;

   /* Function */
   uint8_t                            function;

   /* Range start */
   uint8_t                            range_start;

   /* Range end */
   uint8_t                            range_end;

   /* Assign or Concat */
   bool                               is_assign;

   /* HXS */
   bool                               hxs;
   bool                               hxs_1;
   bool                               hxs_2;
   bool                               hxs_3;
   bool                               hxs_4;

   /* Increment Window Offset */
   bool                               increment_window_offset;

   /* Hardware instruction words */
   char                              *hw_words_str_p[5];
   uint16_t                           hw_words_p[5];
   uint8_t                            num_valid_hw_words;

   /* Number of bits */
   uint8_t                            num_bits;

} _fmsp_assembler_instruction_t;

/* ------------------------------------------------------------------------
 * Cleanup the lexical analyzer.
 * ------------------------------------------------------------------------ */
void _fmsp_assembler_lexical_analyzer_cleanup(void);

/* ------------------------------------------------------------------------
 * Deal with parse error.
 * ------------------------------------------------------------------------ */
void _fmsp_assembler_yyerror (_fmsp_assembler_parser_context_t *context_p,
                              char const                       *str_p);

/* ------------------------------------------------------------------------
 * New assembler parser context object.
 *
 * Parameters:
 *   None.
 *
 * Returns:
 *   Pointer to new context object.
 * ------------------------------------------------------------------------ */
_fmsp_assembler_parser_context_t *_fmsp_new_parse_context(void);

/* ------------------------------------------------------------------------
 * Destroy assembler parser context object.
 *
 * Parameters:
 *   Pointer to context object.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
void _fmsp_destroy_parse_context(_fmsp_assembler_parser_context_t *object_p);

/* ------------------------------------------------------------------------
 * New assembler instruction object.
 *
 * Parameters:
 *   type - Instruction type.
 *
 * Returns:
 *   Pointer to new instruction object.
 * ------------------------------------------------------------------------ */
_fmsp_assembler_instruction_t *_fmsp_new_instruction(_fmsp_assembler_instruction_type_t  type,
                                                     _fmsp_assembler_parser_context_t   *ctx_p);

/* ------------------------------------------------------------------------
 * Destroy assembler instruction object.
 *
 * Parameters:
 *   Pointer to instruction object.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
void _fmsp_destroy_instruction(_fmsp_assembler_instruction_t *object_p);

/* ------------------------------------------------------------------------
 * New label object.
 *
 * Parameters:
 *   label_string - Pointer to label string.
 *
 * Returns:
 *   Pointer to new label object.
 * ------------------------------------------------------------------------ */
_fmsp_label_t *_fmsp_new_label(char     *label_string,
                               uint32_t  program_counter);

/* ------------------------------------------------------------------------
 * Destroy label object.
 *
 * Parameters:
 *   Pointer to label object.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
void _fmsp_destroy_label(_fmsp_label_t *object_p);

/* ------------------------------------------------------------------------
 * Cleanup
 *
 * Parameters:
 *   Pointer to context object.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
void _fmsp_cleanup(_fmsp_assembler_parser_context_t *object_p);

/* ---------------------------------------------------------------------------
 * Compose assembler messages
 *
 * Parameters:
 *   context_p - Pointer to context object.
 *   string_p  - Pointer to string to add to message.
 *
 * Returns:
 *   Error code of type fmsp_error_code_t.
 * ---------------------------------------------------------------------------*/
fmsp_error_code_t _fmsp_compose_user_msg (_fmsp_assembler_parser_context_t *context_p,
                                          char                             *string_p);

/* ---------------------------------------------------------------------------
 * Process instruction list
 *
 * Parameters:
 *   context_p - Pointer to context object.
 *
 * Returns:
 *   Error code of type fmsp_error_code_t.
 * ---------------------------------------------------------------------------*/
fmsp_error_code_t _fmsp_assembler_process_instructions (_fmsp_assembler_parser_context_t *context_p);

/* ---------------------------------------------------------------------------
 * Write out hardware instructions
 *
 * Parameters:
 *   context_p - Pointer to context object.
 *
 * Returns:
 *   Error code of type fmsp_error_code_t.
 * ---------------------------------------------------------------------------*/
fmsp_error_code_t _fmsp_assembler_write_output (_fmsp_assembler_parser_context_t *context_p);

/* ---------------------------------------------------------------------------
 * Save hardware instructions
 *
 * Parameters:
 *   ctx_p        - Pointer to context object.
 *   buffer_p     - Buffer to store assembled opcodes.
 *   label_list_p - List to store labels.
 *
 * Returns:
 *   Error code of type fmsp_error_code_t.
 * ---------------------------------------------------------------------------*/
fmsp_error_code_t _fmsp_assembler_save_instructions (_fmsp_assembler_parser_context_t  *ctx_p,
                                                     uint8_t                           *buffer_p,
                                                     fmsp_label_list_t                **label_list_p);

/* ---------------------------------------------------------------------------
 * Clear context instruction values for next instruction.
 *
 * Parameters:
 *   ctx_p - Pointer to context object.
 *
 * Returns:
 *   Nothing.
 * ---------------------------------------------------------------------------*/
void _fmsp_clear_ctx_instruction_values (_fmsp_assembler_parser_context_t *ctx_p);

/* ---------------------------------------------------------------------------
 * Convert range string to start and end integer values.
 *
 * Parameters:
 *   range_string_p - Range string of form xxx:yyy
 *   start_index_p  - Pointer to start index that function will fill in.
 *   end_index_p    - Pointer to end index that function will fill in.
 *
 * Returns:
 *   Boolean - True if successful, false if not.
 * ---------------------------------------------------------------------------*/
bool _fmsp_convert_range_string (char    *range_string_p,
                                 uint8_t *start_index_p,
                                 uint8_t *end_index_p);

#endif /* __FMSP_PRIVATE_H__ */
