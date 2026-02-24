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

/* --------------------------------------------------------------------------
 *
 * Private function implementations for soft parser.
 *
 * --------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fm_sp_private.h"

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

#define EXTRA_CHARS "(() >> 8) & 0xff, () & 0xff"

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * Static function definitions
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/* ------------------------------------------------------------------------
 * Convert a word string to two byte strings.
 *
 * This function frees the passed in string and returns a newly
 * allocated string on success. On failure, NULL is returned and 
 * original string is left alone.
 *
 * Parameters:
 *   word_p - Word string.
 *
 * Returns:
 *   String of 2 bytes on success, NULL on failure.
 * ------------------------------------------------------------------------ */
static char *_fmsp_word_to_bytes(char *word_p)
{
   int   len;
   char *new_p;

   if (word_p == NULL)
   {
      return(NULL);
   }

   len = (2 * strlen(word_p)) + strlen(EXTRA_CHARS) + 1;

   new_p = (char *)calloc(len, 1);

   if (new_p == NULL)
   {
      perror("_fmsp_word_to_bytes: Memory allocate");
      return(NULL);
   }

   snprintf(new_p,
            len,
            "((%s) >> 8) & 0xff, (%s) & 0xff",
            word_p,
            word_p);

   free(word_p);
   return(new_p);
}

/* ------------------------------------------------------------------------
 * Size of instruction (in words).
 *
 * Parameters:
 *   ctx_p - Parse context.
 *
 * Returns:
 *   Size as uint32_t.
 * ------------------------------------------------------------------------ */
static uint32_t _fmsp_instruction_size(_fmsp_assembler_parser_context_t *ctx_p)
{
   uint32_t size = 1; /* All instructions are at least 1 word in size */

   /* Add 1 for each immediate value */
   size += ctx_p->num_immediate_values;

   return (size);
}

#if 0
/* ------------------------------------------------------------------------
 * Display an instruction.
 *
 * Parameters:
 *   instr_p - The instruction to display.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
static void _fmsp_display_instruction(_fmsp_assembler_instruction_t *instr_p)
{
   uint32_t  count;
   char      line[_FMSP_DISPLAY_LINE_SIZE];
   char     *hex_vals;
   uint32_t  pc;
   uint8_t   sv8;
   uint32_t  iv32;
   uint64_t  iv64;
   char     *op_str_p = NULL;
   char      equal_str_p[]              = "==";
   char      not_equal_str_p[]          = "!=";
   char      less_than_str_p[]          = "<";
   char      greater_than_str_p[]       = ">";
   char      less_than_equal_str_p[]    = "<=";
   char      greater_than_equal_str_p[] = ">=";
   char      HXS_str_p[]                = " HXS ";
   char      NO_HXS_str_p[]             = "";
   char     *hxs_1_str_p;
   char     *hxs_2_str_p;
   char     *hxs_3_str_p;
   char     *hxs_4_str_p;


   /* Precalculate the 64 bit immediate value in case it is to be displayed */
   iv64 = instr_p->hw_words[4];
   iv64 = iv64 << 16;

   iv64 = iv64 | instr_p->hw_words[3];
   iv64 = iv64 << 16;

   iv64 = iv64 | instr_p->hw_words[2];
   iv64 = iv64 << 16;

   iv64 = iv64 | instr_p->hw_words[1];

   /* Set to all spaces */
   memset (line, ' ', _FMSP_DISPLAY_LINE_SIZE - 1);

   /* NULL terminate */
   line[_FMSP_DISPLAY_LINE_SIZE - 1] = 0;

   /* Fill in description */
   switch (instr_p->type)
   {
      case _fmsp_assembler_label_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "=== %s ===",
                   instr_p->jump_label1_p);
         break;

      case _fmsp_assembler_nop_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: NOP",
                   instr_p->program_counter);
         break;

      case _fmsp_assembler_advance_hb_by_wo_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: HB += WO",
                   instr_p->program_counter);
         break;

      case _fmsp_assembler_or_iv_lcv_e:
         iv32 = (instr_p->hw_words[2] << 16) | 
                instr_p->hw_words[1];

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: LCV |= 0x%08x",
                   instr_p->program_counter,
                   iv32);
         break;

      case _fmsp_assembler_jump_e:
         pc = instr_p->hw_words[0] & 0x3FF;

         if (instr_p->hxs)
         {
            snprintf (line,
                      _FMSP_DISPLAY_LINE_SIZE,
                      "%03x: JMP HXS 0x%03x",
                      instr_p->program_counter,
                      pc);
         }
         else
         {
            snprintf (line,
                      _FMSP_DISPLAY_LINE_SIZE,
                      "%03x: JMP 0x%03x",
                      instr_p->program_counter,
                      pc);
         }
         break;

      case _fmsp_assembler_case1_dj_wr_to_wr_e:
         if (instr_p->hxs_1)
         {
            hxs_1_str_p = HXS_str_p;
         }
         else
         {
            hxs_1_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_2)
         {
            hxs_2_str_p = HXS_str_p;
         }
         else
         {
            hxs_2_str_p = NO_HXS_str_p;
         }

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: JMP ?%s0x%03x::%s0x%03x",
                   instr_p->program_counter,
                   hxs_1_str_p,
                   instr_p->hw_words[1],
                   hxs_2_str_p,
                   instr_p->hw_words[2]);
         break;

      case _fmsp_assembler_case2_dc_wr_to_wr_e:
         if (instr_p->hxs_1)
         {
            hxs_1_str_p = HXS_str_p;
         }
         else
         {
            hxs_1_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_2)
         {
            hxs_2_str_p = HXS_str_p;
         }
         else
         {
            hxs_2_str_p = NO_HXS_str_p;
         }

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: JMP ?%s0x%03x|%s0x%03x",
                   instr_p->program_counter,
                   hxs_1_str_p,
                   instr_p->hw_words[1],
                   hxs_2_str_p,
                   instr_p->hw_words[2]);
         break;

      case _fmsp_assembler_case2_dj_wr_to_wr_e:
         if (instr_p->hxs_1)
         {
            hxs_1_str_p = HXS_str_p;
         }
         else
         {
            hxs_1_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_2)
         {
            hxs_2_str_p = HXS_str_p;
         }
         else
         {
            hxs_2_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_3)
         {
            hxs_3_str_p = HXS_str_p;
         }
         else
         {
            hxs_3_str_p = NO_HXS_str_p;
         }

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: JMP ?%s0x%03x|%s0x%03x::%s0x%03x",
                   instr_p->program_counter,
                   hxs_1_str_p,
                   instr_p->hw_words[1],
                   hxs_2_str_p,
                   instr_p->hw_words[2],
                   hxs_3_str_p,
                   instr_p->hw_words[3]);
         break;

      case _fmsp_assembler_case3_dc_wr_to_wr_e:
         if (instr_p->hxs_1)
         {
            hxs_1_str_p = HXS_str_p;
         }
         else
         {
            hxs_1_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_2)
         {
            hxs_2_str_p = HXS_str_p;
         }
         else
         {
            hxs_2_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_3)
         {
            hxs_3_str_p = HXS_str_p;
         }
         else
         {
            hxs_3_str_p = NO_HXS_str_p;
         }

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: JMP ?%s0x%03x|%s0x%03x|%s0x%03x",
                   instr_p->program_counter,
                   hxs_1_str_p,
                   instr_p->hw_words[1],
                   hxs_2_str_p,
                   instr_p->hw_words[2],
                   hxs_3_str_p,
                   instr_p->hw_words[3]);
         break;

      case _fmsp_assembler_case3_dj_wr_to_wr_e:
         if (instr_p->hxs_1)
         {
            hxs_1_str_p = HXS_str_p;
         }
         else
         {
            hxs_1_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_2)
         {
            hxs_2_str_p = HXS_str_p;
         }
         else
         {
            hxs_2_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_3)
         {
            hxs_3_str_p = HXS_str_p;
         }
         else
         {
            hxs_3_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_4)
         {
            hxs_4_str_p = HXS_str_p;
         }
         else
         {
            hxs_4_str_p = NO_HXS_str_p;
         }

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: JMP ?%s0x%03x|%s0x%03x|%s0x%03x::%s0x%03x",
                   instr_p->program_counter,
                   hxs_1_str_p,
                   instr_p->hw_words[1],
                   hxs_2_str_p,
                   instr_p->hw_words[2],
                   hxs_3_str_p,
                   instr_p->hw_words[3],
                   hxs_4_str_p,
                   instr_p->hw_words[4]);
         break;

      case _fmsp_assembler_case4_dc_wr_to_wr_e:
         if (instr_p->hxs_1)
         {
            hxs_1_str_p = HXS_str_p;
         }
         else
         {
            hxs_1_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_2)
         {
            hxs_2_str_p = HXS_str_p;
         }
         else
         {
            hxs_2_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_3)
         {
            hxs_3_str_p = HXS_str_p;
         }
         else
         {
            hxs_3_str_p = NO_HXS_str_p;
         }

         if (instr_p->hxs_4)
         {
            hxs_4_str_p = HXS_str_p;
         }
         else
         {
            hxs_4_str_p = NO_HXS_str_p;
         }

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: JMP ?%s0x%03x|%s0x%03x|%s0x%03x|%s0x%03x",
                   instr_p->program_counter,
                   hxs_1_str_p,
                   instr_p->hw_words[1],
                   hxs_2_str_p,
                   instr_p->hw_words[2],
                   hxs_3_str_p,
                   instr_p->hw_words[3],
                   hxs_4_str_p,
                   instr_p->hw_words[4]);
         break;

      case _fmsp_assembler_raw_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: RAW",
                   instr_p->program_counter);
         break;

      case _fmsp_assembler_load_bytes_ra_to_wr_e:
         if (instr_p->is_assign)
         {
            snprintf (line,
                      _FMSP_DISPLAY_LINE_SIZE,
                      "%03x: WR%d = RA[0x%02x:0x%02x]",
                      instr_p->program_counter,
                      instr_p->working_register,
                      instr_p->range_start,
                      instr_p->range_end);
         }
         else
         {
            snprintf (line,
                      _FMSP_DISPLAY_LINE_SIZE,
                      "%03x: WR%d <<= RA[0x%02x:0x%02x]",
                      instr_p->program_counter,
                      instr_p->working_register,
                      instr_p->range_start,
                      instr_p->range_end);
         }
         break;

      case _fmsp_assembler_store_wr_to_ra_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: RA[0x%02x:0x%02x] = WR%d",
                   instr_p->program_counter,
                   instr_p->range_start,
                   instr_p->range_end,
                   instr_p->working_register);
         break;

      case _fmsp_assembler_store_iv_to_ra_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: RA[0x%02x:0x%02x] = 0x%016lx",
                   instr_p->program_counter,
                   instr_p->range_start,
                   instr_p->range_end,
                   iv64);
         break;

      case _fmsp_assembler_load_sv_to_wo_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: WO = 0x%02x",
                   instr_p->program_counter,
                   instr_p->hw_words[0] & 0xff);
         break;

      case _fmsp_assembler_add_sv_to_wo_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: WO += 0x%02x",
                   instr_p->program_counter,
                   instr_p->hw_words[0] & 0xff);
         break;

      case _fmsp_assembler_zero_wr_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: CLR WR%d",
                   instr_p->program_counter,
                   instr_p->working_register);
         break;

      case _fmsp_assembler_ones_comp_wr1_to_wr0_e:
         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: WR0 = CKSUM(WR0, WR1)",
                   instr_p->program_counter);
         break;

      case _fmsp_assembler_bitwise_wr_wr_to_wr_e:
         switch (instr_p->function)
         {
            case _FMSP_OPERATOR_OR:
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d = WR0 OR WR1",
                         instr_p->program_counter,
                         instr_p->working_register);
               break;

            case _FMSP_OPERATOR_AND:
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d = WR0 AND WR1",
                         instr_p->program_counter,
                         instr_p->working_register);
               break;

            case _FMSP_OPERATOR_XOR:
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d = WR0 XOR WR1",
                         instr_p->program_counter,
                         instr_p->working_register);
               break;

            default:
               printf ("INTERNAL ERROR: Unrecognized function type: %d\n", instr_p->function);
               break;
         }
         break;

      case _fmsp_assembler_bitwise_wr_iv_to_wr_e:
         switch (instr_p->function)
         {
            case _FMSP_OPERATOR_OR:
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d = WR%d OR 0x%016lx",
                         instr_p->program_counter,
                         instr_p->target_working_register,
                         instr_p->source_working_register,
                         iv64);
               break;

            case _FMSP_OPERATOR_AND:
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d = WR%d AND 0x%016lx",
                         instr_p->program_counter,
                         instr_p->target_working_register,
                         instr_p->source_working_register,
                         iv64);
               break;

            case _FMSP_OPERATOR_XOR:
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d = WR%d XOR 0x%016lx",
                         instr_p->program_counter,
                         instr_p->target_working_register,
                         instr_p->source_working_register,
                         iv64);
               break;

            default:
               printf ("INTERNAL ERROR: Unrecognized function type: %d\n", instr_p->function);
               break;
         }
         break;

      case _fmsp_assembler_shift_left_wr_by_sv_e:
         sv8 = (instr_p->hw_words[0] >> 1) & 0x1f;

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: WR%d << 0x%02x",
                   instr_p->program_counter,
                   instr_p->working_register,
                   sv8);
         break;

      case _fmsp_assembler_shift_right_wr_by_sv_e:
         sv8 = (instr_p->hw_words[0] >> 1) & 0x1f;

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: WR%d >> 0x%02x",
                   instr_p->program_counter,
                   instr_p->working_register,
                   sv8);
         break;

      case _fmsp_assembler_load_bits_iv_to_wr_e:
         if (instr_p->is_assign)
         {
            snprintf (line,
                      _FMSP_DISPLAY_LINE_SIZE,
                      "%03x: WR%d = 0x%016lx:%d",
                      instr_p->program_counter,
                      instr_p->working_register,
                      iv64,
                      instr_p->num_bits);
         }
         else
         {
            snprintf (line,
                      _FMSP_DISPLAY_LINE_SIZE,
                      "%03x: WR%d <<= 0x%016lx:%d",
                      instr_p->program_counter,
                      instr_p->working_register,
                      iv64,
                      instr_p->num_bits);
         }
         break;

      case _fmsp_assembler_load_bytes_pa_to_wr_e:
         if (instr_p->is_assign)
         {
            snprintf (line,
                      _FMSP_DISPLAY_LINE_SIZE,
                      "%03x: WR%d = PA[%d:%d]",
                      instr_p->program_counter,
                      instr_p->working_register,
                      instr_p->range_start,
                      instr_p->range_end);
         }
         else
         {
            snprintf (line,
                      _FMSP_DISPLAY_LINE_SIZE,
                      "%03x: WR%d <<= PA[%d:%d]",
                      instr_p->program_counter,
                      instr_p->working_register,
                      instr_p->range_start,
                      instr_p->range_end);
         }
         break;

      case _fmsp_assembler_load_bits_fw_to_wr_e:
         if (instr_p->is_assign)
         {
            if (instr_p->increment_window_offset)
            {
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d = FW[%d..%d] :WO+",
                         instr_p->program_counter,
                         instr_p->working_register,
                         instr_p->range_start,
                         instr_p->range_end);
            }
            else
            {
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d = FW[%d..%d]",
                         instr_p->program_counter,
                         instr_p->working_register,
                         instr_p->range_start,
                         instr_p->range_end);
            }
         }
         else
         {
            if (instr_p->increment_window_offset)
            {
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d <<= FW[%d..%d] :WO+",
                         instr_p->program_counter,
                         instr_p->working_register,
                         instr_p->range_start,
                         instr_p->range_end);
            }
            else
            {
               snprintf (line,
                         _FMSP_DISPLAY_LINE_SIZE,
                         "%03x: WR%d <<= FW[%d..%d]",
                         instr_p->program_counter,
                         instr_p->working_register,
                         instr_p->range_start,
                         instr_p->range_end);
            }
         }
         break;

      case _fmsp_assembler_compare_working_regs_e:
         switch (instr_p->function)
         {
            case _FMSP_OPERATOR_EQUAL:
               op_str_p = equal_str_p;
               break;
            case _FMSP_OPERATOR_NOT_EQUAL:
               op_str_p = not_equal_str_p;
               break;
            case _FMSP_OPERATOR_GREATER_THAN:
               op_str_p = greater_than_str_p;
               break;
            case _FMSP_OPERATOR_LESS_THAN:
               op_str_p = less_than_str_p;
               break;
            case _FMSP_OPERATOR_GREATER_THAN_EQUAL:
               op_str_p = greater_than_equal_str_p;
               break;
            case _FMSP_OPERATOR_LESS_THAN_EQUAL:
               op_str_p = less_than_equal_str_p;
               break;
            default:
               printf ("INTERNAL ERROR: Unrecognized function: %d\n", instr_p->function);
               break;
         }

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: JMP 0x%03x IF WR0 %s WR1",
                   instr_p->program_counter,
                   instr_p->hw_words[1],
                   op_str_p);
         break;

      case _fmsp_assembler_compare_wr0_to_iv_e:
         pc = instr_p->hw_words[0] & 0x3FF;

         switch (instr_p->function)
         {
            case _FMSP_OPERATOR_EQUAL:
               op_str_p = equal_str_p;
               break;
            case _FMSP_OPERATOR_NOT_EQUAL:
               op_str_p = not_equal_str_p;
               break;
            case _FMSP_OPERATOR_GREATER_THAN:
               op_str_p = greater_than_str_p;
               break;
            case _FMSP_OPERATOR_LESS_THAN:
               op_str_p = less_than_str_p;
               break;
            default:
               printf ("INTERNAL ERROR: Unrecognized function: %d\n", instr_p->function);
               break;
         }

         snprintf (line,
                   _FMSP_DISPLAY_LINE_SIZE,
                   "%03x: JMP 0x%03x IF WR0 %s 0x%016lx",
                   instr_p->program_counter,
                   pc,
                   op_str_p,
                   iv64);
         break;

      default:
         printf ("INTERNAL ERROR: Unrecognized instruction type: %d\n", instr_p->type);
         break;
   }

   /* Pad with space up to _FMSP_DISPLAY_DESCR_SIZE then put the 
    * instruction code in hex.
    */

   /* Overwrite NULL at end of description string with space */
   memset(line + strlen(line), ' ', 1);

   hex_vals = line + _FMSP_DISPLAY_DESCR_SIZE;

   switch (instr_p->num_valid_hw_words)
   {
      case 1:
         snprintf (hex_vals,
                   _FMSP_DISPLAY_LINE_SIZE - _FMSP_DISPLAY_DESCR_SIZE,
                   " 0x%04x",
                   instr_p->hw_words[0]);
         break;

      case 2:
         snprintf (hex_vals,
                   _FMSP_DISPLAY_LINE_SIZE - _FMSP_DISPLAY_DESCR_SIZE,
                   " 0x%04x 0x%04x",
                   instr_p->hw_words[0],
                   instr_p->hw_words[1]);
         break;

      case 3:
         snprintf (hex_vals,
                   _FMSP_DISPLAY_LINE_SIZE - _FMSP_DISPLAY_DESCR_SIZE,
                   " 0x%04x 0x%04x 0x%04x",
                   instr_p->hw_words[0],
                   instr_p->hw_words[1],
                   instr_p->hw_words[2]);
         break;

      case 4:
         snprintf (hex_vals,
                   _FMSP_DISPLAY_LINE_SIZE - _FMSP_DISPLAY_DESCR_SIZE,
                   " 0x%04x 0x%04x 0x%04x 0x%04x",
                   instr_p->hw_words[0],
                   instr_p->hw_words[1],
                   instr_p->hw_words[2],
                   instr_p->hw_words[3]);
         break;

      case 5:
         snprintf (hex_vals,
                   _FMSP_DISPLAY_LINE_SIZE - _FMSP_DISPLAY_DESCR_SIZE,
                   " 0x%04x 0x%04x 0x%04x 0x%04x 0x%04x",
                   instr_p->hw_words[0],
                   instr_p->hw_words[1],
                   instr_p->hw_words[2],
                   instr_p->hw_words[3],
                   instr_p->hw_words[4]);
         break;

      default:
         break;
   }


   printf("%s\n", line);
}
#endif

/* ---------------------------------------------------------------------------
 * Get program counter from label.
 *
 * Parameters:
 *   ctx_p     - Pointer to context object.
 *   label_p   - Pointer to label string.
 *
 * Returns:
 *   Program counter number that correlates to the given label. -1 if not found.
 * ---------------------------------------------------------------------------*/
static int32_t _fmsp_pc_from_label(_fmsp_assembler_parser_context_t *ctx_p,
                                   char                             *label_p)
{
   htbl_entry_t  *entry_p;
   _fmsp_label_t *label_obj_p;
   char          *full_label_p;

   full_label_p = (char *)calloc(strlen(label_p)  +
                                 1,
                                 1);

   if (full_label_p == NULL)
   {
      return (-1);
   }

   strcat(full_label_p, label_p);

   /* Find label in hash table */
   entry_p = htbl_get_entry(ctx_p->label_table_p,
                            full_label_p);

   if (entry_p != NULL)
   {
      label_obj_p = HTBL_GET_ENTRY_OBJECT(entry_p,
                                          _fmsp_label_t,
                                          htbl_entry);

      free (full_label_p); //ROEE added to solve memleak
      return (label_obj_p->program_counter);
   }
   else
   {
       free (full_label_p); //ROEE added to solve memleak
      return (-1);
   }
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * Private module function definitions
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/* ------------------------------------------------------------------------
 * New assembler parser context object.
 *
 * Parameters:
 *   None.
 *
 * Returns:
 *   Pointer to new context object (NULL on failure).
 * ------------------------------------------------------------------------ */
_fmsp_assembler_parser_context_t *_fmsp_new_parse_context(void)
{
   _fmsp_assembler_parser_context_t *object_p;

   object_p = (_fmsp_assembler_parser_context_t *)calloc(1,
                                                         sizeof(_fmsp_assembler_parser_context_t));

   if (object_p == NULL)
   {
      return (NULL);
   }

   /* Create hash table for labels */
   object_p->label_table_p = htbl_create(_FMSP_LABEL_TABLE_SIZE);

   if (object_p->label_table_p == NULL)
   {
      free (object_p);
      return (NULL);
   }

   dll_list_init(&(object_p->instruction_list));

   object_p->assemble_failed       = false;
   object_p->line_number           = 1;

   return (object_p);
}

/* ------------------------------------------------------------------------
 * Destroy assembler parser context object.
 *
 * Parameters:
 *   Pointer to context object.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
void _fmsp_destroy_parse_context(_fmsp_assembler_parser_context_t *object_p)
{
   dll_list_t                    *key_list_p;
   dll_node_t                    *node_p;
   htbl_key_t                    *key_obj_p;
   _fmsp_label_t                 *label_p;
   uint32_t                       count;
   uint32_t                       num_items;
   htbl_entry_t                  *entry_p;
   _fmsp_assembler_instruction_t *instr_obj_p;

   if (object_p == NULL)
   {
      return;
   }

   /* Destroy the hash table and the items in it. */
   key_list_p = htbl_get_key_list(object_p->label_table_p);

   if (key_list_p != NULL)
   {
      num_items = dll_count(key_list_p);

      node_p = dll_get_first(key_list_p);

      for (count = 0; count < num_items; count++)
      {
         /* Get key, then delete the hash table entry associated
          * with that key.
          */
         key_obj_p = DLL_STRUCT_FROM_NODE_GET(node_p,
                                              htbl_key_t,
                                              dll_node);

         entry_p = htbl_get_entry(object_p->label_table_p,
                                  key_obj_p->string_p);

         htbl_delete_by_entry(object_p->label_table_p,
                              entry_p);

         /* Destroy the label object associated with the entry. */
         label_p = HTBL_GET_ENTRY_OBJECT(entry_p,
                                         _fmsp_label_t,
                                         htbl_entry);

         _fmsp_destroy_label(label_p);

         /* Move to the next key in the list. */
         node_p = dll_get_next_node(key_list_p,
                                    node_p);
                            
      }

      htbl_destroy_key_list(key_list_p);
   }
   
   htbl_destroy(object_p->label_table_p);

   /* Clear the instruction list */
   num_items = dll_count(&(object_p->instruction_list));
   
   for (count = 0; count < num_items; count++)
   {
      node_p = dll_remove_from_front(&(object_p->instruction_list));

      instr_obj_p = DLL_STRUCT_FROM_NODE_GET(node_p,
                                             _fmsp_assembler_instruction_t,
                                             dll_node);

      _fmsp_destroy_instruction(instr_obj_p);
   }

   /* Clear the LCV value string */
   if (object_p->value_str_p != NULL)
   {
      /* Use free since we used strdup/calloc to create the string. */
      free (object_p->value_str_p);
      object_p->value_str_p = NULL;
   }

   free(object_p);
}

/* ------------------------------------------------------------------------
 * New assembler instruction object.
 *
 * Parameters:
 *   None.
 *
 * Returns:
 *   Pointer to new instruction object.
 * ------------------------------------------------------------------------ */
_fmsp_assembler_instruction_t *_fmsp_new_instruction(_fmsp_assembler_instruction_type_t  type,
                                                     _fmsp_assembler_parser_context_t   *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;

   object_p = calloc(1, sizeof(_fmsp_assembler_instruction_t));

   if (object_p == NULL)
   {
      return (NULL);
   }

   /* Initialize with values */
   object_p->type            = type;
   object_p->program_counter = ctx_p->next_program_counter;
   object_p->line_number     = ctx_p->line_number;

   /* Increment the next_program_counter value for all instructions
    * except labels.
    */
   if (type != _fmsp_assembler_label_e)
   {
      ctx_p->next_program_counter += _fmsp_instruction_size(ctx_p);
   }

   return (object_p);
}

/* ------------------------------------------------------------------------
 * Destroy assembler instruction object.
 *
 * Parameters:
 *   Pointer to instruction object.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
void _fmsp_destroy_instruction(_fmsp_assembler_instruction_t *object_p)
{
   uint32_t count = 0;

   if (object_p == NULL)
   {
      return;
   }
 
   /* Created with strdup */
   if (object_p->jump_label1_p != NULL)
   {
      free (object_p->jump_label1_p);
   }

   if (object_p->jump_label2_p != NULL)
   {
      free (object_p->jump_label2_p);
   }

   if (object_p->jump_label3_p != NULL)
   {
      free (object_p->jump_label3_p);
   }

   if (object_p->jump_label4_p != NULL)
   {
      free (object_p->jump_label4_p);
   }

   /* Allocated with calloc */
   for (count = 0; count < 5; count++)
   {
      if (object_p->hw_words_str_p[count] != NULL)
      {
         free (object_p->hw_words_str_p[count]);
      }
   }

   free(object_p);
}

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
                               uint32_t  program_counter)
{
   _fmsp_label_t *object_p;

   object_p = (_fmsp_label_t *)calloc(1, sizeof(_fmsp_label_t));

   if (object_p == NULL)
   {
      return (NULL);
   }

   /* Initialize with values */
   (object_p->htbl_entry).key_p = strdup(label_string);

   if ((object_p->htbl_entry).key_p == NULL)
   {
      free (object_p);
      return (NULL);
   }

   object_p->program_counter = program_counter;

   return (object_p);
}

/* ------------------------------------------------------------------------
 * Destroy label object.
 *
 * Parameters:
 *   Pointer to label object.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
void _fmsp_destroy_label(_fmsp_label_t *object_p)
{
   if (object_p == NULL)
   {
      return;
   }

   /* key created with strdup */
   if ((object_p->htbl_entry).key_p != NULL)
   {
      free ((object_p->htbl_entry).key_p);
   }

   free (object_p);
}

/* ------------------------------------------------------------------------
 * Cleanup
 *
 * Parameters:
 *   Pointer to context object.
 *
 * Returns:
 *   Nothing.
 * ------------------------------------------------------------------------ */
int _fmsp_assembler_yylex_destroy  (void);

void _fmsp_cleanup(_fmsp_assembler_parser_context_t *object_p)
{
   _fmsp_destroy_parse_context(object_p);
   _fmsp_assembler_yylex_destroy();
}

/* ------------------------------------------------------------------------
 * Deal with parse error.
 * ------------------------------------------------------------------------ */
void _fmsp_assembler_yyerror (_fmsp_assembler_parser_context_t *ctx_p,
                              char const                       *str_p)
{
   uint32_t           str_len        = 0;
   uint32_t           file_info_len  = 0;
   uint32_t           message_len    = 0;
   char              *file_info_p    = NULL;
   char              *message_p      = NULL;
   char              *header_p       = "SPA: ERROR: ";
   fmsp_error_code_t  result;

   /* The assemble has failed */
   ctx_p->assemble_failed = true;

   /* Length of string parameter */
   str_len = strlen(str_p);

   /* Add file name and line number if present
    *
    * "<filename>: Line <linenum>"
    */
   if (ctx_p->current_file_name_p != NULL)
   {
      file_info_len = strlen(ctx_p->current_file_name_p) + 
                      strlen(": Line ")                      +
                      (ctx_p->line_number / 10) + 1      + /* Num chars for line num */
                      1;

      file_info_p = (char *)calloc(1, file_info_len);

      if (file_info_p == NULL)
      {
         /* Indicate that failure occured while composing message */
         ctx_p->assemble_msg_composition_error = fmsp_malloc_failure_e;
         return;
      }

      snprintf(file_info_p,
               file_info_len,
               "%s: Line %d",
               ctx_p->current_file_name_p,
               ctx_p->line_number);
   }

   /* If a string was passed in, append it with file info to the assembler
    * message. 
    */
   if (str_p != NULL)
   {
      message_len = strlen(header_p) +
                    file_info_len    +
                    1                +    /* Space after file info */
                    str_len          +
                    1;                    /* Terminating NULL */

      message_p = (char *)calloc(1, message_len);
      
      if (message_p == NULL)
      {
         /* Indicate that failure occured while composing message */
         ctx_p->assemble_msg_composition_error = fmsp_malloc_failure_e;

         if (file_info_p != NULL)
         {
            free (file_info_p);
         }

         return;
      }

      snprintf(message_p,
               message_len,
               "%s%s %s",
               header_p,
               file_info_p,
               str_p);

      result = _fmsp_compose_user_msg(ctx_p, message_p);

      if (result != fmsp_ok_e)
      {
         ctx_p->assemble_msg_composition_error = result;
      }
   }
   else
   {
      result = _fmsp_compose_user_msg(ctx_p, "No error msg available...");

      if (result != fmsp_ok_e)
      {
         ctx_p->assemble_msg_composition_error = result;
      }
   }

   /* Cleanup */
   if (file_info_p != NULL)
   {
      free (file_info_p);
   }

   if (message_p != NULL)
   {
      free (message_p);
   }
}

/* ---------------------------------------------------------------------------
 * Compose assembler messages
 *
 * Parameters:
 *   ctx_p - Pointer to context object.
 *   string_p  - Pointer to string to add to message.
 *
 * Returns:
 *   Error code of type fmsp_error_code_t.
 * ---------------------------------------------------------------------------*/
fmsp_error_code_t _fmsp_compose_user_msg (_fmsp_assembler_parser_context_t *ctx_p,
                                          char                             *string_p)
{
   int32_t  len;
   char    *tmp_p;

   /* Check context */
   if (ctx_p == NULL)
   {
      return (fmsp_internal_error_e);
   }

   /* Check string */
   if (string_p == NULL)
   {
      /* Assume empty string - do nothing */
      return (fmsp_ok_e);
   }

   /* Check if the user passed in a string for use */
   if (ctx_p->assemble_msg_p == NULL)
   {
      return (fmsp_ok_e);
   }

   /* Check if we are appending or this is the first part of the string */
   if (*(ctx_p->assemble_msg_p) == NULL)
   {
      *(ctx_p->assemble_msg_p) = (char *)calloc(1, strlen(string_p) + 1);

      if (*(ctx_p->assemble_msg_p) == NULL)
      {
         return (fmsp_malloc_failure_e);
      }

      strcpy(*(ctx_p->assemble_msg_p), string_p);
   }
   else
   {
      /* Length of current compile message */
      len = strlen(*(ctx_p->assemble_msg_p));

      /* Length of string to add */
      len += strlen(string_p);

      /* Make sure there is room for terminating NULL */
      len++;

      /* Increase size of compile message to accomodate new string */
      tmp_p = (char *)calloc(1, len);

      if (tmp_p == NULL)
      {
         return (fmsp_malloc_failure_e);
      }

      /* Concat string to original message */
      strcat(tmp_p, *(ctx_p->assemble_msg_p));
      strcat(tmp_p, string_p);

      if (*(ctx_p->assemble_msg_p) != NULL)
      {
         free (*(ctx_p->assemble_msg_p));
      }

      *(ctx_p->assemble_msg_p) = tmp_p;
   }

   return (fmsp_ok_e);
}

/* ---------------------------------------------------------------------------
 * Process instruction list
 *
 * Parameters:
 *   ctx_p - Pointer to context object.
 *
 * Returns:
 *   Error code of type fmsp_error_code_t.
 * ---------------------------------------------------------------------------*/
fmsp_error_code_t _fmsp_assembler_process_instructions (_fmsp_assembler_parser_context_t *ctx_p)
{
   dll_node_t                    *node_p;
   _fmsp_assembler_instruction_t *instr_p;
   int32_t                        program_counter;
   char                          *tmp_str_p;
   uint32_t                       len;
   char                           or_str_p[] = " | ";

   node_p = dll_get_first(&(ctx_p->instruction_list));

   while (node_p != NULL)
   {
      instr_p = DLL_STRUCT_FROM_NODE_GET(node_p,
                                         _fmsp_assembler_instruction_t,
                                         dll_node);

      switch (instr_p->type)
      {
         case _fmsp_assembler_jump_e:

            /* Check for special hardware labels. */
            if (strcmp(instr_p->jump_label1_p, _FMSP_ETH_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_ETH_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_IPV4_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_IPV4_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_IPV6_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_IPV6_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_OTH_L3_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_OTH_L3_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_TCP_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_TCP_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_UDP_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_UDP_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_OTH_L4_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_OTH_L4_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_RETURN_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_RETURN_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_END_PARSE_LABEL) == 0)
            {
               program_counter = _FMSP_END_PARSE;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_LLC_SNAP_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_LLC_SNAP_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_VLAN_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_VLAN_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_PPPOE_PPP_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_PPPOE_PPP_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_MPLS_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_MPLS_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_GRE_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_GRE_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_MINENCAP_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_MINENCAP_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_IPSEC_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_IPSEC_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_SCTP_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_SCTP_HXS;
            }
            else if (strcmp(instr_p->jump_label1_p, _FMSP_DCCP_HXS_LABEL) == 0)
            {
               program_counter = _FMSP_DCCP_HXS;
            }
            else
            {
               /* Check the label exists */
               program_counter = _fmsp_pc_from_label(ctx_p,
                                                     instr_p->jump_label1_p);

               if (program_counter < 0)
               {
                  return(fmsp_invalid_label_e);
               }
            }

            tmp_str_p = instr_p->hw_words_str_p[0];
            
            len = strlen(tmp_str_p) +
                  strlen(or_str_p)  +
                  6                 +  /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[0] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[0],
                     len,
                     "%s%s0x%04x",
                     tmp_str_p,
                     or_str_p,
                     program_counter);

            free (tmp_str_p);

            /* HW opcode */
            instr_p->hw_words_p[0] = instr_p->hw_words_p[0] | program_counter;

            break;

         case _fmsp_assembler_compare_working_regs_e:

            /* Check the label exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label1_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[1] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[1],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[1] = program_counter;

            break;

         case _fmsp_assembler_compare_wr0_to_iv_e:

            /* Check the label exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label1_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            tmp_str_p = instr_p->hw_words_str_p[0];
            
            len = strlen(tmp_str_p) +
                  strlen(or_str_p)  +
                  6                 +   /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[0] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[0],
                     len,
                     "%s%s0x%04x",
                     tmp_str_p,
                     or_str_p,
                     program_counter);

            free (tmp_str_p);

            /* HW opcode */
            instr_p->hw_words_p[0] = instr_p->hw_words_p[0] | program_counter;

            break;

         case _fmsp_assembler_case1_dj_wr_to_wr_e:
         case _fmsp_assembler_case2_dc_wr_to_wr_e:

            /* Check label 1 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label1_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[1] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[1],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[1] = program_counter;

            /* Check label 2 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label2_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[2] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[2],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[2] = program_counter;

            break;

         case _fmsp_assembler_case2_dj_wr_to_wr_e:
         case _fmsp_assembler_case3_dc_wr_to_wr_e:

            /* Check label 1 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label1_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[1] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[1],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[1] = program_counter;

            /* Check label 2 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label2_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[2] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[2],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[2] = program_counter;

            /* Check label 3 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label3_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[3] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[3],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[3] = program_counter;

            break;

         case _fmsp_assembler_case3_dj_wr_to_wr_e:
         case _fmsp_assembler_case4_dc_wr_to_wr_e:

            /* Check label 1 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label1_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[1] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[1],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[1] = program_counter;

            /* Check label 2 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label2_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[2] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[2],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[2] = program_counter;

            /* Check label 3 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label3_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[3] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[3],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[3] = program_counter;

            /* Check label 4 exists */
            program_counter = _fmsp_pc_from_label(ctx_p,
                                                  instr_p->jump_label4_p);

            if (program_counter < 0)
            {
               return(fmsp_invalid_label_e);
            }

            len = 6 + /* 0xNNNN */
                  1;

            instr_p->hw_words_str_p[4] = (char *)calloc(len + 1, 1);

            if (instr_p->hw_words_str_p[4] == NULL)
            {
               return(fmsp_malloc_failure_e);
            }

            program_counter = program_counter & 0x3ff;

            snprintf(instr_p->hw_words_str_p[4],
                     len,
                     "0x%04x",
                     program_counter);

            /* HW opcode */
            instr_p->hw_words_p[4] = program_counter;

            break;

         default:
            /* Do nothing */
            break;
      }

      /* Keep running total of required BYTEs for all instructions.
       * This is used in the output file.
       */
      ctx_p->total_data_bytes += 2 * instr_p->num_valid_hw_words;

      node_p = dll_get_next_node(&(ctx_p->instruction_list),
                                 node_p);
   }
   return (fmsp_ok_e);
}

#if 0
/* ---------------------------------------------------------------------------
 * Display instruction list
 *
 * Parameters:
 *   ctx_p - Pointer to context object.
 *
 * Returns:
 *   Nothing.
 * ---------------------------------------------------------------------------*/
void _fmsp_assembler_display_instruction_list (_fmsp_assembler_parser_context_t *ctx_p)
{
   dll_node_t                    *node_p;
   _fmsp_assembler_instruction_t *instr_p;
   uint32_t                       count;

   printf("\n");
   printf("--------------------------------------------------------------------------------\n");
   printf("                                Instructions\n");
   printf("--------------------------------------------------------------------------------\n");
   printf("\n");

   node_p = dll_get_first(&(ctx_p->instruction_list));

   while (node_p != NULL)
   {
      instr_p = DLL_STRUCT_FROM_NODE_GET(node_p,
                                         _fmsp_assembler_instruction_t,
                                         dll_node);

      /* Debug display of instructions */
      //_fmsp_display_instruction(instr_p);

      node_p = dll_get_next_node(&(ctx_p->instruction_list),
                                 node_p);
   }

   printf("\nTotal bytes of instructions generated: %d\n", ctx_p->total_data_bytes);
}
#endif

/* ---------------------------------------------------------------------------
 * Write out hardware instructions
 *
 * Parameters:
 *   ctx_p - Pointer to context object.
 *
 * Returns:
 *   Error code of type fmsp_error_code_t.
 * ---------------------------------------------------------------------------*/
fmsp_error_code_t _fmsp_assembler_write_output (_fmsp_assembler_parser_context_t *ctx_p)
{
   dll_node_t                    *node_p;
   htbl_key_t                    *key_p;
   dll_list_t                    *key_list_p;
   htbl_entry_t                  *entry_p;
   _fmsp_label_t                 *label_obj_p;
   _fmsp_assembler_instruction_t *instr_p;
   FILE                          *output_file_p;
   uint32_t                       bytes_written;
   uint32_t                       count;
   uint32_t                       len;
   bool                           first;
   char                          *label_str_p;
   char                          *whole_trailer_p;
   char                           prefix_str_p[] = "__assembled__";
   char                           labels_header_p[] =
"/* -------------------------------------------------------------------------\n"
" * Label names.\n"
" * ------------------------------------------------------------------------- */\n"
"typedef enum {\n";

   char                           labels_trailer_p[] = "\n} ";
   char                           labels_name_base_p[] = "soft_parse_label_names_t;\n\n";
   char                           line_feed_p[]      = "\n";
   char                           more_line_feed_p[] = ",\n";
   char                           sep_str_p[]        = ", ";
   char                           assign_str_p[]     = " = ";
   char                           indent_str_p[]     = "   ";
   char                          *name_p;
   size_t                         name_size;
   char                           eol[]              = "\n   ";
   size_t                         eol_len            = strlen(eol);
   char                           pad_word[]         = "0x00, 0x00, ";
   size_t                         pad_word_len       = strlen(pad_word);
   char                           last_pad_word[]    = "0x00, 0x00\n";
   size_t                         last_pad_word_len  = strlen(last_pad_word);
   char                           start_pad[]        = ",\n   ";
   size_t                         start_pad_len      = strlen(start_pad);
   uint32_t                       leading_pad;
   uint32_t                       total_instr_words  = 0;

   /* ====================================================================
    * .h file
    * ====================================================================*/

   name_size = strlen(prefix_str_p) + 3; /* Add 3 for ".h" and NULL */

   name_p = (char *)calloc(name_size, 1);

   if (name_p == NULL)
   {
      return (fmsp_malloc_failure_e);
   }

   snprintf(name_p,
            name_size,
            "%s.h",
            prefix_str_p);

   output_file_p = fopen(name_p, "w");

   if (output_file_p == NULL)
   {
      free(name_p);
      return (fmsp_output_file_open_failure_e);
   }

   /* -------------------------------------------------------
    * Enum table of all labels with their corresponding
    * instruction word address.
    * ------------------------------------------------------- */
   len = strlen(labels_header_p);

   bytes_written = fwrite(labels_header_p,
                          1,              /* 1 byte blocks */
                          len,
                          output_file_p);

   if (bytes_written != len)
   {
      fclose(output_file_p);
      return (fmsp_output_file_write_error_e);
   }

   /* Get list of keys in hash table. */
   key_list_p = htbl_get_key_list(ctx_p->label_table_p);

   first = true;

   /* Walk list of keys. */
   node_p = dll_get_first(key_list_p);

   while (node_p != NULL)
   {
      key_p = DLL_STRUCT_FROM_NODE_GET(node_p,
                                       htbl_key_t,
                                       dll_node);

      entry_p = htbl_get_entry(ctx_p->label_table_p,
                               key_p->string_p);

      /* Find label in hash table */
      if (entry_p != NULL)
      {
         label_obj_p = HTBL_GET_ENTRY_OBJECT(entry_p,
                                             _fmsp_label_t,
                                             htbl_entry);

         len = strlen(indent_str_p)    +
               strlen(key_p->string_p) +
               strlen(assign_str_p)    +
               10                      + /* 0xNNNNNNNN */
               3;                        /* ,\n and NULL */

         label_str_p = (char *)calloc(len + 1, 1);

         if (label_str_p == NULL)
         {
            free(name_p);
            fclose(output_file_p);
            return (fmsp_malloc_failure_e);
         }

         if (first)
         {
            first = false;

            snprintf(label_str_p,
                     len,
                     "%s%s%s0x%08x",
                     indent_str_p,
                     key_p->string_p,
                     assign_str_p,
                     label_obj_p->program_counter);
         }
         else
         {
            snprintf(label_str_p,
                     len,
                     ",\n%s%s%s0x%08x",
                     indent_str_p,
                     key_p->string_p,
                     assign_str_p,
                     label_obj_p->program_counter);
         }

         len = strlen(label_str_p);

         bytes_written = fwrite(label_str_p,
                                1,              /* 1 byte blocks */
                                len,
                                output_file_p);

         if (bytes_written != len)
         {
            free(name_p);
            fclose(output_file_p);
            return (fmsp_output_file_write_error_e);
         }

         free (label_str_p);
      }

      node_p = dll_get_next_node(key_list_p,
                                 node_p);
   }

   /* Cleanup key list */
   htbl_destroy_key_list(key_list_p);

   /* Trailer */
   len = strlen(labels_trailer_p)   +
         strlen(prefix_str_p)       +
         strlen(labels_name_base_p) + 
         1;

   whole_trailer_p = (char *)calloc(len + 1, 1);
   
   if (whole_trailer_p == NULL)
   {
      free(name_p);
      fclose(output_file_p);
      return (fmsp_malloc_failure_e);
   }

   snprintf(whole_trailer_p,
            len,
            "%s%s%s",
            labels_trailer_p,
            prefix_str_p,
            labels_name_base_p);

   len = strlen(whole_trailer_p);

   bytes_written = fwrite(whole_trailer_p,
                          1,              /* 1 byte blocks */
                          len,
                          output_file_p);

   if (bytes_written != len)
   {
      free(name_p);
      fclose(output_file_p);
      return (fmsp_output_file_write_error_e);
   }

   free (whole_trailer_p);

   fclose (output_file_p);

   /* ====================================================================
    * .c file
    * ====================================================================*/

   snprintf(name_p,
            name_size,
            "%s.c",
            prefix_str_p);

   output_file_p = fopen(name_p, "w");

   /* No longer need name */
   free(name_p);

   if (output_file_p == NULL)
   {
      return (fmsp_output_file_open_failure_e);
   }

   /* -------------------------------------------------------
    * Add leading pad if instructions do not start at
    * default location.
    * ------------------------------------------------------- */

   leading_pad = (ctx_p->options).program_space_base_address - FMSP_PARSE_PROGRAM_DEFAULT_BASE_ADDRESS;

   for (count = 0;
        count <  leading_pad;
        count++)
   {
      bytes_written = fwrite(pad_word,
                             1,              /* 1 byte blocks */
                             pad_word_len,
                             output_file_p);

      if (bytes_written != pad_word_len)
      {
         fclose(output_file_p);
         return (fmsp_output_file_write_error_e);
      }

      if ((count + 1) % 8 == 0)
      {
         bytes_written = fwrite(eol,
                                1,              /* 1 byte blocks */
                                eol_len,
                                output_file_p);
   
         if (bytes_written != eol_len)
         {
            fclose(output_file_p);
            return (fmsp_output_file_write_error_e);
         }
      }
   }

   /* -------------------------------------------------------
    * Array of words that defines the soft parse instructions.
    * ------------------------------------------------------- */

   first = true;

   node_p = dll_get_first(&(ctx_p->instruction_list));

   while (node_p != NULL)
   {
      instr_p = DLL_STRUCT_FROM_NODE_GET(node_p,
                                         _fmsp_assembler_instruction_t,
                                         dll_node);

      total_instr_words += instr_p->num_valid_hw_words;

      for (count = 0; count < instr_p->num_valid_hw_words; count++)
      {
         if (!first && count == 0)
         {
            len = strlen(more_line_feed_p);
               
            bytes_written = fwrite(more_line_feed_p,
                                   1,              /* 1 byte blocks */
                                   len,
                                   output_file_p);

            if (bytes_written != len)
            {
               fclose(output_file_p);
               return (fmsp_output_file_write_error_e);
            }
         }
         else
         {
            first = false;
         }

         if (count > 0)
         {
            len = strlen(sep_str_p);
               
            bytes_written = fwrite(sep_str_p,
                                   1,              /* 1 byte blocks */
                                   len,
                                   output_file_p);

            if (bytes_written != len)
            {
               fclose(output_file_p);
               return (fmsp_output_file_write_error_e);
            }
         }
         else
         {
            len = strlen(indent_str_p);
               
            bytes_written = fwrite(indent_str_p,
                                   1,              /* 1 byte blocks */
                                   len,
                                   output_file_p);

            if (bytes_written != len)
            {
               fclose(output_file_p);
               return (fmsp_output_file_write_error_e);
            }
         }

         /* Convert the 2 byte word string into bytes. This is done to avoid
          * endianess problems. */
         instr_p->hw_words_str_p[count] = _fmsp_word_to_bytes(instr_p->hw_words_str_p[count]);

         len = strlen(instr_p->hw_words_str_p[count]);

         bytes_written = fwrite(instr_p->hw_words_str_p[count],
                                1,              /* 1 byte blocks */
                                len,
                                output_file_p);

         if (bytes_written != len)
         {
            fclose(output_file_p);
            return (fmsp_output_file_write_error_e);
         }
      }

      node_p = dll_get_next_node(&(ctx_p->instruction_list),
                                 node_p);
   }

   /* Pad array to max size */

   for (count = 0;
        count <  _FMSP_MAX_INSTR_WORDS - total_instr_words - leading_pad;
        count++)
   {
      if (count == 0)
      {
         bytes_written = fwrite(start_pad,
                                1,              /* 1 byte blocks */
                                start_pad_len,
                                output_file_p);
   
         if (bytes_written != start_pad_len)
         {
            fclose(output_file_p);
            return (fmsp_output_file_write_error_e);
         }
      }

      //if (count == _FMSP_MAX_INSTR_WORDS - (ctx_p->total_data_bytes/2) - 1)
      if (count == _FMSP_MAX_INSTR_WORDS - total_instr_words - 1)
      {
         bytes_written = fwrite(last_pad_word,
                                1,              /* 1 byte blocks */
                                last_pad_word_len,
                                output_file_p);
   
         if (bytes_written != last_pad_word_len)
         {
            fclose(output_file_p);
            return (fmsp_output_file_write_error_e);
         }
      }
      else
      {
         bytes_written = fwrite(pad_word,
                                1,              /* 1 byte blocks */
                                pad_word_len,
                                output_file_p);
   
         if (bytes_written != pad_word_len)
         {
            fclose(output_file_p);
            return (fmsp_output_file_write_error_e);
         }
      }

      if ((count + 1) % 8 == 0)
      {
         bytes_written = fwrite(eol,
                                1,              /* 1 byte blocks */
                                eol_len,
                                output_file_p);
   
         if (bytes_written != eol_len)
         {
            fclose(output_file_p);
            return (fmsp_output_file_write_error_e);
         }
      }
   }


   bytes_written = fwrite(line_feed_p,
                          1,              /* 1 byte blocks */
                          strlen(line_feed_p),
                          output_file_p);

   if (bytes_written != strlen(line_feed_p))
   {
      fclose(output_file_p);
      return (fmsp_output_file_write_error_e);
   }

   fclose(output_file_p);

   return (fmsp_ok_e);
}

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
                                                     fmsp_label_list_t                **label_list_p)
{
   dll_node_t                    *node_p;
   htbl_key_t                    *key_p;
   dll_list_t                    *key_list_p;
   htbl_entry_t                  *entry_p;
   _fmsp_label_t                 *label_obj_p;
   _fmsp_assembler_instruction_t *instr_p;
   uint32_t                       leading_pad;
   uint32_t                       count;
   fmsp_label_list_t             *label_node_p;
   fmsp_label_list_t             *prev_p = NULL;
   uint32_t                       cur_byte = 0;
   uint32_t                       total_instr_words = 0;

   /* ====================================================================
    * Labels
    * ====================================================================*/

   /* -------------------------------------------------------
    * Enum table of all labels with their corresponding
    * instruction word address.
    * ------------------------------------------------------- */

   /* Get list of keys in hash table. */
   key_list_p = htbl_get_key_list(ctx_p->label_table_p);

   /* Walk list of keys. */
   node_p = dll_get_first(key_list_p);

   while (node_p != NULL)
   {
      key_p = DLL_STRUCT_FROM_NODE_GET(node_p,
                                       htbl_key_t,
                                       dll_node);

      entry_p = htbl_get_entry(ctx_p->label_table_p,
                               key_p->string_p);

      /* Find label in hash table */
      if (entry_p != NULL)
      {
         label_obj_p = HTBL_GET_ENTRY_OBJECT(entry_p,
                                             _fmsp_label_t,
                                             htbl_entry);

         label_node_p = malloc(sizeof(fmsp_label_list_t));
   
         if (label_node_p == NULL)
         {
            return (fmsp_malloc_failure_e);
         }

         label_node_p->name          = strdup(key_p->string_p);
         label_node_p->byte_position = label_obj_p->program_counter;
         label_node_p->bit_size      = 0; // TODO
         label_node_p->bit_offset    = 0; // TODO
         label_node_p->next_p        = NULL;

         if (prev_p == NULL)
         {
            *label_list_p = label_node_p;
         }
         else
         {
            prev_p->next_p = label_node_p;
         }
         prev_p = label_node_p;
      }

      node_p = dll_get_next_node(key_list_p,
                                 node_p);
   }

   /* Cleanup key list */
   htbl_destroy_key_list(key_list_p);

   /* ====================================================================
    * Buffer
    * ====================================================================*/

   /* -------------------------------------------------------
    * Add leading pad if instructions do not start at
    * default location.
    * ------------------------------------------------------- */

   leading_pad = (ctx_p->options).program_space_base_address - FMSP_PARSE_PROGRAM_DEFAULT_BASE_ADDRESS;

   for (count = 0;
        count <  leading_pad;
        count++)
   {
      /* Create 1 word (2 bytes) of padding. */

      buffer_p[cur_byte] = 0;
      cur_byte++;

      buffer_p[cur_byte] = 0;
      cur_byte++;
   }

   /* -------------------------------------------------------
    * Array of words that defines the soft parse instructions.
    * ------------------------------------------------------- */

   node_p = dll_get_first(&(ctx_p->instruction_list));

   while (node_p != NULL)
   {
      instr_p = DLL_STRUCT_FROM_NODE_GET(node_p,
                                         _fmsp_assembler_instruction_t,
                                         dll_node);

      total_instr_words += instr_p->num_valid_hw_words;

      for (count = 0; count < instr_p->num_valid_hw_words; count++)
      {
         buffer_p[cur_byte] = (((instr_p->hw_words_p)[count]) >> 8) & 0xff;
         cur_byte++;

         buffer_p[cur_byte] = ((instr_p->hw_words_p)[count]) & 0xff;
         cur_byte++;
      }

      node_p = dll_get_next_node(&(ctx_p->instruction_list),
                                 node_p);
   }

   /* Pad array to max size */

   for (count = 0;
        count <  _FMSP_MAX_INSTR_WORDS - total_instr_words - leading_pad;
        count++)
   {
      /* Create 1 word (2 bytes) of padding. */

      buffer_p[cur_byte] = 0;
      cur_byte++;

      buffer_p[cur_byte] = 0;
      cur_byte++;
   }

   return (fmsp_ok_e);
}

/* ---------------------------------------------------------------------------
 * Clear context instruction values for next instruction.
 *
 * Parameters:
 *   ctx_p - Pointer to context object.
 *
 * Returns:
 *   Nothing.
 * ---------------------------------------------------------------------------*/
void _fmsp_clear_ctx_instruction_values (_fmsp_assembler_parser_context_t *ctx_p)
{
   if (ctx_p->raw_str_p[0] != NULL)
   {
      free (ctx_p->raw_str_p[0]);
      ctx_p->raw_str_p[0] = NULL;
   }

   if (ctx_p->raw_str_p[1] != NULL)
   {
      free (ctx_p->raw_str_p[1]);
      ctx_p->raw_str_p[1] = NULL;
   }

   if (ctx_p->raw_str_p[2] != NULL)
   {
      free (ctx_p->raw_str_p[2]);
      ctx_p->raw_str_p[2] = NULL;
   }

   if (ctx_p->raw_str_p[3] != NULL)
   {
      free (ctx_p->raw_str_p[3]);
      ctx_p->raw_str_p[3] = NULL;
   }

   if (ctx_p->raw_str_p[4] != NULL)
   {
      free (ctx_p->raw_str_p[4]);
      ctx_p->raw_str_p[4] = NULL;
   }
 
   if (ctx_p->value_str_p != NULL)
   {
      free (ctx_p->value_str_p);
      ctx_p->value_str_p = NULL;
   }

   ctx_p->immediate_value[0] = 0x0000;
   ctx_p->immediate_value[1] = 0x0000;
   ctx_p->immediate_value[2] = 0x0000;
   ctx_p->immediate_value[3] = 0x0000;

   ctx_p->num_immediate_values = 0;
}

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
                                 uint8_t *end_index_p)
{
   char  *start_index_string_p;
   char  *end_index_string_p;

   start_index_string_p = strtok(range_string_p,
                                   ":");
                                   //last_str_p);
 
   if (start_index_string_p == NULL)
   {
      return (false);
   }

   end_index_string_p   = strtok(NULL,
                                   ":");
                                   //last_str_p);

   if (end_index_string_p == NULL)
   {
      return (false);
   }

   *start_index_p = (uint8_t)strtoul(start_index_string_p, NULL, 0);
   *end_index_p   = (uint8_t)strtoul(end_index_string_p,   NULL, 0);

   return (true);
}
