/* A Bison parser, made by GNU Bison 2.4.2.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2006, 2009-2010 Free Software
   Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.4.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Using locations.  */
#define YYLSP_NEEDED 0

/* Substitute the variable and function names.  */
#define yyparse         _fmsp_assembler_yyparse
#define yylex           _fmsp_assembler_yylex
#define yyerror         _fmsp_assembler_yyerror
#define yylval          _fmsp_assembler_yylval
#define yychar          _fmsp_assembler_yychar
#define yydebug         _fmsp_assembler_yydebug
#define yynerrs         _fmsp_assembler_yynerrs


/* Copy the first part of user declarations.  */

/* Line 189 of yacc.c  */
#line 14 "fm_sp_assembler.y"

#ifndef _MSC_VER
#include <inttypes.h>  /* For standard int types and print format macros */
#include <stdbool.h>   /* For the bool type */
#endif

#include <errno.h>     /* For errno */
#include <stdlib.h>    /* For strtoull */
#ifdef _MSC_VER
#define _STDLIB_H
#endif
#include <string.h>    /* For strdup */

#include "fm_sp_private.h"

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

/* ---------------------------------------------------------------------------
 * Some defines that will make the grammar easier to read
 * ---------------------------------------------------------------------------*/

/* An action that take no parameters other than the context. */
#define _FMSP_PROC_TOK_P0(action_ok)                \
   if (!action_ok(_fmsp_assembler_context_p))       \
   {                                                \
      return (1);                                   \
   }

/* An action that takes the context and 1 parameter that must be freed
 * (lexical analyzer allocated the memory while collecting tokens).
 */
#define _FMSP_PROC_TOK_P1(action_ok, p1)            \
   if (!action_ok(_fmsp_assembler_context_p, p1))   \
   {                                                \
      free p1;                                      \
      return (1);                                   \
   }                                                \
   free p1;

/* An action that takes the context and 2 parameters that must be freed
 * (lexical analyzer allocated the memory while collecting tokens).
 */
#define _FMSP_PROC_TOK_P2(action_ok, p1, p2)            \
   if (!action_ok(_fmsp_assembler_context_p, p1, p2))   \
   {                                                    \
      free p1;                                          \
      free p2;                                          \
      return (1);                                       \
   }                                                    \
   free p1;                                             \
   free p2;

/* An action that takes the context and 3 parameters that must be freed
 * (lexical analyzer allocated the memory while collecting tokens).
 */
#define _FMSP_PROC_TOK_P3(action_ok, p1, p2, p3)            \
   if (!action_ok(_fmsp_assembler_context_p, p1, p2, p3))   \
   {                                                        \
      free p1;                                              \
      free p2;                                              \
      free p3;                                              \
      return (1);                                           \
   }                                                        \
   free p1;                                                 \
   free p2;                                                 \
   free p3;

/* An action that takes the context and 4 parameters that must be freed
 * (lexical analyzer allocated the memory while collecting tokens).
 */
#define _FMSP_PROC_TOK_P4(action_ok, p1, p2, p3, p4)            \
   if (!action_ok(_fmsp_assembler_context_p, p1, p2, p3, p4))   \
   {                                                            \
      free p1;                                                  \
      free p2;                                                  \
      free p3;                                                  \
      free p4;                                                  \
      return (1);                                               \
   }                                                            \
   free p1;                                                     \
   free p2;                                                     \
   free p3;                                                     \
   free p4;

/* An action that takes the context and 5 parameters that must be freed
 * (lexical analyzer allocated the memory while collecting tokens).
 */
#define _FMSP_PROC_TOK_P5(action_ok, p1, p2, p3, p4, p5)            \
   if (!action_ok(_fmsp_assembler_context_p, p1, p2, p3, p4, p5))   \
   {                                                                \
      free p1;                                                      \
      free p2;                                                      \
      free p3;                                                      \
      free p4;                                                      \
      free p5;                                                      \
      return (1);                                                   \
   }                                                                \
   free p1;                                                         \
   free p2;                                                         \
   free p3;                                                         \
   free p4;                                                         \
   free p5;

/* ---------------------------------------------------------------------------
 * Constants 
 * ---------------------------------------------------------------------------*/

#define MAX_RA_DECIMAL_INDEX_SIZE      3
#define MAX_RESULT_ARRAY_BYTE_INDEX    0x7f 
#define MAX_PARAMETER_ARRAY_BYTE_INDEX 0x3f 
#define MAX_FRAME_WINDOW_BYTE_INDEX    0x0f 
#define MAX_FRAME_WINDOW_BIT_INDEX     0x7f 

/* ---------------------------------------------------------------------------
 * Lexical Analyzer declarations
 * ---------------------------------------------------------------------------*/

int _fmsp_assembler_yylex (void                             *lval_p,
                           _fmsp_assembler_parser_context_t *context_p);

/* ---------------------------------------------------------------------------
 * Action declarations
 * ---------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
 * Action for label
 *
 * Parameters:
 *    ctx_p - Parse context
 *    str_p - String containing label name.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_label_action(_fmsp_assembler_parser_context_t *ctx_p,
                               char                             *str_p)
{
   _fmsp_label_t                 *label_p;
   _fmsp_assembler_instruction_t *instr_p;
   char                          *full_label_p;

   /* The context holds a hash table for all labels.  Each label object
    * in the hash table holds the program counter for the instruction
    * which follows the label.
    */

   /* Build the label name */
   full_label_p = (char *)calloc(strlen(str_p) + 1, 1);

   if (full_label_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      free (full_label_p); /* ROEE fixed mem leak*/
      return (false);
   }

   strcat(full_label_p, str_p);

   /* Store label in a hash table */
   label_p = _fmsp_new_label(full_label_p,
                             ctx_p->next_program_counter);

   if (label_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");

      free (full_label_p); /* ROEE fixed mem leak*/
      return (false);
   }

   if (!htbl_insert(ctx_p->label_table_p,
                    &(label_p->htbl_entry)))
   {
      _fmsp_destroy_label(label_p);

      _fmsp_assembler_yyerror(ctx_p,
                              "Label already exists.");
      free (full_label_p); /* ROEE fixed mem leak*/
      return (false);
   }

   instr_p = _fmsp_new_instruction(_fmsp_assembler_label_e,
                                   ctx_p);

   if (instr_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      free (full_label_p); /* ROEE fixed mem leak*/
      return (false);
   }

   /* Label is just a place holder, not an actual instruction. */
   instr_p->num_valid_hw_words = 0;

   instr_p->jump_label1_p = strdup(str_p);

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(instr_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   free (full_label_p); /* ROEE fixed mem leak*/
   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for five words
 *
 * Parameters:
 *    ctx_p  - Parse context
 *    str1_p - String containing hex value
 *    str2_p - String containing hex value
 *    str3_p - String containing hex value
 *    str4_p - String containing hex value
 *    str5_p - String containing hex value
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_five_hex_words_action(_fmsp_assembler_parser_context_t *ctx_p,
                                        char                             *str1_p,
                                        char                             *str2_p,
                                        char                             *str3_p,
                                        char                             *str4_p,
                                        char                             *str5_p)
{
   ctx_p->raw_str_p[0] = strdup(str1_p);
   ctx_p->raw_str_p[1] = strdup(str2_p);
   ctx_p->raw_str_p[2] = strdup(str3_p);
   ctx_p->raw_str_p[3] = strdup(str4_p);
   ctx_p->raw_str_p[4] = strdup(str5_p);

   if (ctx_p->raw_str_p[0] == NULL ||
       ctx_p->raw_str_p[1] == NULL ||
       ctx_p->raw_str_p[2] == NULL ||
       ctx_p->raw_str_p[3] == NULL ||
       ctx_p->raw_str_p[4] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   ctx_p->num_immediate_values = 4;

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for four words
 *
 * Parameters:
 *    ctx_p  - Parse context
 *    str1_p - String containing hex value
 *    str2_p - String containing hex value
 *    str3_p - String containing hex value
 *    str4_p - String containing hex value
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_four_hex_words_action(_fmsp_assembler_parser_context_t *ctx_p,
                                        char                             *str1_p,
                                        char                             *str2_p,
                                        char                             *str3_p,
                                        char                             *str4_p)
{
   ctx_p->raw_str_p[0] = strdup(str1_p);
   ctx_p->raw_str_p[1] = strdup(str2_p);
   ctx_p->raw_str_p[2] = strdup(str3_p);
   ctx_p->raw_str_p[3] = strdup(str4_p);

   if (ctx_p->raw_str_p[0] == NULL ||
       ctx_p->raw_str_p[1] == NULL ||
       ctx_p->raw_str_p[2] == NULL ||
       ctx_p->raw_str_p[3] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   ctx_p->num_immediate_values = 3;

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for three words
 *
 * Parameters:
 *    ctx_p  - Parse context
 *    str1_p - String containing hex value
 *    str2_p - String containing hex value
 *    str3_p - String containing hex value
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_three_hex_words_action(_fmsp_assembler_parser_context_t *ctx_p,
                                         char                             *str1_p,
                                         char                             *str2_p,
                                         char                             *str3_p)
{
   ctx_p->raw_str_p[0] = strdup(str1_p);
   ctx_p->raw_str_p[1] = strdup(str2_p);
   ctx_p->raw_str_p[2] = strdup(str3_p);

   if (ctx_p->raw_str_p[0] == NULL ||
       ctx_p->raw_str_p[1] == NULL ||
       ctx_p->raw_str_p[2] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   ctx_p->num_immediate_values = 2;

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for two words
 *
 * Parameters:
 *    ctx_p  - Parse context
 *    str1_p - String containing hex value
 *    str2_p - String containing hex value
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_two_hex_words_action(_fmsp_assembler_parser_context_t *ctx_p,
                                       char                             *str1_p,
                                       char                             *str2_p)
{
   ctx_p->raw_str_p[0] = strdup(str1_p);
   ctx_p->raw_str_p[1] = strdup(str2_p);

   if (ctx_p->raw_str_p[0] == NULL ||
       ctx_p->raw_str_p[1] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   ctx_p->num_immediate_values = 1;

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for one word
 *
 * Parameters:
 *    ctx_p  - Parse context
 *    str1_p - String containing hex value
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_one_hex_word_action(_fmsp_assembler_parser_context_t *ctx_p,
                                      char                             *str1_p)
{
   ctx_p->raw_str_p[0] = strdup(str1_p);

   if (ctx_p->raw_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   ctx_p->num_immediate_values = 0;

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for raw instruction
 *
 * Parameters:
 *    ctx_p - Parse context
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_raw_instruction_action(_fmsp_assembler_parser_context_t *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;
   int32_t                        count;

   object_p = _fmsp_new_instruction(_fmsp_assembler_raw_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   for (count = 0; count < ctx_p->num_immediate_values + 1; count++)
   {
      len = strlen(ctx_p->raw_str_p[count]);

      if (len > 0)
      {
         object_p->hw_words_str_p[count] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[count] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            return (false);
         }

         strncpy(object_p->hw_words_str_p[count],
                 ctx_p->raw_str_p[count],
                 len);

         object_p->hw_words_p[count] = (uint16_t)strtol(ctx_p->raw_str_p[count],
                                                        NULL,
                                                        0);
      }
   }

   object_p->num_valid_hw_words = ctx_p->num_immediate_values + 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for jmp label
 *
 * Parameters:
 *    ctx_p - Parse context
 *    str_p - String containing label name.
 *    hxs   - Header examination sequence?
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_action(_fmsp_assembler_parser_context_t *ctx_p,
                                   char                             *str_p,
                                   bool                              hxs)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;
   char                           hxs_bit_p[] = " | 0x400";

   /* No immediate values for jump instruction */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_jump_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   if (hxs)
   {
      len = strlen(_FMSP_INSTR_CODE_JUMP_STR) +
            strlen(hxs_bit_p)                 +
            1;

      object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

      if (object_p->hw_words_str_p[0] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[0],
               len,
               "%s%s",
               _FMSP_INSTR_CODE_JUMP_STR,
               hxs_bit_p);

      object_p->hw_words_p[0] = _FMSP_INSTR_CODE_JUMP | _FMSP_INSTR_MOD_JMP_HXS;
   }
   else
   {
      len = strlen(_FMSP_INSTR_CODE_JUMP_STR) + 1;

      object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

      if (object_p->hw_words_str_p[0] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[0],
               len,
               "%s",
               _FMSP_INSTR_CODE_JUMP_STR);

      object_p->hw_words_p[0] = _FMSP_INSTR_CODE_JUMP;
   }

   object_p->hxs                = hxs;
   object_p->num_valid_hw_words = 1;

   object_p->jump_label1_p      = strdup(str_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for jmp label if wr0 <operator> wr1
 *
 * Parameters:
 *    ctx_p      - Parse context
 *    str_p      - String containing label name.
 *    operator_p - Operator. (==, !=, <=, >=, <, >)
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_if_wr0_wr1_action(_fmsp_assembler_parser_context_t *ctx_p,
                                              char                             *str_p,
                                              uint16_t                          operator)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;
   char                           or_str_p[] = " | ";

   /* 1 immediate value for jump destination. */
   ctx_p->num_immediate_values = 1;

   object_p = _fmsp_new_instruction(_fmsp_assembler_compare_working_regs_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   len = strlen(_FMSP_INSTR_CODE_COMPARE_WORKING_REGS_STR) +
         strlen(or_str_p)                                  +
         6                                                 + /* 0xNNNN */
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s0x%04x",
            _FMSP_INSTR_CODE_COMPARE_WORKING_REGS_STR,
            or_str_p,
            operator);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_COMPARE_WORKING_REGS | operator;

   object_p->num_valid_hw_words = 2;
   object_p->function           = (uint8_t)operator;

   object_p->jump_label1_p      = strdup(str_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for jmp label if wr0 <operator> immediate value
 *
 * Parameters:
 *    ctx_p      - Parse context
 *    str_p      - String containing label name.
 *    operator_p - Operator. (==, !=, <, >)
 *    iv_p       - Immediate value.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_if_wr0_iv_action(_fmsp_assembler_parser_context_t *ctx_p,
                                             char                             *str_p,
                                             uint16_t                          operator,
                                             char                             *iv_p)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           start_shift_str_p[]  = " | (";
   char                           end_shift_12_str_p[] = " << 12)";
   char                           end_shift_10_str_p[] = " << 10)";
   uint32_t                       len;
   uint64_t                       immediate_value      = 0;
   uint16_t                       word_1;
   uint16_t                       word_2;
   uint16_t                       word_3;
   uint16_t                       word_4;
   uint8_t                        iv_word_size         = 0;

   /* Check if the immediate value starts with "0x". If it does then
    * convert the value and base the number of immediate value words
    * on that.  Otherwise, this is a plan id enum which is 1 byte so
    * only use 1 immediate value word.
    */
   if (strncmp(iv_p, "0x", 2) == 0)
   {
      immediate_value = (uint64_t)strtoull(iv_p, NULL, 0);      

      if (immediate_value < 0x10000)
      {
         ctx_p->num_immediate_values = 1;
      }
      else if (immediate_value < 0x100000000ULL)
      {
         ctx_p->num_immediate_values = 2;
      }
      else if (immediate_value < 0x1000000000000ULL)
      {
         ctx_p->num_immediate_values = 3;
      }
      else
      {
         ctx_p->num_immediate_values = 4;
      }
   }

   object_p = _fmsp_new_instruction(_fmsp_assembler_compare_wr0_to_iv_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Set immediate values. */
   if (strncmp(iv_p, "0x", 2) == 0)
   {
      len = 6 + /* 0xNNNN */
            1;

      word_1 =  immediate_value        & 0xffff;
      word_2 = (immediate_value >> 16) & 0xffff;
      word_3 = (immediate_value >> 32) & 0xffff;
      word_4 = (immediate_value >> 48) & 0xffff;

      if (immediate_value < 0x10000)
      {
         object_p->num_valid_hw_words = 2;
         iv_word_size                 = 0;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         object_p->hw_words_p[1] = word_1;
      }
      else if (immediate_value < 0x100000000ULL)
      {
         object_p->num_valid_hw_words = 3;
         iv_word_size                 = 1;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
      }
      else if (immediate_value < 0x1000000000000ULL)
      {
         object_p->num_valid_hw_words = 4;
         iv_word_size                 = 2;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL ||
             object_p->hw_words_str_p[3] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         snprintf(object_p->hw_words_str_p[3],
                  len,
                  "0x%04x",
                  word_3);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
         object_p->hw_words_p[3] = word_3;
      }
      else
      {
         object_p->num_valid_hw_words = 5;
         iv_word_size                 = 3;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[4] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL ||
             object_p->hw_words_str_p[3] == NULL ||
             object_p->hw_words_str_p[4] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         snprintf(object_p->hw_words_str_p[3],
                  len,
                  "0x%04x",
                  word_3);

         snprintf(object_p->hw_words_str_p[4],
                  len,
                  "0x%04x",
                  word_4);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
         object_p->hw_words_p[3] = word_3;
         object_p->hw_words_p[4] = word_4;
      }
   }
   else
   {
      object_p->num_valid_hw_words = 2;
      iv_word_size                 = 0;

      len = strlen(iv_p) + 1;

      object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

      if (object_p->hw_words_str_p[1] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[1],
               len,
               "%s",
               iv_p);

      object_p->hw_words_p[1] = 0; /* Variable that must be filled in later */
   }

   /* Bit layout of this instruction:
    *
    * 01CC IIJJ JJJJ JJJJ
    *
    * C - Comparison operator
    * I - Immediate value size (0, 1, 2, 3)
    * J - Jump destination
    */

   object_p->function = (uint8_t)operator;

   len = strlen(_FMSP_INSTR_CODE_COMPARE_WR0_TO_IV_STR) +
         strlen(start_shift_str_p)                      +
         6                                              + /* 0xNNNN */
         strlen(end_shift_12_str_p)                     +
         strlen(start_shift_str_p)                      +
         6                                              + /* 0xNNNN */
         strlen(end_shift_10_str_p)                     +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s0x%04x%s%s0x%04x%s",
            _FMSP_INSTR_CODE_COMPARE_WR0_TO_IV_STR,
            start_shift_str_p,
            operator,
            end_shift_12_str_p,
            start_shift_str_p,
            iv_word_size,
            end_shift_10_str_p
           );

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_COMPARE_WR0_TO_IV |
                             (operator << 12)                   |
                             (iv_word_size << 10);

   object_p->jump_label1_p = strdup(str_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for case 1 default jump
 *
 * Parameters:
 *    ctx_p    - Parse context
 *    str1_p   - String containing label 1 name.
 *    str2_p   - String containing label 2 name.
 *    hxs      - Header examination sequence?
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_case1dj_action(_fmsp_assembler_parser_context_t *ctx_p,
                                           char                             *str1_p,
                                           char                             *str2_p,
                                           bool                              hxs_1,
                                           bool                              hxs_2)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           or_str_p[]            = " | ";
   char                           hxs_1_not_set_str_p[] = " 0";
   char                           hxs_2_not_set_str_p[] = " (0 << 1)";
   char                           hxs_1_set_str_p[]     = " 1";
   char                           hxs_2_set_str_p[]     = " (1 << 1)";
   char                          *hxs_1_str_p;
   char                          *hxs_2_str_p;
   uint32_t                       len;

   /* Set the number of immediate values this instruction will take. */
   ctx_p->num_immediate_values = 2;

   object_p = _fmsp_new_instruction(_fmsp_assembler_case1_dj_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0000 10AB <label 1> <label 2>
    *
    * A - HXS for label 2
    * B - HXS for label 1
    */

   if (hxs_1)
   {
      hxs_1_str_p = hxs_1_set_str_p;
   }
   else
   {
      hxs_1_str_p = hxs_1_not_set_str_p;
   }

   if (hxs_2)
   {
      hxs_2_str_p = hxs_2_set_str_p;
   }
   else
   {
      hxs_2_str_p = hxs_2_not_set_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_CASE1_DJ_WR_TO_WR_STR) +
         strlen(or_str_p)                               +
         strlen(hxs_1_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_2_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s",
            _FMSP_INSTR_CODE_CASE1_DJ_WR_TO_WR_STR,
            or_str_p,
            hxs_2_str_p,
            or_str_p,
            hxs_1_str_p
           );

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_CASE1_DJ_WR_TO_WR |
                             (hxs_2 << 1)                       |
                             hxs_1;

   object_p->hxs_1              = hxs_1;
   object_p->hxs_2              = hxs_2;
   object_p->num_valid_hw_words = 3;

   object_p->jump_label1_p = strdup(str1_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label2_p = strdup(str2_p);

   if (object_p->jump_label2_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for case 2 default continue
 *
 * Parameters:
 *    ctx_p    - Parse context
 *    str1_p   - String containing label 1 name.
 *    str2_p   - String containing label 2 name.
 *    hxs      - Header examination sequence?
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_case2dc_action(_fmsp_assembler_parser_context_t *ctx_p,
                                           char                             *str1_p,
                                           char                             *str2_p,
                                           bool                              hxs_1,
                                           bool                              hxs_2)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           or_str_p[]            = " | ";
   char                           hxs_1_not_set_str_p[] = " 0";
   char                           hxs_2_not_set_str_p[] = " (0 << 1)";
   char                           hxs_1_set_str_p[]     = " 1";
   char                           hxs_2_set_str_p[]     = " (1 << 1)";
   char                          *hxs_1_str_p;
   char                          *hxs_2_str_p;
   uint32_t                       len;

   /* Set the number of immediate values this instruction will take. */
   ctx_p->num_immediate_values = 2;

   object_p = _fmsp_new_instruction(_fmsp_assembler_case2_dc_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0000 11AB <label 1> <label 2>
    *
    * A - HXS for label 2
    * B - HXS for label 1
    */

   if (hxs_1)
   {
      hxs_1_str_p = hxs_1_set_str_p;
   }
   else
   {
      hxs_1_str_p = hxs_1_not_set_str_p;
   }

   if (hxs_2)
   {
      hxs_2_str_p = hxs_2_set_str_p;
   }
   else
   {
      hxs_2_str_p = hxs_2_not_set_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_CASE2_DC_WR_TO_WR_STR) +
         strlen(or_str_p)                               +
         strlen(hxs_1_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_2_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s",
            _FMSP_INSTR_CODE_CASE2_DC_WR_TO_WR_STR,
            or_str_p,
            hxs_2_str_p,
            or_str_p,
            hxs_1_str_p
           );

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_CASE2_DC_WR_TO_WR |
                             (hxs_2 << 1)                       |
                             hxs_1;

   object_p->hxs_1              = hxs_1;
   object_p->hxs_2              = hxs_2;
   object_p->num_valid_hw_words = 3;

   object_p->jump_label1_p = strdup(str1_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label2_p = strdup(str2_p);

   if (object_p->jump_label2_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for case 2 default jump
 *
 * Parameters:
 *    ctx_p    - Parse context
 *    str1_p   - String containing label 1 name.
 *    str2_p   - String containing label 2 name.
 *    str3_p   - String containing label 3 name.
 *    hxs      - Header examination sequence?
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_case2dj_action(_fmsp_assembler_parser_context_t *ctx_p,
                                           char                             *str1_p,
                                           char                             *str2_p,
                                           char                             *str3_p,
                                           bool                              hxs_1,
                                           bool                              hxs_2,
                                           bool                              hxs_3)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           or_str_p[]            = " | ";
   char                           hxs_1_not_set_str_p[] = " 0";
   char                           hxs_2_not_set_str_p[] = " (0 << 1)";
   char                           hxs_3_not_set_str_p[] = " (0 << 2)";
   char                           hxs_1_set_str_p[]     = " 1";
   char                           hxs_2_set_str_p[]     = " (1 << 1)";
   char                           hxs_3_set_str_p[]     = " (1 << 2)";
   char                          *hxs_1_str_p;
   char                          *hxs_2_str_p;
   char                          *hxs_3_str_p;
   uint32_t                       len;

   /* Set the number of immediate values this instruction will take. */
   ctx_p->num_immediate_values = 3;

   object_p = _fmsp_new_instruction(_fmsp_assembler_case2_dj_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0001 0ABC <label 1> <label 2> <label 3>
    *
    * A - HXS for label 3
    * B - HXS for label 2
    * C - HXS for label 1
    */

   if (hxs_1)
   {
      hxs_1_str_p = hxs_1_set_str_p;
   }
   else
   {
      hxs_1_str_p = hxs_1_not_set_str_p;
   }

   if (hxs_2)
   {
      hxs_2_str_p = hxs_2_set_str_p;
   }
   else
   {
      hxs_2_str_p = hxs_2_not_set_str_p;
   }

   if (hxs_3)
   {
      hxs_3_str_p = hxs_3_set_str_p;
   }
   else
   {
      hxs_3_str_p = hxs_3_not_set_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_CASE2_DJ_WR_TO_WR_STR) +
         strlen(or_str_p)                               +
         strlen(hxs_1_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_2_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_3_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s%s%s",
            _FMSP_INSTR_CODE_CASE2_DJ_WR_TO_WR_STR,
            or_str_p,
            hxs_3_str_p,
            or_str_p,
            hxs_2_str_p,
            or_str_p,
            hxs_1_str_p
           );

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_CASE2_DJ_WR_TO_WR |
                             (hxs_3 << 2)                       |
                             (hxs_2 << 1)                       |
                             hxs_1;

   object_p->hxs_1              = hxs_1;
   object_p->hxs_2              = hxs_2;
   object_p->hxs_3              = hxs_3;
   object_p->num_valid_hw_words = 4;

   object_p->jump_label1_p = strdup(str1_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label2_p = strdup(str2_p);

   if (object_p->jump_label2_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label3_p = strdup(str3_p);

   if (object_p->jump_label3_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for case 3 default continue
 *
 * Parameters:
 *    ctx_p    - Parse context
 *    str1_p   - String containing label 1 name.
 *    str2_p   - String containing label 2 name.
 *    str3_p   - String containing label 3 name.
 *    hxs      - Header examination sequence?
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_case3dc_action(_fmsp_assembler_parser_context_t *ctx_p,
                                           char                             *str1_p,
                                           char                             *str2_p,
                                           char                             *str3_p,
                                           bool                              hxs_1,
                                           bool                              hxs_2,
                                           bool                              hxs_3)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           or_str_p[]            = " | ";
   char                           hxs_1_not_set_str_p[] = " 0";
   char                           hxs_2_not_set_str_p[] = " (0 << 1)";
   char                           hxs_3_not_set_str_p[] = " (0 << 2)";
   char                           hxs_1_set_str_p[]     = " 1";
   char                           hxs_2_set_str_p[]     = " (1 << 1)";
   char                           hxs_3_set_str_p[]     = " (1 << 2)";
   char                          *hxs_1_str_p;
   char                          *hxs_2_str_p;
   char                          *hxs_3_str_p;
   uint32_t                       len;

   /* Set the number of immediate values this instruction will take. */
   ctx_p->num_immediate_values = 3;

   object_p = _fmsp_new_instruction(_fmsp_assembler_case3_dc_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0001 1ABC <label 1> <label 2> <label 3>
    *
    * A - HXS for label 3
    * B - HXS for label 2
    * C - HXS for label 1
    */

   if (hxs_1)
   {
      hxs_1_str_p = hxs_1_set_str_p;
   }
   else
   {
      hxs_1_str_p = hxs_1_not_set_str_p;
   }

   if (hxs_2)
   {
      hxs_2_str_p = hxs_2_set_str_p;
   }
   else
   {
      hxs_2_str_p = hxs_2_not_set_str_p;
   }

   if (hxs_3)
   {
      hxs_3_str_p = hxs_3_set_str_p;
   }
   else
   {
      hxs_3_str_p = hxs_3_not_set_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_CASE3_DC_WR_TO_WR_STR) +
         strlen(or_str_p)                               +
         strlen(hxs_1_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_2_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_3_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s%s%s",
            _FMSP_INSTR_CODE_CASE3_DC_WR_TO_WR_STR,
            or_str_p,
            hxs_3_str_p,
            or_str_p,
            hxs_2_str_p,
            or_str_p,
            hxs_1_str_p
           );

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_CASE3_DC_WR_TO_WR |
                             (hxs_3 << 2)                       |
                             (hxs_2 << 1)                       |
                             hxs_1;

   object_p->hxs_1              = hxs_1;
   object_p->hxs_2              = hxs_2;
   object_p->hxs_3              = hxs_3;
   object_p->num_valid_hw_words = 4;

   object_p->jump_label1_p = strdup(str1_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label2_p = strdup(str2_p);

   if (object_p->jump_label2_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label3_p = strdup(str3_p);

   if (object_p->jump_label3_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for case 3 default jump
 *
 * Parameters:
 *    ctx_p    - Parse context
 *    str1_p   - String containing label 1 name.
 *    str2_p   - String containing label 2 name.
 *    str3_p   - String containing label 3 name.
 *    hxs      - Header examination sequence?
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_case3dj_action(_fmsp_assembler_parser_context_t *ctx_p,
                                           char                             *str1_p,
                                           char                             *str2_p,
                                           char                             *str3_p,
                                           char                             *str4_p,
                                           bool                              hxs_1,
                                           bool                              hxs_2,
                                           bool                              hxs_3,
                                           bool                              hxs_4)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           or_str_p[]            = " | ";
   char                           hxs_1_not_set_str_p[] = " 0";
   char                           hxs_2_not_set_str_p[] = " (0 << 1)";
   char                           hxs_3_not_set_str_p[] = " (0 << 2)";
   char                           hxs_4_not_set_str_p[] = " (0 << 3)";
   char                           hxs_1_set_str_p[]     = " 1";
   char                           hxs_2_set_str_p[]     = " (1 << 1)";
   char                           hxs_3_set_str_p[]     = " (1 << 2)";
   char                           hxs_4_set_str_p[]     = " (1 << 3)";
   char                          *hxs_1_str_p;
   char                          *hxs_2_str_p;
   char                          *hxs_3_str_p;
   char                          *hxs_4_str_p;
   uint32_t                       len;

   /* Set the number of immediate values this instruction will take. */
   ctx_p->num_immediate_values = 4;

   object_p = _fmsp_new_instruction(_fmsp_assembler_case3_dj_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0010 ABCD <label 1> <label 2> <label 3> <label 4>
    *
    * A - HXS for label 4
    * B - HXS for label 3
    * C - HXS for label 2
    * D - HXS for label 1
    */

   if (hxs_1)
   {
      hxs_1_str_p = hxs_1_set_str_p;
   }
   else
   {
      hxs_1_str_p = hxs_1_not_set_str_p;
   }

   if (hxs_2)
   {
      hxs_2_str_p = hxs_2_set_str_p;
   }
   else
   {
      hxs_2_str_p = hxs_2_not_set_str_p;
   }

   if (hxs_3)
   {
      hxs_3_str_p = hxs_3_set_str_p;
   }
   else
   {
      hxs_3_str_p = hxs_3_not_set_str_p;
   }

   if (hxs_4)
   {
      hxs_4_str_p = hxs_4_set_str_p;
   }
   else
   {
      hxs_4_str_p = hxs_4_not_set_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_CASE3_DJ_WR_TO_WR_STR) +
         strlen(or_str_p)                               +
         strlen(hxs_1_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_2_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_3_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_4_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s%s%s%s%s",
            _FMSP_INSTR_CODE_CASE3_DJ_WR_TO_WR_STR,
            or_str_p,
            hxs_4_str_p,
            or_str_p,
            hxs_3_str_p,
            or_str_p,
            hxs_2_str_p,
            or_str_p,
            hxs_1_str_p
           );

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_CASE3_DJ_WR_TO_WR |
                             (hxs_4 << 3)                       |
                             (hxs_3 << 2)                       |
                             (hxs_2 << 1)                       |
                             hxs_1;

   object_p->hxs_1              = hxs_1;
   object_p->hxs_2              = hxs_2;
   object_p->hxs_3              = hxs_3;
   object_p->hxs_4              = hxs_4;
   object_p->num_valid_hw_words = 5;

   object_p->jump_label1_p = strdup(str1_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label2_p = strdup(str2_p);

   if (object_p->jump_label2_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label3_p = strdup(str3_p);

   if (object_p->jump_label3_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label4_p = strdup(str4_p);

   if (object_p->jump_label4_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for case 4 default continue
 *
 * Parameters:
 *    ctx_p    - Parse context
 *    str1_p   - String containing label 1 name.
 *    str2_p   - String containing label 2 name.
 *    str3_p   - String containing label 3 name.
 *    hxs      - Header examination sequence?
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_label_case4dc_action(_fmsp_assembler_parser_context_t *ctx_p,
                                           char                             *str1_p,
                                           char                             *str2_p,
                                           char                             *str3_p,
                                           char                             *str4_p,
                                           bool                              hxs_1,
                                           bool                              hxs_2,
                                           bool                              hxs_3,
                                           bool                              hxs_4)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           or_str_p[]            = " | ";
   char                           hxs_1_not_set_str_p[] = " 0";
   char                           hxs_2_not_set_str_p[] = " (0 << 1)";
   char                           hxs_3_not_set_str_p[] = " (0 << 2)";
   char                           hxs_4_not_set_str_p[] = " (0 << 3)";
   char                           hxs_1_set_str_p[]     = " 1";
   char                           hxs_2_set_str_p[]     = " (1 << 1)";
   char                           hxs_3_set_str_p[]     = " (1 << 2)";
   char                           hxs_4_set_str_p[]     = " (1 << 3)";
   char                          *hxs_1_str_p;
   char                          *hxs_2_str_p;
   char                          *hxs_3_str_p;
   char                          *hxs_4_str_p;
   uint32_t                       len;

   /* Set the number of immediate values this instruction will take. */
   ctx_p->num_immediate_values = 4;

   object_p = _fmsp_new_instruction(_fmsp_assembler_case4_dc_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0011 ABCD <label 1> <label 2> <label 3> <label 4>
    *
    * A - HXS for label 4
    * B - HXS for label 3
    * C - HXS for label 2
    * D - HXS for label 1
    */

   if (hxs_1)
   {
      hxs_1_str_p = hxs_1_set_str_p;
   }
   else
   {
      hxs_1_str_p = hxs_1_not_set_str_p;
   }

   if (hxs_2)
   {
      hxs_2_str_p = hxs_2_set_str_p;
   }
   else
   {
      hxs_2_str_p = hxs_2_not_set_str_p;
   }

   if (hxs_3)
   {
      hxs_3_str_p = hxs_3_set_str_p;
   }
   else
   {
      hxs_3_str_p = hxs_3_not_set_str_p;
   }

   if (hxs_4)
   {
      hxs_4_str_p = hxs_4_set_str_p;
   }
   else
   {
      hxs_4_str_p = hxs_4_not_set_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_CASE4_DC_WR_TO_WR_STR) +
         strlen(or_str_p)                               +
         strlen(hxs_1_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_2_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_3_str_p)                            +
         strlen(or_str_p)                               +
         strlen(hxs_4_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s%s%s%s%s",
            _FMSP_INSTR_CODE_CASE4_DC_WR_TO_WR_STR,
            or_str_p,
            hxs_4_str_p,
            or_str_p,
            hxs_3_str_p,
            or_str_p,
            hxs_2_str_p,
            or_str_p,
            hxs_1_str_p
           );

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_CASE4_DC_WR_TO_WR |
                             (hxs_4 << 3)                       |
                             (hxs_3 << 2)                       |
                             (hxs_2 << 1)                       |
                             hxs_1;

   object_p->hxs_1              = hxs_1;
   object_p->hxs_2              = hxs_2;
   object_p->hxs_3              = hxs_3;
   object_p->hxs_4              = hxs_4;
   object_p->num_valid_hw_words = 5;

   object_p->jump_label1_p = strdup(str1_p);

   if (object_p->jump_label1_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label2_p = strdup(str2_p);

   if (object_p->jump_label2_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label3_p = strdup(str3_p);

   if (object_p->jump_label3_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   object_p->jump_label4_p = strdup(str4_p);

   if (object_p->jump_label4_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate label object.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for nop
 *
 * Parameters:
 *    ctx_p - Parse context
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_nop_action(_fmsp_assembler_parser_context_t *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;

   /* No immediate values */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_nop_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   len = strlen(_FMSP_INSTR_CODE_NOP_STR) + 1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s",
            _FMSP_INSTR_CODE_NOP_STR);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_NOP;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for clm
 *
 * Parameters:
 *    ctx_p - Parse context
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_clm_action(_fmsp_assembler_parser_context_t *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;

   /* No immediate values */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_clm_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   len = strlen(_FMSP_INSTR_CODE_CLM_STR) + 1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s",
            _FMSP_INSTR_CODE_CLM_STR);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_CLM;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for Advance Header Base by Window Offset
 *
 * Parameters:
 *    ctx_p - Parse context
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_advance_hb_by_wo_action(_fmsp_assembler_parser_context_t *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;

   /* No immediate values */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_advance_hb_by_wo_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   len = strlen(_FMSP_INSTR_CODE_ADVANCE_HB_BY_WO_STR) + 1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s",
            _FMSP_INSTR_CODE_ADVANCE_HB_BY_WO_STR);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_ADVANCE_HB_BY_WO;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for set LCV bits.
 *
 * Parameters:
 *    ctx_p - Parse context
 *    str_p - String containing bit mask string.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_set_lcv_bits_action(_fmsp_assembler_parser_context_t *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           start_lsb_str_p[] = "(PE_H2NL(";
   char                           end_lsb_str_p[]   = ")) & 0xffff";
   char                           start_msb_str_p[] = "((PE_H2NL(";
   char                           end_msb_str_p[]   = ")) >> 16) & 0xffff";
   uint32_t                       len;
   uint32_t                       immediate_value;

   /* Always 2 immediate value words */
   ctx_p->num_immediate_values = 2;

   object_p = _fmsp_new_instruction(_fmsp_assembler_or_iv_lcv_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* The bit mask string must be used to create both immediate value words
    * which are part of this instruction.  The words are in little endian.
    *
    * Example:
    *   ctx_p->value_str_p = "l3_row_id | l4_row_id"
    *
    *   =>
    *
    *   1st word after instruction = (l3_row_id | l4_row_id) & 0xffff
    *   2nd word after instruction = ((l3_row_id | l4_row_id) >> 16) & 0xffff
    */

   /* Instruction word */
   len = strlen(_FMSP_INSTR_CODE_OR_IV_LCV_STR) + 1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s",
            _FMSP_INSTR_CODE_OR_IV_LCV_STR);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_OR_IV_LCV;

   /* Attempt to convert immediate value string to a number. */
   errno = 0;
   immediate_value = (uint32_t)strtoll(ctx_p->value_str_p, NULL, 0);
   
   if (errno == 0)
   {
      object_p->hw_words_p[1] = immediate_value & 0xffff;
      object_p->hw_words_p[2] = (immediate_value >> 16) & 0xffff;
   }
   else
   {
      // TODO
      // Variable substitution must be done.
   }

   /* Immediate value word 1 */
   len = strlen(start_lsb_str_p)    +
         strlen(ctx_p->value_str_p) +
         strlen(end_lsb_str_p)      +
         1;

   object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[1] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[1],
            len,
            "%s%s%s",
            start_lsb_str_p,
            ctx_p->value_str_p,
            end_lsb_str_p);

   /* Immediate value word 2 */
   len = strlen(start_msb_str_p)    +
         strlen(ctx_p->value_str_p) +
         strlen(end_msb_str_p)      +
         1;

   object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[2] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[2],
            len,
            "%s%s%s",
            start_msb_str_p,
            ctx_p->value_str_p,
            end_msb_str_p);

   object_p->num_valid_hw_words = 3;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for result array range
 *
 * Parameters:
 *    ctx_p     - Parse context
 *    start_idx - Start index of result array range.
 *    end_idx   - End index of result array range.
 *
 * Returns:
 *   string - NULL means error, otherwise returns a string of form xxx:yyy
 * ---------------------------------------------------------------------------*/
static bool _fmsp_result_array_range_action(_fmsp_assembler_parser_context_t *ctx_p,
                                            int32_t                           start_idx,
                                            int32_t                           end_idx,
                                            bool                              is_gprv)
{
   if (is_gprv)
   {
      if (start_idx > 15)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "General purpose register start index out of bounds");

         return (false);
      }

      if (end_idx > 15)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "General purpose register end index out of bounds");

         return (false);
      }
   }

   if (start_idx < 0)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Result Array start index out of bounds");

      return (false);
   }

   if (end_idx < 0)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Result Array end index out of bounds");

      return (false);
   }

   if (start_idx > MAX_RESULT_ARRAY_BYTE_INDEX)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Result Array start index out of bounds");

      return (false);
   }

   if (end_idx   > MAX_RESULT_ARRAY_BYTE_INDEX)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Result Array end index out of bounds");

      return (false);
   }

   if (start_idx > end_idx)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Result Array start index > end index");

      return (false);
   }

   if (end_idx - start_idx > 7)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Result Array (end index - start index) > 7");

      return (false);
   }

   ctx_p->range_start = start_idx;
   ctx_p->range_end   = end_idx;

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for load bytes from result array to working register.
 *
 * Parameters:
 *    ctx_p      - Parse context.
 *    wr         - Working register.
 *    is_assign  - Boolean value that is true if assign, false if concat.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_load_bytes_ra_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                             uint8_t                           wr,
                                             bool                              is_assign)
{
   char                           wr0_str_p[]           = " | 0";
   char                           wr1_str_p[]           = " | 1";
   char                          *wr_str_p;
   char                           assign_str_p[]        = " | 0x0000";
   char                           concat_str_p[]        = " | 0x0800";
   char                          *funcion_str_p;
   char                           range_end_str_p[]     = " | (0x0000 << 4)";
   char                           num_bytes_str_p[]     = " | (0x0000 << 1)";
   uint32_t                       len;
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       shift = 0;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_load_bytes_ra_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0011 SJJJ JJJJ KKKW
    *
    * S - Shift
    * J - End of register range
    * K - Number of bytes - 1 to load
    * W - Working register (0 or 1)
    */

   /* Set working register */
   if (wr == 0)
   {
      object_p->working_register = 0;
      wr_str_p = wr0_str_p;
   }
   else
   {
      object_p->working_register = 1;
      wr_str_p = wr1_str_p;
   }

   /* Set function */
   if (is_assign)
   {
      object_p->is_assign = true;
      funcion_str_p = assign_str_p;
      shift = 0;
   }
   else
   {
      object_p->is_assign = false;
      funcion_str_p = concat_str_p;
      shift = 1;
   }

   /* Set range */
   object_p->range_start = ctx_p->range_start;
   object_p->range_end   = ctx_p->range_end;

   len = strlen(range_end_str_p) + 1;

   /* Range end */
   snprintf(range_end_str_p,
            len,
            " | (0x%04x << 4)",
            object_p->range_end);

   len = strlen(num_bytes_str_p) + 1;

   /* Num bytes - 1 */
   snprintf(num_bytes_str_p,
            len,
            " | (0x%04x << 1)",
            (object_p->range_end - object_p->range_start));

   len = strlen(_FMSP_INSTR_CODE_LOAD_BYTES_RA_TO_WR_STR) +
         strlen(funcion_str_p)                            +
         strlen(range_end_str_p)                          +
         strlen(num_bytes_str_p)                          +
         strlen(wr_str_p)                                 +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s",
            _FMSP_INSTR_CODE_LOAD_BYTES_RA_TO_WR_STR,
            funcion_str_p,
            range_end_str_p,
            num_bytes_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_LOAD_BYTES_RA_TO_WR           |
                             (shift << 11)                                  |
                             (ctx_p->range_end << 4)                        |
                             ((ctx_p->range_end - ctx_p->range_start) << 1) |
                             wr;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for store working register to result array.
 *
 * Parameters:
 *    ctx_p - Parse context.
 *    wr    - Working register.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_store_wr_to_ra_action(_fmsp_assembler_parser_context_t *ctx_p,
                                        uint8_t                           wr)
{
   char                           wr0_str_p[]           = " | 0";
   char                           wr1_str_p[]           = " | 1";
   char                          *wr_str_p;
   char                           range_end_str_p[]     = " | (0x0000 << 1)";
   char                           num_bytes_str_p[]     = " | (0x0000 << 8)";
   uint32_t                       len;
   _fmsp_assembler_instruction_t *object_p;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_store_wr_to_ra_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0010 1SSS TTTT TTTW
    *
    * S - Number of bytes - 1 to store
    * T - End of register range
    * W - Working register (0 or 1)
    */

   /* Set working register */
   if (wr == 0)
   {
      object_p->working_register = 0;
      wr_str_p = wr0_str_p;
   }
   else
   {
      object_p->working_register = 1;
      wr_str_p = wr1_str_p;
   }

   /* Set range */
   object_p->range_start = ctx_p->range_start;
   object_p->range_end   = ctx_p->range_end;

   len = strlen(range_end_str_p) + 1;

   /* Range end */
   snprintf(range_end_str_p,
            len,
            " | (0x%04x << 1)",
            object_p->range_end);

   len = strlen(num_bytes_str_p) + 1;

   /* Num bytes - 1 */
   snprintf(num_bytes_str_p,
            len,
            " | (0x%04x << 8)",
            (object_p->range_end - object_p->range_start));

   len = strlen(_FMSP_INSTR_CODE_STORE_WR_TO_RA_STR) +
         strlen(num_bytes_str_p)                     +
         strlen(range_end_str_p)                     +
         strlen(wr_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s",
            _FMSP_INSTR_CODE_STORE_WR_TO_RA_STR,
            num_bytes_str_p,
            range_end_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_STORE_WR_TO_RA                |
                             ((ctx_p->range_end - ctx_p->range_start) << 8) |
                             (ctx_p->range_end << 1)                        |
                             wr;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for store immediate value to result array.
 *
 * Parameters:
 *    ctx_p      - Parse context.
 *    iv_p       - String containing immediate value
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_store_iv_to_ra_action(_fmsp_assembler_parser_context_t *ctx_p,
                                        char                             *iv_p)
{
   char                           or_str_p[]           = " | ";
   char                           start_shift_str_p[]  = " | (";
   char                           end_shift_7_str_p[] = " << 7)";
   uint32_t                       len;
   uint64_t                       immediate_value      = 0;
   uint16_t                       word_1;
   uint16_t                       word_2;
   uint16_t                       word_3;
   uint16_t                       word_4;
   uint8_t                        iv_word_size         = 0;
   uint8_t                        num_iv_words         = 0;
   uint8_t                        num_iv_bytes         = 0;

   _fmsp_assembler_instruction_t *object_p;

   num_iv_bytes = ctx_p->range_end - ctx_p->range_start + 1;

   switch (num_iv_bytes)
   {
      case 1:
      case 2:
         num_iv_words = 1;
         ctx_p->num_immediate_values = 1;

         break;

      case 3:
      case 4:
         num_iv_words = 2;
         ctx_p->num_immediate_values = 2;
         break;

      case 5:
      case 6:
         num_iv_words = 3;
         ctx_p->num_immediate_values = 3;
         break;

      case 7:
      case 8:
         num_iv_words = 4;
         ctx_p->num_immediate_values = 4;
         break;

      default:
         _fmsp_assembler_yyerror(ctx_p,
                                 "INTERNAL ERROR: Default case in _fmsp_store_iv_to_ra_action");
         return (false);
         break;
   }

   object_p = _fmsp_new_instruction(_fmsp_assembler_store_iv_to_ra_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Set range */
   object_p->range_start = ctx_p->range_start;
   object_p->range_end   = ctx_p->range_end;

   /* Check if the immediate value starts with "0x". If it does then
    * convert the value and fill in the appropriate number of immediate
    * value words based on the range requested.
    * Otherwise, this is a plan id enum.
    */
   if (strncmp(iv_p, "0x", 2) == 0)
   {
      immediate_value = (uint64_t)strtoull(iv_p, NULL, 0);

      len = 6 + /* 0xNNNN */
            1;

      word_1 =  immediate_value        & 0xffff;
      word_2 = (immediate_value >> 16) & 0xffff;
      word_3 = (immediate_value >> 32) & 0xffff;
      word_4 = (immediate_value >> 48) & 0xffff;

      if (num_iv_words == 1)
      {
         object_p->num_valid_hw_words = 2;
         iv_word_size                 = 0;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         object_p->hw_words_p[1] = word_1;
      }
      else if (num_iv_words == 2)
      {
         object_p->num_valid_hw_words = 3;
         iv_word_size                 = 1;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
      }
      else if (num_iv_words == 3)
      {
         object_p->num_valid_hw_words = 4;
         iv_word_size                 = 2;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL ||
             object_p->hw_words_str_p[3] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         snprintf(object_p->hw_words_str_p[3],
                  len,
                  "0x%04x",
                  word_3);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
         object_p->hw_words_p[3] = word_3;
      }
      else
      {
         object_p->num_valid_hw_words = 5;
         iv_word_size                 = 3;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[4] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL ||
             object_p->hw_words_str_p[3] == NULL ||
             object_p->hw_words_str_p[4] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         snprintf(object_p->hw_words_str_p[3],
                  len,
                  "0x%04x",
                  word_3);

         snprintf(object_p->hw_words_str_p[4],
                  len,
                  "0x%04x",
                  word_4);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
         object_p->hw_words_p[3] = word_3;
         object_p->hw_words_p[4] = word_4;
      }
   }
   else
   {
      /* There will always be 1 word with the enum in it.
       * All subsequent words will be 0x0000.
       */
      len = strlen(iv_p) + 1;

      object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

      if (object_p->hw_words_str_p[1] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[1],
               len,
               "%s",
               iv_p);

      object_p->hw_words_p[1] = 0;

      if (num_iv_words == 1)
      {
         object_p->num_valid_hw_words = 2;
      }
      else if (num_iv_words == 2)
      {
         len = 6 + /* 0xNNNN */
               1;

         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[2] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x0000");

         object_p->hw_words_p[1] = 0;
         object_p->hw_words_p[2] = 0;

         object_p->num_valid_hw_words = 3;
      }
      else if (num_iv_words == 3)
      {
         len = 6 + /* 0xNNNN */
               1;

         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[2] == NULL ||
             object_p->hw_words_str_p[3] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x0000");

         snprintf(object_p->hw_words_str_p[3],
                  len,
                  "0x0000");

         object_p->hw_words_p[1] = 0;
         object_p->hw_words_p[2] = 0;
         object_p->hw_words_p[3] = 0;

         object_p->num_valid_hw_words = 4;
      }
      else
      {
         len = 6 + /* 0xNNNN */
               1;

         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[4] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[2] == NULL ||
             object_p->hw_words_str_p[3] == NULL ||
             object_p->hw_words_str_p[4] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x0000");

         snprintf(object_p->hw_words_str_p[3],
                  len,
                  "0x0000");

         snprintf(object_p->hw_words_str_p[4],
                  len,
                  "0x0000");

         object_p->hw_words_p[1] = 0;
         object_p->hw_words_p[2] = 0;
         object_p->hw_words_p[3] = 0;
         object_p->hw_words_p[4] = 0;

         object_p->num_valid_hw_words = 5;
      }
   }

   /* Bit layout of this instruction:
    *
    * 0000 10SS STTT TTTT
    *
    * S - Number of bytes - 1 to store
    * T - End of register range
    */
   len = strlen(_FMSP_INSTR_CODE_STORE_IV_TO_RA_STR) +
         strlen(start_shift_str_p)                   +
         6                                           + /* 0xNNNN */
         strlen(end_shift_7_str_p)                   +
         strlen(or_str_p)                            +
         6                                           + /* 0xNNNN */
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s0x%04x%s%s0x%04x",
            _FMSP_INSTR_CODE_STORE_IV_TO_RA_STR,
            start_shift_str_p,
            num_iv_bytes - 1,
            end_shift_7_str_p,
            or_str_p,
            object_p->range_end
           );

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_STORE_IV_TO_RA |
                             ((num_iv_bytes - 1) << 7)       |
                             object_p->range_end;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for load specific value to window offset
 *
 * Parameters:
 *    ctx_p      - Parse context.
 *    str_p      - String containing hex value.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_load_sv_to_wo_action(_fmsp_assembler_parser_context_t *ctx_p,
                                       char                             *str_p)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           or_str_p[] = " | ";
   uint32_t                       len;
   uint32_t                       specific_value;

   specific_value = strtol(str_p, NULL, 0);

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_load_sv_to_wo_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0110 VVVV VVVV
    *
    * V - Specific value.
    */

   len = strlen(_FMSP_INSTR_CODE_LOAD_SV_TO_WO_STR) +
         strlen(or_str_p)                           +
         strlen(str_p)                              +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s",
            _FMSP_INSTR_CODE_LOAD_SV_TO_WO_STR,
            or_str_p,
            str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_LOAD_SV_TO_WO |
                             specific_value;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for add specific value to window offset
 *
 * Parameters:
 *    ctx_p      - Parse context.
 *    str_p      - String containing hex value.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_add_sv_to_wo_action(_fmsp_assembler_parser_context_t *ctx_p,
                                      char                             *str_p)
{
   char                           or_str_p[] = " | ";
   uint32_t                       len;
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       specific_value;

   specific_value = strtol(str_p, NULL, 0);


   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_add_sv_to_wo_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0111 VVVV VVVV
    *
    * V - Specific value.
    */
   len = strlen(_FMSP_INSTR_CODE_ADD_SV_TO_WO_STR) +
         strlen(or_str_p)                          +
         strlen(str_p)                             +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s",
            _FMSP_INSTR_CODE_ADD_SV_TO_WO_STR,
            or_str_p,
            str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_ADD_SV_TO_WO |
                             specific_value;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for modifying window offset by a working register
 *
 * Parameters:
 *    ctx_p      - Parse context.
 *    add        - True for add, false for set
 *    wr         - Working register number (0/1)
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_modify_wo_by_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                         bool                              add,
                                         uint8_t                           wr)
{
   char                           wr0_str_p[] = " | 0x0";
   char                           wr1_str_p[] = " | 0x1";
   char                          *wr_str_p;
   char                           add_str_p[] = " | 0x2";
   char                           set_str_p[] = " | 0x0";
   char                          *mod_str_p;
   uint32_t                       len;
   _fmsp_assembler_instruction_t *object_p;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_modify_wo_by_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   if (add)
   {
      mod_str_p = add_str_p;
   }
   else
   {
      mod_str_p = set_str_p;
   }

   if (wr == 0)
   {
      wr_str_p = wr0_str_p;
   }
   else
   {
      wr_str_p = wr1_str_p;
   }

   object_p->working_register = wr;

   /* Bit layout of this instruction:
    *
    * 0000 0000 1000 00AW
    *
    * A - Add or set
    * W - Working register
    */
   len = strlen(_FMSP_INSTR_CODE_MODIFY_WO_BY_WR_STR) +
         strlen(mod_str_p)                            +
         strlen(wr_str_p)                             +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s",
            _FMSP_INSTR_CODE_MODIFY_WO_BY_WR_STR,
            mod_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_MODIFY_WO_BY_WR |
                             (add << 1)                       |
                             wr;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for clear working register.
 *
 * Parameters:
 *    ctx_p - Parse context.
 *    wr    - Working register.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_zero_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                 uint8_t                           wr)
{
   _fmsp_assembler_instruction_t *object_p;
   char                          *wr_str_p;
   char                           wr_0_str_p[] = " | 0x0";
   char                           wr_1_str_p[] = " | 0x1";
   uint32_t                       len;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_zero_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0000 010W
    *
    * W - Working register (0 or 1)
    */

   if (wr == 0)
   {
      wr_str_p = wr_0_str_p;
   }
   else
   {
      wr_str_p = wr_1_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_ZERO_WR_STR) +
         strlen(wr_str_p)                     +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s",
            _FMSP_INSTR_CODE_ZERO_WR_STR,
            wr_str_p);

   object_p->working_register = wr;

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_ZERO_WR | wr;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for onescomp
 *
 * Parameters:
 *    ctx_p - Parse context
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_ones_comp_wr1_to_wr0_action(_fmsp_assembler_parser_context_t *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_ones_comp_wr1_to_wr0_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   len = strlen(_FMSP_INSTR_CODE_ONES_COMP_WR1_TO_WR0_STR) + 1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s",
            _FMSP_INSTR_CODE_ONES_COMP_WR1_TO_WR0_STR);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_ONES_COMP_WR1_TO_WR0;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for bitwise working register to working register operation
 *
 * Parameters:
 *    ctx_p    - Parse context
 *    wr       - Working register to place result in.
 *    function - Function to be used
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_bitwise_wr_wr_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                             uint8_t                           wr,
                                             uint8_t                           function)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;
   char                           or_str_p[]          = " | ";
   char                          *wr_str_p;
   char                           wr_0_str_p[]        = " | 0x0";
   char                           wr_1_str_p[]        = " | 0x1";
   char                           start_shift_str_p[] = " (";
   char                           end_shift_1_str_p[] = " << 1)";

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_bitwise_wr_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0111 0FFW
    *
    * F - Function (AND/OR/XOR)
    * W - Working register (0 or 1)
    */

   if (wr == 0)
   {
      wr_str_p = wr_0_str_p;
   }
   else
   {
      wr_str_p = wr_1_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_BITWISE_WR_WR_TO_WR_STR) +
         strlen(or_str_p)                                 +
         strlen(start_shift_str_p)                        +
         6                                                + /* 0xNNNN */
         strlen(end_shift_1_str_p)                        +
         strlen(wr_str_p)                                 +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s0x%04x%s%s",
            _FMSP_INSTR_CODE_BITWISE_WR_WR_TO_WR_STR,
            or_str_p,
            start_shift_str_p,
            function,
            end_shift_1_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_BITWISE_WR_WR_TO_WR |
                             (function << 1)                      |
                             wr;

   object_p->working_register = wr;
   object_p->function         = function;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for bitwise immediate value to working register operation
 *
 * Parameters:
 *    ctx_p     - Parse context
 *    target_wr - Working register to place result in
 *    source_wr - Working register to operate on with immediate value
 *    function  - Function to be used
 *    iv_p      - Immediate value
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_bitwise_wr_iv_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                             uint8_t                           target_wr,
                                             uint8_t                           source_wr,
                                             uint8_t                           function,
                                             char                             *iv_p)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           start_shift_str_p[] = " | (";
   char                           end_shift_3_str_p[] = " << 3)";
   char                           end_shift_1_str_p[] = " << 1)";
   char                           tgt_wr_0_str_p[]    = " | (0x0 << 5)";
   char                           tgt_wr_1_str_p[]    = " | (0x1 << 5)";
   char                           src_wr_0_str_p[]    = " | 0x0";
   char                           src_wr_1_str_p[]    = " | 0x1";
   char                          *src_wr_str_p;
   char                          *tgt_wr_str_p;
   uint32_t                       len;
   uint64_t                       immediate_value      = 0;
   uint16_t                       word_1;
   uint16_t                       word_2;
   uint16_t                       word_3;
   uint16_t                       word_4;
   uint8_t                        iv_word_size         = 0;

   if (source_wr == 0)
   {
      src_wr_str_p = src_wr_0_str_p;
   }
   else
   {
      src_wr_str_p = src_wr_1_str_p;
   }

   if (target_wr == 0)
   {
      tgt_wr_str_p = tgt_wr_0_str_p;
   }
   else
   {
      tgt_wr_str_p = tgt_wr_1_str_p;
   }

   /* This instruction is always 4 immediate value words */
   ctx_p->num_immediate_values   = 4;

   object_p = _fmsp_new_instruction(_fmsp_assembler_bitwise_wr_iv_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Assume immediate value is always 64 bits as the user
    * will be performing the operation over the whole register.
    * This means all immediate values are padded on the left with 0
    * and the function is performed on the entire source WR. */
   object_p->num_valid_hw_words  = 5;
   iv_word_size                  = 3;

   /* Check if the immediate value starts with "0x". If it does then
    * convert the value. Otherwise, this is a plan id enum.
    */
   if (strncmp(iv_p, "0x", 2) == 0)
   {
      errno = 0;

      immediate_value = (uint64_t)strtoull(iv_p, NULL, 0);

      if (errno != 0)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to convert immediate value.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      len = 6 + /* 0xNNNN */
            1;

      word_1 =  immediate_value        & 0xffff;
      word_2 = (immediate_value >> 16) & 0xffff;
      word_3 = (immediate_value >> 32) & 0xffff;
      word_4 = (immediate_value >> 48) & 0xffff;

      object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
      object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
      object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);
      object_p->hw_words_str_p[4] = (char *)calloc(len + 1, 1);

      object_p->hw_words_p[1] = word_1;
      object_p->hw_words_p[2] = word_2;
      object_p->hw_words_p[3] = word_3;
      object_p->hw_words_p[4] = word_4;

      if (object_p->hw_words_str_p[1] == NULL ||
          object_p->hw_words_str_p[2] == NULL ||
          object_p->hw_words_str_p[3] == NULL ||
          object_p->hw_words_str_p[4] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[1],
               len,
               "0x%04x",
               word_1);

      snprintf(object_p->hw_words_str_p[2],
               len,
               "0x%04x",
               word_2);

      snprintf(object_p->hw_words_str_p[3],
               len,
               "0x%04x",
               word_3);

      snprintf(object_p->hw_words_str_p[4],
               len,
               "0x%04x",
               word_4);
   }
   else
   {
      len = strlen(iv_p) + 1;

      object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

      if (object_p->hw_words_str_p[1] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[1],
               len,
               "%s",
               iv_p);

      /* Pad other immediate value words with 0 */

      len = 6 + /* 0xNNNN */
            1;

      object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
      object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);
      object_p->hw_words_str_p[4] = (char *)calloc(len + 1, 1);

      /* HW opcodes */
      object_p->hw_words_p[1] = 0;
      object_p->hw_words_p[2] = 0;
      object_p->hw_words_p[3] = 0;
      object_p->hw_words_p[4] = 0;

      if (object_p->hw_words_str_p[1] == NULL ||
          object_p->hw_words_str_p[2] == NULL ||
          object_p->hw_words_str_p[3] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[2],
               len,
               "0x0000");

      snprintf(object_p->hw_words_str_p[3],
               len,
               "0x0000");

      snprintf(object_p->hw_words_str_p[4],
               len,
               "0x0000");
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 11VI IFFW
    *
    * V - Target working register (0 or 1)
    * I - Immediate value size
    * F - Function (OR/AND/XOR)
    * W - Source working register (0 or 1)
    */

   len = strlen(_FMSP_INSTR_CODE_BITWISE_WR_IV_TO_WR_STR) +
         strlen(tgt_wr_str_p)                             +
         strlen(start_shift_str_p)                        +
         6                                                + /* 0xNNNN */
         strlen(end_shift_3_str_p)                        +
         strlen(start_shift_str_p)                        +
         6                                                + /* 0xNNNN */
         strlen(end_shift_1_str_p)                        +
         strlen(src_wr_str_p)                             +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s0x%04x%s%s0x%04x%s%s",
            _FMSP_INSTR_CODE_BITWISE_WR_IV_TO_WR_STR,
            tgt_wr_str_p,
            start_shift_str_p,
            iv_word_size,
            end_shift_3_str_p,
            start_shift_str_p,
            function,
            end_shift_1_str_p,
            src_wr_str_p);

   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_BITWISE_WR_IV_TO_WR |
                             (target_wr << 5)                     |
                             (iv_word_size << 3)                  |
                             (function << 1)                      |
                             source_wr;

   object_p->target_working_register = target_wr;
   object_p->source_working_register = source_wr;
   object_p->function                = function;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));


   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for addsub working register to working register operation
 *
 * Parameters:
 *    ctx_p         - Parse context
 *    target        - Working register to place result
 *    left_operand  - Left operand of operation
 *    function      - Function to be used
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_addsub_wr_wr_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                            uint8_t                           target,
                                            uint8_t                           left_operand,
                                            uint8_t                           function)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;
   char                          *target_str_p;
   char                           target_0_str_p[]    = " | 0x0";
   char                           target_1_str_p[]    = " | 0x4";
   char                          *function_str_p;
   char                           add_str_p[]         = " | 0x0";
   char                           sub_str_p[]         = " | 0x2";
   char                          *left_op_str_p;
   char                           left_0_str_p[]      = " | 0x0";
   char                           left_1_str_p[]      = " | 0x1";

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_addsub_wr_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0100 1VOL
    *
    * V - Target working register
    * O - Operation (0 add, 1 subtract)
    * L - Left operand (other working register is the right operand)
    */

   if (target == 0)
   {
      target_str_p = target_0_str_p;
   }
   else
   {
      target_str_p = target_1_str_p;
   }

   if (function == 0)
   {
      function_str_p = add_str_p;
   }
   else
   {
      function_str_p = sub_str_p;
   }

   if (left_operand == 0)
   {
      left_op_str_p = left_0_str_p;
   }
   else
   {
      left_op_str_p = left_1_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_ADDSUB_WR_WR_TO_WR_STR) +
         strlen(target_str_p)                            +
         strlen(function_str_p)                          +
         strlen(left_op_str_p)                           +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s",
            _FMSP_INSTR_CODE_ADDSUB_WR_WR_TO_WR_STR,
            target_str_p,
            function_str_p,
            left_op_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_ADDSUB_WR_WR_TO_WR |
                             (target << 2)                       |
                             (function << 1)                     |
                             left_operand;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for addsub immediate value to working register operation
 *
 * Parameters:
 *    ctx_p         - Parse context
 *    target        - Working register to place result
 *    source        - Working register to use as source operand
 *    function      - Function to be used
 *    iv_p          - Immediate value
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_addsub_wr_iv_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                            uint8_t                           target,
                                            uint8_t                           source,
                                            uint8_t                           function,
                                            char                             *iv_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;
   char                          *size_str_p;
   char                           size16_str_p[]      = " | 0x0";
   char                           size32_str_p[]      = " | 0x8";
   char                          *target_str_p;
   char                           target_0_str_p[]    = " | 0x0";
   char                           target_1_str_p[]    = " | 0x4";
   char                          *function_str_p;
   char                           add_str_p[]         = " | 0x0";
   char                           sub_str_p[]         = " | 0x2";
   char                          *source_str_p;
   char                           source_0_str_p[]    = " | 0x0";
   char                           source_1_str_p[]    = " | 0x1";
   uint64_t                       immediate_value     = 0;
   uint16_t                       word_1;
   uint16_t                       word_2;
   uint32_t                       size = 0;

   /* Check if the immediate value starts with "0x". If it does then
    * convert the value and base the number of immediate value words
    * on that.  Otherwise, this is a plan id enum which is 1 byte so
    * only use 1 immediate value word.
    */
   if (strncmp(iv_p, "0x", 2) == 0)
   {
      errno = 0;
   
      immediate_value = (uint64_t)strtoull(iv_p, NULL, 0);

      if (errno != 0)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to convert immediate value.");
         return (false);
      }

      if (immediate_value < 0x10000)
      {
         size_str_p = size16_str_p;
         ctx_p->num_immediate_values = 1;
         size = 0;
      }
      else if (immediate_value < 0x100000000ULL)
      {
         size_str_p = size32_str_p;
         ctx_p->num_immediate_values = 2;
         size = 1;
      }
      else
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Immediate value > 32 bits. Not allowed for this instruction.");
         return (false);
      }
   }
   else
   {
      size_str_p = size16_str_p;
      ctx_p->num_immediate_values = 1;
      size = 0;
   }

   if (target == 0)
   {
      target_str_p = target_0_str_p;
   }
   else
   {
      target_str_p = target_1_str_p;
   }

   if (source == 0)
   {
      source_str_p = source_0_str_p;
   }
   else
   {
      source_str_p = source_1_str_p;
   }

   object_p = _fmsp_new_instruction(_fmsp_assembler_addsub_wr_wr_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0101 SVOW
    *
    * S - Size of immediate value (0 -> 16 bytes, 1 -> 32 bytes)
    * V - Target working register
    * O - Operation (0 add, 1 subtract)
    * W - Working register to use as operand
    */

   if (target == 0)
   {
      target_str_p = target_0_str_p;
   }
   else
   {
      target_str_p = target_1_str_p;
   }

   if (function == 0)
   {
      function_str_p = add_str_p;
   }
   else
   {
      function_str_p = sub_str_p;
   }

   if (source == 0)
   {
      source_str_p = source_0_str_p;
   }
   else
   {
      source_str_p = source_1_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_ADDSUB_WR_IV_TO_WR_STR) +
         strlen(size_str_p)                              +
         strlen(target_str_p)                            +
         strlen(function_str_p)                          +
         strlen(source_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s",
            _FMSP_INSTR_CODE_ADDSUB_WR_IV_TO_WR_STR,
            size_str_p,
            target_str_p,
            function_str_p,
            source_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_ADDSUB_WR_IV_TO_WR |
                             (size << 3)                         |
                             (target << 2)                       |
                             (function << 1)                     |
                             source;

   if (strncmp(iv_p, "0x", 2) == 0)
   {
      len = 6 + /* 0xNNNN */
            1;

      word_1 =  immediate_value        & 0xffff;
      word_2 = (immediate_value >> 16) & 0xffff;

      if (ctx_p->num_immediate_values == 1)
      {
         object_p->num_valid_hw_words = 2;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         object_p->hw_words_p[1] = word_1;
      }
      else
      {
         object_p->num_valid_hw_words = 3;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
      }
   }
   else
   {
      object_p->num_valid_hw_words = 2;

      len = strlen(iv_p) + 1;

      object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

      if (object_p->hw_words_str_p[1] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[1],
               len,
               "%s",
               iv_p);

         object_p->hw_words_p[1] = 0;
   }

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   free (iv_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for shift left working register by specific value.
 *
 * Parameters:
 *    ctx_p - Parse context
 *    wr    - Working register
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_bitwise_shift_left_wr_by_sv_action(_fmsp_assembler_parser_context_t *ctx_p,
                                                     uint8_t                           wr,
                                                     char                             *sv_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint8_t                        specific_value;
   char                           start_shift_str_p[] = " | (";
   char                           end_shift_1_str_p[] = " << 1)";
   char                           wr_0_str_p[]        = " | 0x0";
   char                           wr_1_str_p[]        = " | 0x1";
   char                          *wr_str_p;
   uint32_t                       len;

   errno = 0;

   specific_value = (uint8_t)strtoul(sv_p, NULL, 0);

   if (errno != 0)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to convert immediate value.");
      return (false);
   }

   if (specific_value == 0)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Shift left value of 0 is not allowed.");
      return (false);
   }

   if (specific_value > 64)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Shift left value too large.");
      return (false);
   }

   /* Specific value is stored as val - 1 in instruction */
   specific_value--;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_shift_left_wr_by_sv_e,
                                    ctx_p);
   
   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }
   
   /* Bit layout of this instruction:
    *
    * 0000 0001 0ZZZ ZZZW
    *
    * W - Working register (0 or 1)
    * Z - Specific value - 1
    */
   
   object_p->working_register = wr;
   
   if (wr == 0)
   {
      wr_str_p = wr_0_str_p;
   }
   else
   {
      wr_str_p = wr_1_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_SHIFT_LEFT_WR_BY_SV_STR) +
         strlen(start_shift_str_p)                        +
         6                                                + /* 0xNNNN */
         strlen(end_shift_1_str_p)                        +
         strlen(wr_str_p)                                 +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s0x%04x%s%s",
            _FMSP_INSTR_CODE_SHIFT_LEFT_WR_BY_SV_STR,
            start_shift_str_p,
            specific_value,
            end_shift_1_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_SHIFT_LEFT_WR_BY_SV |
                             (specific_value << 1)                |
                             wr;

   object_p->num_valid_hw_words = 1;
   
   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for shift right working register by specific value.
 *
 * Parameters:
 *    ctx_p - Parse context
 *    wr    - Working register
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_bitwise_shift_right_wr_by_sv_action(_fmsp_assembler_parser_context_t *ctx_p,
                                                      uint8_t                           wr,
                                                      char                             *sv_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint8_t                        specific_value;
   char                           start_shift_str_p[] = " | (";
   char                           end_shift_1_str_p[] = " << 1)";
   char                           wr_0_str_p[]        = " | 0x0";
   char                           wr_1_str_p[]        = " | 0x1";
   char                          *wr_str_p;
   uint32_t                       len;

   errno = 0;

   specific_value = (uint8_t)strtoul(sv_p, NULL, 0);

   if (errno != 0)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to convert immediate value.");
      return (false);
   }

   if (specific_value == 0)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Shift right value 0 is not allowed.");
      return (false);
   }

   if (specific_value > 64)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Shift right value too large.");
      return (false);
   }

   /* Specific value is stored as val - 1 in instruction */
   specific_value--;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_shift_right_wr_by_sv_e,
                                    ctx_p);
   
   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }
   
   /* Bit layout of this instruction:
    *
    * 0000 0001 1ZZZ ZZZW
    *
    * W - Working register (0 or 1)
    * Z - Specific value - 1
    */
   
   object_p->working_register = wr;
   
   if (wr == 0)
   {
      wr_str_p = wr_0_str_p;
   }
   else
   {
      wr_str_p = wr_1_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_SHIFT_RIGHT_WR_BY_SV_STR) +
         strlen(start_shift_str_p)                         +
         6                                                 + /* 0xNNNN */
         strlen(end_shift_1_str_p)                         +
         strlen(wr_str_p)                                  +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s0x%04x%s%s",
            _FMSP_INSTR_CODE_SHIFT_RIGHT_WR_BY_SV_STR,
            start_shift_str_p,
            specific_value,
            end_shift_1_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_SHIFT_RIGHT_WR_BY_SV |
                             (specific_value << 1)                |
                             wr;

   object_p->num_valid_hw_words = 1;
   
   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for load bits immediate value to working register.
 *
 * Parameters:
 *    ctx_p      - Parse context.
 *    wr         - Working register.
 *    iv_p       - String containing immediate value.
 *    num_bits   - Number of bits to load.
 *    is_assign  - Assignment (true) or concat (false).
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_load_bits_iv_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                            uint8_t                           wr,
                                            char                             *iv_p,
                                            uint8_t                           num_bits,
                                            bool                              is_assign)
{
   uint32_t                       auto_num_bits         = 0;
   _fmsp_assembler_instruction_t *object_p;
   char                           start_shift_str_p[]  = " | (";
   char                           end_shift_1_str_p[]  = " << 1)";
   char                           assign_str_p[]       = " | (0x0 << 7)";
   char                           concat_str_p[]       = " | (0x1 << 7)";
   char                          *func_str_p;
   char                           wr_0_str_p[]         = " | 0x0";
   char                           wr_1_str_p[]         = " | 0x1";
   char                          *wr_str_p;
   uint32_t                       len;
   uint64_t                       immediate_value      = 0;
   uint16_t                       word_1;
   uint16_t                       word_2;
   uint16_t                       word_3;
   uint16_t                       word_4;
   uint32_t                       shift = 0;

   /* Check if the immediate value starts with "0x". If it does then
    * convert the value and base the number of immediate value words
    * on that.  Otherwise, this is a plan id enum which is 1 byte so
    * only use 1 immediate value word.
    */
   if (strncmp(iv_p, "0x", 2) == 0)
   {
      errno = 0;
   
      immediate_value = (uint64_t)strtoull(iv_p, NULL, 0);

      if (errno != 0)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to convert immediate value.");
         return (false);
      }

      if (immediate_value < 0x10000)
      {
         auto_num_bits = 16;
      }
      else if (immediate_value < 0x100000000ULL)
      {
         auto_num_bits = 32;
      }
      else if (immediate_value < 0x1000000000000ULL)
      {
         auto_num_bits = 48;
      }
      else
      {
         auto_num_bits = 64;
      }
   }
   else
   {
      auto_num_bits = 16;
   }

   if (wr == 0)
   {
      wr_str_p = wr_0_str_p;
   }
   else
   {
      wr_str_p = wr_1_str_p;
   }

   /* Use automatic value for number of bits if none supplied. */
   if (num_bits == 0)
   {
      num_bits = auto_num_bits;
   }

   /* Immediate value words */
   if (num_bits < 17)
   {
      ctx_p->num_immediate_values = 1;
   }
   else if (num_bits < 33)
   {
      ctx_p->num_immediate_values = 2;
   }
   else if (num_bits < 49)
   {
      ctx_p->num_immediate_values = 3;
   }
   else
   {
      ctx_p->num_immediate_values = 4;
   }

   object_p = _fmsp_new_instruction(_fmsp_assembler_load_bits_iv_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   if (is_assign)
   {
      func_str_p = assign_str_p;
      object_p->is_assign = true;
      shift = 0;
   }
   else
   {
      func_str_p = concat_str_p;
      object_p->is_assign = false;
      shift = 1;
   }

   /* Check if the immediate value starts with "0x". If it does then
    * convert the value and base the number of immediate value words
    * on that.  Otherwise, this is a plan id enum which is 1 byte so
    * only use 1 immediate value word.
    */
   if (strncmp(iv_p, "0x", 2) == 0)
   {
      len = 6 + /* 0xNNNN */
            1;

      word_1 =  immediate_value        & 0xffff;
      word_2 = (immediate_value >> 16) & 0xffff;
      word_3 = (immediate_value >> 32) & 0xffff;
      word_4 = (immediate_value >> 48) & 0xffff;

      if (num_bits <= 16)
      {
         object_p->num_valid_hw_words = 2;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         object_p->hw_words_p[1] = word_1;
      }
      else if (num_bits <= 32)
      {
         object_p->num_valid_hw_words = 3;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
      }
      else if (num_bits <= 48)
      {
         object_p->num_valid_hw_words = 4;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL ||
             object_p->hw_words_str_p[3] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         snprintf(object_p->hw_words_str_p[3],
                  len,
                  "0x%04x",
                  word_3);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
         object_p->hw_words_p[3] = word_3;
      }
      else
      {
         object_p->num_valid_hw_words = 5;

         object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[2] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[3] = (char *)calloc(len + 1, 1);
         object_p->hw_words_str_p[4] = (char *)calloc(len + 1, 1);

         if (object_p->hw_words_str_p[1] == NULL ||
             object_p->hw_words_str_p[2] == NULL ||
             object_p->hw_words_str_p[3] == NULL ||
             object_p->hw_words_str_p[4] == NULL)
         {
            _fmsp_assembler_yyerror(ctx_p,
                                    "Failed to allocate string.");
            _fmsp_destroy_instruction(object_p);
            return (false);
         }

         snprintf(object_p->hw_words_str_p[1],
                  len,
                  "0x%04x",
                  word_1);

         snprintf(object_p->hw_words_str_p[2],
                  len,
                  "0x%04x",
                  word_2);

         snprintf(object_p->hw_words_str_p[3],
                  len,
                  "0x%04x",
                  word_3);

         snprintf(object_p->hw_words_str_p[4],
                  len,
                  "0x%04x",
                  word_4);

         object_p->hw_words_p[1] = word_1;
         object_p->hw_words_p[2] = word_2;
         object_p->hw_words_p[3] = word_3;
         object_p->hw_words_p[4] = word_4;
      }
   }
   else
   {
      if (num_bits > 16)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Bit size too large. Can only load 16 bits from an id.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      object_p->num_valid_hw_words = 2;

      len = strlen(iv_p) + 1;

      object_p->hw_words_str_p[1] = (char *)calloc(len + 1, 1);

      if (object_p->hw_words_str_p[1] == NULL)
      {
         _fmsp_assembler_yyerror(ctx_p,
                                 "Failed to allocate string.");
         _fmsp_destroy_instruction(object_p);
         return (false);
      }

      snprintf(object_p->hw_words_str_p[1],
               len,
               "%s",
               iv_p);

      object_p->hw_words_p[1] = 0;
   }

   /* Bit layout of this instruction:
    *
    * 0000 0010 SNNN NNNW
    *
    * S - Assign or concat
    * N - Number of bits
    * W - Working register
    */

   len = strlen(_FMSP_INSTR_CODE_LOAD_BITS_IV_TO_WR_STR) +
         strlen(func_str_p)                              +
         strlen(start_shift_str_p)                       +
         6                                               + /* 0xNNNN */
         strlen(end_shift_1_str_p)                       +
         strlen(wr_str_p)                                +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s0x%04x%s%s",
            _FMSP_INSTR_CODE_LOAD_BITS_IV_TO_WR_STR,
            func_str_p,
            start_shift_str_p,
            num_bits - 1,          /* coded as 0 -> 63 for 1 -> 64 */
            end_shift_1_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_LOAD_BITS_IV_TO_WR |
                             (shift << 7)                        |
                             ((num_bits - 1) << 1)               |
                             wr;

   object_p->num_bits = num_bits;
   object_p->working_register = wr;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for load bytes parameter array to working register.
 *
 * Parameters:
 *    ctx_p       - Parse context.
 *    wr          - Working register.
 *    start_range - Start of parameter array range.
 *    end_range   - End of parameter array range.
 *    is_assign   - Assignment (true) or concat (false).
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_load_bytes_pa_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                             uint8_t                           wr,
                                             uint32_t                          range_start,
                                             uint32_t                          range_end,
                                             bool                              is_assign)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           wr0_str_p[]           = " | 0x0";
   char                           wr1_str_p[]           = " | 0x1";
   char                           assign_str_p[]        = " | (0x0 << 10)";
   char                           concat_str_p[]        = " | (0x1 << 10)";
   char                          *wr_str_p;
   char                          *func_str_p;
   char                           range_end_str_p[]     = " | (0x0000 << 4)";
   char                           num_bytes_str_p[]     = " | (0x0000 << 1)";
   uint32_t                       len;
   uint32_t                       shift = 0;

   if (range_start > MAX_PARAMETER_ARRAY_BYTE_INDEX)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Parameter Array start index out of bounds");

      return (false);
   }

   if (range_end   > MAX_PARAMETER_ARRAY_BYTE_INDEX)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Parameter Array end index out of bounds");

      return (false);
   }

   if (range_start > range_end)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Parameter Array start index > end index");

      return (false);
   }

   if (range_end - range_start > 7)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Parameter Array (end index - start index) > 7");

      return (false);
   }

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_load_bytes_pa_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0001 0SJJ JJJJ KKKW
    *
    * S - Assign or concat
    * J - End of range
    * K - Number of bytes - 1
    * W - Working register
    */

   /* Assign or concat */
   if (is_assign)
   {
      func_str_p = assign_str_p;
      object_p->is_assign = true;
      shift = 0;
   }
   else
   {
      func_str_p = concat_str_p;
      object_p->is_assign = false;
      shift = 1;
   }

   /* Set working register */
   if (wr == 0)
   {
      object_p->working_register = 0;
      wr_str_p = wr0_str_p;
   }
   else
   {
      object_p->working_register = 1;
      wr_str_p = wr1_str_p;
   }

   /* Set range */
   object_p->range_start = range_start;
   object_p->range_end   = range_end;

   len = strlen(range_end_str_p) + 1;

   /* Range end */
   snprintf(range_end_str_p,
            len,
            " | (0x%04x << 4)",
            object_p->range_end);

   len = strlen(num_bytes_str_p) + 1;

   /* Num bytes - 1 */
   snprintf(num_bytes_str_p,
            len,
            " | (0x%04x << 1)",
            (object_p->range_end - object_p->range_start));

   len = strlen(_FMSP_INSTR_CODE_LOAD_BYTES_PA_TO_WR_STR) +
         strlen(func_str_p)                               +
         strlen(range_end_str_p)                          +
         strlen(num_bytes_str_p)                          +
         strlen(wr_str_p)                                 +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s",
            _FMSP_INSTR_CODE_LOAD_BYTES_PA_TO_WR_STR,
            func_str_p,
            range_end_str_p,
            num_bytes_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_LOAD_BYTES_PA_TO_WR |
                             (shift << 10)                        |
                             (range_end << 4)                     |
                             ((range_end - range_start) << 1)     |
                             wr;

   object_p->working_register   = wr;
   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for load bits frame window to working register.
 *
 * Parameters:
 *    ctx_p       - Parse context.
 *    wr          - Working register.
 *    range_start - Start of frame window range.
 *    range_end   - End of frame window range.
 *    is_assign   - Assignment (true) or concat (false).
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_load_bits_fw_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                            uint8_t                           wr,
                                            uint32_t                          range_start,
                                            uint32_t                          range_end,
                                            bool                              is_assign)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           wr0_str_p[]           = " | 0x0";
   char                           wr1_str_p[]           = " | 0x1";
   char                           assign_str_p[]        = " | (0x0 << 14)";
   char                           concat_str_p[]        = " | (0x1 << 14)";
   char                          *wr_str_p;
   char                          *func_str_p;
   char                           range_end_str_p[]     = " | (0x0000 << 7)";
   char                           num_bytes_str_p[]     = " | (0x0000 << 1)";
   uint32_t                       len;
   uint32_t                       shift = 0;

   if (range_start > MAX_FRAME_WINDOW_BIT_INDEX)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Frame Window start index out of bounds");

      return (false);
   }

   if (range_end   > MAX_FRAME_WINDOW_BIT_INDEX)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Frame Window end index out of bounds");

      return (false);
   }

   if (range_start > range_end)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Frame Window start index > end index");

      return (false);
   }

   if (range_end - range_start > 63)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Frame Window (end index - start index) > 63");

      return (false);
   }

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_load_bits_fw_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 1SMM MMMM MNNN NNNW
    *
    * S - Assign or concat
    * M - End of range
    * N - Number of bytes - 1
    * W - Working register
    */

   /* Assign or concat */
   if (is_assign)
   {
      func_str_p = assign_str_p;
      object_p->is_assign = true;
      shift = 0;
   }
   else
   {
      func_str_p = concat_str_p;
      object_p->is_assign = false;
      shift = 1;
   }

   /* Set working register */
   if (wr == 0)
   {
      object_p->working_register = 0;
      wr_str_p = wr0_str_p;
   }
   else
   {
      object_p->working_register = 1;
      wr_str_p = wr1_str_p;
   }

   /* Set range */
   object_p->range_start = range_start;
   object_p->range_end   = range_end;

   len = strlen(range_end_str_p) + 1;

   /* Range end */
   snprintf(range_end_str_p,
            len,
            " | (0x%04x << 7)",
            object_p->range_end);

   len = strlen(num_bytes_str_p) + 1;

   /* Num bytes - 1 */
   snprintf(num_bytes_str_p,
            len,
            " | (0x%04x << 1)",
            (object_p->range_end - object_p->range_start));

   len = strlen(_FMSP_INSTR_CODE_LOAD_BITS_FW_TO_WR_STR) +
         strlen(func_str_p)                              +
         strlen(range_end_str_p)                         +
         strlen(num_bytes_str_p)                         +
         strlen(wr_str_p)                                +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s%s%s%s",
            _FMSP_INSTR_CODE_LOAD_BITS_FW_TO_WR_STR,
            func_str_p,
            range_end_str_p,
            num_bytes_str_p,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_LOAD_BITS_FW_TO_WR |
                             (shift << 14)                       |
                             (range_end << 7)                    |
                             ((range_end - range_start) << 1)    |
                             wr;

   object_p->working_register   = wr;
   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for value
 *
 * Parameters:
 *    ctx_p - Parse context
 *    str_p - Value string
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_value_action(_fmsp_assembler_parser_context_t *ctx_p,
                               char                             *str_p)
{
   int   len;
   char *old_str_p = ctx_p->value_str_p;
   char *value_str_p;

   value_str_p = strdup(str_p);

   if (value_str_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   if (old_str_p == NULL)
   {
      ctx_p->value_str_p = value_str_p;
   }
   else
   {
      len = strlen(ctx_p->value_str_p) +
                   strlen(" | ")       +
                   strlen(value_str_p) +
                   1;

      ctx_p->value_str_p = (char *)calloc(len + 1, 1);

      snprintf(ctx_p->value_str_p,
               len,
               "%s | %s",
               old_str_p,
               value_str_p);

      free (value_str_p);
      free (old_str_p);
   }

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for store working register to lineup confirmation vector.
 *
 * Parameters:
 *    ctx_p       - Parse context.
 *    wr          - Working register.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_store_wr_to_lcv_action(_fmsp_assembler_parser_context_t *ctx_p,
                                         uint8_t                           wr)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           wr0_str_p[]   = " | 0x0";
   char                           wr1_str_p[]   = " | 0x1";
   char                          *wr_str_p;
   uint32_t                       len;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_store_wr_to_lcv_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0100 001W
    *
    * W - Working register
    */

   /* Set working register */
   if (wr == 0)
   {
      wr_str_p = wr0_str_p;
   }
   else
   {
      wr_str_p = wr1_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_STORE_WR_TO_LCV_STR) +
         strlen(wr_str_p)                             +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s",
            _FMSP_INSTR_CODE_STORE_WR_TO_LCV_STR,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_STORE_WR_TO_LCV | wr;

   object_p->working_register   = wr;
   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for load lineup confirmation vector to working register.
 *
 * Parameters:
 *    ctx_p       - Parse context.
 *    wr          - Working register.
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_load_lcv_to_wr_action(_fmsp_assembler_parser_context_t *ctx_p,
                                        uint8_t                           wr)
{
   _fmsp_assembler_instruction_t *object_p;
   char                           wr0_str_p[]   = " | 0x0";
   char                           wr1_str_p[]   = " | 0x1";
   char                          *wr_str_p;
   uint32_t                       len;

   /* No immediate value words */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_load_lcv_to_wr_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   /* Bit layout of this instruction:
    *
    * 0000 0000 0100 000W
    *
    * W - Working register
    */

   /* Set working register */
   if (wr == 0)
   {
      wr_str_p = wr0_str_p;
   }
   else
   {
      wr_str_p = wr1_str_p;
   }

   len = strlen(_FMSP_INSTR_CODE_LOAD_LCV_TO_WR_STR) +
         strlen(wr_str_p)                            +
         1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");

      _fmsp_destroy_instruction(object_p);
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s%s",
            _FMSP_INSTR_CODE_LOAD_LCV_TO_WR_STR,
            wr_str_p);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_LOAD_LCV_TO_WR | wr;

   object_p->working_register   = wr;
   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for jmp_nxt_eth_type
 *
 * Parameters:
 *    ctx_p - Parse context
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_nxt_eth_type_action(_fmsp_assembler_parser_context_t *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;

   /* No immediate values */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_jmp_nxt_eth_type_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   len = strlen(_FMSP_INSTR_CODE_JMP_NXT_ETH_TYPE_STR) + 1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s",
            _FMSP_INSTR_CODE_JMP_NXT_ETH_TYPE_STR);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_JMP_NXT_ETH_TYPE;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for jmp_nxt_ip_proto
 *
 * Parameters:
 *    ctx_p - Parse context
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_jmp_nxt_ip_proto_action(_fmsp_assembler_parser_context_t *ctx_p)
{
   _fmsp_assembler_instruction_t *object_p;
   uint32_t                       len;

   /* No immediate values */
   ctx_p->num_immediate_values = 0;

   object_p = _fmsp_new_instruction(_fmsp_assembler_jmp_nxt_ip_proto_e,
                                    ctx_p);

   if (object_p == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate instruction object.");
      return (false);
   }

   len = strlen(_FMSP_INSTR_CODE_JMP_NXT_IP_PROTO_STR) + 1;

   object_p->hw_words_str_p[0] = (char *)calloc(len + 1, 1);

   if (object_p->hw_words_str_p[0] == NULL)
   {
      _fmsp_assembler_yyerror(ctx_p,
                              "Failed to allocate string.");
      return (false);
   }

   snprintf(object_p->hw_words_str_p[0],
            len,
            "%s",
            _FMSP_INSTR_CODE_JMP_NXT_IP_PROTO_STR);

   /* HW opcode */
   object_p->hw_words_p[0] = _FMSP_INSTR_CODE_JMP_NXT_IP_PROTO;

   object_p->num_valid_hw_words = 1;

   dll_add_to_back(&(ctx_p->instruction_list),
                   &(object_p->dll_node));

   /* Clear context values */
   _fmsp_clear_ctx_instruction_values(ctx_p);

   return (true);
}

/* ---------------------------------------------------------------------------
 * Action for define_variable
 *
 * Parameters:
 *    ctx_p      - Parse context
 *    var_type   - Variable type
 *    var_name_p - Variable name
 *
 * Returns:
 *   Bool - True means action succeeded.
 *          False means action did not succeed.
 * ---------------------------------------------------------------------------*/
static bool _fmsp_define_variable_action(_fmsp_assembler_parser_context_t *ctx_p,
                                         _fmsp_assembler_variable_type_t   var_type,
                                         char                             *var_name_p)
{
   return (true);
}



/* Line 189 of yacc.c  */
#line 5586 "fm_sp_assembler.tab.c"

/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     ALPHA_NUMERIC_WORD = 258,
     JMP = 259,
     COLON = 260,
     NOP = 261,
     CONFIRM_LAYER_MASK = 262,
     START_RAW_INSTRUCTION = 263,
     HEX_WORD = 264,
     HEX_VALUE = 265,
     ASSIGN = 266,
     INCREMENT = 267,
     WINDOW_OFFSET = 268,
     HEADER_BASE = 269,
     RETURN = 270,
     SET_BITS = 271,
     LCV = 272,
     START_RESULT_ARRAY = 273,
     RIGHT_BRACKET = 274,
     ETH_HXS = 275,
     IPV4_HXS = 276,
     IPV6_HXS = 277,
     OTH_L3_HXS = 278,
     TCP_HXS = 279,
     UDP_HXS = 280,
     OTH_L4_HXS = 281,
     RETURN_HXS = 282,
     END_PARSE = 283,
     CONCAT = 284,
     WR0 = 285,
     WR1 = 286,
     CLEAR = 287,
     ONESCOMP = 288,
     AND = 289,
     OR = 290,
     XOR = 291,
     SHIFT_LEFT = 292,
     SHIFT_RIGHT = 293,
     IF = 294,
     START_FRAME_WINDOW = 295,
     QUESTION = 296,
     PIPE = 297,
     AMPERSAND = 298,
     HXS = 299,
     BRIDGE = 300,
     START_PARAMETER_ARRAY = 301,
     EQUAL = 302,
     NOT_EQUAL = 303,
     GREATER_THAN = 304,
     LESS_THAN = 305,
     GREATER_THAN_EQUAL = 306,
     LESS_THAN_EQUAL = 307,
     OPEN_PAREN = 308,
     CLOSE_PAREN = 309,
     COMMA = 310,
     CONTEXT_LIST = 311,
     PLUS = 312,
     MINUS = 313,
     NXT_ETH_TYPE = 314,
     NXT_IP_PROTO = 315,
     UINT6_TYPE = 316,
     UINT7_TYPE = 317,
     UINT8_TYPE = 318,
     UINT16_TYPE = 319,
     UINT32_TYPE = 320,
     UINT48_TYPE = 321,
     UINT64_TYPE = 322,
     DEC_VALUE = 323
   };
#endif



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 214 of yacc.c  */
#line 5549 "fm_sp_assembler.y"

          int   integer;
          char *string;
       


/* Line 214 of yacc.c  */
#line 5697 "fm_sp_assembler.tab.c"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


/* Copy the second part of user declarations.  */


/* Line 264 of yacc.c  */
#line 5709 "fm_sp_assembler.tab.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   186

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  69
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  47
/* YYNRULES -- Number of rules.  */
#define YYNRULES  136
/* YYNRULES -- Number of states.  */
#define YYNSTATES  204

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   323

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,     9,    11,    13,    15,    17,
      19,    21,    23,    25,    27,    29,    31,    33,    35,    37,
      39,    41,    43,    45,    47,    49,    51,    53,    55,    57,
      59,    61,    63,    65,    67,    69,    71,    73,    75,    78,
      80,    82,    84,    86,    90,    93,    99,   104,   108,   111,
     113,   116,   119,   122,   125,   128,   130,   132,   134,   136,
     138,   140,   142,   144,   146,   148,   149,   152,   156,   159,
     163,   170,   177,   186,   194,   206,   217,   232,   246,   249,
     252,   254,   256,   260,   264,   268,   272,   274,   276,   282,
     286,   288,   290,   294,   298,   302,   306,   310,   314,   318,
     322,   325,   327,   329,   331,   333,   335,   337,   339,   341,
     343,   345,   347,   349,   351,   353,   355,   357,   359,   361,
     367,   373,   379,   385,   391,   397,   401,   405,   411,   415,
     421,   425,   433,   439,   447,   453,   461
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      70,     0,    -1,    -1,    70,    71,    -1,    76,    -1,    82,
      -1,    85,    -1,    86,    -1,    87,    -1,    88,    -1,    91,
      -1,    90,    -1,    89,    -1,    95,    -1,    96,    -1,    97,
      -1,    98,    -1,    99,    -1,   100,    -1,   101,    -1,   102,
      -1,   107,    -1,   108,    -1,   109,    -1,   110,    -1,   111,
      -1,   112,    -1,   113,    -1,   114,    -1,   115,    -1,    73,
      -1,    61,    -1,    62,    -1,    63,    -1,    64,    -1,    65,
      -1,    66,    -1,    67,    -1,    72,     3,    -1,     9,    -1,
      10,    -1,     3,    -1,    74,    -1,    75,    42,    74,    -1,
       3,     5,    -1,     9,     9,     9,     9,     9,    -1,     9,
       9,     9,     9,    -1,     9,     9,     9,    -1,     9,     9,
      -1,     9,    -1,     8,    77,    -1,     8,    78,    -1,     8,
      79,    -1,     8,    80,    -1,     8,    81,    -1,    20,    -1,
      21,    -1,    22,    -1,    23,    -1,    24,    -1,    25,    -1,
      26,    -1,    27,    -1,    28,    -1,    44,    -1,    -1,     4,
      83,    -1,     4,    44,    83,    -1,     4,     3,    -1,     4,
      44,     3,    -1,     4,     3,    39,    30,   104,    31,    -1,
       4,     3,    39,    30,   105,    94,    -1,     4,    41,    84,
       3,     5,     5,    84,     3,    -1,     4,    41,    84,     3,
      42,    84,     3,    -1,     4,    41,    84,     3,    42,    84,
       3,     5,     5,    84,     3,    -1,     4,    41,    84,     3,
      42,    84,     3,    42,    84,     3,    -1,     4,    41,    84,
       3,    42,    84,     3,    42,    84,     3,     5,     5,    84,
       3,    -1,     4,    41,    84,     3,    42,    84,     3,    42,
      84,     3,    42,    84,     3,    -1,     4,    59,    -1,     4,
      60,    -1,     6,    -1,     7,    -1,    14,    12,    13,    -1,
      17,    11,    92,    -1,    92,    11,    17,    -1,    17,    16,
      75,    -1,    30,    -1,    31,    -1,    18,    68,     5,    68,
      19,    -1,    18,    68,    19,    -1,    10,    -1,     9,    -1,
      92,    11,    93,    -1,    92,    29,    93,    -1,    93,    11,
      92,    -1,    93,    11,    94,    -1,    13,    11,    94,    -1,
      13,    12,    94,    -1,    13,    11,    92,    -1,    13,    12,
      92,    -1,    32,    92,    -1,    33,    -1,    34,    -1,    43,
      -1,    35,    -1,    42,    -1,    36,    -1,    47,    -1,    48,
      -1,    50,    -1,    49,    -1,    52,    -1,    51,    -1,    47,
      -1,    48,    -1,    50,    -1,    49,    -1,    57,    -1,    58,
      -1,    92,    11,    92,   103,    92,    -1,    92,    11,    92,
     103,    94,    -1,    92,    11,    30,   106,    31,    -1,    92,
      11,    31,   106,    30,    -1,    92,    11,    30,   106,    94,
      -1,    92,    11,    31,   106,    94,    -1,    92,    37,    94,
      -1,    92,    38,    94,    -1,    92,    11,    94,     5,    68,
      -1,    92,    11,    94,    -1,    92,    29,    94,     5,    68,
      -1,    92,    29,    94,    -1,    92,    11,    46,    68,     5,
      68,    19,    -1,    92,    11,    46,    68,    19,    -1,    92,
      29,    46,    68,     5,    68,    19,    -1,    92,    29,    46,
      68,    19,    -1,    92,    11,    40,    68,    45,    68,    19,
      -1,    92,    29,    40,    68,    45,    68,    19,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,  5643,  5643,  5645,  5654,  5655,  5656,  5657,  5658,  5659,
    5660,  5661,  5662,  5663,  5664,  5665,  5666,  5667,  5668,  5669,
    5670,  5671,  5672,  5673,  5674,  5675,  5676,  5677,  5678,  5679,
    5680,  5683,  5685,  5687,  5689,  5691,  5693,  5695,  5699,  5705,
    5707,  5709,  5713,  5715,  5723,  5727,  5731,  5735,  5739,  5743,
    5747,  5749,  5751,  5753,  5755,  5759,  5761,  5763,  5765,  5767,
    5769,  5771,  5773,  5775,  5778,  5781,  5784,  5787,  5790,  5794,
    5798,  5802,  5808,  5813,  5818,  5823,  5828,  5833,  5837,  5839,
    5843,  5847,  5851,  5855,  5859,  5863,  5867,  5869,  5873,  5875,
    5879,  5881,  5885,  5887,  5891,  5895,  5899,  5903,  5907,  5909,
    5913,  5917,  5921,  5923,  5925,  5927,  5929,  5933,  5935,  5937,
    5939,  5941,  5943,  5946,  5948,  5950,  5952,  5955,  5957,  5960,
    5964,  5968,  5970,  5974,  5976,  5980,  5984,  5988,  5990,  5992,
    5994,  5998,  6000,  6002,  6004,  6008,  6010
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "ALPHA_NUMERIC_WORD", "JMP", "COLON",
  "NOP", "CONFIRM_LAYER_MASK", "START_RAW_INSTRUCTION", "HEX_WORD",
  "HEX_VALUE", "ASSIGN", "INCREMENT", "WINDOW_OFFSET", "HEADER_BASE",
  "RETURN", "SET_BITS", "LCV", "START_RESULT_ARRAY", "RIGHT_BRACKET",
  "ETH_HXS", "IPV4_HXS", "IPV6_HXS", "OTH_L3_HXS", "TCP_HXS", "UDP_HXS",
  "OTH_L4_HXS", "RETURN_HXS", "END_PARSE", "CONCAT", "WR0", "WR1", "CLEAR",
  "ONESCOMP", "AND", "OR", "XOR", "SHIFT_LEFT", "SHIFT_RIGHT", "IF",
  "START_FRAME_WINDOW", "QUESTION", "PIPE", "AMPERSAND", "HXS", "BRIDGE",
  "START_PARAMETER_ARRAY", "EQUAL", "NOT_EQUAL", "GREATER_THAN",
  "LESS_THAN", "GREATER_THAN_EQUAL", "LESS_THAN_EQUAL", "OPEN_PAREN",
  "CLOSE_PAREN", "COMMA", "CONTEXT_LIST", "PLUS", "MINUS", "NXT_ETH_TYPE",
  "NXT_IP_PROTO", "UINT6_TYPE", "UINT7_TYPE", "UINT8_TYPE", "UINT16_TYPE",
  "UINT32_TYPE", "UINT48_TYPE", "UINT64_TYPE", "DEC_VALUE", "$accept",
  "input", "instruction", "variable_type", "define_variable", "value",
  "values", "label", "five_hex_words", "four_hex_words", "three_hex_words",
  "two_hex_words", "one_hex_word", "raw_instruction", "hard_examination",
  "hxs", "jmp", "nop", "clm", "advance_hb_by_wo", "store_wr_to_lcv",
  "load_lcv_to_wr", "set_lcv_bits", "working_register",
  "result_array_range", "immediate_value", "load_bytes_ra_to_wr",
  "store_wr_to_ra", "store_iv_to_ra", "load_sv_to_wo", "add_sv_to_wo",
  "modify_wo_by_wr", "zero_wr", "ones_comp_wr1_to_wr0", "bitwise_operator",
  "operator_set1", "operator_set2", "addsub_operator",
  "bitwise_wr_wr_to_wr", "bitwise_wr_iv_to_wr", "addsub_wr_wr_to_wr",
  "addsub_wr_iv_to_wr", "shift_left_wr_by_sv", "shift_right_wr_by_sv",
  "load_bits_iv_to_wr", "load_bytes_pa_to_wr", "load_bits_fw_to_wr", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    69,    70,    70,    71,    71,    71,    71,    71,    71,
      71,    71,    71,    71,    71,    71,    71,    71,    71,    71,
      71,    71,    71,    71,    71,    71,    71,    71,    71,    71,
      71,    72,    72,    72,    72,    72,    72,    72,    73,    74,
      74,    74,    75,    75,    76,    77,    78,    79,    80,    81,
      82,    82,    82,    82,    82,    83,    83,    83,    83,    83,
      83,    83,    83,    83,    84,    84,    85,    85,    85,    85,
      85,    85,    85,    85,    85,    85,    85,    85,    85,    85,
      86,    87,    88,    89,    90,    91,    92,    92,    93,    93,
      94,    94,    95,    95,    96,    97,    98,    99,   100,   100,
     101,   102,   103,   103,   103,   103,   103,   104,   104,   104,
     104,   104,   104,   105,   105,   105,   105,   106,   106,   107,
     108,   109,   109,   110,   110,   111,   112,   113,   113,   113,
     113,   114,   114,   114,   114,   115,   115
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     2,     1,
       1,     1,     1,     3,     2,     5,     4,     3,     2,     1,
       2,     2,     2,     2,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     0,     2,     3,     2,     3,
       6,     6,     8,     7,    11,    10,    14,    13,     2,     2,
       1,     1,     3,     3,     3,     3,     1,     1,     5,     3,
       1,     1,     3,     3,     3,     3,     3,     3,     3,     3,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     5,
       5,     5,     5,     5,     5,     3,     3,     5,     3,     5,
       3,     7,     5,     7,     5,     7,     7
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,     0,     0,    80,    81,     0,     0,     0,
       0,     0,    86,    87,     0,   101,    31,    32,    33,    34,
      35,    36,    37,     3,     0,    30,     4,     5,     6,     7,
       8,     9,    12,    11,    10,     0,     0,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    44,    68,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    65,     0,    78,    79,    66,
      49,    50,    51,    52,    53,    54,     0,     0,     0,     0,
       0,     0,   100,    38,     0,     0,     0,     0,     0,     0,
      64,     0,    69,    67,    48,    91,    90,    98,    96,    99,
      97,    82,    83,    41,    39,    40,    42,    85,     0,    89,
      84,    86,    87,     0,     0,     0,    92,   128,     0,     0,
      93,   130,   125,   126,    94,    95,     0,     0,    47,     0,
       0,   117,   118,     0,     0,     0,     0,   102,   104,   106,
     105,   103,     0,     0,     0,     0,     0,   113,   114,   116,
     115,   112,   111,     0,     0,     0,    65,    46,    43,    88,
     121,   123,   122,   124,     0,     0,   132,   119,   120,   127,
       0,     0,   134,   129,    70,    71,    65,     0,    45,     0,
       0,     0,     0,     0,    73,   135,   131,   136,   133,    72,
       0,    65,    65,     0,     0,    75,    74,     0,    65,    65,
       0,     0,    77,    76
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    23,    24,    25,   106,   107,    26,    71,    72,
      73,    74,    75,    27,    69,    91,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    98,    37,    38,    39,    40,
      41,    42,    43,    44,   142,   153,   154,   133,    45,    46,
      47,    48,    49,    50,    51,    52,    53
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -154
static const yytype_int16 yypact[] =
{
    -154,    18,  -154,     8,    66,  -154,  -154,    -7,    60,     5,
     116,   -39,  -154,  -154,    75,  -154,  -154,  -154,  -154,  -154,
    -154,  -154,  -154,  -154,    51,  -154,  -154,  -154,  -154,  -154,
    -154,  -154,  -154,  -154,  -154,    23,    53,  -154,  -154,  -154,
    -154,  -154,  -154,  -154,  -154,  -154,  -154,  -154,  -154,  -154,
    -154,  -154,  -154,  -154,  -154,    36,  -154,  -154,  -154,  -154,
    -154,  -154,  -154,  -154,  -154,    55,    92,  -154,  -154,  -154,
      88,  -154,  -154,  -154,  -154,  -154,    91,    91,    98,    75,
      93,    25,  -154,  -154,    -3,    58,    99,    99,    91,   105,
    -154,   133,  -154,  -154,   130,  -154,  -154,  -154,  -154,  -154,
    -154,  -154,  -154,  -154,  -154,  -154,  -154,   106,    72,  -154,
    -154,    76,    76,    79,    81,    95,  -154,   145,    83,    84,
    -154,   148,  -154,  -154,  -154,  -154,    94,    -1,   146,    93,
     135,  -154,  -154,    46,    10,   111,    28,  -154,  -154,  -154,
    -154,  -154,    91,    89,   113,    54,    96,   128,   129,   131,
     132,  -154,  -154,   134,    99,   156,    55,   157,  -154,  -154,
    -154,  -154,  -154,  -154,   100,   101,  -154,  -154,  -154,  -154,
     102,   103,  -154,  -154,  -154,  -154,    55,   164,  -154,   153,
     154,   155,   158,   172,     0,  -154,  -154,  -154,  -154,  -154,
     171,    55,    55,   175,   176,    11,  -154,   177,    55,    55,
     178,   180,  -154,  -154
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -154,  -154,  -154,  -154,  -154,    56,  -154,  -154,  -154,  -154,
    -154,  -154,  -154,  -154,   114,  -153,  -154,  -154,  -154,  -154,
    -154,  -154,  -154,   -14,    39,   -76,  -154,  -154,  -154,  -154,
    -154,  -154,  -154,  -154,  -154,  -154,  -154,    74,  -154,  -154,
    -154,  -154,  -154,  -154,  -154,  -154,  -154
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -111
static const yytype_int16 yytable[] =
{
      82,   100,    70,   177,   155,   190,    95,    96,   117,   121,
     122,   123,   125,    54,   110,    11,   197,    78,     2,    95,
      96,     3,     4,   183,     5,     6,     7,   111,   112,    81,
     108,     8,     9,   165,    84,    10,    11,   113,   193,   194,
     162,   156,   191,   114,   109,   200,   201,   166,    12,    13,
      14,    15,    85,   198,    83,    95,    96,   161,   163,   171,
      86,    87,    97,    99,    88,   102,   168,    95,    96,    55,
     115,    76,    77,   172,   124,    89,    11,   160,   175,    16,
      17,    18,    19,    20,    21,    22,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    92,   103,    94,   118,    90,
      95,    96,   104,   105,   119,    12,    13,    65,    95,    96,
      66,   101,    56,    57,    58,    59,    60,    61,    62,    63,
      64,    12,    13,   116,   120,    67,    68,    79,   167,   137,
     138,   139,    80,   131,   132,   126,   127,   140,   141,   128,
     130,   147,   148,   149,   150,   151,   152,   135,   129,   136,
     143,   144,   145,   146,   159,   157,   164,   169,   170,  -107,
    -108,   176,  -110,  -109,   173,   174,   178,   184,   179,   180,
     181,   182,   185,   186,   187,   189,   192,   188,   195,   196,
      93,   202,   199,   203,     0,   158,   134
};

static const yytype_int16 yycheck[] =
{
      14,    77,     9,   156,     5,     5,     9,    10,    84,    85,
      86,    87,    88,     5,    17,    18,     5,    12,     0,     9,
      10,     3,     4,   176,     6,     7,     8,    30,    31,    68,
       5,    13,    14,     5,    11,    17,    18,    40,   191,   192,
      30,    42,    42,    46,    19,   198,   199,    19,    30,    31,
      32,    33,    29,    42,     3,     9,    10,   133,   134,     5,
      37,    38,    76,    77,    11,    79,   142,     9,    10,     3,
      84,    11,    12,    19,    88,    39,    18,    31,   154,    61,
      62,    63,    64,    65,    66,    67,    20,    21,    22,    23,
      24,    25,    26,    27,    28,     3,     3,     9,    40,    44,
       9,    10,     9,    10,    46,    30,    31,    41,     9,    10,
      44,    13,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    30,    31,    84,    85,    59,    60,    11,   142,    34,
      35,    36,    16,    57,    58,    30,     3,    42,    43,     9,
      68,    47,    48,    49,    50,    51,    52,    68,    42,    68,
       5,    68,    68,     5,    19,     9,    45,    68,    45,    31,
      31,     5,    31,    31,    68,    31,     9,     3,    68,    68,
      68,    68,    19,    19,    19,     3,     5,    19,     3,     3,
      66,     3,     5,     3,    -1,   129,   112
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    70,     0,     3,     4,     6,     7,     8,    13,    14,
      17,    18,    30,    31,    32,    33,    61,    62,    63,    64,
      65,    66,    67,    71,    72,    73,    76,    82,    85,    86,
      87,    88,    89,    90,    91,    92,    93,    95,    96,    97,
      98,    99,   100,   101,   102,   107,   108,   109,   110,   111,
     112,   113,   114,   115,     5,     3,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    41,    44,    59,    60,    83,
       9,    77,    78,    79,    80,    81,    11,    12,    12,    11,
      16,    68,    92,     3,    11,    29,    37,    38,    11,    39,
      44,    84,     3,    83,     9,     9,    10,    92,    94,    92,
      94,    13,    92,     3,     9,    10,    74,    75,     5,    19,
      17,    30,    31,    40,    46,    92,    93,    94,    40,    46,
      93,    94,    94,    94,    92,    94,    30,     3,     9,    42,
      68,    57,    58,   106,   106,    68,    68,    34,    35,    36,
      42,    43,   103,     5,    68,    68,     5,    47,    48,    49,
      50,    51,    52,   104,   105,     5,    42,     9,    74,    19,
      31,    94,    30,    94,    45,     5,    19,    92,    94,    68,
      45,     5,    19,    68,    31,    94,     5,    84,     9,    68,
      68,    68,    68,    84,     3,    19,    19,    19,    19,     3,
       5,    42,     5,    84,    84,     3,     3,     5,    42,     5,
      84,    84,     3,     3
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  However,
   YYFAIL appears to be in use.  Nevertheless, it is formally deprecated
   in Bison 2.4.2's NEWS entry, where a plan to phase it out is
   discussed.  */

#define YYFAIL		goto yyerrlab
#if defined YYFAIL
  /* This is here to suppress warnings from the GCC cpp's
     -Wunused-macros.  Normally we don't worry about that warning, but
     some users do, and we want to make it easy for users to remove
     YYFAIL uses, which will produce warnings from Bison 2.5.  */
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (_fmsp_assembler_context_p, YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, _fmsp_assembler_context_p)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, _fmsp_assembler_context_p); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, _fmsp_assembler_context_p)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (_fmsp_assembler_context_p);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, _fmsp_assembler_context_p)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, _fmsp_assembler_context_p);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule, _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p)
#else
static void
yy_reduce_print (yyvsp, yyrule, _fmsp_assembler_context_p)
    YYSTYPE *yyvsp;
    int yyrule;
    _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       , _fmsp_assembler_context_p);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule, _fmsp_assembler_context_p); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, _fmsp_assembler_context_p)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (_fmsp_assembler_context_p);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}

/* Prevent warnings from -Wmissing-prototypes.  */
#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (_fmsp_assembler_parser_context_t *_fmsp_assembler_context_p);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */





/*-------------------------.
| yyparse or yypush_parse.  |
`-------------------------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (_fmsp_assembler_parser_context_t *_fmsp_assembler_context_p)
#else
int
yyparse (_fmsp_assembler_context_p)
    _fmsp_assembler_parser_context_t *_fmsp_assembler_context_p;
#endif
#endif
{
/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks thru separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yytoken = 0;
  yyss = yyssa;
  yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */
  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 31:

/* Line 1464 of yacc.c  */
#line 5684 "fm_sp_assembler.y"
    {(yyval.integer) = _fmsp_uint6_type_e;;}
    break;

  case 32:

/* Line 1464 of yacc.c  */
#line 5686 "fm_sp_assembler.y"
    {(yyval.integer) = _fmsp_uint7_type_e;;}
    break;

  case 33:

/* Line 1464 of yacc.c  */
#line 5688 "fm_sp_assembler.y"
    {(yyval.integer) = _fmsp_uint8_type_e;;}
    break;

  case 34:

/* Line 1464 of yacc.c  */
#line 5690 "fm_sp_assembler.y"
    {(yyval.integer) = _fmsp_uint16_type_e;;}
    break;

  case 35:

/* Line 1464 of yacc.c  */
#line 5692 "fm_sp_assembler.y"
    {(yyval.integer) = _fmsp_uint32_type_e;;}
    break;

  case 36:

/* Line 1464 of yacc.c  */
#line 5694 "fm_sp_assembler.y"
    {(yyval.integer) = _fmsp_uint48_type_e;;}
    break;

  case 37:

/* Line 1464 of yacc.c  */
#line 5696 "fm_sp_assembler.y"
    {(yyval.integer) = _fmsp_uint64_type_e;;}
    break;

  case 38:

/* Line 1464 of yacc.c  */
#line 5700 "fm_sp_assembler.y"
    {if (!_fmsp_define_variable_action(_fmsp_assembler_context_p, (yyvsp[(1) - (2)].integer), (yyvsp[(2) - (2)].string))) {return (1);}
                                free (yyvsp[(2) - (2)].string);
                               ;}
    break;

  case 39:

/* Line 1464 of yacc.c  */
#line 5706 "fm_sp_assembler.y"
    {(yyval.string) = (yyvsp[(1) - (1)].string);;}
    break;

  case 40:

/* Line 1464 of yacc.c  */
#line 5708 "fm_sp_assembler.y"
    {(yyval.string) = (yyvsp[(1) - (1)].string);;}
    break;

  case 41:

/* Line 1464 of yacc.c  */
#line 5710 "fm_sp_assembler.y"
    {(yyval.string) = (yyvsp[(1) - (1)].string);;}
    break;

  case 42:

/* Line 1464 of yacc.c  */
#line 5714 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P1(_fmsp_value_action, (yyvsp[(1) - (1)].string));}
    break;

  case 43:

/* Line 1464 of yacc.c  */
#line 5716 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P1(_fmsp_value_action, (yyvsp[(3) - (3)].string));}
    break;

  case 44:

/* Line 1464 of yacc.c  */
#line 5724 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P1(_fmsp_label_action, (yyvsp[(1) - (2)].string));}
    break;

  case 45:

/* Line 1464 of yacc.c  */
#line 5728 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P5(_fmsp_five_hex_words_action, (yyvsp[(1) - (5)].string), (yyvsp[(2) - (5)].string), (yyvsp[(3) - (5)].string), (yyvsp[(4) - (5)].string), (yyvsp[(5) - (5)].string));}
    break;

  case 46:

/* Line 1464 of yacc.c  */
#line 5732 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P4(_fmsp_four_hex_words_action, (yyvsp[(1) - (4)].string), (yyvsp[(2) - (4)].string), (yyvsp[(3) - (4)].string), (yyvsp[(4) - (4)].string));}
    break;

  case 47:

/* Line 1464 of yacc.c  */
#line 5736 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P3(_fmsp_three_hex_words_action, (yyvsp[(1) - (3)].string), (yyvsp[(2) - (3)].string), (yyvsp[(3) - (3)].string));}
    break;

  case 48:

/* Line 1464 of yacc.c  */
#line 5740 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P2(_fmsp_two_hex_words_action, (yyvsp[(1) - (2)].string), (yyvsp[(2) - (2)].string));}
    break;

  case 49:

/* Line 1464 of yacc.c  */
#line 5744 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P1(_fmsp_one_hex_word_action, (yyvsp[(1) - (1)].string));}
    break;

  case 50:

/* Line 1464 of yacc.c  */
#line 5748 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_raw_instruction_action);}
    break;

  case 51:

/* Line 1464 of yacc.c  */
#line 5750 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_raw_instruction_action);}
    break;

  case 52:

/* Line 1464 of yacc.c  */
#line 5752 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_raw_instruction_action);}
    break;

  case 53:

/* Line 1464 of yacc.c  */
#line 5754 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_raw_instruction_action);}
    break;

  case 54:

/* Line 1464 of yacc.c  */
#line 5756 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_raw_instruction_action);}
    break;

  case 55:

/* Line 1464 of yacc.c  */
#line 5760 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_ETH_HXS_LABEL;;}
    break;

  case 56:

/* Line 1464 of yacc.c  */
#line 5762 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_IPV4_HXS_LABEL;;}
    break;

  case 57:

/* Line 1464 of yacc.c  */
#line 5764 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_IPV6_HXS_LABEL;;}
    break;

  case 58:

/* Line 1464 of yacc.c  */
#line 5766 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_OTH_L3_HXS_LABEL;;}
    break;

  case 59:

/* Line 1464 of yacc.c  */
#line 5768 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_TCP_HXS_LABEL;;}
    break;

  case 60:

/* Line 1464 of yacc.c  */
#line 5770 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_UDP_HXS_LABEL;;}
    break;

  case 61:

/* Line 1464 of yacc.c  */
#line 5772 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_OTH_L4_HXS_LABEL;;}
    break;

  case 62:

/* Line 1464 of yacc.c  */
#line 5774 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_RETURN_HXS_LABEL;;}
    break;

  case 63:

/* Line 1464 of yacc.c  */
#line 5776 "fm_sp_assembler.y"
    {(yyval.string) = _FMSP_END_PARSE_LABEL;;}
    break;

  case 64:

/* Line 1464 of yacc.c  */
#line 5779 "fm_sp_assembler.y"
    {(yyval.integer) = true;;}
    break;

  case 65:

/* Line 1464 of yacc.c  */
#line 5781 "fm_sp_assembler.y"
    {(yyval.integer) = false;;}
    break;

  case 66:

/* Line 1464 of yacc.c  */
#line 5785 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_action(_fmsp_assembler_context_p, (yyvsp[(2) - (2)].string), false)) {return (1);}
                               ;}
    break;

  case 67:

/* Line 1464 of yacc.c  */
#line 5788 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_action(_fmsp_assembler_context_p, (yyvsp[(3) - (3)].string), true)) {return (1);}
                               ;}
    break;

  case 68:

/* Line 1464 of yacc.c  */
#line 5791 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_action(_fmsp_assembler_context_p, (yyvsp[(2) - (2)].string), false)) {return (1);}
                                free (yyvsp[(2) - (2)].string);
                               ;}
    break;

  case 69:

/* Line 1464 of yacc.c  */
#line 5795 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_action(_fmsp_assembler_context_p, (yyvsp[(3) - (3)].string), true)) {return (1);}
                                free (yyvsp[(3) - (3)].string);
                               ;}
    break;

  case 70:

/* Line 1464 of yacc.c  */
#line 5799 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_if_wr0_wr1_action(_fmsp_assembler_context_p, (yyvsp[(2) - (6)].string), (yyvsp[(5) - (6)].integer))) {return (1);}
                                free (yyvsp[(2) - (6)].string);
                               ;}
    break;

  case 71:

/* Line 1464 of yacc.c  */
#line 5803 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_if_wr0_iv_action(_fmsp_assembler_context_p, (yyvsp[(2) - (6)].string), (yyvsp[(5) - (6)].integer), (yyvsp[(6) - (6)].string))) {return (1);}
                                free (yyvsp[(2) - (6)].string);
                                free (yyvsp[(6) - (6)].string);
                               ;}
    break;

  case 72:

/* Line 1464 of yacc.c  */
#line 5809 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_case1dj_action(_fmsp_assembler_context_p, (yyvsp[(4) - (8)].string), (yyvsp[(8) - (8)].string), (yyvsp[(3) - (8)].integer), (yyvsp[(7) - (8)].integer))) {return (1);}
                                free (yyvsp[(4) - (8)].string); free (yyvsp[(8) - (8)].string);
                               ;}
    break;

  case 73:

/* Line 1464 of yacc.c  */
#line 5814 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_case2dc_action(_fmsp_assembler_context_p, (yyvsp[(4) - (7)].string), (yyvsp[(7) - (7)].string), (yyvsp[(3) - (7)].integer), (yyvsp[(6) - (7)].integer))) {return (1);}
                                free (yyvsp[(4) - (7)].string); free (yyvsp[(7) - (7)].string);
                               ;}
    break;

  case 74:

/* Line 1464 of yacc.c  */
#line 5819 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_case2dj_action(_fmsp_assembler_context_p, (yyvsp[(4) - (11)].string), (yyvsp[(7) - (11)].string), (yyvsp[(11) - (11)].string), (yyvsp[(3) - (11)].integer), (yyvsp[(6) - (11)].integer), (yyvsp[(10) - (11)].integer))) {return (1);}
                                free (yyvsp[(4) - (11)].string); free (yyvsp[(7) - (11)].string); free (yyvsp[(11) - (11)].string);
                               ;}
    break;

  case 75:

/* Line 1464 of yacc.c  */
#line 5824 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_case3dc_action(_fmsp_assembler_context_p, (yyvsp[(4) - (10)].string), (yyvsp[(7) - (10)].string), (yyvsp[(10) - (10)].string), (yyvsp[(3) - (10)].integer), (yyvsp[(6) - (10)].integer), (yyvsp[(9) - (10)].integer))) {return (1);}
                                free (yyvsp[(4) - (10)].string); free (yyvsp[(7) - (10)].string); free (yyvsp[(10) - (10)].string);
                               ;}
    break;

  case 76:

/* Line 1464 of yacc.c  */
#line 5829 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_case3dj_action(_fmsp_assembler_context_p, (yyvsp[(4) - (14)].string), (yyvsp[(7) - (14)].string), (yyvsp[(10) - (14)].string), (yyvsp[(14) - (14)].string), (yyvsp[(3) - (14)].integer), (yyvsp[(6) - (14)].integer), (yyvsp[(9) - (14)].integer), (yyvsp[(13) - (14)].integer))) {return (1);}
                                free (yyvsp[(4) - (14)].string); free (yyvsp[(7) - (14)].string); free (yyvsp[(10) - (14)].string); free (yyvsp[(14) - (14)].string);
                               ;}
    break;

  case 77:

/* Line 1464 of yacc.c  */
#line 5834 "fm_sp_assembler.y"
    {if (!_fmsp_jmp_label_case4dc_action(_fmsp_assembler_context_p, (yyvsp[(4) - (13)].string), (yyvsp[(7) - (13)].string), (yyvsp[(10) - (13)].string), (yyvsp[(13) - (13)].string), (yyvsp[(3) - (13)].integer), (yyvsp[(6) - (13)].integer), (yyvsp[(9) - (13)].integer), (yyvsp[(12) - (13)].integer))) {return (1);}
                                free (yyvsp[(4) - (13)].string); free (yyvsp[(7) - (13)].string); free (yyvsp[(10) - (13)].string); free (yyvsp[(13) - (13)].string);
                               ;}
    break;

  case 78:

/* Line 1464 of yacc.c  */
#line 5838 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_jmp_nxt_eth_type_action);}
    break;

  case 79:

/* Line 1464 of yacc.c  */
#line 5840 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_jmp_nxt_ip_proto_action);}
    break;

  case 80:

/* Line 1464 of yacc.c  */
#line 5844 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_nop_action);}
    break;

  case 81:

/* Line 1464 of yacc.c  */
#line 5848 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_clm_action);}
    break;

  case 82:

/* Line 1464 of yacc.c  */
#line 5852 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_advance_hb_by_wo_action);}
    break;

  case 83:

/* Line 1464 of yacc.c  */
#line 5856 "fm_sp_assembler.y"
    {if (!_fmsp_store_wr_to_lcv_action(_fmsp_assembler_context_p, (yyvsp[(3) - (3)].integer))) {return (1);};}
    break;

  case 84:

/* Line 1464 of yacc.c  */
#line 5860 "fm_sp_assembler.y"
    {if (!_fmsp_load_lcv_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (3)].integer))) {return (1);};}
    break;

  case 85:

/* Line 1464 of yacc.c  */
#line 5864 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_set_lcv_bits_action);}
    break;

  case 86:

/* Line 1464 of yacc.c  */
#line 5868 "fm_sp_assembler.y"
    {(yyval.integer) = 0;;}
    break;

  case 87:

/* Line 1464 of yacc.c  */
#line 5870 "fm_sp_assembler.y"
    {(yyval.integer) = 1;;}
    break;

  case 88:

/* Line 1464 of yacc.c  */
#line 5874 "fm_sp_assembler.y"
    {if (!_fmsp_result_array_range_action(_fmsp_assembler_context_p, (yyvsp[(2) - (5)].integer), (yyvsp[(4) - (5)].integer), false)) {return (1);};}
    break;

  case 89:

/* Line 1464 of yacc.c  */
#line 5876 "fm_sp_assembler.y"
    {if (!_fmsp_result_array_range_action(_fmsp_assembler_context_p, (yyvsp[(2) - (3)].integer), (yyvsp[(2) - (3)].integer), false)) {return (1);};}
    break;

  case 90:

/* Line 1464 of yacc.c  */
#line 5880 "fm_sp_assembler.y"
    {(yyval.string) = (yyvsp[(1) - (1)].string);;}
    break;

  case 91:

/* Line 1464 of yacc.c  */
#line 5882 "fm_sp_assembler.y"
    {(yyval.string) = (yyvsp[(1) - (1)].string);;}
    break;

  case 92:

/* Line 1464 of yacc.c  */
#line 5886 "fm_sp_assembler.y"
    {if (!_fmsp_load_bytes_ra_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (3)].integer), true)) {return (1);};}
    break;

  case 93:

/* Line 1464 of yacc.c  */
#line 5888 "fm_sp_assembler.y"
    {if (!_fmsp_load_bytes_ra_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (3)].integer), false)) {return (1);};}
    break;

  case 94:

/* Line 1464 of yacc.c  */
#line 5892 "fm_sp_assembler.y"
    {if (!_fmsp_store_wr_to_ra_action(_fmsp_assembler_context_p, (yyvsp[(3) - (3)].integer))) {return (1);};}
    break;

  case 95:

/* Line 1464 of yacc.c  */
#line 5896 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P1(_fmsp_store_iv_to_ra_action, (yyvsp[(3) - (3)].string));}
    break;

  case 96:

/* Line 1464 of yacc.c  */
#line 5900 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P1(_fmsp_load_sv_to_wo_action, (yyvsp[(3) - (3)].string));}
    break;

  case 97:

/* Line 1464 of yacc.c  */
#line 5904 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P1(_fmsp_add_sv_to_wo_action, (yyvsp[(3) - (3)].string));}
    break;

  case 98:

/* Line 1464 of yacc.c  */
#line 5908 "fm_sp_assembler.y"
    {if (!_fmsp_modify_wo_by_wr_action(_fmsp_assembler_context_p, false, (yyvsp[(3) - (3)].integer))) {return (1);};}
    break;

  case 99:

/* Line 1464 of yacc.c  */
#line 5910 "fm_sp_assembler.y"
    {if (!_fmsp_modify_wo_by_wr_action(_fmsp_assembler_context_p, true, (yyvsp[(3) - (3)].integer))) {return (1);};}
    break;

  case 100:

/* Line 1464 of yacc.c  */
#line 5914 "fm_sp_assembler.y"
    {if (!_fmsp_zero_wr_action(_fmsp_assembler_context_p, (yyvsp[(2) - (2)].integer))) {return (1);};}
    break;

  case 101:

/* Line 1464 of yacc.c  */
#line 5918 "fm_sp_assembler.y"
    {_FMSP_PROC_TOK_P0(_fmsp_ones_comp_wr1_to_wr0_action);}
    break;

  case 102:

/* Line 1464 of yacc.c  */
#line 5922 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_AND;;}
    break;

  case 103:

/* Line 1464 of yacc.c  */
#line 5924 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_AND;;}
    break;

  case 104:

/* Line 1464 of yacc.c  */
#line 5926 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_OR;;}
    break;

  case 105:

/* Line 1464 of yacc.c  */
#line 5928 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_OR;;}
    break;

  case 106:

/* Line 1464 of yacc.c  */
#line 5930 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_XOR;;}
    break;

  case 107:

/* Line 1464 of yacc.c  */
#line 5934 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_EQUAL;;}
    break;

  case 108:

/* Line 1464 of yacc.c  */
#line 5936 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_NOT_EQUAL;;}
    break;

  case 109:

/* Line 1464 of yacc.c  */
#line 5938 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_LESS_THAN;;}
    break;

  case 110:

/* Line 1464 of yacc.c  */
#line 5940 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_GREATER_THAN;;}
    break;

  case 111:

/* Line 1464 of yacc.c  */
#line 5942 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_LESS_THAN_EQUAL;;}
    break;

  case 112:

/* Line 1464 of yacc.c  */
#line 5944 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_GREATER_THAN_EQUAL;;}
    break;

  case 113:

/* Line 1464 of yacc.c  */
#line 5947 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_EQUAL;;}
    break;

  case 114:

/* Line 1464 of yacc.c  */
#line 5949 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_NOT_EQUAL;;}
    break;

  case 115:

/* Line 1464 of yacc.c  */
#line 5951 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_LESS_THAN;;}
    break;

  case 116:

/* Line 1464 of yacc.c  */
#line 5953 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_GREATER_THAN;;}
    break;

  case 117:

/* Line 1464 of yacc.c  */
#line 5956 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_PLUS;;}
    break;

  case 118:

/* Line 1464 of yacc.c  */
#line 5958 "fm_sp_assembler.y"
    {(yyval.integer) = _FMSP_OPERATOR_MINUS;;}
    break;

  case 119:

/* Line 1464 of yacc.c  */
#line 5961 "fm_sp_assembler.y"
    {if (!_fmsp_bitwise_wr_wr_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), (yyvsp[(4) - (5)].integer))) {return (1);};}
    break;

  case 120:

/* Line 1464 of yacc.c  */
#line 5965 "fm_sp_assembler.y"
    {if (!_fmsp_bitwise_wr_iv_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), (yyvsp[(3) - (5)].integer), (yyvsp[(4) - (5)].integer), (yyvsp[(5) - (5)].string))) {return (1);} free (yyvsp[(5) - (5)].string);;}
    break;

  case 121:

/* Line 1464 of yacc.c  */
#line 5969 "fm_sp_assembler.y"
    {if (!_fmsp_addsub_wr_wr_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), 0, (yyvsp[(4) - (5)].integer))) {return (1);};}
    break;

  case 122:

/* Line 1464 of yacc.c  */
#line 5971 "fm_sp_assembler.y"
    {if (!_fmsp_addsub_wr_wr_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), 1, (yyvsp[(4) - (5)].integer))) {return (1);};}
    break;

  case 123:

/* Line 1464 of yacc.c  */
#line 5975 "fm_sp_assembler.y"
    {if (!_fmsp_addsub_wr_iv_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), 0, (yyvsp[(4) - (5)].integer), (yyvsp[(5) - (5)].string))) {return (1);};}
    break;

  case 124:

/* Line 1464 of yacc.c  */
#line 5977 "fm_sp_assembler.y"
    {if (!_fmsp_addsub_wr_iv_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), 1, (yyvsp[(4) - (5)].integer), (yyvsp[(5) - (5)].string))) {return (1);};}
    break;

  case 125:

/* Line 1464 of yacc.c  */
#line 5981 "fm_sp_assembler.y"
    {if (!_fmsp_bitwise_shift_left_wr_by_sv_action(_fmsp_assembler_context_p, (yyvsp[(1) - (3)].integer), (yyvsp[(3) - (3)].string))) {return (1);} free (yyvsp[(3) - (3)].string);;}
    break;

  case 126:

/* Line 1464 of yacc.c  */
#line 5985 "fm_sp_assembler.y"
    {if (!_fmsp_bitwise_shift_right_wr_by_sv_action(_fmsp_assembler_context_p, (yyvsp[(1) - (3)].integer), (yyvsp[(3) - (3)].string))) {return (1);} free (yyvsp[(3) - (3)].string);;}
    break;

  case 127:

/* Line 1464 of yacc.c  */
#line 5989 "fm_sp_assembler.y"
    {if (!_fmsp_load_bits_iv_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), (yyvsp[(3) - (5)].string), (yyvsp[(5) - (5)].integer), true)) {return (1);} free (yyvsp[(3) - (5)].string);;}
    break;

  case 128:

/* Line 1464 of yacc.c  */
#line 5991 "fm_sp_assembler.y"
    {if (!_fmsp_load_bits_iv_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (3)].integer), (yyvsp[(3) - (3)].string), 0, true)) {return (1);} free (yyvsp[(3) - (3)].string);;}
    break;

  case 129:

/* Line 1464 of yacc.c  */
#line 5993 "fm_sp_assembler.y"
    {if (!_fmsp_load_bits_iv_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), (yyvsp[(3) - (5)].string), (yyvsp[(5) - (5)].integer), false)) {return (1);} free (yyvsp[(3) - (5)].string);;}
    break;

  case 130:

/* Line 1464 of yacc.c  */
#line 5995 "fm_sp_assembler.y"
    {if (!_fmsp_load_bits_iv_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (3)].integer), (yyvsp[(3) - (3)].string), 0, false)) {return (1);} free (yyvsp[(3) - (3)].string);;}
    break;

  case 131:

/* Line 1464 of yacc.c  */
#line 5999 "fm_sp_assembler.y"
    {if (!_fmsp_load_bytes_pa_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (7)].integer), (yyvsp[(4) - (7)].integer), (yyvsp[(6) - (7)].integer), true)) {return (1);};}
    break;

  case 132:

/* Line 1464 of yacc.c  */
#line 6001 "fm_sp_assembler.y"
    {if (!_fmsp_load_bytes_pa_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), (yyvsp[(4) - (5)].integer), (yyvsp[(4) - (5)].integer), true)) {return (1);};}
    break;

  case 133:

/* Line 1464 of yacc.c  */
#line 6003 "fm_sp_assembler.y"
    {if (!_fmsp_load_bytes_pa_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (7)].integer), (yyvsp[(4) - (7)].integer), (yyvsp[(6) - (7)].integer), false)) {return (1);};}
    break;

  case 134:

/* Line 1464 of yacc.c  */
#line 6005 "fm_sp_assembler.y"
    {if (!_fmsp_load_bytes_pa_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (5)].integer), (yyvsp[(4) - (5)].integer), (yyvsp[(4) - (5)].integer), false)) {return (1);};}
    break;

  case 135:

/* Line 1464 of yacc.c  */
#line 6009 "fm_sp_assembler.y"
    {if (!_fmsp_load_bits_fw_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (7)].integer), (yyvsp[(4) - (7)].integer), (yyvsp[(6) - (7)].integer), true)) {return (1);};}
    break;

  case 136:

/* Line 1464 of yacc.c  */
#line 6011 "fm_sp_assembler.y"
    {if (!_fmsp_load_bits_fw_to_wr_action(_fmsp_assembler_context_p, (yyvsp[(1) - (7)].integer), (yyvsp[(4) - (7)].integer), (yyvsp[(6) - (7)].integer), false)) {return (1);};}
    break;



/* Line 1464 of yacc.c  */
#line 7905 "fm_sp_assembler.tab.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (_fmsp_assembler_context_p, YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (_fmsp_assembler_context_p, yymsg);
	  }
	else
	  {
	    yyerror (_fmsp_assembler_context_p, YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, _fmsp_assembler_context_p);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp, _fmsp_assembler_context_p);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined(yyoverflow) || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (_fmsp_assembler_context_p, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, _fmsp_assembler_context_p);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, _fmsp_assembler_context_p);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}



