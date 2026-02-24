/* A Bison parser, made by GNU Bison 2.4.2.  */

/* Skeleton interface for Bison's Yacc-like parsers in C
   
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

/* Line 1685 of yacc.c  */
#line 5549 "fm_sp_assembler.y"

          int   integer;
          char *string;
       


/* Line 1685 of yacc.c  */
#line 126 "fm_sp_assembler.tab.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif




