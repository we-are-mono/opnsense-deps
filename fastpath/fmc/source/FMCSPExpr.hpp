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
     OBJECT = 258,
     VARIABLE = 259,
     SUB_VARIABLE = 260,
     FIELD = 261,
     PROTOCOL = 262,
     PROTOCOL_FIELD = 263,
     HEADERSIZE = 264,
     DEFAULT_HEADER_SIZE = 265,
     VARIABLE_A = 266,
     SUB_VARIABLE_A = 267,
     FIELD_A = 268,
     PROTOCOL_FIELD_A = 269,
     ACCESS_ERROR = 270,
     DEC = 271,
     HEX = 272,
     BIN = 273,
     OPEN_PARENTHESIS = 274,
     CLOSE_PARENTHESIS = 275,
     OPEN_BRACKET = 276,
     CLOSE_BRACKET = 277,
     COMMA = 278,
     END = 279,
     AND = 280,
     OR = 281,
     NOTEQU = 282,
     EQU = 283,
     LESSEQU = 284,
     LESS = 285,
     GREATEREQU = 286,
     GREATER = 287,
     CONCAT = 288,
     SHL = 289,
     SHR = 290,
     BIT_OR = 291,
     XOR = 292,
     BIT_AND = 293,
     ADD_CARRY = 294,
     MINUS = 295,
     PLUS = 296,
     CHECKSUM = 297,
     BIT_NOT = 298,
     NOT = 299
   };
#endif



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 1685 of yacc.c  */
#line 42 ".\\FMCSPExpr.y"

    uint64_t	number;
    CENode	    *node;



/* Line 1685 of yacc.c  */
#line 102 "FMCSPExpr.hpp"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE FMCSPExprlval;


