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
 * File Name : FMCUtils.cpp
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#include "FMCUtils.h"

std::string stripBlanks( std::string str )
{
    std::string res = "";
    int len = str.length();
    int i;
    // Skip leading blanks
    for( i = 0; ( i < len ) && ( str[i] == ' ' ); ++i );
    // Copy the rest. Stop at the first blank
    for( ; ( i < len ) && ( str[i] != ' ' ); ++i ) res += str[i];

    return res;
}

bool innerBlanks( std::string str )
{
    std::string res = "";
    int len = str.length();
    int i;
    // Skip leading blanks
    for( i = 0; ( i < len ) && ( str[i] == ' ' ); ++i );
    // Stop at the first blank
    for( ; ( i < len ) && ( str[i] != ' ' ); ++i );
    // Skip ending blanks
    for( ; ( i < len ) && ( str[i] == ' ' ); ++i );
    if (i!=len)
        return 1;
    else
        return 0;
}


std::string stripDollar( std::string str )
{
    std::string res = "";
    int len = str.length();
    int i;
    if (str[0] != '$')
        return str;
    else
        for(i=1; i < len; i++ )
            res += str[i];

    return res;
}

bool insensitiveCompare (std::string str1, std::string str2)
{
    uint32_t i;
    char temp1, temp2;
    if (str1.length()!=str2.length())
        return 0;
    for (i = 0; i < str1.length(); i++)
    {
        temp1 = toupper(str1[i]);
        temp2 = toupper(str2[i]);
        if (temp1 != temp2)
            return 0;
    }
    return 1;
}

/*convert a string to an integer and check that it's not longer than 8 bytes*/
bool stringToInt (const std::string &str, uint64_t &n, int line)
{
    int firstOne=0, initZero=0;
    double doub = 0;

    /*Boolean*/
    if ( str.substr( 0, 2 ) == "0b" )
    {
        uint64_t mul = 1;
        n = 0;
        for (unsigned int i = str.length()-1; i>1; i--, mul=mul*2)
        {
            if (str[i] == '1')
            {
                n += mul;
                initZero=0;
            }
            else if (str[i] == '0')
                initZero++;
            else
                return 0;
        }
        if (str.length()-initZero > 66)
            throw CGenericErrorLine(ERR_INTEGER_RANGE, line, str);

        return 1;
    }
    else
    {
        std::istringstream ss(str);
        char c;
        /*Hexadecimal*/
        if ( str.substr( 0, 2 ) == "0x" )
        {
            for (unsigned int i = 2; i< str.length(); i++)
                if (str[i] == '0')
                    initZero+=4;
                else
                    break;
            if ( (str.length()-2)*4 - initZero > 64)
                throw CGenericErrorLine(ERR_INTEGER_RANGE, line, str);
            if (! (ss >> std::hex >> n) || ss.get(c))
                return 0;
            else
                return 1;
        }
        else
        {
            /*Decimal*/
            for (unsigned int i = 2; i< str.length(); i++)
                if (str[i] == '0')
                    initZero+=0;
                else
                    break;
            if (str.length()-initZero > 12)
                throw CGenericErrorLine(ERR_INTEGER_RANGE, line, str);

            if (! (ss >> doub) || ss.get(c))
                return 0;
            if (doub > 0xffffffff)
                throw CGenericErrorLine(ERR_INTEGER_RANGE, line, str);
            n = (uint64_t)doub;
            return 1;
        }
    }
}

/*Receive a string with a hex value and convert to a string with a dec value*/
std::string hexToDecString (std::string &str)
{
    uint64_t v;
    std::istringstream iss(str);
    iss >> std::setbase(0) >> v;
    return intToString(v);
}

std::string intToString (uint64_t num)
{
    std::stringstream returnString;
    returnString << num;
    return returnString.str();
}

/*Workaround for error when include iostream and calling the tolower func*/
char mytolower(char c)
{
    return tolower(static_cast<unsigned char>(c));
}
