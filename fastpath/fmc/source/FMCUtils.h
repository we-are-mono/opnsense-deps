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
 * File Name : FMCUtils.h
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#ifndef FMCUTILS_H
#define FMCUTILS_H

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <utility>
#ifdef WIN32
#include <stdint.h>
#else
#include "types_linux.h"
#endif
#include "FMCGenericError.h"

// Public functions
std::string stripBlanks( std::string str );
std::string stripDollar( std::string str );
bool innerBlanks( std::string str );
bool insensitiveCompare (std::string str1, std::string str2);
bool stringToInt  (const std::string &str, uint64_t &n, int line=NO_LINE);
std::string intToString (uint64_t num);
std::string hexToDecString (std::string &str);
char mytolower(char c);


// A helper functor for XML names comparison
struct MyXMLCharComparator
{
   bool operator()(const xmlChar * A, const xmlChar * B) const
   {
       return (std::string((char*)A) < std::string((char*)B));
   }
} ;


// Class definitions
template <typename T> class IntBits
{
  public:
    IntBits()                          { val = 0; };
    IntBits( const T value )           { val = value; };
    IntBits( const IntBits& ib )       { val = ib.val; };
    IntBits operator=( const T value ) { val = value; return *this; };

    uint32_t size() const          { return ( 8 * sizeof( T ) ); };

    uint32_t count1s() const
    {
        uint32_t      count = 0;
        T            mask  = 1;

        for ( unsigned int i = 0; i < 8*sizeof( T ); ++i, mask <<= 1 ) {
            if ( val & mask ) {
                ++count;
            }
        }

        return count;
    };

    uint32_t count0s() const
    {
        return ( size() - count1s() );
    };

    typedef std::vector< std::pair< uint32_t, uint32_t > > Masks;

    Masks getMasks() const
    {
        uint32_t begin;
        bool         started = false;
        T            mask    = 1;
        std::vector< std::pair< uint32_t, uint32_t > > result;

        for ( unsigned int i = 0; i < 8*sizeof( T ); ++i ) {
            if ( val & mask ) {
                if ( !started ) {
                    started = true;
                    begin   = i;
                }
            }
            else {
                if ( started ) {
                    started = false;
                    result.push_back( std::pair< uint32_t, uint32_t >
                                      ( begin, i - 1 ) );
                }
            }
            mask = mask << 1;
        }

        if ( started ) {
            result.push_back( std::pair< uint32_t, uint32_t >
                              ( begin, 8*sizeof( T ) - 1 ) );
        }

        return result;
    };

    uint32_t getFirstSet()
    {
        T mask = 1;

        uint32_t i;
        for ( i = 0; i < 8*sizeof( T ); ++i ) {
            if ( val & mask ) {
                break;
            }
            mask = mask << 1;
        }

        return i;
    }

    static T buildMask( uint32_t begin, uint32_t end )
    {
        T result = 0;
        T mask   = 1;

        for ( unsigned int i = 0; i < 8*sizeof( T ); ++i ) {
            if ( ( begin <= i ) && ( i <= end ) ) {
                result |= mask;
            }
            mask = mask << 1;
        }

        return result;
    };

    static std::string buildMaskAsStr( uint32_t begin, uint32_t end )
    {
        std::ostringstream oss;

        oss << std::hex
            << std::setfill( '0' )
            << std::setw( 2*sizeof( T ) )
            << std::uppercase
            << buildMask( begin, end );

        return oss.str();
    };

  private:
    T val;
};

#endif  // FMCUTILS_H
