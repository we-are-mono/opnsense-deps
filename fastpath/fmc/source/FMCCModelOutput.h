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
 * File Name : FMCCModelOutput.h
 * Author    : Serge Lamikhov-Center
 *
 * ===================================================================*/

#ifndef FMCCMODELOUTPUT_H
#define FMCCMODELOUTPUT_H

#include "fmc.h"
#include "FMCPCDModel.h"

class CFMCCModelOutput
{
public:
    unsigned int current_engine;
public:
    void output( const CFMCModel& model, fmc_model_t* cmodel,
                 std::ostream& oss, size_t indent );
protected:
    void output_fmc_fman( const CFMCModel& model, fmc_model_t* cmodel,
                          unsigned int index,
                          std::ostream& oss, size_t indent );
    void output_fmc_port( const CFMCModel& model, fmc_model_t* cmodel,
                          unsigned int index,
                          std::ostream& oss, size_t indent );
    void output_fmc_scheme( const CFMCModel& model, fmc_model_t* cmodel,
                            unsigned int index,
                            std::ostream& oss, size_t indent );
    void output_fmc_ccnode( const CFMCModel& model, fmc_model_t* cmodel,
                            unsigned int index,
                            std::ostream& oss, size_t indent );
    void output_fmc_htnode( const CFMCModel& model, fmc_model_t* cmodel,
                            unsigned int index,
                            std::ostream& oss, size_t indent );
    void output_fmc_policer( const CFMCModel& model, fmc_model_t* cmodel,
                             unsigned int index,
                             std::ostream& oss, size_t indent );
#if (DPAA_VERSION >= 11)
    void output_fmc_replicator( const CFMCModel& model, fmc_model_t* cmodel,
                                unsigned int index,
                                std::ostream& oss, size_t indent );
#endif /* (DPAA_VERSION >= 11) */
    void output_fmc_applier( const CFMCModel& model, fmc_model_t* cmodel,
                             unsigned int index,
                             std::ostream& oss, size_t indent );

    fmc_apply_order_e get_fmc_type    ( ApplyOrder::Type t ) const;
    std::string       get_fmc_type_str( ApplyOrder::Type t ) const;
    std::string       get_apply_item_name( fmc_model_t* cmodel,
                                           ApplyOrder::Entry e );

    void check_bounds( unsigned int used,
                       unsigned int available,
                       std::string  entity );
};

#endif
