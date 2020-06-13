/*
 * Copyright 2002-2019 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

/*! @file
 *  Check how many instructions use EAX when it contains 0, using xed APIs.
 *  The purpose of this test is to check INS_XedExactMapToPinReg API.
 */

#include <iostream>
#include "pin.H"
extern "C" {
#include "xed-interface.h"
}

using std::string;
using std::endl;
using std::cout;

UINT32 eaxIsZeroCount = 0;

VOID CountIfZero(INT32 eaxVal)
{
    if (!eaxVal) eaxIsZeroCount++;
}

VOID InstrumentOperand(
    INS ins,
    xed_decoded_inst_t const* const xedd,
    xed_inst_t const* const xedi,
    unsigned int operand_index)
{
    const xed_operand_t* operand = xed_inst_operand(xedi, operand_index);
    const xed_operand_enum_t operand_name = xed_operand_name(operand);

    if (xed_operand_is_register(operand_name)) {
        xed_reg_enum_t xedreg = xed_decoded_inst_get_reg(xedd, operand_name);
        xed_reg_class_enum_t reg_class =  xed_reg_class(xedreg);
        if (reg_class == XED_REG_CLASS_GPR) {
            xed_reg_enum_t fullreg = xed_get_largest_enclosing_register(xedreg);
            xed_uint32_t reg;
#if defined(TARGET_IA32)
            reg = fullreg - XED_REG_GPR64_FIRST + XED_REG_GPR32_FIRST;
#else
            reg = fullreg;
#endif
            REG pinreg  = INS_XedExactMapToPinReg(reg);
                
            if (pinreg == REG_EAX)
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CountIfZero, IARG_REG_VALUE, REG_EAX, IARG_END);
        }
     }
}

VOID Ins(INS ins, VOID* v)
{
    xed_decoded_inst_t const* const xedd = INS_XedDec(ins);
    const xed_inst_t*  xedi = xed_decoded_inst_inst(xedd);
    const unsigned int  operand_count =  xed_inst_noperands(xedi);
    for (unsigned int i=0 ; i < operand_count ; i++)
        InstrumentOperand(ins, xedd, xedi, i);
}

VOID Fini(INT32 code, VOID *v)
{
    cout << "eaxIsZeroCount = " << eaxIsZeroCount << endl;
}

int main(INT32 argc, CHAR **argv)
{
    PIN_InitSymbols();
    PIN_Init(argc, argv);
    
    INS_AddInstrumentFunction(Ins, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    // Never returns
    PIN_StartProgram();
    
    return 0;
}
