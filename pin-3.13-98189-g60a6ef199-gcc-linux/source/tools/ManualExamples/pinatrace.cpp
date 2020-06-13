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

/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include "pin.H"


FILE * trace;

unsigned long mem_read_count = 0;
unsigned long mem_write_count = 0;
unsigned long aes_enc_count = 0;
unsigned long aes_dec_count = 0;

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{
    mem_read_count++;
    if (mem_read_count % 10 == 0) {
        fprintf(trace, "mem read: %lu\n", mem_read_count);
    }
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{
    mem_write_count++;
    if (mem_write_count % 10 == 0) {
        fprintf(trace, "mem write: %lu\n", mem_write_count);
    }
}

VOID RecordAesEnc(VOID * ip) {
    aes_enc_count++;
    //if (aes_enc_count % 1000 == 0) {
        fprintf(trace, "aes encryptions: %lu\n", aes_enc_count); 
    //}
}

VOID RecordAesDec(VOID * ip) {
    aes_dec_count++;
    //if (aes_dec_count % 1000 == 0) {
        fprintf(trace, "aes decryptions: %lu\n", aes_dec_count); 
    //}
}
// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Insert tracking for the aes encryption / decryption routines
    if (XED_ICLASS_AESDEC == INS_Opcode(ins)) {
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)RecordAesDec, IARG_INST_PTR, IARG_END);
    } else if (XED_ICLASS_AESENC == INS_Opcode(ins)) {
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)RecordAesEnc, IARG_INST_PTR, IARG_END);
    }
    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be 
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    PIN_ERROR( "This Pintool prints a trace of memory addresses\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    trace = fopen("pinatrace.out", "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
