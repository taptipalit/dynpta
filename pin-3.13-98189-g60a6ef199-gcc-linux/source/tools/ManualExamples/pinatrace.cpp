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
#include <map>
#include <string>


FILE * trace;

std::map<ADDRINT, int> taintMap;
std::map<ADDRINT, const char*> lookupCallerMap;

unsigned long mem_read_count = 0;
unsigned long mem_write_count = 0;
unsigned long aes_enc_count = 0;
unsigned long aes_dec_count = 0;
unsigned long taint_set_count = 0;
unsigned long taint_lookup_count = 0;
unsigned long writeback_count = 0;
unsigned long fn_call_count = 0;

unsigned long encrypt_cache_count = 0;
unsigned long decrypt_cache_count = 0;
unsigned long encrypt_external_count = 0;
unsigned long decrypt_external_count = 0;

unsigned long inst_count = 0;

ADDRINT taintLookupFnAddr = 0;
ADDRINT taintSetFnAddr = 0;
ADDRINT writebackFnAddr = 0;
ADDRINT encryptCacheFnAddr = 0;
ADDRINT decryptCacheFnAddr = 0;
ADDRINT encryptExternalFnAddr = 0;
ADDRINT decryptExternalFnAddr = 0;
ADDRINT mainFnAddr = 0;

ADDRINT setEncryptedValueByteFnAddr = 0;
ADDRINT setEncryptedValueWordFnAddr = 0;
ADDRINT setEncryptedValueDWordFnAddr = 0;
ADDRINT setEncryptedValueQWordFnAddr = 0;

ADDRINT getDecryptedValueByteFnAddr = 0;
ADDRINT getDecryptedValueWordFnAddr = 0;
ADDRINT getDecryptedValueDWordFnAddr = 0;
ADDRINT getDecryptedValueQWordFnAddr = 0;

VOID ClearCounters(VOID *ip, VOID * addr) {
    mem_read_count = 0;
    mem_write_count = 0;
    aes_enc_count = 0;
    aes_dec_count = 0;
    taint_set_count = 0;
    taint_lookup_count = 0;
    writeback_count = 0;
    fn_call_count = 0;

    encrypt_cache_count = 0;
    decrypt_cache_count = 0;
    encrypt_external_count = 0;
    decrypt_external_count = 0;

    inst_count = 0;
}

VOID RecordInst(VOID *ip, VOID * addr) {
    inst_count ++;
    /*
    if (inst_count %1000 == 0) {
        fprintf(trace, "inst_count: %lu\n", inst_count);
    }
    */
}

VOID RecordDecryptExternCall(VOID *ip, VOID * addr) {
    decrypt_external_count++;
    /*
    if (decrypt_external_count % 10 == 0) {
        fprintf(trace, "decrypt_external: %lu\n", decrypt_external_count);
    }
    */
}

VOID RecordEncryptExternCall(VOID *ip, VOID * addr) {
    encrypt_external_count++;
    /*
    if (encrypt_external_count % 10 == 0) {
        fprintf(trace, "encrypt_external: %lu\n", encrypt_external_count);
    }
    */
}

VOID RecordEncryptCacheCall(VOID *ip, VOID * addr) {
    /*
    encrypt_cache_count++;
    if (encrypt_cache_count % 10 == 0) {
        fprintf(trace, "encrypt_cache: %lu\n", encrypt_cache_count);
    }
    */
}

VOID RecordDecryptCacheCall(VOID *ip, VOID * addr) {
    /*
    decrypt_cache_count++;
    if (decrypt_cache_count % 10 == 0) {
        fprintf(trace, "decrypt_cache: %lu\n", decrypt_cache_count);
    }
    */
}

VOID RecordCacheDecryptCall(VOID *ip, VOID *addr) {
    decrypt_cache_count++;
    /*
    if (decrypt_cache_count % 10 == 0) {
        fprintf(trace, "getDecXXXX: %lu\n", decrypt_cache_count);
    }
    */
}

VOID RecordCacheEncryptCall(VOID* ip, VOID *addr) {
    encrypt_cache_count++;
    /*
    if (encrypt_cache_count % 10 == 0) {
        fprintf(trace, "setEncXXXX: %lu\n", encrypt_cache_count);
    }
    */
}

VOID RecordWritebackCall(VOID *ip, VOID * addr) {
    writeback_count++;
    /*
    if (writeback_count % 100 == 0) {
        fprintf(trace, "writeback: %lu\n", writeback_count);
    }
    */
}

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{
    //fprintf(trace, "mem read address: %p\n", addr);
    if (addr > (void*)0x7f000000000) {
        mem_read_count++;
    } else {
        taint_lookup_count++;
    }
    /*
    if (mem_read_count % 100 == 0) {
        fprintf(trace, "mem read: %lu\n", mem_read_count);
    }
    */
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{
    mem_write_count++;
    /*
    if (mem_write_count % 100 == 0) {
        fprintf(trace, "mem write: %lu\n", mem_write_count);
    }
    */
}

VOID RecordAesEnc(VOID * ip) {
    aes_enc_count++;
    /*
    if (aes_enc_count % 100 == 0) {
        fprintf(trace, "aes encryptions: %lu\n", aes_enc_count); 
    }
    */
}

VOID RecordAesDec(VOID * ip) {
    aes_dec_count++;
    /*
    if (aes_dec_count % 100 == 0) {
        fprintf(trace, "aes decryptions: %lu\n", aes_dec_count); 
    }
    */
}

VOID RecordTaintLookupCall(VOID * ip) {
    taint_lookup_count++;
    /*
    if (taint_lookup_count % 1000 == 0) {
        fprintf(trace, "taint lookups: %lu\n", taint_lookup_count); 
    }
    */
}

VOID RecordTaintSetCall(VOID * ip) {
    taint_set_count++;
    /*
    if (taint_set_count % 1000 == 0) {
        fprintf(trace, "taint sets: %lu\n", taint_set_count); 
    }
    */
}

VOID buildTaintLookupProfile(VOID * ip) {
    taintMap[(ADDRINT)ip]++;
}

VOID RecordFnCall(VOID * ip) {
    fn_call_count++;
    /*
    if (fn_call_count % 10 == 0) {
        fprintf(trace, "fn calls: %lu\n", fn_call_count); 
    }
    */
}

VOID Image(IMG img, VOID *v)
{
    fprintf(trace, "img type: %d\n", IMG_Type(img));

    RTN mainFn = RTN_FindByName(img, "main");
    // Instrument the malloc() and free() functions.  Print the input argument
    // of each malloc() or free(), and the return value of malloc().
    //
    //  Find the malloc() function.
    RTN taintLookupFn = RTN_FindByName(img, "dfsan_read_label");
    RTN taintSetFn = RTN_FindByName(img, "dfsan_set_label");
    RTN writebackFn = RTN_FindByName(img, "writeback_cache"); 
    RTN encryptCacheFn = RTN_FindByName(img, "encrypt_cache");
    RTN decryptCacheFn = RTN_FindByName(img, "decrypt_cache");
    RTN encryptExternalFn = RTN_FindByName(img, "encryptArrayForLibCall");
    RTN decryptExternalFn = RTN_FindByName(img, "decryptArrayForLibCall");

    // The get/set cache routines
    RTN setEncryptedValueByteFn = RTN_FindByName(img, "setEncryptedValueByte");
    RTN setEncryptedValueWordFn = RTN_FindByName(img, "setEncryptedValueWord");
    RTN setEncryptedValueDWordFn = RTN_FindByName(img, "setEncryptedValueDWord");
    RTN setEncryptedValueQWordFn = RTN_FindByName(img, "setEncryptedValueQWord");

    RTN getDecryptedValueByteFn = RTN_FindByName(img, "getDecryptedValueByte");
    RTN getDecryptedValueWordFn = RTN_FindByName(img, "getDecryptedValueWord");
    RTN getDecryptedValueDWordFn = RTN_FindByName(img, "getDecryptedValueDWord");
    RTN getDecryptedValueQWordFn = RTN_FindByName(img, "getDecryptedValueQWord");

    if (RTN_Valid(mainFn)) {
        mainFnAddr = RTN_Address(mainFn);
    }
    if (RTN_Valid(taintLookupFn)) {
        taintLookupFnAddr = RTN_Address(taintLookupFn);
    }
    if (RTN_Valid(taintSetFn)) {
        taintSetFnAddr = RTN_Address(taintSetFn);
    }
    if (RTN_Valid(writebackFn)) {
        writebackFnAddr = RTN_Address(writebackFn);
    }
    if (RTN_Valid(encryptCacheFn)) {
        fprintf(trace, "Found encrypt_cache fn\n");
        encryptCacheFnAddr = RTN_Address(encryptCacheFn);
        fprintf(trace, "Address: %lx\n", encryptCacheFnAddr);
    }
    if (RTN_Valid(decryptCacheFn)) {
        fprintf(trace, "Found decrypt_cache fn\n");
        decryptCacheFnAddr = RTN_Address(decryptCacheFn);
        fprintf(trace, "Address: %lx\n", decryptCacheFnAddr);

    }
    if (RTN_Valid(encryptExternalFn)) {
        fprintf(trace, "Found decryptArray fn\n");
        encryptExternalFnAddr = RTN_Address(encryptExternalFn);
        fprintf(trace, "Address: %lx\n", encryptExternalFnAddr);
    }
    if (RTN_Valid(decryptExternalFn)) {
        fprintf(trace, "Found encryptArray fn\n");
        decryptExternalFnAddr = RTN_Address(decryptExternalFn);
    }

    if (RTN_Valid(setEncryptedValueByteFn)) {
        fprintf(trace, "Found setEncryptedValueByte fn\n");
        setEncryptedValueByteFnAddr = RTN_Address(setEncryptedValueByteFn);
    }
    if (RTN_Valid(setEncryptedValueWordFn)) {
        fprintf(trace, "Found setEncryptedValueWord fn\n");
        setEncryptedValueWordFnAddr = RTN_Address(setEncryptedValueWordFn);
    }
    if (RTN_Valid(setEncryptedValueDWordFn)) {
        fprintf(trace, "Found setEncryptedValueDWord fn\n");
        setEncryptedValueDWordFnAddr = RTN_Address(setEncryptedValueDWordFn);
    }
    if (RTN_Valid(setEncryptedValueQWordFn)) {
        fprintf(trace, "Found setEncryptedValueQword fn\n");
        setEncryptedValueQWordFnAddr = RTN_Address(setEncryptedValueQWordFn);
    }

    if (RTN_Valid(getDecryptedValueByteFn)) {
        fprintf(trace, "Found getDecryptedValueByte fn\n");
        getDecryptedValueByteFnAddr = RTN_Address(getDecryptedValueByteFn);
    }
    if (RTN_Valid(getDecryptedValueWordFn)) {
        fprintf(trace, "Found getDecryptedValueWord fn\n");
        getDecryptedValueWordFnAddr = RTN_Address(getDecryptedValueWordFn);
    }
    if (RTN_Valid(getDecryptedValueDWordFn)) {
        fprintf(trace, "Found getDecryptedValueDWord fn\n");
        getDecryptedValueDWordFnAddr = RTN_Address(getDecryptedValueDWordFn);
    }
    if (RTN_Valid(getDecryptedValueQWordFn)) {
        fprintf(trace, "Found getDecryptedValueQword fn\n");
        getDecryptedValueQWordFnAddr = RTN_Address(getDecryptedValueQWordFn);
    }
}
 
VOID InstrumentDfsanReadLabel(INS ins, VOID *v) {
    if (INS_IsDirectCall(ins)) {
        ADDRINT targetCallAddr = INS_DirectControlFlowTargetAddress(ins);
        RTN caller = INS_Rtn(ins);
        // What's the symbol at this address?
        if (taintLookupFnAddr == targetCallAddr) {
            char * funcName = (char*)malloc(strlen(RTN_Name(caller).c_str()));
            strcpy(funcName, RTN_Name(caller).c_str());
            lookupCallerMap[INS_Address(ins)] = funcName;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)buildTaintLookupProfile, IARG_INST_PTR, IARG_END);
        }
    }
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

    if (mainFnAddr == INS_Address(ins)) {
        // Then clear everything
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ClearCounters, IARG_INST_PTR, IARG_END);
    }
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInst, IARG_INST_PTR, IARG_END);

    // Insert tracking for the aes encryption / decryption routines
    if (XED_ICLASS_AESDEC == INS_Opcode(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordAesDec, IARG_INST_PTR, IARG_END);
    } else if (XED_ICLASS_AESENC == INS_Opcode(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordAesEnc, IARG_INST_PTR, IARG_END);
    } else if (INS_IsDirectCall(ins)) {

        if (INS_IsDirectCall(ins)) {
            ADDRINT targetCallAddr = INS_DirectControlFlowTargetAddress(ins);
            // What's the symbol at this address?
            /*
            if (taintLookupFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordTaintLookupCall, IARG_INST_PTR, IARG_END);
            }
            if (taintSetFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordTaintSetCall, IARG_INST_PTR, IARG_END);
            }
            */
            if (writebackFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWritebackCall, IARG_INST_PTR, IARG_END);
            }
            if (encryptCacheFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordEncryptCacheCall, IARG_INST_PTR, IARG_END);
            }
            if (decryptCacheFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDecryptCacheCall, IARG_INST_PTR, IARG_END);
            }
            if (encryptExternalFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordEncryptExternCall, IARG_INST_PTR, IARG_END);
            }
            if (decryptExternalFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDecryptExternCall, IARG_INST_PTR, IARG_END);
            }
            if (getDecryptedValueByteFnAddr == targetCallAddr || getDecryptedValueWordFnAddr == targetCallAddr || getDecryptedValueDWordFnAddr == targetCallAddr || getDecryptedValueQWordFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordCacheDecryptCall, IARG_INST_PTR, IARG_END);
            }
            if (setEncryptedValueByteFnAddr == targetCallAddr || setEncryptedValueWordFnAddr == targetCallAddr || setEncryptedValueDWordFnAddr == targetCallAddr || setEncryptedValueQWordFnAddr == targetCallAddr) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordCacheEncryptCall, IARG_INST_PTR, IARG_END);
            }
        }
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordFnCall, IARG_INST_PTR, IARG_END);
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
    /*
    for (auto const& x: lookupCallerMap) {
        fprintf(trace, "%lx: %s\n", x.first, x.second);
    }
    */
    /*
    for (auto const& x : taintMap) {
        fprintf(trace, "----> %lx: %s: %d\n", x.first, lookupCallerMap[x.first], x.second);
    }
    */

    fprintf(trace, "inst_count: %lu\n", inst_count);
    fprintf(trace, "decrypt_external: %lu\n", decrypt_external_count);
    fprintf(trace, "encrypt_external: %lu\n", encrypt_external_count);
    //fprintf(trace, "encrypt_cache: %lu\n", encrypt_cache_count);
    //fprintf(trace, "decrypt_cache: %lu\n", decrypt_cache_count);
    fprintf(trace, "setEncXXXX: %lu\n", encrypt_cache_count);
    fprintf(trace, "getDecXXXX: %lu\n", decrypt_cache_count);
    fprintf(trace, "writeback: %lu\n", writeback_count);
    fprintf(trace, "mem read: %lu\n", mem_read_count);
    fprintf(trace, "mem write: %lu\n", mem_write_count);
    fprintf(trace, "aes encryptions: %lu\n", aes_enc_count); 
    fprintf(trace, "aes decryptions: %lu\n", aes_dec_count); 
    fprintf(trace, "taint lookups: %lu\n", taint_lookup_count); 
    fprintf(trace, "taint sets: %lu\n", taint_set_count); 
    fprintf(trace, "fn calls: %lu\n", fn_call_count); 
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
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

    trace = fopen("pinatrace.out", "w");

    IMG_AddInstrumentFunction(Image, 0);

    INS_AddInstrumentFunction(Instruction, 0);
    INS_AddInstrumentFunction(InstrumentDfsanReadLabel, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
