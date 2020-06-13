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

/*!
 *  Starting from Linux kernel XYZ, vsyscall area is execute only (XO). Therefore PIN cannot fetch and/or instrument it.
 *  Pin needs to ran it "natively" from VM. Currently implemented under -run_vsyscall_natively knob.
 *  The tool checks that vsyscall area is not instrumented when when the knob is on.
 *  Once we know the kernel version number, we can get rid of the knob and check that vsyscall area is not instrumented only
 *  when the current kernel version is higher than the kernel version mentioned before.
 */

#include <iostream>
#include <fstream>
#include <linux/unistd.h>
#include "pin.H"
using std::ofstream;
using std::cerr;
using std::string;
using std::endl;


// Global variables

// A knob for defining the file with list of loaded images
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "vsyscall_area_tool.log", "log file for the tool");

ofstream outFile; // The tool's output file for printing the loaded images.
BOOL vsyscallAreaUsed = false; // True if vsyscall area is being fetched and instrumented

/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */


// This function is called before every instruction is executed
VOID InsAnalysis(ADDRINT iaddr, ADDRINT target, BOOL taken)
{
    if ((target >= 0xffffffffff600000) && (target < 0xffffffffff601000))
    {
        outFile << std::hex << "instruction  in address = 0x" << iaddr << " branch to vsyscall area at address = 0x" <<
                target << ", taken = " << taken << endl;
    }
}


// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    ADDRINT insAddress = INS_Address(ins);

    if (INS_IsControlFlow(ins))
    {
        // record taken branch targets
        INS_InsertCall(
            ins, IPOINT_BEFORE, AFUNPTR(InsAnalysis),
            IARG_INST_PTR,
            IARG_BRANCH_TARGET_ADDR,
            IARG_BRANCH_TAKEN,
            IARG_END);
    }

    if ((insAddress >= 0xffffffffff600000) && (insAddress < 0xffffffffff601000))
    {
        outFile << "Reached ins of vsyscall area, adderss = 0x" << std::hex << insAddress<< endl;
        vsyscallAreaUsed = true;
    }
}

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */




static VOID Fini(INT32 code, VOID *v)
{
    // Starting from Linux kernel XYZ, vsyscall area is execute only (XO). Therefore PIN cannot fetch and/or instrument it.
    // on Linux distributions greater than  kernel XYZ, if Pin doesn't handle correctly indirect branches to vsyscall area
    // it will crash before getting to this assert. So this assert should never occur on these distributions.
    // On distributions with older kernels this assert will fail, however since currently we run this test with
    // -run_vsyscall_natively, it's safe to use it.
    ASSERT(vsyscallAreaUsed==false, "Starting from Linux kernel XYZ, vsyscall area is execute only (XO). Therefore PIN cannot "
            "fetch and/or instrument it.\n");
    outFile.close();
}


int main( INT32 argc, CHAR *argv[] )
{
    // Initialization.
    PIN_InitSymbols();
    PIN_Init(argc, argv);

    // Open the tool's output file for printing the loaded images.
    outFile.open(KnobOutputFile.Value().c_str());
    if(!outFile.is_open() || outFile.fail())
    {
        cerr << "TOOL ERROR: Unable to open the output file." << endl;
        PIN_ExitProcess(1);
    }

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program.
    PIN_StartProgram(); // never returns

    return 1; // return error value
}
