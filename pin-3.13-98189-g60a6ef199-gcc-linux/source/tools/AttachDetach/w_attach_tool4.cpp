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

#include "pin.H"
#include <iostream>

namespace WIND
{
#include <windows.h>
}
using std::endl;
using std::cout;
using std::string;
using std::cerr;
using std::flush;
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

/* ===================================================================== */
/* Global variables and declarations */
/* ===================================================================== */
typedef int (__cdecl * DO_LOOP_TYPE)();

static volatile int doLoopPred = 1;

/* ===================================================================== */

int rep_DoLoop()
{
    PIN_LockClient();
        
    volatile int localPred =  doLoopPred;
    
    PIN_UnlockClient(); 
    
    return localPred;
}


/* ===================================================================== */

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_LockClient();
    static volatile INT32 threadCreated = 0;
    threadCreated++;
    if(threadCreated == 7)
    {
        //eventhough this is not an error - print to cerr (in order to see it on the screen)
        std::cerr << "success - exiting from application!" << endl;
        doLoopPred = 0;
    }   
    PIN_UnlockClient();
}

/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v)
{
    cout << IMG_Name(img) << endl;    
    
    if ( ! IMG_IsMainExecutable(img) )
    {
        return;
    }
    const string sFuncName("DoLoop");
    
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
    { 
        string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
        if (undFuncName == sFuncName)
        {
            RTN rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
            if (RTN_Valid(rtn))
            {
                //eventhough this is not an error - print to cerr (in order to see it on the screen)
                cerr << "Replacing DoLoop() in " << IMG_Name(img) << endl;

                RTN_Replace(rtn, AFUNPTR(rep_DoLoop));
            }           
        }      
    }
}


int main(INT32 argc, CHAR **argv)
{
    PIN_InitSymbols();

    PIN_Init(argc, argv);

    IMG_AddInstrumentFunction(ImageLoad, 0);

    PIN_AddThreadStartFunction(ThreadStart, 0);

    std::cerr << "Application is starting" << endl << flush;
 
    // Never returns
    PIN_StartProgram();

    return 0;
}
