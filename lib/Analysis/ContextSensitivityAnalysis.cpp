//===- ContextSensitivityAnalysisPass.cpp -- Context sensitivity analysis pass------------------------------//
//
//
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===-----------------------------------------------------------------------===//

#include "llvm/Analysis/ContextSensitivityAnalysis.h"

using namespace llvm;

char ContextSensitivityAnalysisPass::ID = 0;

/**
 * A function is a memory allocation wrapper if it allocates memory using
 * malloc / calloc, and returns the same pointer
 */
bool ContextSensitivityAnalysisPass::returnsAllocedMemory(Function* F) {
    // The function should return a pointer 
    Type* retType = F->getFunctionType()->getReturnType();
    if (!retType->isPointerTy()) {
        return false;
    }
   
    // A malloc-wrapper can have multiple malloc calls on different
    // conditional branches. Similarly multiple return instructions
    std::vector<Value*> mallockedPtrs;
    std::vector<ReturnInst*> retInsts;

    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        if (CallInst* callInst = dyn_cast<CallInst>(&*I)) {
            // Direct call
            if (Function* func = callInst->getCalledFunction()) {
                if (std::find(mallocWrappers.begin(), mallocWrappers.end(), func) != mallocWrappers.end()) {
                    // Track where this is stored
                    Value* sink = findSink(callInst);
                    if (ReturnInst* retInst = dyn_cast<ReturnInst>(sink)) {
                        // Then just mark this function as returning malloced
                        // memory
                        return true;
                    } else {
                        mallockedPtrs.push_back(sink);
                    }
                }
            } /*Indirect Call */ else if (Value* funcValue = callInst->getCalledValue()) {
                // Find if the function pointer is a global pointer to malloc
                if (LoadInst* loadedFrom = dyn_cast<LoadInst>(funcValue)) {
                    if (std::find(globalMallocWrapperPtrs.begin(), globalMallocWrapperPtrs.end(), loadedFrom->getPointerOperand()) != globalMallocWrapperPtrs.end()) {
                        Value* sink = findSink(callInst);
                        if (ReturnInst* retInst = dyn_cast<ReturnInst>(sink)) {
                            // Then this function clearly returns mallocked
                            // memory
                            return true;
                        } else {
                            mallockedPtrs.push_back(sink);
                        }
                    }
                }
            }
        } else if (ReturnInst* returnInst = dyn_cast<ReturnInst>(&*I)) {
            retInsts.push_back(returnInst);        
        }
    }

    // If we didn't malloc anything
    if (mallockedPtrs.size() == 0) {
        return false;
    }
    // For all the return insts, check that they are in the mallockedPtrs
    for (ReturnInst* retInst: retInsts) {
        if (!isReturningMallockedPtr(retInst, mallockedPtrs)) {
            return false;
        }
    }
}

bool ContextSensitivityAnalysisPass::isReturningMallockedPtr(ReturnInst* retInst, std::vector<Value*>& mallockedPtrs) {
    // Where did this return inst come from a mallocked ptr?
    Value* returnValue = retInst->getReturnValue();
    // Is this a LoadInst?
    if (LoadInst* loadInst = dyn_cast<LoadInst>(returnValue)) {
        Value* potentialMallocPtr = loadInst->getPointerOperand();
        for (Value* mallockedPtr: mallockedPtrs) {
            if (potentialMallocPtr == mallockedPtr) {
                return true;
            }
        }
    }
    return false;
}

Value* ContextSensitivityAnalysisPass::findSink(Value* mallockedPtr) {
    std::vector<Value*> workList;
    workList.push_back(mallockedPtr);
    while(!workList.empty()) {
        Value* work = workList.back();
        workList.pop_back();
        if (StoreInst* storeInst = dyn_cast<StoreInst>(work)) {
            return storeInst->getPointerOperand(); 
        } else if (ReturnInst* retInst = dyn_cast<ReturnInst>(work)) {
            return retInst;
        }
        for (User* user: work->users()) {
            if (user != work) {
                workList.push_back(user);
            }
        }
    }
    assert(false && "Mallocked pointer isn't stored anywhere or returned!");
    return nullptr;
}

void ContextSensitivityAnalysisPass::handleGlobalFunctionPointers(llvm::Module& M) {
    for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
        if (I->getName() != "llvm.global.annotations") {
            GlobalVariable* GV = llvm::cast<GlobalVariable>(I);
            // If the global variable has an initializer and if it is the
            // malloc Functions 
            if (GV->hasInitializer()) {
                Constant* init = GV->getInitializer();
                if (std::find(mallocWrappers.begin(), mallocWrappers.end(), init) != mallocWrappers.end()) {
                    globalMallocWrapperPtrs.push_back(GV);
                }
            }
        }
    }
}

/*!
 * We start from here
 */
bool ContextSensitivityAnalysisPass::runOnModule(Module& M) {

    Function* mallocFunction = M.getFunction("malloc");
    Function* callocFunction = M.getFunction("calloc");
    Function* reallocFunction = M.getFunction("realloc");

    if (mallocFunction) 
        mallocWrappers.insert(mallocFunction);
    if (callocFunction)
        mallocWrappers.insert(callocFunction);
    if (reallocFunction)
        mallocWrappers.insert(reallocFunction);
    
    for (int num = 0; num < 4; num++) {
        // Handle Global Function pointers
        handleGlobalFunctionPointers(M);

        for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
            if (auto *F = dyn_cast<Function>(MIterator)) {
                if (returnsAllocedMemory(F)) {
                    mallocWrappers.insert(F);
                }
            }
        }
    }

    for (Function* mallocWrapper: mallocWrappers) {
        errs() << mallocWrapper->getName() << "\n";
    }
    return false;
}

ModulePass* llvm::createContextSensitivityAnalysisPass() {
    return new ContextSensitivityAnalysisPass();
}

INITIALIZE_PASS_BEGIN(ContextSensitivityAnalysisPass, "csa", "Context Sensitivity Analysis", true, true);
INITIALIZE_PASS_END(ContextSensitivityAnalysisPass, "csa", "Context Sensitivity Analysis", true, true);
