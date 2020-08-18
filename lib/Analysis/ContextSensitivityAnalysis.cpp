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
#include "llvm/IR/InstIterator.h"

using namespace llvm;

char ContextSensitivityAnalysisPass::ID = 0;

static cl::opt<int> mallocIterations("malloc-iter", cl::desc("How many iterations of csa should be done to find malloc wrappers"), cl::value_desc("malloc-iter"), cl::init(5));

static cl::opt<bool> skipContextSensitivity("skip-csa", cl::desc("Skip context-sensitivity"), cl::value_desc("skip-csa"), cl::init(false));

static cl::opt<int> callsiteThreshold("callsite-threshold", cl::desc("How many callsites should the malloc wrappers be called from to be treated as context-sensitive"), cl::value_desc("callsite-threshold"), cl::init(5));

static cl::opt<int> calldepthThreshold("calldepth-threshold", cl::desc("How many other functions can a malloc wrapper call, and still be treated as context-sensitive"), cl::value_desc("calldepth-threshold"), cl::init(2));

static cl::opt<int> freeCallsiteThreshold("free-callsite-threshold", cl::desc("How many callsites should the free wrappers be called from to be identified as a free wrapper"), cl::value_desc("free-callsite-threshold"), cl::init(100));

/* 
 * Some values:
 * For SensitiveMemAllocTracker: -callsite-threshold=1 -calldepth-threshold=20 -csa-iter=5
 *          The low callsite-threshold, and high calldepth-threshold, is because we are tracking all possible
 *          memory allocations
 * To identify nginx + openssl: -callsite-threshold=50 -calldepth-threshold=4 -csa-iter=5
 */

/**
 * A function is a memory free wrapper if it frees the memory pointed to by
 * the argument passed to the function
 */
bool ContextSensitivityAnalysisPass::freesPassedMemoryViaIndirectCall(Function* F) {
    FunctionType* functionTy = F->getFunctionType();
    if (functionTy->getNumParams() != 1) {
        return false; // has to take only one argument
    }
    Type* argType = functionTy->getParamType(0);
    if (!isa<PointerType>(argType)) {
        return false;
    }
   
    // A free-wrapper can have multiple free calls on different
    // conditional branches, each with different free pointers which should
    // all alias to the argument passed
    std::vector<Value*> freedPtrs;
    Argument* arg = nullptr;
    for (Argument& argObj: F->args()) {
        arg = &argObj; // should have only one argument
        break;
    }

    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        if (CallInst* callInst = dyn_cast<CallInst>(&*I)) {
            // We don't care about direct calls
            // Remember: Finding free-wrappers is for a different purpose than
            // malloc wrappers. We only need them to clear the sensitivity
            // taint
            /*
            if (Function* func = callInst->getCalledFunction()) {
                if (std::find(freeWrappers.begin(), freeWrappers.end(), func) != freeWrappers.end()) {
                    freedPtrs.push_back(callInst->getArgOperand(0));
                }
            }*/
            /*Indirect Call */ 
            if (callInst->getCalledFunction() == nullptr) {
                if (Value* funcValue = callInst->getCalledValue()) {
                    // Find if the function pointer is a global pointer to malloc
                    if (LoadInst* loadedFrom = dyn_cast<LoadInst>(funcValue)) {
                        if (std::find(globalFreeWrapperPtrs.begin(), globalFreeWrapperPtrs.end(), loadedFrom->getPointerOperand()) != globalFreeWrapperPtrs.end()) {
                            freedPtrs.push_back(callInst->getArgOperand(0));
                        }
                    }
                }
            }
        }
    }

    // If we didn't free anything
    if (freedPtrs.size() == 0) {
        return false;
    }
    // For all the freed pointers, check that they alias to the argument to
    // the function
    bool freesArg = false;
    for (Value* freedObj: freedPtrs) {
        if (CFLAA->query(MemoryLocation(arg), MemoryLocation(freedObj)) == AliasResult::LikelyAlias) {
            freesArg = true;
        }
    }
    return freesArg;
}




/**
 * A function is a memory allocation wrapper if it allocates memory using
 * malloc / calloc, and returns the same pointer
 */
bool ContextSensitivityAnalysisPass::returnsAllocedMemory(Function* F) {
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
                    mallockedPtrs.push_back(callInst);
                }
            } /*Indirect Call */ else if (Value* funcValue = callInst->getCalledValue()) {
                // Find if the function pointer is a global pointer to malloc
                if (LoadInst* loadedFrom = dyn_cast<LoadInst>(funcValue)) {
                    if (std::find(globalMallocWrapperPtrs.begin(), globalMallocWrapperPtrs.end(), loadedFrom->getPointerOperand()) != globalMallocWrapperPtrs.end()) {
                        mallockedPtrs.push_back(callInst);
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
    
    /* May be we don't need to skip functions because malloced address has
     * been written? we can encrypt the whole block after the call...
     * But we can not comment out this call because it sets the funcRetPairList inside
     * isReturningUnwrittenMallockedPtr function.
     * TODO: Separate these two functionalities*/
    for (ReturnInst* retInst: retInsts) {
        if (!isReturningUnwrittenMallockedPtr(retInst, mallockedPtrs)) {
            return false;
            
        }
    }
    return true;
}

bool ContextSensitivityAnalysisPass::findNumFuncRooted(llvm::Function* F, int& num) {
    // TODO: Doesn't really do rooted, but whatever
    bool retVal = false;
    num = 0;
    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        if (CallInst* callInst = dyn_cast<CallInst>(&*I)) {
            if (Function* calledFunction = callInst->getCalledFunction()) {
                if (!calledFunction->isDeclaration()) {
                    // We don't care about libc stuff
                    num++;
                }
            } else {
                retVal = true;
            }
        }
    }
    return retVal;
}

bool ContextSensitivityAnalysisPass::isReturningUnwrittenMallockedPtr(ReturnInst* retInst, std::vector<Value*>& mallockedPtrs){
    Function* function = retInst->getParent()->getParent();
    bool returnsMalloc = false;
    bool writesToMalloc = false;
    for (Value* mallockedObj: mallockedPtrs) {
        if (CFLAA->query(MemoryLocation(retInst->getOperand(0)), MemoryLocation(mallockedObj)) == AliasResult::LikelyAlias) {
            returnsMalloc = true;
            funcRetPairList.push_back(std::make_pair(function, mallockedObj));
        }
    }
    if (!returnsMalloc) {
        return false;
    } else {
        // Check if the returned malloc is the target of any write
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            if (StoreInst* storeInst = dyn_cast<StoreInst>(&*I)) {
                if (CFLAA->query(MemoryLocation(retInst->getOperand(0)), MemoryLocation(storeInst->getPointerOperand())) == AliasResult::LikelyAlias) {
                    writesToMalloc = true;
                }
            }
        }
    }
    /* Even though malloced address has been written, we're still considering 
     * it as a mallocWrapper; so we are not returning false from here
     */
    if (returnsMalloc/* && !writesToMalloc*/) {
        return true;
    } else {
        return false;
    }
}

void ContextSensitivityAnalysisPass::handleGlobalFunctionPointersForMallocWrappers(llvm::Module& M) {
    for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
        if (I->getName() != "llvm.global.annotations") {
            GlobalVariable* GV = llvm::cast<GlobalVariable>(I);
            // If the global variable has an initializer and if it is the
            // malloc Functions 
            if (GV->hasInitializer()) {
                Constant* init = GV->getInitializer();
                if (std::find(mallocWrappers.begin(), mallocWrappers.end(), init) != mallocWrappers.end()) {
                    globalMallocWrapperPtrs.insert(GV);
                } 
            }
        }
    }
}


void ContextSensitivityAnalysisPass::handleGlobalFunctionPointersForFreeWrappers(llvm::Module& M) {
    for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
        if (I->getName() != "llvm.global.annotations") {
            GlobalVariable* GV = llvm::cast<GlobalVariable>(I);
            // If the global variable has an initializer and if it is the
            // malloc Functions 
            if (GV->hasInitializer()) {
                Constant* init = GV->getInitializer();
                if (std::find(freeWrappers.begin(), freeWrappers.end(), init) != freeWrappers.end()) {
                    globalFreeWrapperPtrs.insert(GV);
                }
            }
        }
    }
}

void ContextSensitivityAnalysisPass::profileFuncCalls(Module& M) {
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
                if (CallInst* callInst = dyn_cast<CallInst>(&*I)) {
                    if (Function* calledFunc = callInst->getCalledFunction()) {
                        funcCallNumMap[calledFunc]++;
                    }
                }
            }
        }
    }
    for (Function* mallocWrapper: mallocWrappers) {
        mallocWrapperCallNumMap.push_back(std::make_pair(mallocWrapper, funcCallNumMap[mallocWrapper]));
    }

    for (Function* freeWrapper: newFreeWrappers) {
        freeWrapperCallNumMap.push_back(std::make_pair(freeWrapper, funcCallNumMap[freeWrapper]));
    }


    // Sort the elements in the map in the right way and then filter it
    struct {
        bool operator()(std::pair<Function*, int>& pair1, std::pair<Function*, int>& pair2) const
        {
            return pair1.second < pair2.second;
        }
    } sorter;

    std::sort(mallocWrapperCallNumMap.begin(), mallocWrapperCallNumMap.end(), sorter);
    std::sort(freeWrapperCallNumMap.begin(), freeWrapperCallNumMap.end(), sorter);

    errs() << "Sorted malloc callers\n";

    for (auto pair: mallocWrapperCallNumMap) {
        errs() << pair.first->getName() << " : " << pair.second << "\n";
    }

    errs() << "Sorted free callers\n";

    for (auto pair: freeWrapperCallNumMap) {
        errs() << pair.first->getName() << " : " << pair.second << "\n";
    }

    // For malloc
    for (auto pair: mallocWrapperCallNumMap) {
        int numCallees = 0;
        findNumFuncRooted(pair.first, numCallees);
        errs() << " Function: " << pair.first->getName() << " calls: " << numCallees << " other functions\n";
        if (numCallees <= calldepthThreshold && (pair.second >=callsiteThreshold || pair.second == 0)) {
            criticalFunctions.push_back(pair.first);
        }
    }

    // For free
    for (auto pair: freeWrapperCallNumMap) {
        int numCallees = 0;
        findNumFuncRooted(pair.first, numCallees);
        errs() << " Function: " << pair.first->getName() << " calls: " << numCallees << " other functions\n";
        if (numCallees <= calldepthThreshold && pair.second >=freeCallsiteThreshold ) {
            criticalFreeFunctions.push_back(pair.first);
        }
    }
    for (int i = criticalFunctions.size() - 1; i >= 0; i--) {
        top10CriticalFunctions.push_back(criticalFunctions[i]);
        if (top10CriticalFunctions.size() == 10) {
            // top 10!
            break;
        }
    }

    for(Function* critFunction: criticalFunctions) {
        errs() << "Critical Function: " << critFunction->getName() << "\n";
    }

    for (Function* freeCritFunction: criticalFreeFunctions) {
        errs() << "Critical free function: " << freeCritFunction->getName() << "\n";
    }
}

bool ContextSensitivityAnalysisPass::recompute(Module& M, int callsiteThres, int calldepthThres) {
    callsiteThreshold = callsiteThres;
    calldepthThreshold = calldepthThres;
    mallocWrappers.clear();
    mallocWrapperCallNumMap.clear();
    funcCallNumMap.clear();
    globalMallocWrapperPtrs.clear();
    criticalFunctions.clear();
    top10CriticalFunctions.clear();
    return runOnModule(M);
}

/*!
 * We start from here
 */
bool ContextSensitivityAnalysisPass::runOnModule(Module& M) {

    /* Passthrough */
    if (skipContextSensitivity) {
        return false;
    }
    Function* mallocFunction = M.getFunction("malloc");
    Function* callocFunction = M.getFunction("calloc");
    Function* reallocFunction = M.getFunction("realloc");
    Function* freeFunction = M.getFunction("free");

    if (mallocFunction) 
        mallocWrappers.insert(mallocFunction);
    if (callocFunction)
        mallocWrappers.insert(callocFunction);
    if (reallocFunction)
        mallocWrappers.insert(reallocFunction); 
    
    if (freeFunction)
        freeWrappers.insert(freeFunction);

    for (int num = 0; num < mallocIterations; num++) {
        // Handle Global Function pointers
        handleGlobalFunctionPointersForMallocWrappers(M);
        for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
            if (auto *F = dyn_cast<Function>(MIterator)) {
                CFLAA = &(getAnalysis<CFLSteensAAWrapperPass>().getResult());
                if (returnsAllocedMemory(F)) {
                    mallocWrappers.insert(F);
                }
            }
        }
    }

    // The purpose of finding the free wrappers is different from finding
    // malloc wrappers.
    // We need free wrappers only to be able to reset the sensitivity flag
    // when the memory object is freed.
    // 
    // To do this, we need to find the immediate wrappers, like CRYPTO_free,
    // and do not need to go up to the BN_free wrapper. So we can get away
    // with a single iteration
    //
    // Actually, just finding that the function pointer in CRYPTO_free was
    // pointing to free would have been enough.
    handleGlobalFunctionPointersForFreeWrappers(M);
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            CFLAA = &(getAnalysis<CFLSteensAAWrapperPass>().getResult());
            if (freesPassedMemoryViaIndirectCall(F)) {
                newFreeWrappers.insert(F);
            }
        }
    }
    errs() << "All malloc wrapper functions that qualify:\n";
    // Now, filter out the functions that aren't called from too many places
    for (Function* mallocWrapper: mallocWrappers) {
        errs() << mallocWrapper->getName() << "\n";
    }

    errs() << "All free wrapper functions that qualify:\n";
    for (Function* freeWrapper: newFreeWrappers) {
        errs() << freeWrapper->getName() << "\n";
    }
    // Profile the module
    profileFuncCalls(M);

    return false;
}

ModulePass* llvm::createContextSensitivityAnalysisPass() {
    return new ContextSensitivityAnalysisPass();
}

INITIALIZE_PASS_BEGIN(ContextSensitivityAnalysisPass, "csa", "Context Sensitivity Analysis", true, true);
INITIALIZE_PASS_DEPENDENCY(CFLSteensAAWrapperPass)
INITIALIZE_PASS_DEPENDENCY(LibcPreprocessPass)

INITIALIZE_PASS_END(ContextSensitivityAnalysisPass, "csa", "Context Sensitivity Analysis", true, true);
