//===- SensitiveMemAllocTrackerPass.cpp -- Track sensitive memory allocator pass------------------------------//
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

#include "llvm/Analysis/SensitiveMemAllocTrackerPass.h"

using namespace llvm;

char SensitiveMemAllocTrackerPass::ID = 0;

/**
 * The programmer annotated one gep instruction as sensitive.
 * Need to find all other geps with the same base and same offset
 * And mark them as sensitive too.
 *
 * Later, we'll track any stores to those pointers
 */
void SensitiveMemAllocTrackerPass::findAllSensitiveGepPtrs(Value* gepValue) {
    GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(gepValue);
    sensitiveGepPtrs.push_back(gepInst);
    assert(gepInst && "Not a gepinst, what is it?");
    // Shouldn't be very complicated to handle this
    Value* gepBase = gepInst->getPointerOperand();
    Value* offsetValue = gepInst->getOperand(gepInst->getNumOperands()-1);
    ConstantInt* constOffset = dyn_cast<ConstantInt>(offsetValue);
    assert(constOffset && "How did we annotate a gep with a non-constant offset as sensitive?");
    int offset = constOffset->getZExtValue();

    // Find all users (gepInsts) of the base with the same offset
    for (User* user: gepBase->users()) {
       if (GetElementPtrInst* otherGep = dyn_cast<GetElementPtrInst>(user)) {
           Value* otherGepOffsetValue = otherGep->getOperand(otherGep->getNumOperands()-1);
           ConstantInt* otherGepOffsetConst = dyn_cast<ConstantInt>(otherGepOffsetValue);
           if (otherGepOffsetConst) {
               int otherGepOffset = otherGepOffsetConst->getZExtValue();
               if (otherGepOffset == offset) {
                   sensitiveGepPtrs.push_back(otherGep);
               }
           }
       }
    }
}

void SensitiveMemAllocTrackerPass::collectLocalSensitiveAnnotations(Module &M) {
    // For each function ... 
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
                // Check if it's an annotation
                if (CallInst* CInst = dyn_cast<CallInst>(&*I)) {
                    // CallInst->getCalledValue() gives us a pointer to the Function
                    if (CInst->getCalledValue()->getName().startswith("llvm.ptr.annotation")) {
                        Value* SV = CInst->getArgOperand(0);
                        for (Value::use_iterator useItr = SV->use_begin(), useEnd = SV->use_end(); useItr != useEnd; useItr++) {
                            Value* annotationArg = dyn_cast<Value>(*useItr);
                            // If this is a direct gep, then yay!
                            if (GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(annotationArg)) {
                                findAllSensitiveGepPtrs(gepInst);
                            } else if (BitCastInst* bitCastInst = dyn_cast<BitCastInst>(annotationArg)) {
                                findAllSensitiveGepPtrs(bitCastInst->getOperand(0));
                            }
                        }
                    } else if (CInst->getCalledValue()->getName().startswith("llvm.var.annotation")) {
                        Value* SV = CInst->getArgOperand(0);
                        for (Value::use_iterator useItr = SV->use_begin(), useEnd = SV->use_end(); useItr != useEnd; useItr++) {
                            Value* annotationArg = dyn_cast<Value>(*useItr);
                            // If this is a direct gep, then yay!
                            if (AllocaInst* allocaInst = dyn_cast<AllocaInst>(annotationArg)) {
                                sensitiveAllocaPtrs.push_back(allocaInst);
                            } else if (BitCastInst* bitCastInst = dyn_cast<BitCastInst>(annotationArg)) {
                                // Get the first operand, if it is an alloca
                                if (AllocaInst* allocaInst = dyn_cast<AllocaInst>(bitCastInst->getOperand(0))) {
                                    sensitiveAllocaPtrs.push_back(allocaInst);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/*!
 * We start from here
 */
bool SensitiveMemAllocTrackerPass::runOnModule(Module& M) {

    Function* mallocFunction = M.getFunction("malloc");
    Function* callocFunction = M.getFunction("calloc");
    Function* reallocFunction = M.getFunction("realloc");

    if (mallocFunction) 
        mallocRoutines.insert(mallocFunction);
    if (callocFunction)
        mallocRoutines.insert(callocFunction);
    if (reallocFunction)
        mallocRoutines.insert(reallocFunction);

    errs()<<"Critical Functions in MallocTracker Pass are:\n";
    for (Function* criticalFunctions : getAnalysis<ContextSensitivityAnalysisPass>().getCriticalFunctions()){
        errs()<<"Function name is: " << criticalFunctions->getName() << "\n";
        mallocRoutines.insert(criticalFunctions);
    }

    collectLocalSensitiveAnnotations(M);

    // Find if there are any stores going in to these pointers

    findStoresAtSensitivePtrs();

    // Any of these stores come from a malloc/calloc/realloc thing?
    // Then we return these as the sensitive calls
    findMemAllocsReachingSensitivePtrs();

    
    for (CallInst* callInst: sensitiveMemAllocCalls) {
        if (Function* calledFunction = callInst->getCalledFunction()) {
            errs() << "Sensitive memory alloc: " << calledFunction->getName() << " in function: " 
                << callInst->getParent()->getParent()->getName() << "\n";
        }
    }

    return false;
}

void SensitiveMemAllocTrackerPass::findMemAllocsReachingSensitivePtrs() {
    // Go over each store to a sensitive gep ptr
    std::vector<Value*> workList;
    std::vector<Value*> seenList;

    for (StoreInst* sensitiveStore: storesAtSensitivePtrs) {
        // Get the value operands and check if they're coming from a
        // malloc/calloc 
        workList.push_back(sensitiveStore->getValueOperand());
    }

    while (!workList.empty()) {
        Value* value = workList.back();
        seenList.push_back(value);
        workList.pop_back();
        if (CallInst* callInst = dyn_cast<CallInst>(value)) {
            if (Function* calledFunction = callInst->getCalledFunction()) {
                if (std::find(mallocRoutines.begin(), mallocRoutines.end(), calledFunction)
                        != mallocRoutines.end()) {
                    sensitiveMemAllocCalls.push_back(callInst);
                }
                Value* callVal = getAnalysis<ContextSensitivityAnalysisPass>().getReturnedAllocation(calledFunction);
                if (callVal) {
                    CallInst* allocCallInst = dyn_cast<CallInst>(callVal);
                    assert(allocCallInst && "If context-sensitivity pass found something here, it should be a call-inst");
                    if (allocCallInst) {
                        sensitiveMemAllocCalls.push_back(allocCallInst);
                    }
                }
            }
        } else if (Instruction* inst = dyn_cast<Instruction>(value)) {
            if (AllocaInst* allocInst = dyn_cast<AllocaInst>(inst->getOperand(0))) {
                // A pointer is stored to another sensitive pointer
                // We should find whatever was stored into this pointer
                for (User* user: allocInst->users()) {
                    if (StoreInst* sensitiveStore = dyn_cast<StoreInst>(user)) {
                        if (sensitiveStore->getPointerOperand() == allocInst) {
                            if (std::find(seenList.begin(), seenList.end(), sensitiveStore->getValueOperand()) 
                                    == seenList.end()) {
                                workList.push_back(sensitiveStore->getValueOperand());
                            }
                        }
                    }
                }
            } else {
                if (std::find(seenList.begin(), seenList.end(), inst->getOperand(0))
                        == seenList.end()) {
                    workList.push_back(inst->getOperand(0));  // hail mary?
                }
            }
        }
    }
}

void SensitiveMemAllocTrackerPass::findStoresAtSensitivePtrs() {
    std::vector<Value*> workList;
    for (AllocaInst* allocInst: sensitiveAllocaPtrs) {
        workList.push_back(allocInst);
    }
    for (GetElementPtrInst* gepInst: sensitiveGepPtrs) {
        workList.push_back(gepInst);
    }
    while (!workList.empty()) {
        Value* val = workList.back();
        workList.pop_back();
        for (User* user: val->users()) {
            if (user == val)
                continue;
            if (StoreInst* storeInst = dyn_cast<StoreInst>(user)) {
                storesAtSensitivePtrs.push_back(storeInst);
            } else if (CastInst* castInst = dyn_cast<CastInst>(user)) {
                workList.push_back(castInst);
            } else if (CallInst* callInst = dyn_cast<CallInst>(user)) {
                if (Function* calledFunc = callInst->getCalledFunction()) {
                    if (calledFunc->getName().startswith("llvm.ptr.annotation")) {
                        workList.push_back(callInst);
                    }
                }
            }
        }
    }
}

ModulePass* llvm::createSensitiveMemAllocTrackerPass() {
    return new SensitiveMemAllocTrackerPass();
}

INITIALIZE_PASS_BEGIN(SensitiveMemAllocTrackerPass, "smat", "Sensitive Memory Alloc Tracker Pass", true, true);
INITIALIZE_PASS_DEPENDENCY(ContextSensitivityAnalysisPass);
INITIALIZE_PASS_END(SensitiveMemAllocTrackerPass, "smat", "Sensitive Memory Alloc Tracker", true, true);
