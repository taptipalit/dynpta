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

std::vector<Value*>& SensitiveMemAllocTrackerPass::findAllGepBases(Value* gepBase) {
    Type* gepBaseType = gepBase->getType();
    if (gepMap[gepBaseType].size() > 0) {
        return gepMap[gepBaseType];
    }
    // Find all other gep instructions that have the same base type
    for (Module::iterator MIterator = mod->begin(); MIterator != mod->end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            // Get the local sensitive values
            for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                    //outs() << "Basic block found, name : " << BB->getName() << "\n";
                    for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                        if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                            if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(Inst)) {
                                if (gep->getPointerOperand()->getType() == gepBaseType) {
                                    gepMap[gepBaseType].push_back(gep->getPointerOperand());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return gepMap[gepBaseType];
}

AllocaInst* SensitiveMemAllocTrackerPass::doBackwardSlice(GetElementPtrInst* gepInst) {
    std::vector<Value*> workList;
    workList.push_back(gepInst);

    while (!workList.empty()) {
        Value* work = workList.back();
        workList.pop_back();
        if (User* workUser = dyn_cast<User>(work)) {
            for (Value* op: workUser->operands()) {
                if (AllocaInst* stackObj = dyn_cast<AllocaInst>(op)) {
                    return stackObj;
                }
                workList.push_back(op);
            }
        }
    }
}

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
    int offset = -1;
    if (constOffset) {
        offset = constOffset->getZExtValue();
    } // if not constOffset Treat the whole object as sensitive

    errs() << "Finding all sensitive gep ptrs with base: " << *gepBase << " and offset: " << offset << "\n";
    std::vector<Value*> gepBases = findAllGepBases(gepBase); 
    for (Value* gepBase: gepBases) {
        // Find all users (gepInsts) of the base with the same offset
        for (User* user: gepBase->users()) {
            if (GetElementPtrInst* otherGep = dyn_cast<GetElementPtrInst>(user)) {
                Value* otherGepOffsetValue = otherGep->getOperand(otherGep->getNumOperands()-1);
                ConstantInt* otherGepOffsetConst = dyn_cast<ConstantInt>(otherGepOffsetValue);
                if (offset != -1) {
                    if (otherGepOffsetConst) {
                        int otherGepOffset = otherGepOffsetConst->getZExtValue();
                        if (otherGepOffset == offset) {
                            sensitiveGepPtrs.push_back(otherGep);
                        }
                    }
                } else {
                    sensitiveGepPtrs.push_back(otherGep);
                }
                /*
                if (otherGepOffsetConst) {
                    int otherGepOffset = otherGepOffsetConst->getZExtValue();
                    if (offset == -1) {
                        sensitiveGepPtrs.push_back(otherGep);
                    } else {
                        if (otherGepOffset == offset) {
                            sensitiveGepPtrs.push_back(otherGep);
                        }
                    }
                }
                */
            }
        }
    }
    /*
    for (GetElementPtrInst* gep: sensitiveGepPtrs) {
        errs() << "Sensitive gep ptr: " << *gep << "\n";
    }
    */
}

void SensitiveMemAllocTrackerPass::collectLocalSensitiveAnnotations(Module &M) {
    this->mod = &M;
    // For each function ... 
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
                // Check if it's an annotation
                if (CallInst* CInst = dyn_cast<CallInst>(&*I)) {
                    // CallInst->getCalledValue() gives us a pointer to the Function
                    if (CInst->getCalledValue()->getName() == "annotate" || CInst->getCalledValue()->getName() == "annotate1" || CInst->getCalledValue()->getName() == "annotateStr") {
                        Value* annotationArg = CInst->getArgOperand(0);
                        // If this is a direct gep, then yay!
                        if (GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(annotationArg)) {
                            findAllSensitiveGepPtrs(gepInst);
                        } else if (BitCastInst* bitCastInst = dyn_cast<BitCastInst>(annotationArg)) {
                            if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(bitCastInst->getOperand(0))) {
                                findAllSensitiveGepPtrs(gep);
                            } else if (LoadInst* loadInst = dyn_cast<LoadInst>(bitCastInst->getOperand(0))){
                                if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(loadInst->getOperand(0))) {
                                    findAllSensitiveGepPtrs(gep);
                                } else if (AllocaInst* allocaInst = dyn_cast<AllocaInst>(loadInst->getOperand(0))) {
                                    sensitiveAllocaPtrs.push_back(allocaInst);
                                }
                            } else if (AllocaInst* allocaInst = dyn_cast<AllocaInst>(bitCastInst->getOperand(0))) {
                                sensitiveAllocaPtrs.push_back(allocaInst);
                            }
                        } else if (LoadInst* ldInst = dyn_cast<LoadInst>(annotationArg)) {
                            if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(ldInst->getPointerOperand())) {
                                findAllSensitiveGepPtrs(gep);
                            } else if (LoadInst* lldInst = dyn_cast<LoadInst>(ldInst->getPointerOperand())) {
                                if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(lldInst->getOperand(0))) {
                                    findAllSensitiveGepPtrs(gep);
                                }
                            } else if (AllocaInst* alloc = dyn_cast<AllocaInst>(ldInst->getPointerOperand())) {
                                sensitiveAllocaPtrs.push_back(alloc);
                            } else if (BitCastInst* bitCastInst = dyn_cast<BitCastInst>(ldInst->getPointerOperand())) {
                                if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(bitCastInst->getOperand(0))) {
                                    findAllSensitiveGepPtrs(gep);
                                } else if (LoadInst* lldInst = dyn_cast<LoadInst>(bitCastInst->getOperand(0))){
                                    if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(lldInst->getOperand(0))) {
                                        findAllSensitiveGepPtrs(gep);
                                    }
                                }
                            } else if (GlobalVariable* gvar = dyn_cast<GlobalVariable>(ldInst->getPointerOperand())) {
                                sensitiveGlobalPtrs.push_back(gvar);
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
    // Critical Free Functions
    errs()<<"Critical Free Functions in MallocTracker Pass are:\n";
    for (Function* criticalFreeFunctions : getAnalysis<ContextSensitivityAnalysisPass>().getCriticalFreeFunctions()){
        errs()<<"Function name is: " << criticalFreeFunctions->getName() << "\n";
    }

    collectLocalSensitiveAnnotations(M);

    // Find if there are any stores going in to these pointers

    findStoresAtSensitivePtrs();

    // Any of these stores come from a malloc/calloc/realloc thing?
    // Then we return these as the sensitive calls
    findMemAllocsReachingSensitivePtrs();

    
    for (Value* sensitiveMemAlloc: sensitiveMemAllocCalls) {
        if (AllocaInst* allocInst = dyn_cast<AllocaInst>(sensitiveMemAlloc)) {
            errs() << "Sensitive memory alloc: " << allocInst->getName() << " in function: " << allocInst->getParent()->getParent()->getName() << "\n";
        } else if (CallInst* callInst = dyn_cast<CallInst>(sensitiveMemAlloc)) {
            if (Function* calledFunction = callInst->getCalledFunction()) {
                errs() << "Sensitive memory alloc: " << calledFunction->getName() << " in function: " 
                    << callInst->getParent()->getParent()->getName() << "\n";
            }
        } else {
            errs() << "Global variable: " << *sensitiveMemAlloc << "\n";
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
        if (BitCastInst* bcInst = dyn_cast<BitCastInst>(value)) {
            if (std::find(seenList.begin(), seenList.end(), bcInst->getOperand(0)) 
                    == seenList.end()) {
                workList.push_back(bcInst->getOperand(0));
            }
        } else if (CallInst* callInst = dyn_cast<CallInst>(value)) {
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
            }/* else {
                if (std::find(seenList.begin(), seenList.end(), inst->getOperand(0))
                        == seenList.end()) {
                    workList.push_back(inst->getOperand(0));  // hail mary?
                }
            }*/
        }
    }
}

void SensitiveMemAllocTrackerPass::findStoresAtSensitivePtrs() {
    std::vector<Value*> workList;
    for (AllocaInst* allocInst: sensitiveAllocaPtrs) {
        workList.push_back(allocInst);
    }
    for (GlobalVariable* gptr: sensitiveGlobalPtrs) {
        if (gptr->hasInitializer()) {
            Value* init = gptr->getInitializer();
            if (ConstantExpr* ce = dyn_cast<ConstantExpr>(init)) {
                if (ce->getOpcode() == Instruction::GetElementPtr) {
                    Value* val = ce->getOperand(0);
                    sensitiveMemAllocCalls.push_back(val);
                }
            }
        }
        workList.push_back(gptr);
    }
    for (GetElementPtrInst* gepInst: sensitiveGepPtrs) {
        workList.push_back(gepInst);
        // if this gep is not a pointer to pointer type
        if (gepInst->getType()->getPointerElementType() && !gepInst->getType()->getPointerElementType()->isPointerTy()) {
            // If the base pointer is an alloca
            if (AllocaInst* allocInst = dyn_cast<AllocaInst>(gepInst->getPointerOperand())) {
                sensitiveMemAllocCalls.push_back(allocInst);
            }
        }
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
    /*
    for (Instruction* inst: storesAtSensitivePtrs) {
        errs() << "Stores at sensitive ptrs: " << *inst << "\n";
    }
    */
}

ModulePass* llvm::createSensitiveMemAllocTrackerPass() {
    return new SensitiveMemAllocTrackerPass();
}

INITIALIZE_PASS_BEGIN(SensitiveMemAllocTrackerPass, "smat", "Sensitive Memory Alloc Tracker Pass", true, true);
INITIALIZE_PASS_DEPENDENCY(ContextSensitivityAnalysisPass);
INITIALIZE_PASS_END(SensitiveMemAllocTrackerPass, "smat", "Sensitive Memory Alloc Tracker", true, true);
