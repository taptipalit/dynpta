#include "llvm/Transforms/FunctionPointerAnalysis.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/CallSite.h"

#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/Constants.h"

#include <vector>
#include <algorithm>
#include <map>
#include <set>
#include <string>

#include "llvm/IR/Metadata.h"

#define DEBUG_TYPE "funcptr-analysis"

using namespace llvm;

namespace {

	struct FunctionPointerAnalysisPass : public ModulePass {
		static char ID;
        std::map<Value*, std::set<Value*>> callGraph;
        std::set<Function*> allFuncSet;
        std::map<std::string, std::set<Function*>*> argListFunctionMap;
        std::set<Function*> ctorsSet;
        std::set<Function*> dtorsSet;
		
		FunctionPointerAnalysisPass() : ModulePass(ID) {
			initializeFunctionPointerAnalysisPassPass(*PassRegistry::getPassRegistry());

		}

        void updateMap(std::string argStr, Function* F) {
            if (argListFunctionMap.find(argStr) == argListFunctionMap.end()) {
                argListFunctionMap[argStr] = new std::set<Function*>();
            }
            argListFunctionMap[argStr]->insert(F);
        }

		void getAnalysisUsage(AnalysisUsage &AU) const {
			AU.setPreservesCFG();
		}

		bool contains(Value* V, std::vector<Value*>& L) {
			if (std::find(L.begin(), L.end(), V) != L.end()) {
				return true;
			} else {
				return false;
			}
		}

        void dumpCallGraphFunction(Module& M, Value* value) {
            LLVM_DEBUG("Dumping function\n");
            assert(isa<Function>(value));
            Function* f = dyn_cast<Function>(value);
            PointerType* ptrToFn = PointerType::get(f->getType(), 0);
            GlobalVariable* gVar = new GlobalVariable(M, f->getType(), true, GlobalValue::InternalLinkage, 0, f->getName());
            gVar->setAlignment(8);
            gVar->setInitializer(f);
            gVar->setSection(".callgraph");
        }

        void dumpCtorDtorFunction(Module& M, Value* value) {
            LLVM_DEBUG("Dumping ctor/dtor\n");
            assert(isa<Function>(value));
            Function* f = dyn_cast<Function>(value);
            PointerType* ptrToFn = PointerType::get(f->getType(), 0);
            GlobalVariable* gVar = new GlobalVariable(M, f->getType(), true, GlobalValue::InternalLinkage, 0, f->getName());
            gVar->setAlignment(8);
            gVar->setInitializer(f);
            gVar->setSection(".callgraph_ctor_dtor");

        }

        void dumpCallGraphConstant(Module& M, long number) {
            GlobalVariable* gVar = new GlobalVariable(M, IntegerType::get(M.getContext(), 64), true, GlobalValue::InternalLinkage, 0, "len");
            gVar->setAlignment(8);
            gVar->setInitializer(ConstantInt::get(IntegerType::get(M.getContext(), 64), number));
            gVar->setSection(".callgraph");
        }

        Value* getCalledFunction(CallSite& cs) {
            if (cs.getCalledFunction()) {
                return cs.getCalledFunction();
            }

            if (ConstantExpr* consExpr = dyn_cast<ConstantExpr>(cs.getCalledValue())) {
                return consExpr->getOperand(0);
            }

            if (PointerType* pointerType = dyn_cast<PointerType>(cs.getCalledValue()->getType())) {
                if (FunctionType* functionType = dyn_cast<FunctionType>(pointerType->getPointerElementType())) {
                    // Clearly a function pointer, return it
                    return cs.getCalledValue();
                }
            }
            //errs() << *value << "\n";

            assert(false);
            /*
            std::vector<Value*> workList;
            workList.push_back(value);
            while (!workList.empty()) {
                Value* work = workList.back();
                workList.pop_back();
                for (Value::use_iterator useItr = work->use_begin(), useEnd = work->use_end(); useItr != useEnd; useItr++) {
                    Value* useVal = dyn_cast<Value>(&*useItr);
                    if (useVal) {
                        if (Function* function = dyn_cast<Function>(useVal)) {
                            return useVal;
                        } else if (PointerType* pointerType = dyn_cast<PointerType>(useVal->getType())) {
                            if (FunctionType* functionType = dyn_cast<FunctionType>(pointerType->getPointerElementType())) {
                                // Clearly a function pointer, return it
                                return useVal;
                            } else {
                                errs() << "pushed " << *useVal << "\n";
                                workList.push_back(useVal);
                            }
                        } else {
                            errs() << "pushed " << *useVal << "\n";
                            workList.push_back(useVal);
                        }
                    }
                }
            }
            */
        }

		bool runOnModule(Module &M) override {
            //M.dump();
			// Handle the ctors and dtors
			GlobalVariable *GVCtor = M.getGlobalVariable("llvm.global_ctors");
			if (GVCtor) {
                if (GVCtor->getInitializer() != nullptr) {
                    if (ConstantArray *CA = dyn_cast<ConstantArray>(GVCtor->getInitializer())) {
                        for (auto &V : CA->operands()) {
                            if (ConstantStruct *CS = dyn_cast<ConstantStruct>(V)) {
                                if (Function* F = dyn_cast<Function>(CS->getOperand(1))) {
                                    ctorsSet.insert(F);
                                }
                            }
                        }
                    }
                }
            }

            GlobalVariable *GVDtor = M.getGlobalVariable("llvm.global_dtors");
			if (GVDtor) {
                if (GVDtor->getInitializer() != nullptr) {
                    if (ConstantArray *CA = dyn_cast<ConstantArray>(GVDtor->getInitializer())) {
                        for (auto &V : CA->operands()) {
                            if (ConstantStruct *CS = dyn_cast<ConstantStruct>(V)) {
                                if (Function* F = dyn_cast<Function>(CS->getOperand(1))) {
                                    dtorsSet.insert(F);
                                }
                            }
                        }
                    }
                }
            }

            // Build list of all internal functions
            for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
                if (auto *F = dyn_cast<Function>(MIterator)) {
                    if (!F->isDeclaration()) {
                        allFuncSet.insert(F);
                        if (F->isVarArg()) {
                            updateMap("VAR", F);
                        } else {
                            std::string argTypeStr = "";
                            for (Function::arg_iterator AI = F->arg_begin(), AE = F->arg_end();
                                            AI != AE; ++AI) {
                                Type *Ty = AI->getType();
                                std::string type_str;
                                llvm::raw_string_ostream rso(type_str);
                                Ty->print(rso);
                                if ((rso.str().find("class") != std::string::npos) && (F->arg_size() > 1)) {
                                    continue;
                                }
                                argTypeStr += rso.str();
                            }
                            updateMap(argTypeStr, F);
                        }
                    }
                }
            }
             
            /*
            PAG* pag = getAnalysis<WPAPass>().getPAG();
            CallSiteToFunPtrMap indirectCallMap = pag->getIndirectCallSites();
            */
            for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
                if (auto *F = dyn_cast<Function>(MIterator)) {
                    for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                        if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                            //outs() << "Basic block found, name : " << BB->getName() << "\n";
                            for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                                CallSite cs(&*BBIterator);
                                if (cs.getInstruction()) { // CallInst *CInst = dyn_cast<CallInst>(BBIterator)
                                    if (cs.getCalledFunction() != nullptr && cs.getCalledFunction()->getName().equals("llvm.dbg.declare"))
                                        continue;

                                    Value* calledFunctionVal = getCalledFunction(cs); // Handle any casts
                                    
                                    if (Function* calledFunc = dyn_cast<Function>(calledFunctionVal)) {
                                        callGraph[&*MIterator].insert(calledFunc);
                                    } else {
                                        // Indirect call site
                                        if (isa<InlineAsm>(calledFunctionVal)) 
                                            continue; // Inline assembly is not a function.
                                        /*
                                        NodeID funPtrNodeId = indirectCallMap[new CallSite(CInst)];
                                        PAGNode* funPtrNode = pag->getValueNode(funPtrNodeId);
                                        */
                                        std::string argStr = "";
                                        for (Value* operand: cs.args()) {
                                            std::string type_str;
                                            llvm::raw_string_ostream rso(type_str);
                                            operand->getType()->print(rso);
                                            if ((rso.str().find("class") != std::string::npos) && (cs.getNumArgOperands() > 1)) {
                                                continue;
                                            }
                                            argStr += rso.str();
                                        }
                                        std::set<Function*>* functionSetPtr = argListFunctionMap[argStr];
                                        if (functionSetPtr != nullptr) {
                                            for (Function* calledFunc: *functionSetPtr) {
                                                callGraph[&*MIterator].insert(calledFunc);
                                            }
                                        }
                                        /*
                                        for (Value* fnPtrTarget : fnPtsToMap[calledFunctionVal]) {
                                            if (!isa<Function>(fnPtrTarget))
                                                continue;
                                            callGraph[&*MIterator].insert(fnPtrTarget);
                                            LLVM_DEBUG(dbgs() << MIterator->getName() << " has a function pointer, and calls " << fnPtrTarget->getName() << "\n");
                                        }
                                        if (fnPtsToMap[calledFunctionVal].size() == 0) {
                                            LLVM_DEBUG(dbgs() << MIterator->getName() << " has a fptr, " << *CInst << ", but analysis broke\n");
                                        }
                                        */
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Dump out the ctors and dtors
            for(Function* ctorFun: ctorsSet) {
                dumpCtorDtorFunction(M, ctorFun);
            }
            for(Function* dtorFun: dtorsSet) {
                dumpCtorDtorFunction(M, dtorFun);
            }

            // Dump out the map as global variables
            std::map<Value*, std::set<Value*>>::iterator callGraphIt;
            for (callGraphIt = callGraph.begin(); callGraphIt != callGraph.end(); callGraphIt++) {
                Value* function = callGraphIt->first;
                std::set<Value*> calledFunctions = callGraphIt->second;
                dumpCallGraphFunction(M, function);
                long size = 0;
                for (Value* calledFunction: calledFunctions) {
                    if (std::find(allFuncSet.begin(), allFuncSet.end(), calledFunction) != allFuncSet.end()) {
                        size++;
                    }
                }
                dumpCallGraphConstant(M, size);
                //errs() << "Wrote size = " << size << "\n";
                //int test = 0;
                for (Value* calledFunction: calledFunctions) {
                    if (std::find(allFuncSet.begin(), allFuncSet.end(), calledFunction) != allFuncSet.end()) {
                        dumpCallGraphFunction(M, calledFunction);
                        dbgs() << function->getName() << " calls " << calledFunction->getName() << "\n";
                        //test++;
                    }
                }
                //errs() << "Wrote functions size = " << test << "\n";
                // Signal the end of the record
                dumpCallGraphConstant(M, 0xFFFFFFFFFFFFFFFF);
            }
		}
	};
}  // end of anonymous namespace

char FunctionPointerAnalysisPass::ID = 0;

ModulePass* llvm::createFunctionPointerAnalysisPass() { return new FunctionPointerAnalysisPass(); } 

INITIALIZE_PASS_BEGIN(FunctionPointerAnalysisPass, "function-ptr-analysis", "Function Pointer Analysis", false, true)
INITIALIZE_PASS_END(FunctionPointerAnalysisPass, "function-ptr-analysis", "Function Pointer Analysis", false, true)

