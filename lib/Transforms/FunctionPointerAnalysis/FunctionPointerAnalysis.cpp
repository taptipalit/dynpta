#include "llvm/Transforms/FunctionPointerAnalysis.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"

//#include "llvm/Analysis/AndersenAnalysis/AndersenAA.h"

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
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/Constants.h"

#include <vector>
#include <algorithm>
#include <map>
#include <set>

#include "llvm/IR/Metadata.h"
using namespace llvm;

namespace {
	class AsArg {
		private:
		Function* function;
		int argNum;

		public:
		AsArg(Function* function, int argNum) {
			this->function = function;
			this->argNum = argNum;
		}

		void dump() {
			errs() << "Function Name: " << this->function->getName() << "\n";
			errs() << "Argument Number: " << this->argNum << "\n";
		}

	};

	class FunctionPointerDetail {
		private:
		Value* fnPtr;
		std::vector<AsArg*> inAsArgList; // Passed as an argument from external Function
		std::vector<AsArg*> outAsArgList; // Passed as an argument from external Function
		std::set<Value*> ptsToFunctions;

		public:
		FunctionPointerDetail(Value* fnPtr, std::set<Value*> ptsToFunctions) {
			this->fnPtr = fnPtr;
			this->ptsToFunctions = ptsToFunctions;
		}

		void addInAsArgList(AsArg* inAsArg) {
			this->inAsArgList.push_back(inAsArg);
		}

		void addOutAsArgList(AsArg* outAsArg) {
			this->outAsArgList.push_back(outAsArg);
		}

		Value* getFnPtr() {
			return fnPtr;
		}

		void dump() {
			errs() << "Function Pointer :\n";
			fnPtr->dump();
			errs() << "Incoming list :\n";
			for (AsArg* inAsArg: inAsArgList) {
				inAsArg->dump();
			}
			errs() << "Outgoing list :\n";
			for (AsArg* outAsArg: outAsArgList) {
				outAsArg->dump();
			}
		}
	};

	struct FunctionPointerAnalysisPass : public ModulePass {
		static char ID;
		
		// The list of function pointers that are created
		std::vector<FunctionPointerDetail*> FunctionPointerDetails;

		// The list of all functions
		std::vector<Value*> AllFunctions;

		// The list of external functions
		std::vector<CallInst*> ExternalFunctionCallInsts;

		FunctionPointerAnalysisPass() : ModulePass(ID) {
			initializeFunctionPointerAnalysisPassPass(*PassRegistry::getPassRegistry());

		}

		void getAnalysisUsage(AnalysisUsage &AU) const {
			AU.setPreservesCFG();
			//AU.addRequired<AndersenAAWrapperPass>();
		}

		bool containsFunctionPointerType(Constant* constant, Module& M) {
			int numOperands = constant->getNumOperands();
			for (int i = 0; i < numOperands; i++) {
				Value* operand = constant->getOperand(i);
				Constant* constOperand = dyn_cast<Constant>(operand);
				assert(constOperand); // should always be true
				Type* constType = constOperand->getType();
				if (constType->isPointerTy()) {
					//constOperand->dump();
					PointerType* ptrType = dyn_cast<PointerType>(constType);
					Type* pointedElemType = ptrType->getPointerElementType();
					if (pointedElemType->isFunctionTy()) {
						return true;
					}
				}
				if (constType->isStructTy() || constType->isArrayTy() || constType->isVectorTy()) {
					return containsFunctionPointerType(constOperand, M);
				}
			}
			return false;
		}

		bool contains(llvm::Value* V, std::vector<llvm::Value*>& L) {
			if (std::find(L.begin(), L.end(), V) != L.end()) {
				return true;
			} else {
				return false;
			}
		}

		void findExternalFunctionCallInsts(Module& M) {
            /*
            std::map<llvm::Value*, std::set<llvm::Value*>> fnPtsToMap = getAnalysis<AndersenAAWrapperPass>().getResult().getSanitizedPtsToGraph();

			// Populate list of all functions
			for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
				if (auto *F = dyn_cast<Function>(MIterator)) {
					if (!F->isDeclaration()) {
						AllFunctions.push_back(F);
					}
				}
			}

			// All Call instructions
			for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
				if (auto *F = dyn_cast<Function>(MIterator)) {
					for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
						if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
							//outs() << "Basic block found, name : " << BB->getName() << "\n";
							for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
								if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
									if (CallInst* cI = dyn_cast<CallInst>(Inst)) {
										Function* calledFunction = cI->getCalledFunction();
										if (calledFunction) {
											if (!contains(calledFunction, AllFunctions)) {
												ExternalFunctionCallInsts.push_back(cI);
											}
										} else {
											Value* calledValue = cI->getCalledValue();
											for (Value* val : fnPtsToMap[calledValue]) {
												Function* fn = dyn_cast<Function>(val);
												if (!contains(fn, AllFunctions)) {
													ExternalFunctionCallInsts.push_back(cI);
													break;
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
            */

		}

		void populateOutgoingFunctionPointers(Module& M) {
			// Check if a function pointer is passed to the external function call
			for (CallInst* extCI : ExternalFunctionCallInsts) {
				int numArgs = extCI->getNumArgOperands();
				for (int i = 0; i < numArgs; i++) {
					Value* argVal = extCI->getArgOperand(i);
					for (FunctionPointerDetail* fpDet : FunctionPointerDetails) {
						//TODO - Functions called via function pointers
						if (fpDet->getFnPtr() == argVal) {
							// External function accepts function pointer as input
							fpDet->addOutAsArgList(new AsArg(extCI->getCalledFunction(), i));
						}
					}
				}
			}
		}


		void populateIncomingFunctionPointers(Module& M) {
			for (Value* val: AllFunctions) {
				Function* func = dyn_cast<Function>(val);
				int argNum = 0;
				for(Function::arg_iterator arg = func->arg_begin(), argEnd = func->arg_end(); arg != argEnd; ++arg) {
					Value* argVal = dyn_cast<Value>(arg);
					// If this is a function pointer
					for (FunctionPointerDetail* fpDet : FunctionPointerDetails) {
						//TODO - Functions called via function pointers
						if (fpDet->getFnPtr() == argVal) {
							fpDet->addInAsArgList(new AsArg(func, argNum));
						}
					}
					argNum++;
				}
			}
		}

		bool runOnModule(Module &M) override {
            /*
            std::map<llvm::Value*, std::set<llvm::Value*>> fnPtsToMap = getAnalysis<AndersenAAWrapperPass>().getResult().getSanitizedPtsToGraph();

            std::map<Value*, std::set<Value*>>::iterator it;
            for (it = fnPtsToMap.begin(); it != fnPtsToMap.end(); it++) {
				FunctionPointerDetail* fpDet = new FunctionPointerDetail(it->first, it->second);
				FunctionPointerDetails.push_back(fpDet);
			}

			// Find all external functions invoked by this module
			findExternalFunctionCallInsts(M);

			// Check if these function pointers are passed as arguments to other external functions
			populateOutgoingFunctionPointers(M);

			// Check if any function pointer was accepted as input to a function
			populateIncomingFunctionPointers(M);

			// Dump out all the details of the function pointers
			for (FunctionPointerDetail* fpDet: FunctionPointerDetails) {
				fpDet->dump();
			}
            */
            for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
                if (I->getName() != "llvm.global.annotations") {
                    GlobalVariable* GV = cast<GlobalVariable>(I);
                    dbgs() << ".... global variable .... \n";
                    if (GV) {
                        dbgs () << GV << "\n";
                        GV->dump();
                        dbgs() << " .... users ....\n";
                        for (User* user: GV->users()) {
                            dbgs() << user << "\n";
                            user->dump();
                        }
                    }
                    
                }
            }


            for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
                if (auto *F = dyn_cast<Function>(MIterator)) {
                    for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                        if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                            //outs() << "Basic block found, name : " << BB->getName() << "\n";
                            for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                                if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                                    if (LoadInst* loadInst = dyn_cast<LoadInst>(Inst)) {
                                        Value* loadPtr = loadInst->getPointerOperand();
                                        if (ConstantExpr* expr = dyn_cast<ConstantExpr>(loadPtr)) {
                                            dbgs() << " .... constant expr .... \n";
                                            dbgs() << expr << "\n";
                                            expr->dump();
                                            for (Value::use_iterator useIt = expr->use_begin(), useEnd = expr->use_end(); useIt != useEnd; useIt++) {
                                                Value* useVal = dyn_cast<Value>(*useIt);
                                                dbgs() << useVal << "\n";
                                                dbgs() << "  .... use .... \n";
                                                useVal->dump();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }


		}
	};
}  // end of anonymous namespace

char FunctionPointerAnalysisPass::ID = 0;

ModulePass* llvm::createFunctionPointerAnalysisPass() { return new FunctionPointerAnalysisPass(); } 

INITIALIZE_PASS_BEGIN(FunctionPointerAnalysisPass, "function-ptr-analysis", "Function Pointer Analysis", false, true)
//INITIALIZE_PASS_DEPENDENCY(AndersenAAWrapperPass);
INITIALIZE_PASS_END(FunctionPointerAnalysisPass, "function-ptr-analysis", "Function Pointer Analysis", false, true)

//static RegisterPass<FunctionPointerAnalysisPass> X("function-ptr-analysis", "Function Pointer Analysis", false, true);
