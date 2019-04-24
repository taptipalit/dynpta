#include "llvm/Transforms/LibcTransform.h"
#include <iostream>
using namespace std;
using namespace llvm;


    bool LibcTransformPass::runOnModule(Module &M) {
        /*
        // Give each call to memcpy, memset, and memcmp, its own function
        PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
        IntegerType* longType = IntegerType::get(M.getContext(), 64);
        IntegerType* intType = IntegerType::get(M.getContext(), 32);

        // Build the Function Types, and the Functions
        // internal_memcpy
        ArrayRef<Type*> memcpyArrRef({voidPtrType, voidPtrType, intType});
        FunctionType* FTypeMemcpy = FunctionType::get(voidPtrType, memcpyArrRef, false);

        // internal_memcmp
        ArrayRef<Type*> memcmpArrRef({voidPtrType, voidPtrType, intType});
        FunctionType* FTypeMemcmp = FunctionType::get(intType, memcmpArrRef, false);

        // internal_memset
        ArrayRef<Type*> memsetArrRef({voidPtrType, intType, intType});
        FunctionType* FTypeMemset = FunctionType::get(voidPtrType, memsetArrRef, false);
        */


        Function* internalMemcpyFn = M.getFunction("internal_memcpy");
        Function* internalMemsetFn = M.getFunction("internal_memset");
        Function* internalMemcmpFn = M.getFunction("internal_memcmp");

        Function* internalStrlenFn = M.getFunction("internal_strlen");
        Function* internalStrcatFn = M.getFunction("internal_strcat");
        Function* internalStrcpyFn = M.getFunction("internal_strcpy");
        Function* internalStrcmpFn = M.getFunction("internal_strcmp");
        Function* internalStrstrFn = M.getFunction("internal_strstr");

        StringRef memcmpStr("memcmp");
//        dbgs() << "lIbbc global variable .... \n";
        for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
            if (auto *F = dyn_cast<Function>(MIterator)) {
                for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                    if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                        for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                            if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                                if (CallInst* callInst = dyn_cast<CallInst>(Inst)) {
                                    if (Function* calledFunction = callInst->getCalledFunction()) {
                                        if (calledFunction->getName().find("llvm.memset") != StringRef::npos) {
                                            ValueToValueMapTy VMap;
                                            //Function* clonedFunction = CloneFunction(internalMemsetFn, VMap, true);
                                            Function* clonedFunction = CloneFunction(internalMemsetFn, VMap, NULL);
                                            clonedFunction->setLinkage(GlobalValue::InternalLinkage);
                                            //internalMemsetFn->getParent()->getFunctionList().push_back(clonedFunction);
                                            callInst->setCalledFunction(clonedFunction);
                                            //callInst->setCalledFunction(internalMemsetFn);
                                        } else if (calledFunction->getName().find("llvm.memcpy") != StringRef::npos) {
                                            ValueToValueMapTy VMap;
                                            //Function* clonedFunction = CloneFunction(internalMemcpyFn, VMap, true);
                                            Function* clonedFunction = CloneFunction(internalMemcpyFn, VMap, NULL);
                                            clonedFunction->setLinkage(GlobalValue::InternalLinkage);
                                            //internalMemcpyFn->getParent()->getFunctionList().push_back(clonedFunction);
                                            callInst->setCalledFunction(clonedFunction);
                                            //callInst->setCalledFunction(internalMemcpyFn);
                                        } else if (calledFunction->getName().equals("memcmp")) {
                                            ValueToValueMapTy VMap;
                                            //Function* clonedFunction = CloneFunction(internalMemcmpFn, VMap, true);
                                            Function* clonedFunction = CloneFunction(internalMemcmpFn, VMap, NULL);
                                            clonedFunction->setLinkage(GlobalValue::InternalLinkage);
                                            //internalMemcmpFn->getParent()->getFunctionList().push_back(clonedFunction);
                                            callInst->setCalledFunction(clonedFunction);
                                            //callInst->setCalledFunction(internalMemcmpFn);
                                        } else if (calledFunction->getName().equals("strlen")) {
                                            ValueToValueMapTy VMap;
                                            //Function* clonedFunction = CloneFunction(internalMemcmpFn, VMap, true);
                                            Function* clonedFunction = CloneFunction(internalStrlenFn, VMap, NULL);
                                            clonedFunction->setLinkage(GlobalValue::InternalLinkage);
                                            //internalStrlenFn->getParent()->getFunctionList().push_back(clonedFunction);
                                            callInst->setCalledFunction(clonedFunction);
                                            //callInst->setCalledFunction(internalMemcmpFn);
                                        } else if (calledFunction->getName().equals("strcat")) {
                                            ValueToValueMapTy VMap;
                                            //Function* clonedFunction = CloneFunction(internalMemcmpFn, VMap, true);
                                            Function* clonedFunction = CloneFunction(internalStrcatFn, VMap, NULL);
                                            clonedFunction->setLinkage(GlobalValue::InternalLinkage);
                                            //internalStrcatFn->getParent()->getFunctionList().push_back(clonedFunction);
                                            callInst->setCalledFunction(clonedFunction);
                                            //callInst->setCalledFunction(internalMemcmpFn);
                                        } else if (calledFunction->getName().equals("strcpy")) {
                                            ValueToValueMapTy VMap;
                                            //Function* clonedFunction = CloneFunction(internalMemcmpFn, VMap, true);
                                            Function* clonedFunction = CloneFunction(internalStrcpyFn, VMap, NULL);
                                            clonedFunction->setLinkage(GlobalValue::InternalLinkage);
                                            //internalStrcpyFn->getParent()->getFunctionList().push_back(clonedFunction);
                                            callInst->setCalledFunction(clonedFunction);
                                            //callInst->setCalledFunction(internalMemcmpFn);
                                        } else if (calledFunction->getName().equals("strcmp")) {
                                            ValueToValueMapTy VMap;
                                            //Function* clonedFunction = CloneFunction(internalMemcmpFn, VMap, true);
                                            Function* clonedFunction = CloneFunction(internalStrcmpFn, VMap, NULL);
                                            clonedFunction->setLinkage(GlobalValue::InternalLinkage);
                                            //internalStrcmpFn->getParent()->getFunctionList().push_back(clonedFunction);
                                            callInst->setCalledFunction(clonedFunction);
                                            //callInst->setCalledFunction(internalMemcmpFn);
                                        } else if (calledFunction->getName().equals("strstr")) {
                                            ValueToValueMapTy VMap;
                                            //Function* clonedFunction = CloneFunction(internalMemcmpFn, VMap, true);
                                            Function* clonedFunction = CloneFunction(internalStrstrFn, VMap, NULL);
                                            clonedFunction->setLinkage(GlobalValue::InternalLinkage);
                                            //internalStrstrFn->getParent()->getFunctionList().push_back(clonedFunction);
                                            callInst->setCalledFunction(clonedFunction);
                                            //callInst->setCalledFunction(internalMemcmpFn);
                                        }



                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return true;
    }

char LibcTransformPass::ID = 0;

ModulePass* llvm::createLibcTransformPass() { return new LibcTransformPass(); } 

INITIALIZE_PASS_BEGIN(LibcTransformPass, "libc-transform", "Transform calls to memcpy, memset, memcmp and their string equivalents", false, true)
INITIALIZE_PASS_END(LibcTransformPass, "libc-transform", "Transform calls to memcpy, memset, memcmp, and their string equivalents", false, true)

