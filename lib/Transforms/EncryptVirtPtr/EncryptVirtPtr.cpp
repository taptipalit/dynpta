#include "llvm/Transforms/EncryptVirtPtr.h"
#include <iostream>
using namespace std;
using namespace llvm;

Type* EncryptVirtPtrPass::getBaseType(Type* ptrType) {
    Type* pointerElType = ptrType->getPointerElementType();
    if (pointerElType->isPointerTy()) {
        return getBaseType(pointerElType);
    } else {
        return pointerElType;
    }
}

bool EncryptVirtPtrPass::runOnModule(Module &M) {
    for (StructType* stType: M.getIdentifiedStructTypes()) {
        if (stType->isPolymorphic()) {
            addPolymorphicType(stType);
        }
    }

    std::vector<BitCastInst*> bitcastInstList;
    // The pattern LLVM seems to follow seems to be to cast a pointer
    // to the struct type, which is polymorphic, to a
    // pointer-to-a-pointer-to-a-function type.
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (Function *func = dyn_cast<Function> (MIterator)) {
            for (inst_iterator I = inst_begin(func), E = inst_end(func); I != E; ++I) {
                if (BitCastInst* bcInst = dyn_cast<BitCastInst>(&*I)) {
                    Type* srcType = bcInst->getSrcTy();
                    Type* dstType = bcInst->getDestTy();
                    if (isa<PointerType>(srcType)) {
                        Type* baseElType = getBaseType(srcType);
                        if (StructType* stSrcType = dyn_cast<StructType>(baseElType)) {
                            if (stSrcType->isPolymorphic()) {
                                // Check if the target is a pointer to a function
                                if (isa<PointerType>(dstType)) {
                                    Type* baseDstType = getBaseType(dstType);
                                    if (isa<FunctionType>(baseDstType)) {
                                        bitcastInstList.push_back(bcInst);
                                    }
                                }
                            }
                        } 
                    }
                }
            }
        }
    }

    for (BitCastInst* bcInst: bitcastInstList) {
        bcInst->dump();
    }
    return false;
}

char EncryptVirtPtrPass::ID = 0;

ModulePass* llvm::createEncryptVirtPtrPass() { return new EncryptVirtPtrPass(); } 

static RegisterPass<EncryptVirtPtrPass> X("enc-vir-ptr", "Protect virtual pointers from coop attacks");

/*
INITIALIZE_PASS_BEGIN(EncryptVirtPtrPass, "enc-vir-ptr", "Encrypt virtual pointer", false, true)
INITIALIZE_PASS_END(EncryptVirtPtrPass, "enc-vir-ptr", "Encrypt virtual pointer", false, true)
*/
