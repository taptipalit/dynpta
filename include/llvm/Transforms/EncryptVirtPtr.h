//===-- EncryptVirtPtr.h - Encryption of Virtual Pointers Transformations -----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This header file defines prototypes for accessor functions that expose passes
// in the Scalar transformations library.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_ENCRYPT_VIRT_PTR_H
#define LLVM_TRANSFORMS_ENCRYPT_VIRT_PTR_H

#include "llvm/ADT/StringRef.h"
#include <functional>
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"


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
#include "llvm/Transforms/Utils/Cloning.h"

#include <vector>
#include <algorithm>
#include <map>

#include "llvm/IR/Metadata.h"

class EncryptVirtPtrPass : public llvm::ModulePass {

    private:
        std::set<llvm::StructType*> polymorphicTypes;
        llvm::Type* getBaseType(llvm::Type*);

    public:
    static char ID;

    void addPolymorphicType(llvm::StructType* stType) {
        polymorphicTypes.insert(stType);
    }

    std::set<llvm::StructType*>& getPolymorphicTypes() {
        return polymorphicTypes;
    }

    void getAnalysisUsage(llvm::AnalysisUsage &AU) const {
        //AU.setPreservesCFG();
    }

    EncryptVirtPtrPass() : llvm::ModulePass(ID) {
        //initializeEncryptVirtPtrPassPass(*llvm::PassRegistry::getPassRegistry());
    }

    bool runOnModule(llvm::Module&) override;

};
namespace llvm {
	class ModulePass;

	ModulePass * createEncryptVirtPtrPass();	
}	// End llvm namespace


#endif
