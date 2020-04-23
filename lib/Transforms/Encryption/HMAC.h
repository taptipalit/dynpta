#ifndef HMAC_H
#define HMAC_H

#include "EncryptionInternal.h"
#include <cstring>
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

namespace external{
    using namespace llvm;

    class HMAC {
        private:


            llvm::Function* computeFunction;
            llvm::Function* checkFunction;
            llvm::IntegerType* I64Ty;
            llvm::IntegerType* I128Ty;
            llvm::VectorType* V512Ty;
            llvm::VectorType* V768Ty;
            llvm::Module* M;

            Type* findBaseType(Type*);

            void addExternHMACFuncDecls(llvm::Module&);
            
            Function* computeHMACFunction;
            Function* checkHMACFunction;

            // Some types that we need over and over again
            // We initialize these in addExternHMACFuncDecls
            PointerType* voidPtrType;
            Type* voidType;

        public:
            void initializeHMAC(llvm::Module&);

            bool allFieldsSensitive(StructType*);

            bool findTrueOffset(StructType*, int, int*, StructType**, int*);
            bool widenSensitiveComplexType(GepObjPN*);
            void widenSensitiveAllocationSites(llvm::Module&, std::vector<PAGNode*>&);

            void insertCheckAuthentication(LoadInst*);
            void insertComputeAuthentication(StoreInst*);
    };
}
#endif
