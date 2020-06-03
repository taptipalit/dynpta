#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

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

    class OffsetXMMPair {
        public:

            int startOffsetBytes;
            int XMMReg;
            llvm::Value* ptrOperand;

            OffsetXMMPair(int startOffsetBytes, llvm::Value* ptrOperand, int XMMReg) {
                this->XMMReg = XMMReg;
                this->ptrOperand = ptrOperand;
                this->startOffsetBytes = startOffsetBytes;
            }

    };

    class AESBasic {
        private:
            llvm::Function* encryptBasicFunction;
            llvm::Function* decryptBasicFunction;
            void addExternAESFuncDecls(llvm::Module&);

        public:
            void initializeAes(llvm::Module&);
            void widenPointersAndCastInst(llvm::Module&, llvm::Value* , llvm::Value* , llvm::Value* , std::vector<llvm::Value*>& ,
                    std::map<llvm::Value*, llvm::Value*>&);

            void widenUsers(llvm::Module&, llvm::Value*, llvm::Value*, std::map<llvm::Value*, llvm::Value*>&, llvm::Value* skipInstruction = nullptr);
            void widenMallocCall(llvm::Module&, llvm::CallInst*, llvm::Type*, std::vector<llvm::Value*>&, std::map<llvm::Value*, std::set<llvm::Value*>>&,
                    std::map<llvm::Value*, llvm::Value*>&);
            void widenAllocaInst(llvm::Module&, llvm::AllocaInst*, std::vector<llvm::Value*>&, std::map<llvm::Value*, std::set<llvm::Value*>>&,
                    std::map<llvm::Value*, llvm::Value*>&);
            void widenGlobalVariable(llvm::Module&, llvm::GlobalVariable*, std::vector<llvm::Value*>&, std::map<llvm::Value*, std::set<llvm::Value*>>&, 
                    std::map<llvm::Value*, llvm::Value*>&);
            void widenSensitiveVariables(llvm::Module&, std::vector<llvm::Value*>&,
                    std::map<llvm::Value*, std::set<llvm::Value*>>&, std::map<llvm::Value*, std::set<llvm::Value*>>&);


            llvm::Value* setEncryptedValue(llvm::StoreInst*);
            llvm::Value* getDecryptedValue(llvm::LoadInst*);

            // Utility functions
            void removeFromList(llvm::Value*, std::vector<llvm::Value*>&);
            void updateReferences(std::map<llvm::Value*, std::set<llvm::Value*>>&, llvm::Value*, llvm::Value*);
    };

    class AESCache {
        private:
            std::map<llvm::Value*, std::vector<OffsetXMMPair*>> cacheMap;


            llvm::Function* encryptCacheFunction;
            llvm::Function* decryptCacheFunction;
            llvm::Function* writebackFunction;
            llvm::Function* getEncDecCountFunction;

            llvm::Function* encryptLoopByteFunction;
            llvm::Function* encryptLoopWordFunction;
            llvm::Function* encryptLoopDWordFunction;
            llvm::Function* encryptLoopQWordFunction;
            llvm::Function* encryptLoopDoubleFunction;
            llvm::Function* encryptLoopVecFunction;
            llvm::Function* encryptLoopVec4Function;

            llvm::Function* decryptLoopByteFunction;
            llvm::Function* decryptLoopWordFunction;
            llvm::Function* decryptLoopDWordFunction;
            llvm::Function* decryptLoopQWordFunction;
            llvm::Function* decryptLoopDoubleFunction;
            llvm::Function* decryptLoopVectorFunction;
            llvm::Function* decryptLoopVector4Function;

            llvm::Function* DFSanSetLabelFn;
            llvm::Function* setLabelForContextSensitiveCallsFn;
            llvm::Function* DFSanReadLabelFn;

            llvm::Function* aesMallocFunction;
            llvm::Function* aesCallocFunction;
            llvm::Function* aesReallocFunction;
            llvm::Function* aesStrdupFunction;
            llvm::Function* aesFreeFunction;
            llvm::Function* freeWrapperFunction;
            llvm::Function* aesFreeWithBitcastFunction;
            llvm::Function* memcpySensDstFunction;
            llvm::Function* memcpySensSrcFunction;

            llvm::IntegerType* I128Ty;

            void addExternAESFuncDecls(llvm::Module&);
            bool findTrueOffset(StructType*, int, int*, StructType**, int*);
            llvm::Module* M;
            void findReturnInstsOfFunction(llvm::Function*, std::vector<ReturnInst*>&);

        public:
            void initializeAes(llvm::Module&);

            void clearLabelForSensitiveObjects(llvm::Module&, std::vector<PAGNode*>&);
            bool allFieldsSensitive(StructType*);
            bool  widenSensitiveComplexType(GepObjPN*, std::map<PAGNode*, std::set<PAGNode*>>&);
            // For AES Cache
            void widenSensitiveAllocationSites(llvm::Module&, std::vector<PAGNode*>&,
                    std::map<PAGNode*, std::set<PAGNode*>>&, std::map<PAGNode*, std::set<PAGNode*>>&);
            void gepCallInstHandlerForPartitioning(llvm::Module&, CallInst*, GepObjPN*);
            void gepAllocaInstHandlerForPartitioning(llvm::Module&, AllocaInst* , GepObjPN*, Value*);
            void setLabelsForSensitiveObjects(llvm::Module&, std::set<PAGNode*>*,
                    std::map<PAGNode*, std::set<PAGNode*>>&, std::map<PAGNode*, std::set<PAGNode*>>&);
            void unsetLabelsForCriticalFreeWrapperFunctions(llvm::Module&, std::set<Function*>&);
            void trackDownAllRecursiveSensitiveAllocations(llvm::Module&);
            void addDynamicCheckForSetLabel(StoreInst*, CallInst*);
            Type* findBaseType(Type*);
            OffsetXMMPair* findValueInCache(llvm::Value* ptr, int offsetBytes);
            llvm::Value* setEncryptedValueCached(llvm::StoreInst*);
            llvm::Value* setEncryptedValueCachedDfsan(llvm::StoreInst*);
            llvm::Value* getDecryptedValueCached(llvm::LoadInst*);
            llvm::Value* getDecryptedValueCachedDfsan(llvm::LoadInst*);

            llvm::Value* insertExtractByteFromXMM(llvm::LoadInst*, int byteOffset, int xmmRegNo);
            llvm::Value* insertExtractWordFromXMM(llvm::LoadInst*, int wordOffset, int xmmRegNo);
            llvm::Value* insertExtractDWordFromXMM(llvm::LoadInst*, int dwordOffset, int xmmRegNo);
            llvm::Value* insertExtractQWordFromXMM(llvm::LoadInst*, int qwordOffset, int xmmRegNo);

            void insertInsertByteToXMM(llvm::StoreInst*, int byteOffset, int xmmRegNo);
            void insertInsertWordToXMM(llvm::StoreInst*, int wordOffset, int xmmRegNo);
            void insertInsertDWordToXMM(llvm::StoreInst*, int dwordOffset, int xmmRegNo);
            void insertInsertQWordToXMM(llvm::StoreInst*, int qwordOffset, int xmmRegNo);

            void writeback(llvm::Instruction*);

    };
}
#endif
