#include "AES.h"

using namespace llvm;

namespace external {
	
    void AESCache::addExternAESFuncDecls(Module &M) {
        // The write back function
        std::vector<Type*> typeWriteback;
        //typeWriteback.push_back(Type::getVoidTy(M.getContext()));
        ArrayRef<Type*> typeWritebackArr(typeWriteback);

        FunctionType* writebackFnTy = FunctionType::get(Type::getVoidTy(M.getContext()), typeWritebackArr, false);
        this->writebackFunction = Function::Create(writebackFnTy, Function::ExternalLinkage, "writeback_cache", &M);

        this->getEncDecCountFunction = Function::Create(writebackFnTy, Function::ExternalLinkage, "getEncDecCount", &M);
        

        // Build the signature of the function
        PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
        IntegerType* intType = IntegerType::get(M.getContext(), 32);
        IntegerType* longType = IntegerType::get(M.getContext(), 64);

        std::vector<Type*> typeVecDec;
        typeVecDec.push_back(voidPtrType);
        ArrayRef<Type*> paramArgArray1(typeVecDec);

        FunctionType* FTypeDec = FunctionType::get(IntegerType::get(M.getContext(), 64), paramArgArray1, false);
        this->decryptCacheFunction = Function::Create(FTypeDec, Function::ExternalLinkage, "decrypt_cache", &M);
        this->encryptCacheFunction = Function::Create(FTypeDec, Function::ExternalLinkage, "encrypt_cache", &M);

        // The in-memory encryption/decryption handlers for external libraries
        Function::Create(FTypeDec, Function::ExternalLinkage, "decrypt_memory", &M);
        Function::Create(FTypeDec, Function::ExternalLinkage, "encrypt_memory", &M);


        // Cache loops
        IntegerType* byteType = IntegerType::get(M.getContext(), 8);
        IntegerType* wordType = IntegerType::get(M.getContext(), 16);
        IntegerType* dwordType = IntegerType::get(M.getContext(), 32);
        IntegerType* qwordType = IntegerType::get(M.getContext(), 64);
        VectorType* vectorType = VectorType::get(qwordType,2);
        VectorType* vector4Type = VectorType::get(qwordType,4);
        Type *doubleType = Type::getDoubleTy(M.getContext());

        std::vector<Type*> loopDecTypes;
        loopDecTypes.push_back(voidPtrType);
        ArrayRef<Type*> loopDecTypeArray(loopDecTypes);

        Type *int32Ty, *int64Ty, *voidTy;
        PointerType  *int8PtrTy;
        int8PtrTy = Type::getInt8PtrTy(M.getContext());
        int64Ty = Type::getInt64Ty(M.getContext());
        int32Ty = Type::getInt32Ty(M.getContext());
        voidTy = Type::getVoidTy(M.getContext());


        // Definitions for creating functions for DFSan set_label and read_label
        const DataLayout &DL = M.getDataLayout();
        enum {
            ShadowWidth = 16
        };
        Module *Mod;
        LLVMContext *Ctx;
        Mod = &M;
        Ctx = &M.getContext();
        IntegerType* ShadowTy = IntegerType::get(*Ctx, ShadowWidth);
        IntegerType* IntptrTy = DL.getIntPtrType(*Ctx);
        Type *DFSanSetLabelArgs[3] = { ShadowTy, Type::getInt8PtrTy(*Ctx), IntptrTy };
        Type *DFSanReadLabelArgs[2] = { Type::getInt8PtrTy(*Ctx), IntptrTy };


        FunctionType* FTypeDecLoopByte = FunctionType::get(byteType, loopDecTypeArray, false);
        FunctionType* FTypeDecLoopWord = FunctionType::get(wordType, loopDecTypeArray, false);
        FunctionType* FTypeDecLoopDWord = FunctionType::get(dwordType, loopDecTypeArray, false);
        FunctionType* FTypeDecLoopQWord = FunctionType::get(qwordType, loopDecTypeArray, false);
        FunctionType* FTypeDecLoopDouble = FunctionType::get(doubleType, loopDecTypeArray, false);
        FunctionType* FTypeDecLoopVector = FunctionType::get(vectorType, loopDecTypeArray, false);
        FunctionType* FTypeDecLoopVector4 = FunctionType::get(vector4Type, loopDecTypeArray, false);


        FunctionType* FTypeSetLabel = FunctionType::get(Type::getVoidTy(*Ctx), DFSanSetLabelArgs, false);
        FunctionType* FTypeSetLabelForContextSensitiveCalls = FunctionType::get(Type::getVoidTy(*Ctx), Type::getInt8PtrTy(*Ctx), false);
        FunctionType* FTypeReadLabel = FunctionType::get(ShadowTy, DFSanReadLabelArgs, false);

        // All versions
        this->decryptLoopByteFunction = Function::Create(FTypeDecLoopByte, Function::ExternalLinkage, "getDecryptedValueByte", &M);
        this->decryptLoopWordFunction = Function::Create(FTypeDecLoopWord, Function::ExternalLinkage, "getDecryptedValueWord", &M);
        this->decryptLoopDWordFunction = Function::Create(FTypeDecLoopDWord, Function::ExternalLinkage, "getDecryptedValueDWord", &M);
        this->decryptLoopQWordFunction = Function::Create(FTypeDecLoopQWord, Function::ExternalLinkage, "getDecryptedValueQWord", &M);
        this->decryptLoopDoubleFunction = Function::Create(FTypeDecLoopDouble, Function::ExternalLinkage, "getDecryptedValueDouble", &M);
        this->decryptLoopVectorFunction = Function::Create(FTypeDecLoopVector, Function::ExternalLinkage, "getDecryptedValueVector", &M);
        this->decryptLoopVector4Function = Function::Create(FTypeDecLoopVector4, Function::ExternalLinkage, "getDecryptedValueVector4", &M);


        this->DFSanSetLabelFn = Function::Create(FTypeSetLabel, Function::ExternalLinkage, "dfsan_set_label", &M);
        //adding zeroext for function parameter
        if (Function *F = dyn_cast<Function>(DFSanSetLabelFn)) {
            F->addParamAttr(0, Attribute::ZExt);
        }

        this->setLabelForContextSensitiveCallsFn = Function::Create(FTypeSetLabelForContextSensitiveCalls, Function::ExternalLinkage, "setLabelForContextSensitiveCalls", &M);

        this->DFSanReadLabelFn = Function::Create(FTypeReadLabel, Function::ExternalLinkage, "dfsan_read_label", &M);
        //adding zeroext for return type
        if (Function *F = dyn_cast<Function>(DFSanReadLabelFn)) {
            F->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);
        }

        std::vector<Type*> loopEncTypeByte;
        loopEncTypeByte.push_back(voidPtrType);
        loopEncTypeByte.push_back(byteType);
        ArrayRef<Type*> loopEncTypeByteArray(loopEncTypeByte);

        std::vector<Type*> loopEncTypeWord;
        loopEncTypeWord.push_back(voidPtrType);
        loopEncTypeWord.push_back(wordType);
        ArrayRef<Type*> loopEncTypeWordArray(loopEncTypeWord);

        std::vector<Type*> loopEncTypeDWord;
        loopEncTypeDWord.push_back(voidPtrType);
        loopEncTypeDWord.push_back(dwordType);
        ArrayRef<Type*> loopEncTypeDWordArray(loopEncTypeDWord);

        std::vector<Type*> loopEncTypeQWord;
        loopEncTypeQWord.push_back(voidPtrType);
        loopEncTypeQWord.push_back(qwordType);
        ArrayRef<Type*> loopEncTypeQWordArray(loopEncTypeQWord);

        std::vector<Type*> loopEncTypeVec;
        loopEncTypeVec.push_back(voidPtrType);
        loopEncTypeVec.push_back(vectorType);
        /*loopEncTypeVec.push_back(qwordType);
        loopEncTypeVec.push_back(qwordType);*/
        ArrayRef<Type*> loopEncTypeVecArray(loopEncTypeVec);

        std::vector<Type*> loopEncTypeVec4;
        loopEncTypeVec4.push_back(voidPtrType);
        loopEncTypeVec4.push_back(vector4Type);
        ArrayRef<Type*> loopEncTypeVec4Array(loopEncTypeVec4);

        std::vector<Type*> loopEncTypeDouble;
        loopEncTypeDouble.push_back(voidPtrType);
        loopEncTypeDouble.push_back(doubleType);
        ArrayRef<Type*> loopEncTypeDoubleArray(loopEncTypeDouble);

        FunctionType* FTypeEncLoopByte = FunctionType::get(voidPtrType, loopEncTypeByteArray, false);
        FunctionType* FTypeEncLoopWord = FunctionType::get(voidPtrType, loopEncTypeWordArray, false);
        FunctionType* FTypeEncLoopDWord = FunctionType::get(voidPtrType, loopEncTypeDWordArray, false);
        FunctionType* FTypeEncLoopQWord = FunctionType::get(voidPtrType, loopEncTypeQWordArray, false);
        FunctionType* FTypeEncLoopDouble = FunctionType::get(voidPtrType, loopEncTypeDoubleArray, false);
        FunctionType* FTypeEncLoopVec = FunctionType::get(voidPtrType, loopEncTypeVecArray, false);
        FunctionType* FTypeEncLoopVec4 = FunctionType::get(voidPtrType, loopEncTypeVec4Array, false);

        this->encryptLoopByteFunction = Function::Create(FTypeEncLoopByte, Function::ExternalLinkage, "setEncryptedValueByte", &M);
        this->encryptLoopWordFunction = Function::Create(FTypeEncLoopWord, Function::ExternalLinkage, "setEncryptedValueWord", &M);
        this->encryptLoopDWordFunction = Function::Create(FTypeEncLoopDWord, Function::ExternalLinkage, "setEncryptedValueDWord", &M);
        this->encryptLoopQWordFunction = Function::Create(FTypeEncLoopQWord, Function::ExternalLinkage, "setEncryptedValueQWord", &M);
        this->encryptLoopDoubleFunction = Function::Create(FTypeEncLoopDouble, Function::ExternalLinkage, "setEncryptedValueDouble", &M);
        this->encryptLoopVecFunction = Function::Create(FTypeEncLoopVec, Function::ExternalLinkage, "setEncryptedValueVector", &M);
        this->encryptLoopVec4Function = Function::Create(FTypeEncLoopVec4, Function::ExternalLinkage, "setEncryptedValueVector4", &M);

        // The instrumented malloc function
        std::vector<Type*> mallocVec;
        mallocVec.push_back(longType);
        ArrayRef<Type*> mallocArrRef(mallocVec);
        FunctionType* FTypeMalloc = FunctionType::get(voidPtrType, mallocArrRef, false);

        this->aesMallocFunction = Function::Create(FTypeMalloc, Function::ExternalLinkage, "aes_malloc", &M);

        // The instrumented calloc function
        std::vector<Type*> callocVec;
        callocVec.push_back(longType);
        callocVec.push_back(longType);
        ArrayRef<Type*> callocArrRef(callocVec);
        FunctionType* FTypeCalloc = FunctionType::get(voidPtrType, callocArrRef, false);

        this->aesCallocFunction = Function::Create(FTypeCalloc, Function::ExternalLinkage, "aes_calloc", &M);

        // The instrumented realloc function
        std::vector<Type*> reallocVec;
        reallocVec.push_back(voidPtrType);
        reallocVec.push_back(longType);
        ArrayRef<Type*> reallocArrRef(reallocVec);
        FunctionType* FTypeRealloc = FunctionType::get(voidPtrType, reallocArrRef, false);

        this->aesReallocFunction = Function::Create(FTypeRealloc, Function::ExternalLinkage, "aes_realloc", &M);

        // The instrumented strdup function
        std::vector<Type*> strdupVec;
        strdupVec.push_back(voidPtrType);
        ArrayRef<Type*> strdupArrRef(strdupVec);
        FunctionType* FTypeStrdup = FunctionType::get(voidPtrType, strdupArrRef, false);

        this->aesStrdupFunction = Function::Create(FTypeStrdup, Function::ExternalLinkage, "aes_strdup", &M);

        // The instrumented free function
        std::vector<Type*> freeVec;
        freeVec.push_back(voidPtrType);
        ArrayRef<Type*> freeArrRef(freeVec);
        FunctionType* FTypeFree = FunctionType::get(Type::getVoidTy(*Ctx), freeArrRef, false);

        this->aesFreeFunction = Function::Create(FTypeFree, Function::ExternalLinkage, "aes_free", &M);

        // The instrumented critical free function
        this->freeWrapperFunction = Function::Create(FTypeFree, Function::ExternalLinkage, "free_wrapper", &M);

        // The instrumented free function
        std::vector<Type*> freeWithBitcastVec;
        freeWithBitcastVec.push_back(voidPtrType);
        ArrayRef<Type*> freeWithBitcastArrRef(freeWithBitcastVec);
        FunctionType* FTypeFreeWithBitcast = FunctionType::get(voidPtrType, freeWithBitcastArrRef, false);

        this->aesFreeWithBitcastFunction = Function::Create(FTypeFreeWithBitcast, Function::ExternalLinkage, "aes_freeWithBitcast", &M);


        // The "sensitivity" aware versions of memcpy
        std::vector<Type*> memcpyVec;
        memcpyVec.push_back(voidPtrType);
        memcpyVec.push_back(voidPtrType);
        memcpyVec.push_back(dwordType);
        ArrayRef<Type*> memcpyArrRef(memcpyVec);
        FunctionType* FTypeMemcpy = FunctionType::get(voidPtrType, memcpyArrRef, false);

        this->memcpySensSrcFunction = Function::Create(FTypeMemcpy, Function::ExternalLinkage, "memcpy_sens_src", &M);
        this->memcpySensDstFunction = Function::Create(FTypeMemcpy, Function::ExternalLinkage, "memcpy_sens_dst", &M);
    }

    void AESCache::initializeAes(Module &M, bool skip, std::set<Function*>& writebackCacheFunctions) {
        I128Ty = IntegerType::get(M.getContext(), 128);
        this->M = &M;
        addExternAESFuncDecls(M);
        skipVFA = skip;
        this->wbCFs = &writebackCacheFunctions;
    }

    bool AESCache::findTrueOffset(StructType* topLevelType, int topLevelOffset, int* beginOffset, StructType** nestedTypePtr, int* nestedOffsetPtr) {
        for (int i = 0; i < topLevelType->getNumElements(); i++) {
            Type* subType = topLevelType->getElementType(i);

            if (StructType* stSubType = dyn_cast<StructType>(subType)) {
                if(findTrueOffset(stSubType, topLevelOffset, beginOffset, nestedTypePtr, nestedOffsetPtr)) {
                    return true;
                }
                continue;
            }
            if (*beginOffset == topLevelOffset) {
                *nestedTypePtr = topLevelType;
                *nestedOffsetPtr = i;
                return true;
            }

            if (!isa<StructType>(subType)) {
                (*beginOffset)++;
            }
        }
        /*
           if (beginOffset == topLevelOffset) {
         *nestedTypePtr = topLevelType;
         *nestedOffsetPtr = topLevelType->getNumElements() - 1;
         errs() << "Top level type: " << *topLevelType << " top level offset: " << topLevelOffset << " true type: " << **nestedTypePtr << " true offset : " << *nestedOffsetPtr << "\n";
         return true;
         }
         */
        return false;
    }


    bool AESCache::widenSensitiveComplexType(GepObjPN* gepObjPN, std::map<PAGNode*, std::set<PAGNode*>>& ptsFromMap) {
        assert(gepObjPN->getLocationSet().isConstantOffset() && "can't handle non constant offsets in gep yet");
        std::map<std::string, StructType*> structNameTypeMap;
        for (StructType* stType: M->getIdentifiedStructTypes()) {
            structNameTypeMap[stType->getName()] = stType;
        }

        int offset = gepObjPN->getLocationSet().getOffset();
        // The usual types
        // Extract the true type
        PointerType* pointerType = dyn_cast<PointerType>(gepObjPN->getValue()->getType());
        if (pointerType) {
            // Pointer to what?
            Type* trueType = pointerType->getPointerElementType();
            StructType* nestedType = nullptr;
            int nestedOffset = -1;
            if (StructType* stType = dyn_cast<StructType>(trueType)) {
                // Because offsets are flattened we need to do this
                int beg = 0;
                findTrueOffset(stType, offset, &beg, &nestedType, &nestedOffset);
                // Widen the field
                if (nestedType) {
                    // Else it's an array within a struct
                    nestedType->addSensitiveFieldOffset(nestedOffset);
                    errs() << "Widening sensitive complex type: " << nestedType->getName() << " with offset: " << nestedOffset << " original type: " << stType->getName() << " original offset: " << offset << " \n";
                    return true;
                }
            }
        }

        Type* sizeOfType = nullptr;
        if (const CallInst* CI = dyn_cast<CallInst>(gepObjPN->getValue())) {
            MDNode* argIndNode = CI->getMetadata("sizeOfTypeArgNum");
            MDNode* sizeOfTypeNode = CI->getMetadata("sizeOfTypeName");
            if (argIndNode && sizeOfTypeNode) {
                MDString* sizeOfTypeNameStr = cast<MDString>(sizeOfTypeNode->getOperand(0));
                sizeOfType = structNameTypeMap[sizeOfTypeNameStr->getString()];
                if (!sizeOfType) {
                    sizeOfType = structNameTypeMap["struct."+sizeOfTypeNameStr->getString().str()];
                    if (!sizeOfType) {
                        assert(false && "Cannot find sizeof type");
                    }
                }
            }
        }
        if (!sizeOfType) 
            return false;
        if (StructType* stType = dyn_cast<StructType>(sizeOfType)) {
            StructType* nestedType = nullptr;
            int nestedOffset = -1;
            int beg = 0;

            // Because offsets are flattened we need to do this
            findTrueOffset(stType, offset, &beg, &nestedType, &nestedOffset);
            // Widen the field
            if (nestedType) {
                nestedType->addSensitiveFieldOffset(nestedOffset);
                errs() << "Widening sensitive complex type: " << nestedType->getName() << " with offset: " << nestedOffset << " original type: " << stType->getName() << " original offset: " << offset << " \n";
            }

            return true;
        }
        return false;
    }

    bool AESCache::allFieldsSensitive(StructType* stType) {
        bool allFieldsSen = true;
        for (int i = 0; i < stType->getNumElements(); i++) {
            if (StructType* subType = dyn_cast<StructType>(stType->getElementType(i))) {
                allFieldsSen &= allFieldsSensitive(subType);
            } else {
                allFieldsSen &= stType->isSensitiveField(i);
            }
        }
        return allFieldsSen;
    }

    void AESCache::gepCallInstHandlerForPartitioning(Module &M, CallInst* callInst, GepObjPN* gepNode){

        LLVMContext *Ctx;
        Ctx = &M.getContext();
        const DataLayout &DL = M.getDataLayout();

        std::map<std::string, StructType*> structNameTypeMap;
        for (StructType* stType: M.getIdentifiedStructTypes()) {
            structNameTypeMap[stType->getName()] = stType;
        }


        IRBuilder<> Builder(callInst);
        Builder.SetInsertPoint(callInst->getNextNode());

        ConstantInt* label = Builder.getInt16(1);
        ConstantInt* noOfByte = Builder.getInt64(1);
        Value* PtrOperand = nullptr;
        CallInst* setLabel = nullptr;
        IntegerType *IntptrTy;
        IntptrTy = Type::getInt32Ty(M.getContext());
        Size_t offset = gepNode->getLocationSet().getOffset();
        //errs()<<"Offset is "<<offset;

        // For a gepNode with callInst, we need to find the
        // type of struct and actual offset to create gep
        // Instruction
        Type* structType = nullptr;
        MDNode* argIndNode = callInst->getMetadata("sizeOfTypeArgNum");
        MDNode* structTypeNode = callInst->getMetadata("sizeOfTypeName");

        if (argIndNode && structTypeNode) {
            MDString* structTypeNameStr = cast<MDString>(structTypeNode->getOperand(0));
            structType = structNameTypeMap[structTypeNameStr->getString()];
            if (!structType) {
                structType = structNameTypeMap["struct."+structTypeNameStr->getString().str()];
                if (!structType) {
                    assert(false && "Cannot find sizeof type");
                }
            }
        }
        if(!structType){
            setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, callInst, noOfByte});
            setLabel->addParamAttr(0, Attribute::ZExt);
            return;
        }
        if (StructType* stType = dyn_cast<StructType>(structType)) {
            StructType* nestedType = nullptr;
            int nestedOffset = -1;
            int beg = 0;

            findTrueOffset(stType, offset, &beg, &nestedType, &nestedOffset);
            if (nestedType) {
                //errs() << "Nested type name: " << nestedType->getName() << " with offset: " << nestedOffset << " original struct type: ";
                //errs() << stType->getName() << " original offset: " << offset << " \n";

                Value* bitcast = nullptr;
                bitcast = Builder.CreateBitCast(callInst, llvm::PointerType::getUnqual(nestedType));
                //errs()<<"bitcast "<<*bitcast<<"\n";

                Value* indexList[2] = {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, nestedOffset)};
                Value* gepInst = Builder.CreateInBoundsGEP(bitcast, ArrayRef<Value*>(indexList, 2));
                PtrOperand = Builder.CreateBitCast(gepInst, Type::getInt8PtrTy(*Ctx));
                //Type* T = dyn_cast<PointerType>((dyn_cast<Instruction>(PtrOperand)->getOperand(0))->getType())->getElementType();
                Type *T = dyn_cast<PointerType>(gepInst->getType())->getElementType();
                if(T->isArrayTy()){
                    ArrayType* Arr = dyn_cast<ArrayType>(T);
                    int noOfElements = Arr->getNumElements();
                    int bitWidth = cast<IntegerType>(Arr->getElementType())->getBitWidth();
                    int byteLength = (noOfElements * bitWidth)/8;
                    noOfByte = Builder.getInt64(byteLength);
                    //errs()<<"Array and size is "<<noOfElements<<" and bitwidth is "<<bitWidth<<"\n";
                }
                setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, PtrOperand, noOfByte});
                setLabel->addParamAttr(0, Attribute::ZExt);
            }
        }

    }


    void AESCache::gepAllocaInstHandlerForPartitioning(Module &M, AllocaInst* allocInst, GepObjPN* gepNode, Value* senVal){

        LLVMContext *Ctx;
        Ctx = &M.getContext();
        const DataLayout &DL = M.getDataLayout();

        IRBuilder<> Builder(allocInst);
        Builder.SetInsertPoint(allocInst->getNextNode());

        ConstantInt* label = Builder.getInt16(1);
        ConstantInt* noOfByte = Builder.getInt64(1);
        Value* PtrOperand = nullptr;
        CallInst* setLabel = nullptr;
        //For a gepNode we need to create gepELementPtr instruction
        IntegerType *IntptrTy;  
        IntptrTy = Type::getInt32Ty(M.getContext());
        Size_t offset = gepNode->getLocationSet().getOffset();
        //errs()<<"Offset is "<<offset<<"\n";
        Type* type = dyn_cast<PointerType>(senVal->getType())->getElementType();
        if(type->isStructTy()){
            StructType* structType = dyn_cast<StructType>(type);
            //errs()<< " Type of alloca "<<structType->getName()<<"\n";
            StructType* nestedType = nullptr;
            int nestedOffset = -1;
            int beg = 0;

            findTrueOffset(structType, offset, &beg, &nestedType, &nestedOffset);
            if (nestedType) {
                //errs() << "Nested type name: " << nestedType->getName() << " with offset: " << nestedOffset << " original struct type: ";
                //errs() << structType->getName() << " original offset: " << offset << " \n";

                Value* bitcast = nullptr;
                bitcast = Builder.CreateBitCast(allocInst, llvm::PointerType::getUnqual(nestedType));
                errs()<<"bitcast "<<*bitcast<<"\n";

                Value* indexList[2] = {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, nestedOffset)};
                Value* gepInst = Builder.CreateInBoundsGEP(bitcast, ArrayRef<Value*>(indexList, 2));
                PtrOperand = Builder.CreateBitCast(gepInst, Type::getInt8PtrTy(*Ctx));
                //Type* T = dyn_cast<PointerType>((dyn_cast<Instruction>(PtrOperand)->getOperand(0))->getType())->getElementType();
            } else {
                Value* indexList[2] = {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, offset)};
                Value* gepInst = Builder.CreateInBoundsGEP(senVal, ArrayRef<Value*>(indexList, 2));
                PtrOperand = Builder.CreateBitCast(gepInst, Type::getInt8PtrTy(*Ctx));
            }
        } else {
            PtrOperand = Builder.CreateBitCast(senVal, Type::getInt8PtrTy(*Ctx));
        }

        //finding size of type
        Type* T = dyn_cast<PointerType>((dyn_cast<Instruction>(PtrOperand)->getOperand(0))->getType())->getElementType();
        int sizeOfType = M.getDataLayout().getTypeAllocSize(T);
        //errs()<<"Size of Type is "<<sizeOfType<<"\n";
        noOfByte = Builder.getInt64(sizeOfType);

        /*Value* size = nullptr;
          ConstantInt* multiplier = Builder.getInt64(128);
          size = Builder.CreateMul(dyn_cast<Value>(noOfByte), dyn_cast<Value>(multiplier));*/

        setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, PtrOperand, noOfByte});
        setLabel->addParamAttr(0, Attribute::ZExt);
    }

    void AESCache::findReturnInstsOfFunction(Function* func, std::vector<ReturnInst*>& returnVec) {
        for (inst_iterator I = inst_begin(func), E = inst_end(func); I != E; ++I) {
            if (ReturnInst* retInst = dyn_cast<ReturnInst>(&*I)) {
                returnVec.push_back(retInst);
            }
        }
    }                             

    void AESCache::clearLabelForSensitiveObjects(Module& M, std::vector<PAGNode*>& SensitiveObjList) {
        // Stack variables can also have sensitive labels associated with them
        // We need to clear them right before the return statements of their
        // functions.

        LLVMContext& Ctx = M.getContext();
        // For every stack variable that is sensitive
        for (PAGNode* sensitiveNode: SensitiveObjList) {
            Value* sensitiveValue = const_cast<Value*>(sensitiveNode->getValue());
            if (AllocaInst* sensitiveStackVar = dyn_cast<AllocaInst>(sensitiveValue)) {
                std::vector<ReturnInst*> returnInsts;
                findReturnInstsOfFunction(sensitiveStackVar->getParent()->getParent(), returnInsts);

                for (ReturnInst* returnInst: returnInsts) {
                    IRBuilder<> Builder(returnInst);

                    ConstantInt* label = Builder.getInt16(0); // 0 to clear
                    Type* sensitiveTy = sensitiveStackVar->getAllocatedType();
                    ConstantInt* noOfBytes = Builder.getInt64(M.getDataLayout().getTypeAllocSize(sensitiveTy));

                    Value* ptr = Builder.CreateBitCast(sensitiveStackVar, Type::getInt8PtrTy(Ctx));

                    CallInst* clearCall = Builder.CreateCall(this->DFSanSetLabelFn, {label, ptr, noOfBytes});
                } 
            }
        }
    }

    void AESCache::setLabelsForSensitiveObjects(Module &M, std::set<PAGNode*>* SensitiveAllocaList,
            std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap, std::map<PAGNode*, std::set<PAGNode*>>& ptsFromMap) {
        LLVMContext *Ctx;
        Ctx = &M.getContext();
        const DataLayout &DL = M.getDataLayout();
        //Setting Label for Sensitive Objects

        for (PAGNode* senNode: *SensitiveAllocaList) {
            assert(senNode->hasValue());
            Value* senVal = const_cast<Value*>(senNode->getValue());
            if(Instruction *I = dyn_cast<Instruction>(senVal)){
                //errs() << "Value " << *senVal<<"\n";
                IRBuilder<> Builder(I);
                Builder.SetInsertPoint(I->getNextNode());

                // For now, we are adding constant single label for all sensitive objects
                ConstantInt* label = Builder.getInt16(1);
                ConstantInt* noOfByte = Builder.getInt64(1);
                Value* PtrOperand = nullptr;
                CallInst* setLabel = nullptr;

                if (AllocaInst* allocInst = dyn_cast<AllocaInst>(senVal)) {
                    if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senNode)) {
                        gepAllocaInstHandlerForPartitioning(M, allocInst, gepNode, senVal);
                    } else {
                        // Is an alloca instruction
                        PtrOperand = Builder.CreateBitCast(senVal, Type::getInt8PtrTy(*Ctx));

                        //finding size of type
                        //Type* T = dyn_cast<PointerType>((dyn_cast<Instruction>(PtrOperand)->getOperand(0))->getType())->getElementType();
                        Type* T = allocInst->getAllocatedType();
                        int sizeOfType = M.getDataLayout().getTypeAllocSize(T);
                        //errs()<<"Size of Type is "<<sizeOfType<<"\n";
                        noOfByte = Builder.getInt64(sizeOfType);

                        setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, PtrOperand, noOfByte});
                        setLabel->addParamAttr(0, Attribute::ZExt);
                    }
                } else if (CallInst* callInst = dyn_cast<CallInst>(senVal)){
                    if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senNode)){
                        gepCallInstHandlerForPartitioning(M, callInst, gepNode);
                    } else {
                        // Call Instruction, no need to add bitcast
                        Function* function = callInst->getCalledFunction();
                        Value* size = nullptr;
                        ConstantInt* multiplier = Builder.getInt64(128);
                        if (function) {
                            StringRef mallocStr("aes_malloc");
                            StringRef callocStr("aes_calloc");
                            StringRef reallocStr("aes_realloc");
                            if (mallocStr.equals(function->getName())) {
                                Value* argumentOfMalloc = callInst->getArgOperand(0);
                                size = argumentOfMalloc;
                                //errs()<<"Argument of Malloc is "<<*argumentOfMalloc<<"\n";
                            } else if (callocStr.equals(function->getName())) {
                                Value* argument1OfCalloc = callInst->getArgOperand(0);
                                Value* argument2OfCalloc = callInst->getArgOperand(1);
                                size = Builder.CreateMul(argument1OfCalloc, argument2OfCalloc);
                            } else if (reallocStr.equals(function->getName())) {
                                    Value* argumentOfRealloc = callInst->getArgOperand(1);
                                    size = argumentOfRealloc;
                            } else {//Context Sensitive function calls
                                if (PointerType* ptrType = dyn_cast<PointerType>(callInst->getType())) {
                                    IntegerType* voidType = IntegerType::get(callInst->getContext(), 8);
                                    PointerType* voidPtrType = PointerType::get(voidType, 0);
                                    Value* argVal = dyn_cast<Value>(callInst);
                                    if (ptrType != voidPtrType){
                                        argVal = Builder.CreateBitCast(callInst, voidPtrType);
                                    }
                                    /* widening memory allocation for context sensitive malloc calls*/
                                    // skip if wrapper does not have any argument
                                    /*
                                    if(callInst->getNumOperands() > 1){
                                        IRBuilder<> builder(callInst);
                                        ConstantInt* multiplier1 = builder.getInt32(128);
                                        Value* arg = callInst->getArgOperand(0);
                                        Value* mul = builder.CreateMul(arg, dyn_cast<Value>(multiplier1));
                                        callInst->setOperand(0,mul);
                                    }
                                    */
                                    Builder.CreateCall(this->setLabelForContextSensitiveCallsFn, {argVal});
                                    continue;
                                }else {
                                    assert(dyn_cast<PointerType>(callInst->getType()) && "Not a pointerType; can't set label for non-pointer type");
                                }
                            }
                            size = Builder.CreateMul(size, dyn_cast<Value>(multiplier));
                        }
                        setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, callInst, size});
                        setLabel->addParamAttr(0, Attribute::ZExt);
                    }
                }
            }
        }
    }
    void AESCache::unsetLabelsForCriticalFreeWrapperFunctions (Module &M, std::set<Function*>& CriticalFreeWrapperFunctions) {
        /* Finding corresponding callInsts for Critical Free Wrapper Functions so that we can 
         * add instrumentations */
        for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
            if (auto *F = dyn_cast<Function>(MIterator)) {
                for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                    if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                        for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                            if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                                if (CallInst* callInst = dyn_cast<CallInst>(Inst)) {
                                    Function* function = callInst->getCalledFunction();
                                    if (std::find(CriticalFreeWrapperFunctions.begin(), CriticalFreeWrapperFunctions.end(), function) != CriticalFreeWrapperFunctions.end()) {
                                        IRBuilder<> Builder(callInst);
                                        Value* argument = callInst->getArgOperand(0);
                                        if (PointerType* argType = dyn_cast<PointerType>(argument->getType())) {
                                            IntegerType* voidType = IntegerType::get(callInst->getContext(), 8);
                                            PointerType* voidPtrType = PointerType::get(voidType, 0);
                                            // bitcast if not a void pointer
                                            if (argType != voidPtrType){
                                                argument = Builder.CreateBitCast(argument, voidPtrType);
                                            }
                                            Value* val  = Builder.CreateCall(this->freeWrapperFunction, {argument});
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
    void AESCache::addDynamicCheckForSetLabel(StoreInst* stInst, CallInst* callInst){
        
        IRBuilder<> Builder(stInst);

        Value* PtrOperand = nullptr;
        CallInst* readLabel = nullptr;
        Value* size = nullptr;
        CallInst* setLabel = nullptr;

        Value* stInstPtrOperand = stInst->getPointerOperand();
        Type* byteType = Type::getInt8Ty(callInst->getContext());
        PointerType* voidPtrType = PointerType::get(byteType, 0);

        ConstantInt* noOfByte = Builder.getInt64(1);
        ConstantInt *One = Builder.getInt16(1);
        ConstantInt* label = Builder.getInt16(1);
        ConstantInt* multiplier = Builder.getInt64(128);

        Function* function = callInst->getCalledFunction();
        StringRef mallocStr("aes_malloc");
        StringRef callocStr("aes_calloc");
        StringRef reallocStr("aes_realloc");
        if (PointerType* ptrType = dyn_cast<PointerType>(stInstPtrOperand->getType()->getPointerElementType())){
            
            PtrOperand = Builder.CreateBitCast(stInstPtrOperand, voidPtrType);
            
            readLabel = Builder.CreateCall(DFSanReadLabelFn,{PtrOperand , noOfByte});
            readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

            Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
            Instruction* SplitBefore = cast<Instruction>(stInst);
            TerminatorInst* ThenTerm = SplitBlockAndInsertIfThen(cmpInst, SplitBefore, false);

            Builder.SetInsertPoint(ThenTerm);
            if (mallocStr.equals(function->getName())){
                Value* argumentOfMalloc = callInst->getArgOperand(0);
                size = argumentOfMalloc;
            } else if (callocStr.equals(function->getName())){
                Value* argument1OfCalloc = callInst->getArgOperand(0);
                Value* argument2OfCalloc = callInst->getArgOperand(1);
                size = Builder.CreateMul(argument1OfCalloc, argument2OfCalloc);
            } else if (reallocStr.equals(function->getName())){
                Value* argumentOfRealloc = callInst->getArgOperand(1);
                size = argumentOfRealloc;
            }

            size = Builder.CreateMul(size, dyn_cast<Value>(multiplier));
            setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, callInst, size});
            setLabel->addParamAttr(0, Attribute::ZExt);

            Builder.SetInsertPoint(SplitBefore);
        }
    }


    void AESCache::trackDownAllRecursiveSensitiveAllocations(Module &M){
        /* Finds out all users of malloc/calloc/realloc calls and add checks
         * for the store instructions; high level idea is wheneven a pointer will
         * take address, we will add check to it. If the pointer itself
         * sensitive, then we will tag the address it points to as sensiitve*/
        for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
            if (auto *F = dyn_cast<Function>(MIterator)) {
                for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                    if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                        for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                            if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                                if (CallInst* callInst = dyn_cast<CallInst>(Inst)) {
                                    Function* function = callInst->getCalledFunction();
                                    if (function) {
                                        StringRef mallocStr("aes_malloc");
                                        StringRef callocStr("aes_calloc");
                                        StringRef reallocStr("aes_realloc");
                                        if (mallocStr.equals(function->getName()) || callocStr.equals(function->getName()) || reallocStr.equals(function->getName()))  {
                                            for (User* callInstUser: callInst->users()) {
                                                if (BitCastInst* bcInst = dyn_cast<BitCastInst>(callInstUser)){
                                                    for (User* bitCastUser: bcInst->users()){
                                                        if (StoreInst* stInst = dyn_cast<StoreInst>(bitCastUser)){
                                                            addDynamicCheckForSetLabel(stInst, callInst);
                                                        }
                                                    }
                                                } else if (StoreInst* storeInst = dyn_cast<StoreInst>(callInstUser)){
                                                    addDynamicCheckForSetLabel(storeInst, callInst);
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
        }
    }

        void AESCache::widenSensitiveAllocationSites(Module &M, std::vector<PAGNode*>& SensitiveAllocaList,
                std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap, std::map<PAGNode*, std::set<PAGNode*>>& ptsFromMap) {
            for (PAGNode* senNode: SensitiveAllocaList) {
                bool widenedStructType = false;
                // If it is a GepObjPN we need to be careful about what to widen in it
                if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senNode)) {
                    errs() << "This is what I tried to widen: " << *gepNode << " " << gepNode->getLocationSet().getOffset() << "\n";
                    widenedStructType = widenSensitiveComplexType(gepNode, ptsFromMap);
                } 
                assert(senNode->hasValue());
                // Add padding regardless if we've padded individual fields
                // Easy stuff
                Value* senVal = const_cast<Value*>(senNode->getValue());
                if (AllocaInst* allocInst = dyn_cast<AllocaInst>(senVal)) {
                    // Is an alloca instruction
                    allocInst->setAlignment(16);
                    IRBuilder<> Builder(allocInst);
                    AllocaInst* paddingAllocaInst2 = Builder.CreateAlloca(I128Ty, 0, "padding");
                    MDNode* N2 = MDNode::get(allocInst->getContext(), MDString::get(allocInst->getContext(), "padding"));
                    paddingAllocaInst2->setMetadata("PADDING", N2);

                    // Find insertion point for the store
                    BasicBlock* parentBB = allocInst->getParent();
                    Instruction* insertionPoint = nullptr;
                    for (BasicBlock::iterator BBIterator = parentBB->begin(); BBIterator != parentBB->end(); BBIterator++) {
                        if (Instruction* Inst = dyn_cast<Instruction>(BBIterator)) {
                            if (!isa<AllocaInst>(Inst)) {
                                insertionPoint = Inst;
                                break;
                            }
                        }
                    }
                }
            }

            // As for global variables, just align all of them to a 128 bit boundary
            for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
                if (I->getName() != "llvm.global.annotations") {
                    GlobalVariable* GV = cast<GlobalVariable>(I);
                    GV->setAlignment(16);
                }
            }

            // Do processing for all globalvariables
            for (GlobalVariable& gVar: M.getGlobalList()) {
                if (gVar.hasInitializer()) {
                    Constant* init = gVar.getInitializer();
                    if (Function* function = dyn_cast<Function>(init)) {
                        if (function->getName() == "malloc") {
                            // Change this to aes_malloc
                            gVar.setInitializer(aesMallocFunction);
                        } else if (function->getName() == "calloc") {
                            gVar.setInitializer(aesCallocFunction);
                        } else if (function->getName() == "realloc") {
                            gVar.setInitializer(aesReallocFunction);
                        } else if (function->getName() == "strdup") {
                            gVar.setInitializer(aesStrdupFunction);
                        }
                    }
                }
            }

            // Do processing for all instructions
            for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
                if (auto *F = dyn_cast<Function>(MIterator)) {
                    // Get the local sensitive values
                    for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                        if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                            //outs() << "Basic block found, name : " << BB->getName() << "\n";
                            for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                                if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                                    if (CallInst* callInst = dyn_cast<CallInst>(Inst)) {
                                        // Is a malloc instruction
                                        Function* function = callInst->getCalledFunction();
                                        StringRef freeStr("free");
                                        if (function) {
                                            StringRef mallocStr("malloc");
                                            StringRef callocStr("calloc");
                                            StringRef reallocStr("realloc");
                                            StringRef strdupStr("strdup");
                                            StringRef exitStr("exit");
                                            if (mallocStr.equals(function->getName()))  {
                                                // Change the called function to inst_malloc
                                                callInst->setCalledFunction(aesMallocFunction);
                                            } else if (callocStr.equals(function->getName())) {
                                                callInst->setCalledFunction(aesCallocFunction);
                                            } else if (reallocStr.equals(function->getName())) {
                                                callInst->setCalledFunction(aesReallocFunction);
                                            } else if (strdupStr.equals(function->getName())) {
                                                callInst->setCalledFunction(aesStrdupFunction);
                                            } else if (freeStr.equals(function->getName()) ) {
                                                // No need to writeback
                                                /*
                                                std::vector<Value*> argList;
                                                CallInst* writebackInst = CallInst::Create(this->writebackFunction, argList);
                                                writebackInst->insertAfter(callInst);
                                                */
                                                callInst->setCalledFunction(aesFreeFunction);
                                            } else if (exitStr.equals(function->getName()) ) {
                                                IRBuilder<> Builder(callInst);
                                                std::vector<Value*> argList;
                                                Builder.CreateCall(this->getEncDecCountFunction, argList);
                                            }
                                        } else {
                                            if (BitCastOperator* castOp = dyn_cast<BitCastOperator>(callInst->getCalledValue())) {
                                                for (int i = 0; i < castOp->getNumOperands(); i++) {
                                                    Value* op = castOp->getOperand(i);
                                                    if (Function* func = dyn_cast<Function>(op)) {
                                                        if (freeStr.equals(func->getName())) {
                                                            // No need to
                                                            // writeback 
                                                            /*
                                                            std::vector<Value*> argList;
                                                            CallInst* writebackInst = CallInst::Create(this->writebackFunction, argList);
                                                            writebackInst->insertAfter(callInst);
                                                            */
                                                            callInst->setCalledFunction(aesFreeWithBitcastFunction);
                                                        }
                                                    }
                                                }

                                            }
                                        }
                                    } else if (ReturnInst* retInst = dyn_cast<ReturnInst>(Inst)) {
                                        if ( F->getName() == "main"){
                                            IRBuilder<> Builder(retInst);
                                            std::vector<Value*> argList;
                                            Builder.CreateCall(this->getEncDecCountFunction, argList);
                                        }
                                        // Only if this function is identified
                                        // as something that needs
                                        // writebackCacheFunctions
                                        if (std::find(wbCFs->begin(), wbCFs->end(), retInst->getParent()->getParent()) != wbCFs->end()) {
                                            writeback(retInst); // Invalidate the cache
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            std::set<StructType*> typeSet;
            // Now consolidate. If all fields of a struct are sensitive, then
            // nothing
            for (StructType* stType: M.getIdentifiedStructTypes()) {
                bool allFieldsSen = allFieldsSensitive(stType);
                if (allFieldsSen) {
                    errs() << "Type: " << *stType << " became fully sensitive!\n";
                    //stType->getSensitiveFieldOffsets().clear();
                    typeSet.insert(stType);
                }
            }

            for (StructType* stType: typeSet) {
                stType->getSensitiveFieldOffsets().clear();
            }

            // So which types finally became sensitive?
            for (StructType* stType: M.getIdentifiedStructTypes()) {
                if (stType->getNumSensitiveFields() > 0) {
                    errs() << "Partially sensitive type: "<< *stType << " has following sensitive offsets: ";
                    for (int fld: stType->getSensitiveFieldOffsets()) {
                        errs() << fld << " ";
                    }
                    errs() << "\n";
                }

            }

            // Now that we've done this, we should also take care of type casts
            for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
                if (auto *F = dyn_cast<Function>(MIterator)) {
                    // Get the local sensitive values
                    for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                        if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                            //outs() << "Basic block found, name : " << BB->getName() << "\n";
                            for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                                if (BitCastInst *BCInst = dyn_cast<BitCastInst>(BBIterator)) {
                                    Type* srcType = BCInst->getSrcTy();
                                    Type* destType = BCInst->getDestTy();
                                    Type* srcBaseType = findBaseType(srcType);
                                    Type* destBaseType = findBaseType(destType);
                                    if (StructType* destStType = dyn_cast<StructType>(destBaseType)) {
                                        if (StructType* srcStType = dyn_cast<StructType>(srcBaseType)) {
                                            //errs() << srcStType->getName() << " casted to " << destStType->getName() << "\n";
                                            // Copy over sensitive fields
                                            for (int sensitiveField: srcStType->getSensitiveFieldOffsets()) {
                                                destStType->addSensitiveFieldOffset(sensitiveField);
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

        Type* AESCache::findBaseType(Type* type) {
            Type* trueType = type;
            while (trueType->isPointerTy()) {
                trueType = trueType->getPointerElementType();
            }
            return trueType;
        }

        /*
         * Check if the particular offset of the value pointed to by ptr is in the cache
         * Return the register if it is, null otherwise
         */
        OffsetXMMPair* AESCache::findValueInCache(Value* ptr, int offsetBytes) {
            std::map<Value*, std::vector<OffsetXMMPair*>>::iterator it = cacheMap.find(ptr);
            if (it != cacheMap.end()) {
                std::vector<OffsetXMMPair*> offXMMList = it->second;
                for (OffsetXMMPair* pair: offXMMList) {
                    if (offsetBytes >= pair->startOffsetBytes && offsetBytes < pair->startOffsetBytes + 16) {
                        return pair;
                    }
                }
            }

            return nullptr;
        }

        void AESCache::insertInsertByteToXMM(llvm::StoreInst* SI, int byteOffset, int xmmRegNo) {
            IRBuilder<> Builder(SI);
            std::vector<llvm::Type *> asmArgTypes;
            asmArgTypes.push_back(IntegerType::get(SI->getContext(), 8));
            ArrayRef<Type*> asmArgArrayRef(asmArgTypes);

            FunctionType* FuncTy = FunctionType::get(Type::getVoidTy(SI->getContext()), asmArgArrayRef, false);
            std::string AsmStringStr = "pinsrb $$" + std::to_string(byteOffset) + ", $0, %xmm13 ;";
            StringRef AsmString(AsmStringStr) ;
            StringRef Constraints = "r";
            InlineAsm* pextAsm = InlineAsm::get(FuncTy, AsmString, Constraints, true /*hasSideEffects*/, false /*align stack*/, llvm::InlineAsm::AD_ATT);
            std::vector<llvm::Value*> argsArr;
            argsArr.push_back(SI->getValueOperand());

            ArrayRef<Value*> args(argsArr);
            Value* result = Builder.CreateCall(pextAsm, args); 
        }

        void AESCache::insertInsertWordToXMM(llvm::StoreInst* SI, int wordOffset, int xmmRegNo) {
            IRBuilder<> Builder(SI);
            std::vector<llvm::Type *> asmArgTypes;
            asmArgTypes.push_back(IntegerType::get(SI->getContext(), 16));
            ArrayRef<Type*> asmArgArrayRef(asmArgTypes);

            FunctionType* FuncTy = FunctionType::get(Type::getVoidTy(SI->getContext()), asmArgArrayRef, false);
            std::string AsmStringStr = "pinsrw $$" + std::to_string(wordOffset) + ", $0, %xmm13 ;";
            StringRef AsmString(AsmStringStr) ;
            StringRef Constraints = "r";
            InlineAsm* pextAsm = InlineAsm::get(FuncTy, AsmString, Constraints, true /*hasSideEffects*/, false /*align stack*/, llvm::InlineAsm::AD_ATT);
            std::vector<llvm::Value*> argsArr;
            argsArr.push_back(SI->getValueOperand());

            ArrayRef<Value*> args(argsArr);
            Value* result = Builder.CreateCall(pextAsm, args); 
        }

        void AESCache::insertInsertDWordToXMM(llvm::StoreInst* SI, int dwordOffset, int xmmRegNo) {
            IRBuilder<> Builder(SI);
            std::vector<llvm::Type *> asmArgTypes;
            asmArgTypes.push_back(IntegerType::get(SI->getContext(), 32));

            ArrayRef<Type*> asmArgArrayRef(asmArgTypes);

            FunctionType* FuncTy = FunctionType::get(Type::getVoidTy(SI->getContext()), asmArgArrayRef, false);
            std::string AsmStringStr = "pinsrd $$" + std::to_string(dwordOffset) + ", $0, %xmm13 ;";
            StringRef AsmString(AsmStringStr) ;
            StringRef Constraints = "r";
            InlineAsm* pextAsm = InlineAsm::get(FuncTy, AsmString, Constraints, true /*hasSideEffects*/, false /*align stack*/, llvm::InlineAsm::AD_ATT);
            std::vector<llvm::Value*> argsArr;
            argsArr.push_back(SI->getValueOperand());

            ArrayRef<Value*> args(argsArr);
            Value* result = Builder.CreateCall(pextAsm, args); 

        }

        void AESCache::insertInsertQWordToXMM(llvm::StoreInst* SI, int qwordOffset, int xmmRegNo) {
            IRBuilder<> Builder(SI);
            std::vector<llvm::Type *> asmArgTypes;
            asmArgTypes.push_back(IntegerType::get(SI->getContext(), 64));

            ArrayRef<Type*> asmArgArrayRef(asmArgTypes);

            FunctionType* FuncTy = FunctionType::get(Type::getVoidTy(SI->getContext()), asmArgArrayRef, false);
            std::string AsmStringStr = "pinsrq $$" + std::to_string(qwordOffset) + ", $0, %xmm13 ;";
            StringRef AsmString(AsmStringStr) ;
            StringRef Constraints = "r";
            InlineAsm* pextAsm = InlineAsm::get(FuncTy, AsmString, Constraints, true /*hasSideEffects*/, false /*align stack*/, llvm::InlineAsm::AD_ATT);
            std::vector<llvm::Value*> argsArr;
            argsArr.push_back(SI->getValueOperand());

            ArrayRef<Value*> args(argsArr);
            Value* result = Builder.CreateCall(pextAsm, args); 
        }

        Value* AESCache::insertExtractByteFromXMM(LoadInst* LI, int byteOffset, int xmmRegNo) {
            IRBuilder<> Builder(LI);
            std::vector<llvm::Type *> asmArgTypes; 
            ArrayRef<Type*> asmArgArrayRef(asmArgTypes);

            FunctionType* FuncTy = FunctionType::get(IntegerType::get(LI->getContext(), 8), asmArgArrayRef, false);
            std::string AsmStringStr = "pextrb $$"+std::to_string(byteOffset) + ", %xmm13, $0;";

            StringRef AsmString(AsmStringStr) ;
            StringRef Constraints = "=r";
            InlineAsm* pextAsm = InlineAsm::get(FuncTy, AsmString, Constraints, true /*hasSideEffects*/, false /*align stack*/, llvm::InlineAsm::AD_ATT);
            std::vector<llvm::Value*> argsArr;

            ArrayRef<Value*> args(argsArr);
            Value* result = Builder.CreateCall(pextAsm, args); 
            return result;
        }

        Value* AESCache::insertExtractWordFromXMM(LoadInst* LI, int wordOffset, int xmmRegNo) {
            IRBuilder<> Builder(LI);
            std::vector<llvm::Type *> asmArgTypes; 
            ArrayRef<Type*> asmArgArrayRef(asmArgTypes);

            FunctionType* FuncTy = FunctionType::get(IntegerType::get(LI->getContext(), 16), asmArgArrayRef, false);
            std::string AsmStringStr = "pextrw $$"+std::to_string(wordOffset) + ", %xmm13, $0;";

            StringRef AsmString (AsmStringStr);
            StringRef Constraints = "=r";
            InlineAsm* pextAsm = InlineAsm::get(FuncTy, AsmString, Constraints, true /*hasSideEffects*/, false /*align stack*/, llvm::InlineAsm::AD_ATT);
            std::vector<llvm::Value*> argsArr;

            ArrayRef<Value*> args(argsArr);
            Value* result = Builder.CreateCall(pextAsm, args); 
            return result;

        }

        Value* AESCache::insertExtractDWordFromXMM(LoadInst* LI, int dwordOffset, int xmmRegNo) {
            IRBuilder<> Builder(LI);
            std::vector<llvm::Type *> asmArgTypes; 
            ArrayRef<Type*> asmArgArrayRef(asmArgTypes);

            FunctionType* FuncTy = FunctionType::get(IntegerType::get(LI->getContext(), 32), asmArgArrayRef, false);
            std::string AsmStringStr = "pextrd $$"+std::to_string(dwordOffset) + ", %xmm13, $0;";
            StringRef AsmString(AsmStringStr);
            StringRef Constraints = "=r";
            InlineAsm* pextAsm = InlineAsm::get(FuncTy, AsmString, Constraints, true /*hasSideEffects*/, false /*align stack*/, llvm::InlineAsm::AD_ATT);
            std::vector<llvm::Value*> argsArr;

            ArrayRef<Value*> args(argsArr);
            Value* result = Builder.CreateCall(pextAsm, args); 
            return result;
        }

        Value* AESCache::insertExtractQWordFromXMM(LoadInst* LI, int qwordOffset, int xmmRegNo) {
            IRBuilder<> Builder(LI);
            std::vector<llvm::Type *> asmArgTypes; 
            ArrayRef<Type*> asmArgArrayRef(asmArgTypes);

            FunctionType* FuncTy = FunctionType::get(IntegerType::get(LI->getContext(), 64), asmArgArrayRef, false);
            std::string AsmStringStr = "pextrq $$"+std::to_string(qwordOffset) + ", %xmm13, $0;";
            StringRef AsmString(AsmStringStr);
            StringRef Constraints = "=r";
            InlineAsm* pextAsm = InlineAsm::get(FuncTy, AsmString, Constraints, true /*hasSideEffects*/, false /*align stack*/, llvm::InlineAsm::AD_ATT);
            std::vector<llvm::Value*> argsArr;

            ArrayRef<Value*> args(argsArr);
            Value* result = Builder.CreateCall(pextAsm, args); 
            return result;
        }

        Value* AESCache::setEncryptedValueCached(StoreInst* plainTextVal) {
            int byteOffset = 0;
            Value* PointerVal = nullptr;
            Type* PlainTextValType = nullptr;
            GetElementPtrInst* GEPVal;
            IRBuilder<> Builder(plainTextVal);
            IntegerType* PlainTextValIntType = nullptr;
            Type* PlainTextValDoubleType = nullptr;
            PointerType* PlainTextValPtrType = nullptr;
            VectorType* PlainTextValVecType = nullptr;

            StoreInst* stInst = dyn_cast<StoreInst>(plainTextVal);
            Value* stInstPtrOperand = stInst->getPointerOperand();
            Value* stInstValueOperand = stInst->getValueOperand();

            /*if (stInstPtrOperand->getType()->getPointerElementType()->isPointerTy()) {
              errs()<<" Pointer Type "<<*stInstPtrOperand<<"\n";
              auto* originalStore = stInst->clone();
              originalStore->insertBefore(stInst);
              errs()<<"Created Store "<<*originalStore<<"\n";
              return nullptr;
              }*/
            Type* byteType = Type::getInt8Ty(plainTextVal->getContext());
            PointerType* bytePtrType = PointerType::get(byteType, 0);

            bool isLoop = false;
            int INCREMENT = 0;
            PlainTextValIntType = dyn_cast<IntegerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
            PlainTextValPtrType = dyn_cast<PointerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
            PlainTextValVecType = dyn_cast<VectorType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());

            if (Type* thisType = plainTextVal->getPointerOperand()->getType()->getPointerElementType()) {
                if (thisType->isDoubleTy()) {
                    PlainTextValDoubleType = thisType;
                }
            }
            int vectorNumElements = 0;
            if (VectorType *vectorType = dyn_cast<VectorType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType())){
                Type* thisType = dyn_cast<Type>(vectorType);
                //errs()<<"Bitsize "<<thisType->getScalarSizeInBits()<<" and no of elements "<<thisType->getVectorNumElements()<<"\n";
                vectorNumElements = thisType->getVectorNumElements();
            }

            if (PlainTextValIntType) {
                if (PlainTextValIntType->getBitWidth() == 8) {
                    INCREMENT = 1;
                } else if (PlainTextValIntType->getBitWidth() == 16) {
                    INCREMENT = 2;
                } else if (PlainTextValIntType->getBitWidth() == 32) {
                    INCREMENT = 4;
                } else if (PlainTextValIntType->getBitWidth() == 64) {
                    INCREMENT = 8;
                }
            } else if (PlainTextValPtrType) {
                INCREMENT = 8; // Pointer always 64 bit
            } else if (PlainTextValVecType){
                if (vectorNumElements == 2){
                    INCREMENT = 16;
                } else if (vectorNumElements == 4){
                    INCREMENT = 32;
                } else {
                    assert((vectorNumElements == 2 || vectorNumElements == 4) && "Unknown Type for vector type");
                }
            }else {
                assert(PlainTextValDoubleType && "Unknown Type!");
            }
            std::vector<Value*> encryptArgList;
            PointerType* stInstPtrType = dyn_cast<PointerType>(stInstPtrOperand->getType());
            IntegerType* stInstIntegerType = dyn_cast<IntegerType>(stInstPtrType->getPointerElementType());
            PointerType* stInstPtrElemType = dyn_cast<PointerType>(stInstPtrType->getPointerElementType());
            VectorType* stInstVectorType = dyn_cast<VectorType>(stInstPtrType->getPointerElementType());
            //assert((stInstIntegerType != nullptr) || (stInstPtrElemType != nullptr));
            Value* PtrOperand = nullptr;
            Value* ValueOperand = nullptr;

            if (stInstIntegerType && stInstIntegerType->getBitWidth() == 8) {
                PtrOperand = stInstPtrOperand;
            } else {
                PtrOperand = Builder.CreateBitCast(stInstPtrOperand, bytePtrType);
            }

            if (stInstIntegerType) {
                ValueOperand = stInstValueOperand;
            } else if (stInstVectorType) {
                ValueOperand = stInstValueOperand;
            } else {
                // Check needed for NULL assignments
                if (stInstValueOperand->getType()->isPointerTy()) {
                    // Convert the pointer to i64
                    ValueOperand = Builder.CreatePtrToInt(stInstValueOperand, IntegerType::get(stInstPtrOperand->getContext(), 64));
                } else {
                    ValueOperand = stInstValueOperand;
                }
            }

            encryptArgList.push_back(PtrOperand);
            encryptArgList.push_back(ValueOperand);

            Value* val = nullptr;
            if (!PlainTextValDoubleType) {
                switch(INCREMENT) {
                    case 1:
                        val = Builder.CreateCall(this->encryptLoopByteFunction, encryptArgList);
                        break;
                    case 2:
                        val = Builder.CreateCall(this->encryptLoopWordFunction, encryptArgList);
                        break;
                    case 4:
                        val = Builder.CreateCall(this->encryptLoopDWordFunction, encryptArgList);
                        break;
                    case 8:
                        val = Builder.CreateCall(this->encryptLoopQWordFunction, encryptArgList);
                        break;
                    case 16:
                        val = Builder.CreateCall(this->encryptLoopVecFunction, encryptArgList);
                        break;
                    case 32:
                        val = Builder.CreateCall(this->encryptLoopVec4Function, encryptArgList);
                        break;
                }
            } else {
                val = Builder.CreateCall(this->encryptLoopDoubleFunction, encryptArgList);
            }
            return nullptr;
        }


        Value* AESCache::setEncryptedValueCachedDfsan(StoreInst* plainTextVal) {
            int byteOffset = 0;
            Value* PointerVal = nullptr;
            Type* PlainTextValType = nullptr;
            GetElementPtrInst* GEPVal;
            IRBuilder<> Builder(plainTextVal);
            IntegerType* PlainTextValIntType = nullptr;
            Type* PlainTextValDoubleType = nullptr;
            PointerType* PlainTextValPtrType = nullptr;
            VectorType* PlainTextValVecType = nullptr;

            StoreInst* stInst = dyn_cast<StoreInst>(plainTextVal);
            Value* stInstPtrOperand = stInst->getPointerOperand();
            Value* stInstValueOperand = stInst->getValueOperand();

            Type* byteType = Type::getInt8Ty(plainTextVal->getContext());
            PointerType* bytePtrType = PointerType::get(byteType, 0);

            bool isLoop = false;
            int INCREMENT = 0;
            PlainTextValIntType = dyn_cast<IntegerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
            PlainTextValPtrType = dyn_cast<PointerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
            PlainTextValVecType = dyn_cast<VectorType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
            if (Type* thisType = plainTextVal->getPointerOperand()->getType()->getPointerElementType()) {
                if (thisType->isDoubleTy()) {
                    PlainTextValDoubleType = thisType;
                }
            }

            int vectorNumElements = 0;
            if (VectorType *vectorType = dyn_cast<VectorType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType())){
                Type* thisType = dyn_cast<Type>(vectorType);
                vectorNumElements = thisType->getVectorNumElements();
            }
            if (PlainTextValIntType) {
                if (PlainTextValIntType->getBitWidth() == 8) {
                    INCREMENT = 1;
                } else if (PlainTextValIntType->getBitWidth() == 16) {
                    INCREMENT = 2;
                } else if (PlainTextValIntType->getBitWidth() == 32) {
                    INCREMENT = 4;
                } else if (PlainTextValIntType->getBitWidth() == 64) {
                    INCREMENT = 8;
                }
            } else if (PlainTextValPtrType) {
                INCREMENT = 8; // Pointer always 64 bit 
            } else if (PlainTextValVecType){
                if (vectorNumElements == 2){
                    INCREMENT = 16;
                } else if (vectorNumElements == 4){
                    INCREMENT = 32;
                } else {
                    assert((vectorNumElements == 2 || vectorNumElements == 4) && "Unknown Type for vector type");
                }
            } else {
                auto* originalStore = stInst->clone();
                originalStore->insertBefore(stInst);
                return nullptr;
                //assert(PlainTextValDoubleType && "Unknown Type!");
            }
            std::vector<Value*> encryptArgList;
            PointerType* stInstPtrType = dyn_cast<PointerType>(stInstPtrOperand->getType());
            IntegerType* stInstIntegerType = dyn_cast<IntegerType>(stInstPtrType->getPointerElementType());
            PointerType* stInstPtrElemType = dyn_cast<PointerType>(stInstPtrType->getPointerElementType()); 
            VectorType* stInstVectorType = dyn_cast<VectorType>(stInstPtrType->getPointerElementType());
            //assert((stInstIntegerType != nullptr) || (stInstPtrElemType != nullptr));
            //assert((stInstIntegerType != nullptr) || (stInstPtrElemType != nullptr));
            Value* PtrOperand = nullptr;
            Value* ValueOperand = nullptr;

            if (stInstIntegerType && stInstIntegerType->getBitWidth() == 8) {
                PtrOperand = stInstPtrOperand;
            } else {
                PtrOperand = Builder.CreateBitCast(stInstPtrOperand, bytePtrType);
            }

            if (stInstIntegerType) {
                ValueOperand = stInstValueOperand; 
            } else if (stInstVectorType) {
                ValueOperand = stInstValueOperand;
            } else {
                // Check needed for NULL assignments
                if (stInstValueOperand->getType()->isPointerTy()) {
                    // Convert the pointer to i64
                    ValueOperand = Builder.CreatePtrToInt(stInstValueOperand, IntegerType::get(stInstPtrOperand->getContext(), 64));
                } else {
                    ValueOperand = stInstValueOperand;
                }
            }

            // Adding call to dfsan_read_label. Since we added constant 1 as label, we check against 1; 
            // depending on the compare result we create branch
            CallInst* readLabel = nullptr;
            ConstantInt* noOfByte = Builder.getInt64(1);
            readLabel = Builder.CreateCall(this->DFSanReadLabelFn, {PtrOperand, noOfByte});
            readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

            Type *int32Ty;
            int32Ty = Type::getInt32Ty(plainTextVal->getContext());


            ConstantInt *One = Builder.getInt16(1);
            Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
            Instruction* SplitBefore = cast<Instruction>(plainTextVal);

            TerminatorInst *ThenTerm, *ElseTerm;
            SplitBlockAndInsertIfThenElse(cmpInst, SplitBefore, &ThenTerm, &ElseTerm);

            Builder.SetInsertPoint(ThenTerm);

            encryptArgList.push_back(PtrOperand);
            encryptArgList.push_back(ValueOperand);

            Value* val = nullptr;
            if (!PlainTextValDoubleType) {
                switch(INCREMENT) {
                    case 1:
                        val = Builder.CreateCall(this->encryptLoopByteFunction, encryptArgList);
                        break;
                    case 2:
                        val = Builder.CreateCall(this->encryptLoopWordFunction, encryptArgList);
                        break;
                    case 4:
                        val = Builder.CreateCall(this->encryptLoopDWordFunction, encryptArgList);
                        break;
                    case 8:
                        val = Builder.CreateCall(this->encryptLoopQWordFunction, encryptArgList);
                        break;
                    case 16:
                        val = Builder.CreateCall(this->encryptLoopVecFunction, encryptArgList);
                        break;
                    case 32:
                        val = Builder.CreateCall(this->encryptLoopVec4Function, encryptArgList);
                        break;
                }
            } else {
                val = Builder.CreateCall(this->encryptLoopDoubleFunction, encryptArgList);
            }

            Builder.SetInsertPoint(ElseTerm);
            //auto originalStore = Builder.CreateStore(stInstValueOperand,stInstPtrOperand);
            
            auto* originalStore = stInst->clone();
            originalStore->insertBefore(ElseTerm);

            Builder.SetInsertPoint(SplitBefore);

            return nullptr;
        }


        Value* AESCache::getDecryptedValueCached(LoadInst* encVal) {
            Value* retVal = nullptr;
            int byteOffset = 0;
            Value* PointerVal = nullptr;
            Type* EncValType = nullptr;
            GetElementPtrInst* GEPVal;
            IRBuilder<> Builder(encVal);
            IntegerType* EncValIntType = nullptr;
            Type* EncValDoubleType = nullptr;
            PointerType* EncValPtrType = nullptr;
            VectorType* EncValVectorType = nullptr;

            bool isLoop = false;

            LoadInst* ldInst = dyn_cast<LoadInst>(encVal);
            Value* ldInstPtrOperand = ldInst->getPointerOperand();

            /*errs()<<"Original Load "<<*ldInst<<"\n";
              if (ldInstPtrOperand->getType()->getPointerElementType()->isPointerTy()) {
              errs()<<" Pointer Type "<<*ldInstPtrOperand<<"\n";
              auto* originalLoad = ldInst->clone();
              originalLoad->insertBefore(ldInst);
              errs()<<"Created Load "<<*originalLoad<<"\n";
              return originalLoad;
              }*/

            Type* byteType = Type::getInt8Ty(encVal->getContext());
            PointerType* bytePtrType = PointerType::get(byteType, 0);

            int INCREMENT = 0;
            EncValIntType =  dyn_cast<IntegerType>(encVal->getPointerOperand()->getType()->getPointerElementType());
            EncValPtrType = dyn_cast<PointerType>(encVal->getPointerOperand()->getType()->getPointerElementType());
            EncValVectorType = dyn_cast<VectorType>(encVal->getPointerOperand()->getType()->getPointerElementType());

            int vectorNumElements = 0;
            if (VectorType *vectorType = dyn_cast<VectorType>(encVal->getPointerOperand()->getType()->getPointerElementType())){
                Type* thisType = dyn_cast<Type>(vectorType);
                vectorNumElements = thisType->getVectorNumElements();
            }
            if (Type* thisType = encVal->getPointerOperand()->getType()->getPointerElementType()) {
                if (thisType->isDoubleTy()) {
                    EncValDoubleType = thisType;
                }
            }

            if (EncValIntType) {
                if (EncValIntType->getBitWidth() == 8) {
                    INCREMENT = 1;
                } else if (EncValIntType->getBitWidth() == 16) {
                    INCREMENT = 2;
                } else if (EncValIntType->getBitWidth() == 32) {
                    INCREMENT = 4;
                } else if (EncValIntType->getBitWidth() == 64) {
                    INCREMENT = 8;
                }
            } else if (EncValPtrType) {
                INCREMENT = 8;
            } else if (EncValVectorType){

                if (vectorNumElements == 2){
                    INCREMENT = 16;
                } else if (vectorNumElements == 4){
                    INCREMENT = 32;
                } else {
                    assert((vectorNumElements == 2 || vectorNumElements == 4) && "Unknown Type for vector type");
                }
            }else {
                assert(EncValDoubleType && "Unknown type!");
            }

            PointerType* ldInstPtrType = dyn_cast<PointerType>(ldInstPtrOperand->getType());
            IntegerType* ldInstIntegerType = dyn_cast<IntegerType>(ldInstPtrType->getPointerElementType());
            PointerType* ldInstPtrElemType = dyn_cast<PointerType>(ldInstPtrType->getPointerElementType());

            //assert((ldInstIntegerType != nullptr) || (ldInstPtrElemType != nullptr));
            Value* PtrOperand = nullptr;
            if (ldInstIntegerType && ldInstIntegerType->getBitWidth() == 8) {
                PtrOperand = ldInstPtrOperand;
            } else {
                PtrOperand = Builder.CreateBitCast(ldInstPtrOperand, bytePtrType);
            }

            std::vector<Value*> decryptArgList;
            decryptArgList.push_back(PtrOperand);

            if (!EncValDoubleType) {
                switch(INCREMENT) {
                    case 1:
                        retVal = Builder.CreateCall(this->decryptLoopByteFunction, decryptArgList);
                        break;
                    case 2:
                        retVal = Builder.CreateCall(this->decryptLoopWordFunction, decryptArgList);
                        break;
                    case 4:
                        retVal = Builder.CreateCall(this->decryptLoopDWordFunction, decryptArgList);
                        break;
                    case 8:
                        retVal = Builder.CreateCall(this->decryptLoopQWordFunction, decryptArgList);
                        break;
                    case 16:
                        retVal = Builder.CreateCall(this->decryptLoopVectorFunction, decryptArgList);
                        break;
                    case 32:
                        retVal = Builder.CreateCall(this->decryptLoopVector4Function, decryptArgList);
                        break;
                }
            } else {
                retVal = Builder.CreateCall(this->decryptLoopDoubleFunction, decryptArgList);
            }

            if (ldInstPtrElemType) {
                // If it's a pointer type, then the return value must be cast to the correct type
                // int to ptr
                retVal = Builder.CreateIntToPtr(retVal, ldInst->getType());
            }
            return retVal;

        }

        Value* AESCache::getDecryptedValueCachedDfsan(LoadInst* encVal) {
            Value* retVal = nullptr;
            int byteOffset = 0;
            Value* PointerVal = nullptr;
            Type* EncValType = nullptr;
            GetElementPtrInst* GEPVal;
            IRBuilder<> Builder(encVal);
            IntegerType* EncValIntType = nullptr;
            PointerType* EncValPtrType = nullptr;
            Type* EncValDoubleType = nullptr;
            VectorType* EncValVectorType = nullptr;

            bool isLoop = false;

            LoadInst* ldInst = dyn_cast<LoadInst>(encVal);
            Value* ldInstPtrOperand = ldInst->getPointerOperand();
            //errs()<<"Value of loadptr check "<<*ldInstPtrOperand<<"\n";


            Type* byteType = Type::getInt8Ty(encVal->getContext());
            PointerType* bytePtrType = PointerType::get(byteType, 0);

            int INCREMENT = 0;
            EncValIntType =  dyn_cast<IntegerType>(encVal->getPointerOperand()->getType()->getPointerElementType());
            EncValPtrType = dyn_cast<PointerType>(encVal->getPointerOperand()->getType()->getPointerElementType());
            EncValVectorType = dyn_cast<VectorType>(encVal->getPointerOperand()->getType()->getPointerElementType());

            int vectorNumElements = 0;
            if (VectorType *vectorType = dyn_cast<VectorType>(encVal->getPointerOperand()->getType()->getPointerElementType())){
                Type* thisType = dyn_cast<Type>(vectorType);
                vectorNumElements = thisType->getVectorNumElements();
            }

            if (Type* thisType = encVal->getPointerOperand()->getType()->getPointerElementType()) {
                if (thisType->isDoubleTy()) {
                    EncValDoubleType = thisType;
                }
            }

            if (EncValIntType) {
                if (EncValIntType->getBitWidth() == 8) {
                    INCREMENT = 1;
                } else if (EncValIntType->getBitWidth() == 16) {
                    INCREMENT = 2;
                } else if (EncValIntType->getBitWidth() == 32) {
                    INCREMENT = 4;
                } else if (EncValIntType->getBitWidth() == 64) {
                    INCREMENT = 8;
                }
            } else if (EncValPtrType) {
                INCREMENT = 8;
            } else if (EncValVectorType){

                if (vectorNumElements == 2){
                    INCREMENT = 16;
                } else if (vectorNumElements == 4){
                    INCREMENT = 32;
                } else {
                    assert((vectorNumElements == 2 || vectorNumElements == 4) && "Unknown Type for vector type");
                }
            } else {
                // Skipping assertion because we didn't handle the type when a complex struct
                // is returned by value; this situation occured in OpenVPN. But this type
                // doesn't become senstitve, so we are just skipping the instrumentation for
                // these cases. May be in future, we will need to handle these types
                auto* originalLoad = ldInst->clone();
                originalLoad->insertBefore(ldInst);
                return originalLoad;
                //assert(EncValDoubleType && "Unknown type!");
            }

            PointerType* ldInstPtrType = dyn_cast<PointerType>(ldInstPtrOperand->getType());
            IntegerType* ldInstIntegerType = dyn_cast<IntegerType>(ldInstPtrType->getPointerElementType());
            PointerType* ldInstPtrElemType = dyn_cast<PointerType>(ldInstPtrType->getPointerElementType());
            
            //assert((ldInstIntegerType != nullptr) || (ldInstPtrElemType != nullptr));
            Value* PtrOperand = nullptr;
            if (ldInstIntegerType && ldInstIntegerType->getBitWidth() == 8) {
                PtrOperand = ldInstPtrOperand;
            } else {
                PtrOperand = Builder.CreateBitCast(ldInstPtrOperand, bytePtrType);
            }

            CallInst* readLabel = nullptr;
            ConstantInt* noOfByte = Builder.getInt64(1);
            readLabel = Builder.CreateCall(this->DFSanReadLabelFn, {PtrOperand, noOfByte});
            readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

            Type *int32Ty;
            int32Ty = Type::getInt32Ty(encVal->getContext());


            ConstantInt *One = Builder.getInt16(1);
            Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
            Instruction* SplitBefore = cast<Instruction>(encVal);

            TerminatorInst *ThenTerm, *ElseTerm;
            SplitBlockAndInsertIfThenElse(cmpInst, SplitBefore, &ThenTerm, &ElseTerm);

            Builder.SetInsertPoint(ThenTerm);

            std::vector<Value*> decryptArgList;
            decryptArgList.push_back(PtrOperand);

            if (!EncValDoubleType) {
                switch(INCREMENT) {
                    case 1:
                        retVal = Builder.CreateCall(this->decryptLoopByteFunction, decryptArgList);
                        if (CallInst* cInst = dyn_cast<CallInst>(retVal)) {
                            addTaintMetaData(cInst);
                        }
                        break;
                    case 2:
                        retVal = Builder.CreateCall(this->decryptLoopWordFunction, decryptArgList);
                        if (CallInst* cInst = dyn_cast<CallInst>(retVal)) {
                            addTaintMetaData(cInst);
                        }
                        break;
                    case 4:
                        retVal = Builder.CreateCall(this->decryptLoopDWordFunction, decryptArgList);
                        if (CallInst* cInst = dyn_cast<CallInst>(retVal)) {
                            addTaintMetaData(cInst);
                        }
                        break;
                    case 8:
                        retVal = Builder.CreateCall(this->decryptLoopQWordFunction, decryptArgList);
                        if (CallInst* cInst = dyn_cast<CallInst>(retVal)) {
                            addTaintMetaData(cInst);
                        }
                        break;
                    case 16:
                        retVal = Builder.CreateCall(this->decryptLoopVectorFunction, decryptArgList);
                        break;
                    case 32:
                        retVal = Builder.CreateCall(this->decryptLoopVector4Function, decryptArgList);
                        break;
                }
            } else {
                retVal = Builder.CreateCall(this->decryptLoopDoubleFunction, decryptArgList);
            }

            if (ldInstPtrElemType) {
                retVal = Builder.CreateIntToPtr(retVal, ldInst->getType());
            }

            Builder.SetInsertPoint(ElseTerm);
            //auto originalLoad = Builder.CreateLoad(ldInstPtrOperand);

            auto* originalLoad = ldInst->clone();
            originalLoad->insertBefore(ElseTerm);

            Builder.SetInsertPoint(SplitBefore);

            PHINode *phi = Builder.CreatePHI(retVal->getType(), 2);
            phi->addIncoming(retVal, ThenTerm->getParent());
            phi->addIncoming(originalLoad, ElseTerm->getParent());

            return phi;

        }

        void AESCache::writeback(Instruction* insertionPoint) {
            IRBuilder<> Builder(insertionPoint);
            std::vector<Value*> argList;
            Builder.CreateCall(this->writebackFunction, argList);
        }

    }
