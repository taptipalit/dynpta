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
	FunctionType* FTypeSafeMalloc = FunctionType::get(int8PtrTy, {int64Ty}, false);
	FunctionType* FTypeCheckBounds = FunctionType::get(int32Ty, {voidPtrType}, false);
	FunctionType* FTypeCustomMalloc = FunctionType::get(voidTy,  false);
	FunctionType* FTypeSetLabel = FunctionType::get(Type::getVoidTy(*Ctx), DFSanSetLabelArgs, false);
	FunctionType* FTypeReadLabel = FunctionType::get(ShadowTy, DFSanReadLabelArgs, false);

	// All versions
	this->decryptLoopByteFunction = Function::Create(FTypeDecLoopByte, Function::ExternalLinkage, "getDecryptedValueByte", &M);
	this->decryptLoopWordFunction = Function::Create(FTypeDecLoopWord, Function::ExternalLinkage, "getDecryptedValueWord", &M);
	this->decryptLoopDWordFunction = Function::Create(FTypeDecLoopDWord, Function::ExternalLinkage, "getDecryptedValueDWord", &M);
	this->decryptLoopQWordFunction = Function::Create(FTypeDecLoopQWord, Function::ExternalLinkage, "getDecryptedValueQWord", &M);
	
	//myfunctions
	this->safeMalloc = Function::Create(FTypeSafeMalloc, Function::ExternalLinkage, "getSafeMalloc", &M);
	this->checkBounds = Function::Create(FTypeCheckBounds, Function::ExternalLinkage, "checkBounds", &M);
	this->initializeCustomMalloc = Function::Create(FTypeCustomMalloc, Function::ExternalLinkage, "initializeCustomMalloc", &M);
	this->DFSanSetLabelFn = Function::Create(FTypeSetLabel, Function::ExternalLinkage, "dfsan_set_label", &M);
	//adding zeroext for function parameter
	if (Function *F = dyn_cast<Function>(DFSanSetLabelFn)) {
		F->addParamAttr(0, Attribute::ZExt);
	}
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

	FunctionType* FTypeEncLoopByte = FunctionType::get(voidPtrType, loopEncTypeByteArray, false);
	FunctionType* FTypeEncLoopWord = FunctionType::get(voidPtrType, loopEncTypeWordArray, false);
	FunctionType* FTypeEncLoopDWord = FunctionType::get(voidPtrType, loopEncTypeDWordArray, false);
	FunctionType* FTypeEncLoopQWord = FunctionType::get(voidPtrType, loopEncTypeQWordArray, false);

	this->encryptLoopByteFunction = Function::Create(FTypeEncLoopByte, Function::ExternalLinkage, "setEncryptedValueByte", &M);
	this->encryptLoopWordFunction = Function::Create(FTypeEncLoopWord, Function::ExternalLinkage, "setEncryptedValueWord", &M);
	this->encryptLoopDWordFunction = Function::Create(FTypeEncLoopDWord, Function::ExternalLinkage, "setEncryptedValueDWord", &M);
	this->encryptLoopQWordFunction = Function::Create(FTypeEncLoopQWord, Function::ExternalLinkage, "setEncryptedValueQWord", &M);


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

void AESCache::initializeAes(Module &M) {
        I128Ty = IntegerType::get(M.getContext(), 128);
        this->M = &M;
		addExternAESFuncDecls(M);
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
                nestedType->addSensitiveFieldOffset(nestedOffset);
                errs() << "Widening sensitive complex type: " << nestedType->getName() << " with offset: " << nestedOffset << " original type: " << stType->getName() << " original offset: " << offset << " \n";
                return true;
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
			false;
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

                           
                                  
/*
 * Widen the buffer to a multiple of 128 bits
 */
void AESCache::allocateSeparateMemoryForHeapObjects(Module &M, std::set<PAGNode*>* SensitiveAllocaList,
            std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap, std::map<PAGNode*, std::set<PAGNode*>>& ptsFromMap) {
 	for (PAGNode* senNode: *SensitiveAllocaList) {
            bool widenedStructType = false;
            // If it is a GepObjPN we need to be careful about what to widen in it
            if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senNode)) {
                errs() << "This is what I tried to widen: " << *gepNode << " " << gepNode->getLocationSet().getOffset() << "\n";
                widenedStructType = widenSensitiveComplexType(gepNode, ptsFromMap);
            }
            //if (!widenedStructType) {
            assert(senNode->hasValue());
            // Add padding regardless if we've padded individual fields
            // Easy stuff
            Value* senVal = const_cast<Value*>(senNode->getValue());
	    if (CallInst* callInst = dyn_cast<CallInst>(senVal)){

                        Function* function = callInst->getCalledFunction();
                        if (function) {
                                StringRef mallocStr("malloc");
                                StringRef callocStr("calloc");
                                if (mallocStr.equals(function->getName())) {
                                        callInst->setCalledFunction(safeMalloc);
                                }
                                else if (callocStr.equals(function->getName())) {
                                        callInst->setCalledFunction(safeMalloc);
                                }
                        }

            }
	}
}

void AESCache::SetLabelsForSensitiveObjects(Module &M, std::set<PAGNode*>* SensitiveAllocaList,
            std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap, std::map<PAGNode*, std::set<PAGNode*>>& ptsFromMap) {
	LLVMContext *Ctx;
	Ctx = &M.getContext();
	const DataLayout &DL = M.getDataLayout();
	errs() << "Setting Label for Sensitive Objects: \n";
        for (PAGNode* senNode: *SensitiveAllocaList) {
		assert(senNode->hasValue());
		Value* senVal = const_cast<Value*>(senNode->getValue());
		errs() << "Value " << *senVal<<"\n";

		//Creating insert position
		Instruction *I = dyn_cast<Instruction>(senVal);
		IRBuilder<> Builder(I);
		Builder.SetInsertPoint(I->getNextNode());

		/*For now, we are adding constant single label for all sensitive objects and setting in only 
		first byte. It something break, will look into it later on. 
		*/
		ConstantInt* label = Builder.getInt16(1);
		ConstantInt* noOfByte = Builder.getInt64(1);
		if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senNode)) {
			IntegerType *IntptrTy;
			IntptrTy = Type::getInt32Ty(M.getContext());
			//Getting offset for GEP instruction 
			Size_t offset = gepNode->getLocationSet().getOffset();
			//Value* indexList[2] = {Builder.getInt32(0),Builder.getInt32(offset)};
			//Value* gepInst = Builder.CreateGEP(senVal, ArrayRef<Value*>(indexList, 2));
			Value* indexList[2] = {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, offset)};
			//Creating getelementptr instruction to get address of struct field
			Value* gepInst = Builder.CreateInBoundsGEP(senVal, ArrayRef<Value*>(indexList, 2));
			Value* PtrOperand = nullptr;
			PtrOperand = Builder.CreateBitCast(gepInst, Type::getInt8PtrTy(*Ctx));
			CallInst* setLabel = nullptr;
			setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, PtrOperand, noOfByte}); 
			setLabel->addParamAttr(0, Attribute::ZExt);
			errs()<< "Value of setLabel is :"<<*setLabel<<"\n";
		}
		else if (AllocaInst* allocInst = dyn_cast<AllocaInst>(senVal)) {
                	// Is an alloca instruction
			//Type* byteType = Type::getInt8Ty(M.getContext());
			//PointerType* bytePtrType = PointerType::get(byteType, 0);
			Value* PtrOperand = nullptr;
			PtrOperand = Builder.CreateBitCast(senVal, Type::getInt8PtrTy(*Ctx));
			CallInst* setLabel = nullptr;


			setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, PtrOperand, noOfByte});
			setLabel->addParamAttr(0, Attribute::ZExt);
			errs()<< "Value of setLabel is :"<<*setLabel<<"\n";
	
        	}
		else if (CallInst* callInst = dyn_cast<CallInst>(senVal)){
			// Call Instruction, no need to add bitcast
			CallInst* setLabel = nullptr;
			setLabel = Builder.CreateCall(this->DFSanSetLabelFn, {label, callInst, noOfByte});
                	setLabel->addParamAttr(0, Attribute::ZExt);
                	errs()<< "Value of setLabel is :"<<*setLabel<<"\n";
		}
	}
}


void AESCache::widenAllocaAllocations(Module &M, std::set<PAGNode*>* SensitiveAllocaList,
            std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap, std::map<PAGNode*, std::set<PAGNode*>>& ptsFromMap) {
	//initialize CUstom Malloc	
	int initializeCount = 0;		
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
            if (auto *F = dyn_cast<Function>(MIterator)) {
		//errs() << "Function " << F->getName()<< "\n"i;
		if ( F->getName() == "main"){
                	for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                    		if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
					if ( BB->getName() == "entry"){
					for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                            			if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
							errs()<<" Instruction "<<*Inst<< "\n";
							IRBuilder<> Builder(Inst);
                					Value* initialize = Builder.CreateCall(this->initializeCustomMalloc);
                					initializeCount++;
							break;
						}
					}
					break;
					}
				}
                        }
			break;
               }
 	}
	}
        for (PAGNode* senNode: *SensitiveAllocaList) {
            bool widenedStructType = false;
            // If it is a GepObjPN we need to be careful about what to widen in it
            if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senNode)) {
                errs() << "This is what I tried to widen: " << *gepNode << " " << gepNode->getLocationSet().getOffset() << "\n";
                widenedStructType = widenSensitiveComplexType(gepNode, ptsFromMap);
            } 
            //if (!widenedStructType) {
            assert(senNode->hasValue());
            // Add padding regardless if we've padded individual fields
            // Easy stuff
            Value* senVal = const_cast<Value*>(senNode->getValue());
	    //intialize Custom Malloc
            /*if (initializeCount == 0){
		Instruction* inst = dyn_cast<Instruction>(senVal);
		IRBuilder<> Builder(inst);
                Value* initialize = Builder.CreateCall(this->initializeCustomMalloc);
                initializeCount++;
            }*/

            if (AllocaInst* allocInst = dyn_cast<AllocaInst>(senVal)) {
                // Is an alloca instruction
                allocInst->setAlignment(16);
                IRBuilder<> Builder(allocInst);
                /*
                   AllocaInst* paddingAllocaInst1 = new AllocaInst (I128Ty, 0, "padding");
                   MDNode* N1 = MDNode::get(allocInst->getContext(), MDString::get(allocInst->getContext(), "padding"));
                   paddingAllocaInst1->setMetadata("PADDING", N1);
                   paddingAllocaInst1->insertAfter(allocInst);
                   */
                AllocaInst* paddingAllocaInst2 = Builder.CreateAlloca(I128Ty, 0, "padding");
                MDNode* N2 = MDNode::get(allocInst->getContext(), MDString::get(allocInst->getContext(), "padding"));
                paddingAllocaInst2->setMetadata("PADDING", N2);
		errs()<<" Get Padded \n";
		errs()<< "ValueAlloca "<<*senVal<<"\n";
		

		//myTestCode
		//Value* allocaInstPtrOperand = allocInst->getPointerOperand();
		//errs()<< "Value of alloca ptr "<< *allocaInstPtrOperand<<"\n";
		/*Type *int64Ty;
                PointerType  *int8PtrTy;
                int8PtrTy = Type::getInt8PtrTy(M.getContext());
                int64Ty = Type::getInt64Ty(M.getContext());
		auto DL = M.getDataLayout();
		auto sz = DL.getTypeAllocSize(allocInst->getType()->getPointerElementType());
      		auto sizeVal = ConstantInt::get(int64Ty, sz);

		Value* val = nullptr;
		val = Builder.CreateCall(this->safeMalloc, {sizeVal});
		*/
		
		/*Function *safeMalloc;		
		safeMalloc = dyn_cast<Function>(M.getOrInsertFunction("safeMalloc", ));
		Value* retVal = nullptr;
		retVal = Builder.CreateCall(safeMalloc, nullptr);
		
		Type* ITy = IntegerType::getInt32Ty(allocInst->getContext());
		Type* Ty = IntegerType::getInt8Ty(allocInst->getContext());
		Constant* allocsize = ConstantExpr::getSizeOf(Ty);
		allocsize = ConstantExpr::getTruncOrBitCast(allocsize, ITy);
		Instruction* Malloc = CallInst::CreateMalloc(allocInst, ITy, Ty, allocsize,
                                             nullptr, nullptr, "Malloc");		
		*/
		//mycode endis

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
	    /*else if (CallInst* callInst = dyn_cast<CallInst>(senVal)){

			Function* function = callInst->getCalledFunction();
			if (function) {
				StringRef mallocStr("malloc");
				StringRef callocStr("calloc");
				if (mallocStr.equals(function->getName())) {
					callInst->setCalledFunction(safeMalloc);
				}
				else if (callocStr.equals(function->getName())) {
					callInst->setCalledFunction(aesCallocFunction);
				}
			}
	
	    }*/
			//}
        }

        //M.dump();
        // As for global variables, just align all of them to a 128 bit boundary
        for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
            if (I->getName() != "llvm.global.annotations") {
                GlobalVariable* GV = cast<GlobalVariable>(I);
                GV->setAlignment(16);
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
                                if (ReturnInst* retInst = dyn_cast<ReturnInst>(Inst)) {
                                    writeback(retInst); // Invalidate the cache
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

void AESCache::widenSensitiveAllocationSites(Module &M, std::vector<PAGNode*>& SensitiveAllocaList,
            std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap, std::map<PAGNode*, std::set<PAGNode*>>& ptsFromMap) {
        for (PAGNode* senNode: SensitiveAllocaList) {
            bool widenedStructType = false;
            // If it is a GepObjPN we need to be careful about what to widen in it
            if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senNode)) {
                errs() << "This is what I tried to widen: " << *gepNode << " " << gepNode->getLocationSet().getOffset() << "\n";
                widenedStructType = widenSensitiveComplexType(gepNode, ptsFromMap);
            } 
            //if (!widenedStructType) {
            assert(senNode->hasValue());
            // Add padding regardless if we've padded individual fields
            // Easy stuff
            Value* senVal = const_cast<Value*>(senNode->getValue());
            if (AllocaInst* allocInst = dyn_cast<AllocaInst>(senVal)) {
                // Is an alloca instruction
                allocInst->setAlignment(16);
                IRBuilder<> Builder(allocInst);
                /*
                   AllocaInst* paddingAllocaInst1 = new AllocaInst (I128Ty, 0, "padding");
                   MDNode* N1 = MDNode::get(allocInst->getContext(), MDString::get(allocInst->getContext(), "padding"));
                   paddingAllocaInst1->setMetadata("PADDING", N1);
                   paddingAllocaInst1->insertAfter(allocInst);
                   */
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
			//}
        }

        //M.dump();
        // As for global variables, just align all of them to a 128 bit boundary
        for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
            if (I->getName() != "llvm.global.annotations") {
                GlobalVariable* GV = cast<GlobalVariable>(I);
                GV->setAlignment(16);
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
                                    if (function) {
                                        StringRef mallocStr("malloc");
                                        StringRef callocStr("calloc");
                                        if (mallocStr.equals(function->getName())) {
                                            // Change the called function to inst_malloc
					    //need to check changing malloc and calloc for DFSan
                                            callInst->setCalledFunction(aesMallocFunction);
                                        } else if (callocStr.equals(function->getName())) {
                                            callInst->setCalledFunction(aesCallocFunction);
                                        }
                                    }
                                } else if (ReturnInst* retInst = dyn_cast<ReturnInst>(Inst)) {
                                    writeback(retInst); // Invalidate the cache
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
        	PointerType* PlainTextValPtrType = nullptr;

		StoreInst* stInst = dyn_cast<StoreInst>(plainTextVal);
		Value* stInstPtrOperand = stInst->getPointerOperand();
		Value* stInstValueOperand = stInst->getValueOperand();

		Type* byteType = Type::getInt8Ty(plainTextVal->getContext());
		PointerType* bytePtrType = PointerType::get(byteType, 0);

		bool isLoop = false;
		int INCREMENT = 0;
		PlainTextValIntType = dyn_cast<IntegerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
        	PlainTextValPtrType = dyn_cast<PointerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
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
        	} else {
            		errs() << "Unknown type. Can't encrypt!\n";
            		assert(false);
        	}
        	std::vector<Value*> encryptArgList;
        	PointerType* stInstPtrType = dyn_cast<PointerType>(stInstPtrOperand->getType());
        	IntegerType* stInstIntegerType = dyn_cast<IntegerType>(stInstPtrType->getPointerElementType());
        	PointerType* stInstPtrElemType = dyn_cast<PointerType>(stInstPtrType->getPointerElementType());
        	assert((stInstIntegerType != nullptr) || (stInstPtrElemType != nullptr));
        	Value* PtrOperand = nullptr;
        	Value* ValueOperand = nullptr;

        	if (stInstIntegerType && stInstIntegerType->getBitWidth() == 8) {
            		PtrOperand = stInstPtrOperand;
        	} else {
            		PtrOperand = Builder.CreateBitCast(stInstPtrOperand, bytePtrType);
       		}

        	if (stInstIntegerType) {
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
        	}
        	return nullptr;
}
	

Value* AESCache::setEncryptedValueCachedPartitioning(StoreInst* plainTextVal) {
		int byteOffset = 0;
		Value* PointerVal = nullptr;
		Type* PlainTextValType = nullptr;
		GetElementPtrInst* GEPVal;
		IRBuilder<> Builder(plainTextVal);
		IntegerType* PlainTextValIntType = nullptr;
	        PointerType* PlainTextValPtrType = nullptr;

		StoreInst* stInst = dyn_cast<StoreInst>(plainTextVal);
		Value* stInstPtrOperand = stInst->getPointerOperand();
		Value* stInstValueOperand = stInst->getValueOperand();

		Type* byteType = Type::getInt8Ty(plainTextVal->getContext());
		PointerType* bytePtrType = PointerType::get(byteType, 0);

		bool isLoop = false;
		int INCREMENT = 0;
		PlainTextValIntType = dyn_cast<IntegerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
        	PlainTextValPtrType = dyn_cast<PointerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
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
        		} else {
            			errs() << "Unknown type. Can't encrypt!\n";
            			assert(false);
        	}
        	std::vector<Value*> encryptArgList;
        	PointerType* stInstPtrType = dyn_cast<PointerType>(stInstPtrOperand->getType());
        	IntegerType* stInstIntegerType = dyn_cast<IntegerType>(stInstPtrType->getPointerElementType());
        	PointerType* stInstPtrElemType = dyn_cast<PointerType>(stInstPtrType->getPointerElementType());
        	assert((stInstIntegerType != nullptr) || (stInstPtrElemType != nullptr));
        	Value* PtrOperand = nullptr;
        	Value* ValueOperand = nullptr;

        	if (stInstIntegerType && stInstIntegerType->getBitWidth() == 8) {
            		PtrOperand = stInstPtrOperand;
        	} else {
            		PtrOperand = Builder.CreateBitCast(stInstPtrOperand, bytePtrType);
        	}

        	if (stInstIntegerType) {
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

		//mycode
		Value* safeRegion = nullptr;
                safeRegion = Builder.CreateCall(this->checkBounds, {PtrOperand});
                errs()<< "Value of safeRegion is :"<<*safeRegion<<"\n";

                Type *int32Ty;
                int32Ty = Type::getInt32Ty(plainTextVal->getContext());
                //auto sizeVal = ConstantInt::get(int32Ty, 0);


                ConstantInt *Zero = Builder.getInt32(0);
                Value* cmpInst = Builder.CreateICmpEQ(safeRegion, Zero, "cmp");
                //Value* safeRegion1 = Builder.CreateCall(this->checkBounds, {PtrOperand});
                //Instruction* SplitBefore = cast<Instruction>(safeRegion1);
                Instruction* SplitBefore = cast<Instruction>(plainTextVal);

                TerminatorInst *ThenTerm, *ElseTerm;
                SplitBlockAndInsertIfThenElse(cmpInst, SplitBefore, &ThenTerm, &ElseTerm);

                Builder.SetInsertPoint(ThenTerm);

        	encryptArgList.push_back(PtrOperand);
        	encryptArgList.push_back(ValueOperand);

        	Value* val = nullptr;
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
        	}

		Builder.SetInsertPoint(ElseTerm);
                auto originalStore = Builder.CreateStore(stInstValueOperand,stInstPtrOperand);

                Builder.SetInsertPoint(SplitBefore);
                //PHINode *phi = Builder.CreatePHI(int32Ty, 2);
                //phi->addIncoming(val, ThenTerm->getParent());
                //phi->addIncoming(originalStore, ElseTerm->getParent());

        	return nullptr;
}

Value* AESCache::setEncryptedValueCachedDfsan(StoreInst* plainTextVal) {
                int byteOffset = 0;
                Value* PointerVal = nullptr;
                Type* PlainTextValType = nullptr;
                GetElementPtrInst* GEPVal;
                IRBuilder<> Builder(plainTextVal);
                IntegerType* PlainTextValIntType = nullptr;
                PointerType* PlainTextValPtrType = nullptr;

                StoreInst* stInst = dyn_cast<StoreInst>(plainTextVal);
                Value* stInstPtrOperand = stInst->getPointerOperand();
                Value* stInstValueOperand = stInst->getValueOperand();

                Type* byteType = Type::getInt8Ty(plainTextVal->getContext());
                PointerType* bytePtrType = PointerType::get(byteType, 0);

                bool isLoop = false;
                int INCREMENT = 0;
                PlainTextValIntType = dyn_cast<IntegerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
                PlainTextValPtrType = dyn_cast<PointerType>(plainTextVal->getPointerOperand()->getType()->getPointerElementType());
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
                        } else {
                                errs() << "Unknown type. Can't encrypt!\n";
                                assert(false);
                }
                std::vector<Value*> encryptArgList;
                PointerType* stInstPtrType = dyn_cast<PointerType>(stInstPtrOperand->getType());
                IntegerType* stInstIntegerType = dyn_cast<IntegerType>(stInstPtrType->getPointerElementType());
                PointerType* stInstPtrElemType = dyn_cast<PointerType>(stInstPtrType->getPointerElementType());
                assert((stInstIntegerType != nullptr) || (stInstPtrElemType != nullptr));
                Value* PtrOperand = nullptr;
                Value* ValueOperand = nullptr;

                if (stInstIntegerType && stInstIntegerType->getBitWidth() == 8) {
                        PtrOperand = stInstPtrOperand;
                } else {
                        PtrOperand = Builder.CreateBitCast(stInstPtrOperand, bytePtrType);
                }

                if (stInstIntegerType) {
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

                //Adding call to dfsan_read_label. Since we added constant 1 as label, we check against 1; 
		// depending on the compare result we create branch
                CallInst* readLabel = nullptr;
		ConstantInt* noOfByte = Builder.getInt64(1);
                readLabel = Builder.CreateCall(this->DFSanReadLabelFn, {PtrOperand, noOfByte});
		readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);
                errs()<< "Value of readlabel is :"<<*readLabel<<"\n";

                Type *int32Ty;
                int32Ty = Type::getInt32Ty(plainTextVal->getContext());
                //auto sizeVal = ConstantInt::get(int32Ty, 0);


                ConstantInt *One = Builder.getInt16(1);
                Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
                //Value* safeRegion1 = Builder.CreateCall(this->checkBounds, {PtrOperand});
                //Instruction* SplitBefore = cast<Instruction>(safeRegion1);
                Instruction* SplitBefore = cast<Instruction>(plainTextVal);

                TerminatorInst *ThenTerm, *ElseTerm;
                SplitBlockAndInsertIfThenElse(cmpInst, SplitBefore, &ThenTerm, &ElseTerm);

                Builder.SetInsertPoint(ThenTerm);

                encryptArgList.push_back(PtrOperand);
                encryptArgList.push_back(ValueOperand);

                Value* val = nullptr;
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
                }

                Builder.SetInsertPoint(ElseTerm);
                auto originalStore = Builder.CreateStore(stInstValueOperand,stInstPtrOperand);

                Builder.SetInsertPoint(SplitBefore);
                //PHINode *phi = Builder.CreatePHI(int32Ty, 2);
                //phi->addIncoming(val, ThenTerm->getParent());
                //phi->addIncoming(originalStore, ElseTerm->getParent());

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
	        PointerType* EncValPtrType = nullptr;

		bool isLoop = false;

		LoadInst* ldInst = dyn_cast<LoadInst>(encVal);
		Value* ldInstPtrOperand = ldInst->getPointerOperand();

		Type* byteType = Type::getInt8Ty(encVal->getContext());
		PointerType* bytePtrType = PointerType::get(byteType, 0);

		int INCREMENT = 0;
		EncValIntType =  dyn_cast<IntegerType>(encVal->getPointerOperand()->getType()->getPointerElementType());
        	EncValPtrType = dyn_cast<PointerType>(encVal->getPointerOperand()->getType()->getPointerElementType());

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
        	} else {
            		errs() << "Unknown type - can't encrypt!\n";
            		assert(false);
        	}

        	PointerType* ldInstPtrType = dyn_cast<PointerType>(ldInstPtrOperand->getType());
        	IntegerType* ldInstIntegerType = dyn_cast<IntegerType>(ldInstPtrType->getPointerElementType());
        	PointerType* ldInstPtrElemType = dyn_cast<PointerType>(ldInstPtrType->getPointerElementType());

        	assert((ldInstIntegerType != nullptr) || (ldInstPtrElemType != nullptr));
        	Value* PtrOperand = nullptr;
        	if (ldInstIntegerType && ldInstIntegerType->getBitWidth() == 8) {
            		PtrOperand = ldInstPtrOperand;
        	} else {
            		PtrOperand = Builder.CreateBitCast(ldInstPtrOperand, bytePtrType);
        	}

        	std::vector<Value*> decryptArgList;
        	decryptArgList.push_back(PtrOperand);

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
        	}

        	if (ldInstPtrElemType) {
            		// If it's a pointer type, then the return value must be cast to the correct type
            		// int to ptr
            		retVal = Builder.CreateIntToPtr(retVal, ldInst->getType());
        	}
		return retVal;

}

Value* AESCache::getDecryptedValueCachedPartitioning(LoadInst* encVal) {
		Value* retVal = nullptr;
		int byteOffset = 0;
		Value* PointerVal = nullptr;
		Type* EncValType = nullptr;
		GetElementPtrInst* GEPVal;
		IRBuilder<> Builder(encVal);
		IntegerType* EncValIntType = nullptr;
        	PointerType* EncValPtrType = nullptr;

		bool isLoop = false;

		LoadInst* ldInst = dyn_cast<LoadInst>(encVal);
		Value* ldInstPtrOperand = ldInst->getPointerOperand();

		

		Type* byteType = Type::getInt8Ty(encVal->getContext());
		PointerType* bytePtrType = PointerType::get(byteType, 0);

		int INCREMENT = 0;
		EncValIntType =  dyn_cast<IntegerType>(encVal->getPointerOperand()->getType()->getPointerElementType());
        	EncValPtrType = dyn_cast<PointerType>(encVal->getPointerOperand()->getType()->getPointerElementType());

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
        		} else {
            			errs() << "Unknown type - can't encrypt!\n";
            			assert(false);
        	}

        	PointerType* ldInstPtrType = dyn_cast<PointerType>(ldInstPtrOperand->getType());
        	IntegerType* ldInstIntegerType = dyn_cast<IntegerType>(ldInstPtrType->getPointerElementType());
        	PointerType* ldInstPtrElemType = dyn_cast<PointerType>(ldInstPtrType->getPointerElementType());

        	assert((ldInstIntegerType != nullptr) || (ldInstPtrElemType != nullptr));
        	Value* PtrOperand = nullptr;
        	if (ldInstIntegerType && ldInstIntegerType->getBitWidth() == 8) {
            		PtrOperand = ldInstPtrOperand;
        	} else {
            		PtrOperand = Builder.CreateBitCast(ldInstPtrOperand, bytePtrType);
        	}

		/*mycode*/
		errs()<< "Value of original load "<<*ldInst << "\n";
		errs()<< "Value of decrypt ptr "<< *PtrOperand<<"\n";
		errs()<< "Value of (ldInstPtrOperand ptr "<< *ldInstPtrOperand<<"\n";
		Value* safeRegion = nullptr;
		safeRegion = Builder.CreateCall(this->checkBounds, {PtrOperand});
		errs()<< "Value of safeRegion is :"<<*safeRegion<<"\n";

		Type *int32Ty;
        	int32Ty = Type::getInt32Ty(encVal->getContext());
        	//auto sizeVal = ConstantInt::get(int32Ty, 0);
	
	
		ConstantInt *Zero = Builder.getInt32(0);
		Value* cmpInst = Builder.CreateICmpEQ(safeRegion, Zero, "cmp");
		//Value* safeRegion1 = Builder.CreateCall(this->checkBounds, {PtrOperand});
		//Instruction* SplitBefore = cast<Instruction>(safeRegion1);
		Instruction* SplitBefore = cast<Instruction>(encVal);

		TerminatorInst *ThenTerm, *ElseTerm;
		SplitBlockAndInsertIfThenElse(cmpInst, SplitBefore, &ThenTerm, &ElseTerm);
	
		Builder.SetInsertPoint(ThenTerm);
	
		/*auto originalLoad = Builder.CreateLoad(ldInstPtrOperand);

		Builder.SetInsertPoint(ElseTerm);
        	auto originalLoad1 = Builder.CreateLoad(ldInstPtrOperand);

       		Builder.SetInsertPoint(SplitBefore);

		PHINode *phi = Builder.CreatePHI(int32Ty, 2);
		phi->addIncoming(originalLoad, ThenTerm->getParent());
		phi->addIncoming(originalLoad1, ElseTerm->getParent());*/

        	std::vector<Value*> decryptArgList;
        	decryptArgList.push_back(PtrOperand);

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
        	}

        	if (ldInstPtrElemType) {
            		// If it's a pointer type, then the return value must be cast to the correct type
            		// int to ptr
            		retVal = Builder.CreateIntToPtr(retVal, ldInst->getType());
        	}

		Builder.SetInsertPoint(ElseTerm);
		auto originalLoad = Builder.CreateLoad(ldInstPtrOperand);
        
		Builder.SetInsertPoint(SplitBefore);
		//PHINode *phi = Builder.CreatePHI(int32Ty, 2);
		PHINode *phi = Builder.CreatePHI(retVal->getType(), 2);
        	phi->addIncoming(retVal, ThenTerm->getParent());
        	phi->addIncoming(originalLoad, ElseTerm->getParent());

		return phi;

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

                bool isLoop = false;

                LoadInst* ldInst = dyn_cast<LoadInst>(encVal);
                Value* ldInstPtrOperand = ldInst->getPointerOperand();



                Type* byteType = Type::getInt8Ty(encVal->getContext());
                PointerType* bytePtrType = PointerType::get(byteType, 0);

                int INCREMENT = 0;
                EncValIntType =  dyn_cast<IntegerType>(encVal->getPointerOperand()->getType()->getPointerElementType());
                EncValPtrType = dyn_cast<PointerType>(encVal->getPointerOperand()->getType()->getPointerElementType());

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
                        } else {
                                errs() << "Unknown type - can't encrypt!\n";
                                assert(false);
                }

                PointerType* ldInstPtrType = dyn_cast<PointerType>(ldInstPtrOperand->getType());
                IntegerType* ldInstIntegerType = dyn_cast<IntegerType>(ldInstPtrType->getPointerElementType());
                PointerType* ldInstPtrElemType = dyn_cast<PointerType>(ldInstPtrType->getPointerElementType());

                assert((ldInstIntegerType != nullptr) || (ldInstPtrElemType != nullptr));
                Value* PtrOperand = nullptr;
                if (ldInstIntegerType && ldInstIntegerType->getBitWidth() == 8) {
                        PtrOperand = ldInstPtrOperand;
                } else {
                        PtrOperand = Builder.CreateBitCast(ldInstPtrOperand, bytePtrType);
                }

                /*mycode*/
		CallInst* readLabel = nullptr;
                ConstantInt* noOfByte = Builder.getInt64(1);
                readLabel = Builder.CreateCall(this->DFSanReadLabelFn, {PtrOperand, noOfByte});
                readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);
                errs()<< "Value of readlabel is :"<<*readLabel<<"\n";

                Type *int32Ty;
                int32Ty = Type::getInt32Ty(encVal->getContext());
                //auto sizeVal = ConstantInt::get(int32Ty, 0);


                ConstantInt *One = Builder.getInt16(1);
                Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
                //Value* safeRegion1 = Builder.CreateCall(this->checkBounds, {PtrOperand});
                //Instruction* SplitBefore = cast<Instruction>(safeRegion1);
                Instruction* SplitBefore = cast<Instruction>(encVal);

                TerminatorInst *ThenTerm, *ElseTerm;
                SplitBlockAndInsertIfThenElse(cmpInst, SplitBefore, &ThenTerm, &ElseTerm);

                Builder.SetInsertPoint(ThenTerm);

                /*auto originalLoad = Builder.CreateLoad(ldInstPtrOperand);

                Builder.SetInsertPoint(ElseTerm);
                auto originalLoad1 = Builder.CreateLoad(ldInstPtrOperand);

                Builder.SetInsertPoint(SplitBefore);

                PHINode *phi = Builder.CreatePHI(int32Ty, 2);
                phi->addIncoming(originalLoad, ThenTerm->getParent());
                phi->addIncoming(originalLoad1, ElseTerm->getParent());*/

                std::vector<Value*> decryptArgList;
                decryptArgList.push_back(PtrOperand);

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
                }

                if (ldInstPtrElemType) {
                        // If it's a pointer type, then the return value must be cast to the correct type
                        // int to ptr
                        retVal = Builder.CreateIntToPtr(retVal, ldInst->getType());
                }

                Builder.SetInsertPoint(ElseTerm);
                auto originalLoad = Builder.CreateLoad(ldInstPtrOperand);

                Builder.SetInsertPoint(SplitBefore);
                //PHINode *phi = Builder.CreatePHI(int32Ty, 2);

		//Need to add phiNode to decide which branch result will be used later on.
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
