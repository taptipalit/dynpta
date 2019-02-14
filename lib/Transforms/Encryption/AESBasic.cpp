#include "AES.h"

using namespace llvm;

namespace external {

	void AESBasic::addExternAESFuncDecls(Module &M) {
		// Build the signature of the function
		PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
		IntegerType* longType = IntegerType::get(M.getContext(), 64);

		std::vector<Type*> typeVecDec;
		typeVecDec.push_back(voidPtrType); // Pointer
		ArrayRef<Type*> paramArgArray1(typeVecDec);

		FunctionType* FTypeDec = FunctionType::get(IntegerType::get(M.getContext(), 64), paramArgArray1, false);
		this->decryptBasicFunction = Function::Create(FTypeDec, Function::ExternalLinkage, "decrypt_basic", &M);

		std::vector<Type*> typeVecEnc;
		typeVecEnc.push_back(longType); // Value
		typeVecEnc.push_back(voidPtrType);
		ArrayRef<Type*> paramArgArray2(typeVecEnc);

		FunctionType* FTypeEnc = FunctionType::get(Type::getVoidTy(M.getContext()), paramArgArray2, false);

		this->encryptBasicFunction = Function::Create(FTypeEnc, Function::ExternalLinkage, "encrypt_basic", &M);

	}

	void AESBasic::initializeAes(Module &M) {
		addExternAESFuncDecls(M);
	}

	void AESBasic::removeFromList(Value* val, std::vector<Value*>& SensitiveAllocaList) {
		 SensitiveAllocaList.erase(std::remove(SensitiveAllocaList.begin(), SensitiveAllocaList.end(), val), SensitiveAllocaList.end());
	}

	void AESBasic::widenPointersAndCastInst(Module& M, Value* ptsFrom, Value* oldVal, Value* newVal, std::vector<Value*>& SensitiveAllocaList,
			std::map<Value*, Value*>& replacementMap) {
		LLVMContext& C = oldVal->getContext();
		IntegerType* wideIntType = IntegerType::get(C, 128);

		// Any pointer or Cast Instruction that points to the widened allocation site is a candidate for widening too. Cast instructions are tricky - it could be narrowing to pass to external functions, which we can not instrument. So we do not handle these situations.
		// First handle pointers - aka AllocaInst, these are the easiest
		if (AllocaInst* allocaInst = dyn_cast<AllocaInst>(ptsFrom)) {
			PointerType* allocaType = dyn_cast<PointerType>(allocaInst->getType());
			assert(allocaType && allocaType->getPointerElementType()->isPointerTy()); // Nothing but a C pointer can point to an allocation site!
			// Widen it!
			IRBuilder<> Builder(allocaInst);
			// IntegerType* oldIntType = dyn_cast<IntegerType>(allocaInst->getType());
			AllocaInst* newAllocaPtr = Builder.CreateAlloca(PointerType::get(wideIntType, 0));
			newAllocaPtr->setAlignment(8);
			newAllocaPtr->setName(allocaInst->getName());
			widenUsers(M, allocaInst, newAllocaPtr, replacementMap);
		} else if (CastInst* castInst = dyn_cast<CastInst>(ptsFrom)) {
			// First check if this cast instruction is an argument to an external library 
			// TODO - Handle this correctly
			for (User* U: castInst->users()) {
				if (CallInst* callInst = dyn_cast<CallInst>(U)) {
					Function* externalFunction = callInst->getCalledFunction();
					if (externalFunction->hasExternalLinkage()) {
						continue;
					}
				}
				if (BitCastInst* BCInst = dyn_cast<BitCastInst>(U)) {
					IRBuilder<> Builder(BCInst);
					Value* newBCInst = Builder.CreateBitCast(BCInst->getOperand(0), wideIntType);
					widenUsers(M, BCInst, newBCInst, replacementMap);
				}
			}
		} else if (Argument* arg = dyn_cast<Argument>(ptsFrom)){
			// Widening arguments which are pointers are complicated
			// From LLVMDEV it looks like the only way to do this is to clone the Function
			// and then change the function signature.
			//
			// The simple way we deal with it is by adding another variable
			// TODO - What are we going to do when we have data flow analysis?
			PointerType* argPtrType = dyn_cast<PointerType>(arg->getType());
			assert(argPtrType);
			PointerType* widePtrType = PointerType::get(wideIntType, 0);

			// Find the insertion site
			Function* F = arg->getParent();
			Instruction* firstIns = nullptr;
			Instruction* lastAllocaIns = nullptr;
			for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
				if (firstIns == nullptr) {
					firstIns = &(*I);
				} 
				Instruction* inst = &(*I);
				AllocaInst* allocaInst = dyn_cast<AllocaInst>(inst);
				if (allocaInst) {
					lastAllocaIns = allocaInst;
				}
			}

			IRBuilder<> Builder(firstIns);
			AllocaInst* widenedArgPtr = Builder.CreateAlloca(widePtrType);
			IRBuilder<> Builder2(lastAllocaIns);
			Value* bcVal = Builder2.CreateBitCast(arg, widePtrType);
			/*StoreInst* stInst = */Builder2.CreateAlignedStore(bcVal, widenedArgPtr, 8);
			LoadInst* widenedArg = Builder2.CreateAlignedLoad(widenedArgPtr, 8);
			widenUsers(M, arg, widenedArg, replacementMap, bcVal);
		}
	}

	void AESBasic::widenUsers(Module& M, Value* oldVal, Value* newVal, std::map<Value*, Value*>& replacementMap, Value* skipInstruction) {
		std::vector<User*> oldValUsers;
		LLVMContext& C = oldVal->getContext();
		IntegerType* wideIntType = IntegerType::get(C, 128);
		PointerType* ptrToWideIntType = PointerType::get(wideIntType, 0);

		for (User *U: oldVal->users()) {
			if (oldVal != U) {
				oldValUsers.push_back(U);
			}

		}

		// Handle any pointers that could point to oldVal - TODO
		for (User* U: oldValUsers) {
			if (U != skipInstruction) {
				int i, NumOperands = U->getNumOperands();
				for (i = 0; i < NumOperands; i++) {
					// Update the correct operand
					if (U->getOperand(i) == oldVal) {
						if (!isa<ConstantExpr>(U)) {
							U->setOperand(i, newVal); // Deal with constant expressions in the next part of function
						}
					}
				}
			}

			// First check if it is ConstantExpr ==> don't change order of if checks
			if (ConstantExpr* consExpr = dyn_cast<ConstantExpr>(U)) {
				// Need to replace this Constant Expression, with a new one we create
				assert(isa<Constant>(newVal));
				Constant* constNewVal = dyn_cast<Constant>(newVal);
				if (GEPOperator* GEPOp = dyn_cast<GEPOperator>(consExpr)) {
					ArrayType* oldArrayType = dyn_cast<ArrayType>(GEPOp->getSourceElementType());
					assert(oldArrayType != nullptr);
					long numElements = oldArrayType->getNumElements();
					// TODO - widening must be done recursively, to find all embedded integer attributes
					ArrayType* wideArrayType = ArrayType::get(wideIntType, numElements);

					std::vector<Value*> IdxList;
					for (User::op_iterator Idx = GEPOp->idx_begin(); Idx != GEPOp->idx_end(); ++Idx) {
						if (ConstantInt* constant = dyn_cast<ConstantInt>(Idx)) {
							Constant* wideConst = ConstantInt::get(wideIntType, constant->getValue().getLimitedValue());
							IdxList.push_back(wideConst);
						} else {
							assert(false); // Can't have constant GEPOperator expression, with non-constant index
						}
					}
					ArrayRef<Value*> idxListArrayRef(IdxList);

					Constant* newGEPOp = nullptr;
					if (GEPOp->isInBounds()){
						newGEPOp = ConstantExpr::getInBoundsGetElementPtr(wideArrayType, constNewVal, idxListArrayRef);
					} else {
						newGEPOp = ConstantExpr::getGetElementPtr(wideArrayType, constNewVal, idxListArrayRef);
					}
					std::vector<User*> GEPOpUserList;
					for (User* GEPOpU: GEPOp->users()) {
						if (GEPOpU != GEPOp) {
							GEPOpUserList.push_back(GEPOpU);	
						}
					}
					for (User* GepOpU: GEPOpUserList) {
						if (isa<Constant>(GepOpU)) {
							continue; // TODO - This happens because of the global.annotations variable. How do I remove the global variable?
						}
						int j, GepOpNumOperands = GepOpU->getNumOperands();
						for (j = 0; j < GepOpNumOperands; j++) {
							if (GepOpU->getOperand(j) == GEPOp) {
								GepOpU->setOperand(j, newGEPOp);
							}
						}
					}
					replacementMap[GEPOp] = newGEPOp;
					//SensitiveAllocaList.push_back(newGEPOp);
				} else {
					// Don't handle anything but GEPConstExpr
					//assert(false);
					// TODO - Argghhh! var.annotations. contains some other constants
				}

			} else if (CastInst* CInst = dyn_cast<CastInst>(U)) {
				//SensitiveAllocaList.push_back(CInst);
			} else if (GetElementPtrInst* GEPInst = dyn_cast<GetElementPtrInst>(U)) {
				IRBuilder<> Builder(GEPInst);
				// Special handling for GEP instructions
				//GEPInst->setSourceElementType(wideIntType);
				//GEPInst->setResultElementType(wideIntType);
				std::vector<Value*> idxList;
				for (User::op_iterator Idx = GEPInst->idx_begin(); Idx != GEPInst->idx_end(); ++Idx) {
					if (ConstantInt* constant = dyn_cast<ConstantInt>(Idx)) {
						Constant* wideConst = ConstantInt::get(wideIntType, constant->getValue().getLimitedValue());
						idxList.push_back(wideConst);
					} else {
						// Create a widened version of the virtual register
						// Do not remove the previous version, someone might need it down the line
						Value* virtReg = dyn_cast<Value>(Idx);
						Value* virtRegWiden = Builder.CreateSExt(virtReg, wideIntType);
						idxList.push_back(virtRegWiden);
					}
				}
				ArrayRef<Value*> idxListArrayRef(idxList);
				//Value* GEPPtr = GEPInst->getPointerOperand();
				Value* GEPPtr = newVal;
				Value* newGEPInst = Builder.CreateGEP(GEPPtr, idxListArrayRef, GEPInst->getName());
				// Replace users
				//GEPInst->replaceAllUsesWith(newGEPInst);
				std::vector<User*> GepUserList;
				for (User* GepU: GEPInst->users()) {
					GepUserList.push_back(GepU);
				}
				widenUsers(M, GEPInst, newGEPInst, replacementMap);
				replacementMap[GEPInst] = newGEPInst;
			} else if (LoadInst* LdInst = dyn_cast<LoadInst>(U)) {
				// A load is a source, widen all subsequent instructions that depend on this
				if (PointerType* LdPtrType = dyn_cast<PointerType>(LdInst->getPointerOperand()->getType())) {
					if (PointerType* LdFromPtrType = dyn_cast<PointerType>(LdPtrType->getPointerElementType())) {
						// Special Case - Something is being loaded from a Pointer that points to widened variable / array
						// Widen all dependencies
						unsigned int alignment = LdInst->getAlignment();
						IRBuilder<> Builder(LdInst);
						Value* newLdInst = Builder.CreateAlignedLoad(LdInst->getPointerOperand(), alignment);
						widenUsers(M, LdInst, newLdInst, replacementMap);	
						replacementMap[LdInst] = newLdInst;
					}
				}
			} else if (StoreInst* StInst = dyn_cast<StoreInst>(U)) {
				// If the widened value is the sink, then we need to bitcast the actual operand for it to fit
				if (PointerType* StPtrType = dyn_cast<PointerType>(StInst->getPointerOperand()->getType())) {
					if (PointerType* StToPtrType = dyn_cast<PointerType>(StPtrType->getPointerElementType())) {
						// Add bitcast and get done with this
						IRBuilder<> Builder(StInst);
						Value* bcVal = Builder.CreateBitCast(StInst->getValueOperand(), ptrToWideIntType);
						StInst->setOperand(0, bcVal);
					}
				}
			}
		}


	}

	// TODO - Global arrays not handled
	void AESBasic::widenGlobalVariable(Module& M, GlobalVariable* gVar, std::vector<Value*>& SensitiveAllocaList, std::map<llvm::Value*, std::set<llvm::Value*>>& ptsFromMap, 
			std::map<Value*, Value*>& replacementMap ) {
		// Is a Global variable
		// Create a new Global Variable
		LLVMContext& C = gVar->getContext();
		IntegerType* wideIntType = IntegerType::get(C, 128);
		GlobalVariable* newGVar = nullptr;

		PointerType* oldPointerType = gVar->getType();
		Type* oldType = oldPointerType->getPointerElementType();

		if (IntegerType* oldIntType = dyn_cast<IntegerType>(oldType)) {
			newGVar = new GlobalVariable(M, 
					/*Type=*/ wideIntType,
					/*isConstant=*/false,
					/*Linkage=*/GlobalValue::CommonLinkage,
					/*Initializer=*/0, // has initializer, specified below
					/*Name=*/"widenGlobal");
			newGVar->setAlignment(16);
			newGVar->setName(gVar->getName());

			Constant* nullInitializer = Constant::getIntegerValue(wideIntType, APInt::getNullValue(128));
			newGVar->setInitializer(nullInitializer);
		} else if (ArrayType* oldArrayType = dyn_cast<ArrayType>(oldType)) {
			int numElements = oldArrayType->getNumElements();
			ArrayType* newArrayType = ArrayType::get(wideIntType, numElements);
			newGVar = new GlobalVariable(M, 
					/*Type=*/ newArrayType,
					/*isConstant=*/false,
					/*Linkage=*/GlobalValue::CommonLinkage,
					/*Initializer=*/0, // has initializer, specified below
					/*Name=*/"widenGlobal");
			long size = 16*numElements;
			//newGVar->setAlignment(pow(2, ceil(log(size)/log(2))));
			newGVar->setAlignment(16);
			newGVar->setName(gVar->getName());

			bool noInitializer = true;
			if (gVar->hasInitializer()) {
				Constant* initializer = gVar->getInitializer();
				if (ConstantInt* initInt = dyn_cast<ConstantInt>(initializer)) {
					uint64_t constValue = initInt->getValue().getLimitedValue();
					ConstantInt* wideInitInt = ConstantInt::get(wideIntType, constValue);
					newGVar->setInitializer(wideInitInt);
				}
			       	else if (ConstantArray* initArray = dyn_cast<ConstantArray>(initializer)) {
					ArrayType* initArrayTy = initArray->getType();
					Type* arrayElemTy = initArrayTy->getElementType();
					int numElements = initArrayTy->getNumElements();
					std::vector<Constant*> newConstArrayVec;
					ArrayType* wideInitArrayTy = ArrayType::get(wideIntType, numElements);
					for (int i = 0; i < numElements; i++) {
						Constant* arrayElem = initArray->getAggregateElement(i);
						if (ConstantInt* arrayElemInt = dyn_cast<ConstantInt>(arrayElem)) {
							uint64_t elemVal = arrayElemInt->getValue().getLimitedValue();
							ConstantInt* wideElemVal = ConstantInt::get(wideIntType, elemVal);
							newConstArrayVec.push_back(wideElemVal);
						}

					}
					ArrayRef<Constant*> constArrayRef(newConstArrayVec);
					Constant* wideInitArray = ConstantArray::get(wideInitArrayTy, constArrayRef);
					newGVar->setInitializer(wideInitArray);
					noInitializer = true;
				}
			} 
		        if (noInitializer) {
				ConstantAggregateZero* nullInitializer = ConstantAggregateZero::get(newArrayType);
				newGVar->setInitializer(nullInitializer);
			}

		}

		widenUsers(M, gVar, newGVar, replacementMap);
		SensitiveAllocaList.push_back(newGVar);
		std::vector<Value*> oldValUsers;
		for (User *U: gVar->users()) {
			// Apart from Constant Expressions, we should have no other user
			if (!isa<ConstantExpr>(U)) {
				oldValUsers.push_back(U);
			}
		}
		assert(oldValUsers.size() == 0);
		replacementMap[gVar] = newGVar;
		for (Value* ptsFrom: ptsFromMap[gVar]) {
			if (ptsFrom != newGVar) {
				widenPointersAndCastInst(M, ptsFrom, gVar, newGVar, SensitiveAllocaList, replacementMap);
			}
		}
	}

	void AESBasic::widenMallocCall(Module& M, CallInst* cI, Type* ptrType, std::vector<Value*>& SensitiveAllocaList, std::map<llvm::Value*, std::set<llvm::Value*>>& ptsFromMap, 
			std::map<Value*, Value*>& replacementMap) {

		PointerType* actualPtrType = dyn_cast<PointerType>(ptrType);
		assert(actualPtrType);
		IntegerType* actualIntegerType = dyn_cast<IntegerType>(actualPtrType->getPointerElementType());
		assert(actualIntegerType);
		Function* calledFunction = cI->getCalledFunction();
		if ("malloc" == calledFunction->getName()) {
			// Widen the operand to the right size
			Value* sizeOperand = cI->getArgOperand(0);
			Value* newCI = nullptr;
			// Handle constants and variables differently
			if (ConstantInt* constantInt = dyn_cast<ConstantInt>(sizeOperand)) {
				uint64_t numBytes = constantInt->getValue().getLimitedValue();
				long numElements = numBytes / (actualIntegerType->getBitWidth()/8);
				long newNumBytes = numElements*16;
				ConstantInt* newConstantInt = ConstantInt::get(IntegerType::get(M.getContext(), 64), newNumBytes);

				std::vector<Value*> args;
				args.push_back(newConstantInt);
				ArrayRef<Value*> paramArgArray(args);

				IRBuilder<> Builder(cI);
				newCI = Builder.CreateCall(calledFunction, args);
			} else {
				// Variable
				// We need to multiply it by the required factor to make each element 128 bits
				int originalByteSize = actualIntegerType->getBitWidth();
				long multiplyFactor = 16/(originalByteSize/8);
				
				IRBuilder<> Builder(cI);
				ConstantInt* constMulFactor = ConstantInt::get(IntegerType::get(M.getContext(), 64), multiplyFactor);
				Value* newSizeVal = Builder.CreateMul(sizeOperand, constMulFactor);

				std::vector<Value*> args;
				args.push_back(newSizeVal);
				ArrayRef<Value*> paramArgArray(args);

				newCI = Builder.CreateCall(calledFunction, args);

			}

			widenUsers(M, cI, newCI, replacementMap);
			SensitiveAllocaList.push_back(newCI);
			std::vector<Value*> oldValUsers;
			for (User *U: cI->users()) {
				// Apart from Constant Expressions, we should have no other user
				if (!isa<ConstantExpr>(U)) {
					oldValUsers.push_back(U);
				}
			}
			assert(oldValUsers.size() == 0);
			replacementMap[cI] = newCI;

			// Also deal with any other "casted version" or other pointer that could point to this allocation site
			for (Value* ptsFrom: ptsFromMap[cI]) {
				if (ptsFrom != cI) {
					widenPointersAndCastInst(M, ptsFrom, cI, newCI, SensitiveAllocaList, replacementMap);
				}
			}
		}
		
	}

	void AESBasic::widenAllocaInst(Module& M, AllocaInst* aI, std::vector<Value*>& SensitiveAllocaList, std::map<llvm::Value*, std::set<llvm::Value*>>& ptsFromMap,
			std::map<Value*, Value*>& replacementMap) {
		// Alloca Instruction
		LLVMContext& C = aI->getContext();
		PointerType* oldPointerType = aI->getType();
		Type* oldType = oldPointerType->getPointerElementType();
		AllocaInst* newAI = nullptr;
		IntegerType* wideIntType = IntegerType::get(C, 128);
		if (IntegerType* oldIntType = dyn_cast<IntegerType>(oldType)) {
			IRBuilder<> Builder(aI);
			newAI = Builder.CreateAlloca(wideIntType);
			newAI->setAlignment(16);
			newAI->setName(aI->getName());
		} else if (ArrayType* oldArrayType = dyn_cast<ArrayType>(oldType)) {
			long numElements = oldArrayType->getNumElements();
			long alignment = pow(2, ceil(log(numElements*16)/log(2)));
			// TODO - widening must be done recursively, to find all embedded integer attributes
			ArrayType* wideArrayType = ArrayType::get(wideIntType, numElements);
			IRBuilder<> Builder(aI);
			newAI = Builder.CreateAlloca(wideArrayType);
			newAI->setAlignment(alignment);
			newAI->setName(aI->getName());
		}

		widenUsers(M, aI, newAI, replacementMap);
		SensitiveAllocaList.push_back(newAI);
		std::vector<Value*> oldValUsers;
		for (User *U: aI->users()) {
			// Apart from Constant Expressions, we should have no other user
			if (!isa<ConstantExpr>(U)) {
				oldValUsers.push_back(U);
			}
		}
		assert(oldValUsers.size() == 0);
		replacementMap[aI] = newAI;

		for (Value* ptsFrom: ptsFromMap[aI]) {
			if (ptsFrom != aI) {
				widenPointersAndCastInst(M, ptsFrom, aI, newAI, SensitiveAllocaList, replacementMap);
			}
		}

	}

	void AESBasic::updateReferences(std::map<Value*, std::set<Value*>>& targetMap, Value* oldVal, Value* newVal) {
		// First pass check if oldVal is a key, if it is, then update it
		std::map<Value*,std::set<Value*>>::iterator iter = targetMap.find(oldVal);
		if (iter != targetMap.end()) {
			// Found!
			std::set<Value*> valueList = iter->second;
			targetMap[newVal] = valueList;
			targetMap.erase(iter);
		}
		// Second pass iterate over all values, check if oldVal is a Value, if it is, then update it
		for(std::map<Value*,std::set<Value*>>::iterator iter = targetMap.begin(); iter != targetMap.end(); ++iter)
		{
		//	Value* key =  iter->first;
			std::set<Value*>::iterator vecIter = std::find(iter->second.begin(), iter->second.end(), oldVal);
			if (vecIter != iter->second.end()) {
				// Found!
				iter->second.erase(vecIter);
				iter->second.insert(newVal);
			}
		}

	}

	void AESBasic::widenSensitiveVariables(Module &M, std::vector<Value*>& SensitiveAllocaList,
		std::map<llvm::Value*, std::set<llvm::Value*>>& ptsToMap, std::map<llvm::Value*, std::set<llvm::Value*>>& ptsFromMap) {
		std::vector<Value*> OldSensitiveAllocaList(SensitiveAllocaList);

		SensitiveAllocaList.clear();
		std::set<Value*> removedList;

		std::sort(OldSensitiveAllocaList.begin(), OldSensitiveAllocaList.end());
		OldSensitiveAllocaList.erase(unique(OldSensitiveAllocaList.begin(), OldSensitiveAllocaList.end()), OldSensitiveAllocaList.end());

		for (Value* allocSite: OldSensitiveAllocaList) {
			std::map<Value*, Value*> replacementMap;
			LLVMContext& C = allocSite->getContext();
			bool updated = false;
			if (AllocaInst* aI = dyn_cast<AllocaInst>(allocSite)) {
				widenAllocaInst(M, aI, SensitiveAllocaList, ptsFromMap, replacementMap);
				updated = true;
			} else if (CallInst* callInst = dyn_cast<CallInst>(allocSite)) {
				// Is a malloc instruction
				// Additional sanity needed, make sure that different sized pointers do not point to this
				Type* singlePointerType = nullptr;
				for (Value* ptrVal: ptsFromMap[callInst]) {
					if (PointerType* ptrType = dyn_cast<PointerType>(ptrVal->getType())) {
						if (PointerType* actualPointerType = dyn_cast<PointerType>(ptrType->getPointerElementType())) {
							if (singlePointerType != nullptr) {
								assert(actualPointerType == singlePointerType);
							} else {
								singlePointerType = actualPointerType;
							}
						}
					}
				}
				widenMallocCall(M, callInst, singlePointerType, SensitiveAllocaList, ptsFromMap, replacementMap);
				updated = true;
			} else if (GlobalVariable* gVar = dyn_cast<GlobalVariable>(allocSite)) {
				widenGlobalVariable(M, gVar, SensitiveAllocaList, ptsFromMap, replacementMap);
				updated = true;
			}
			if (updated) {
				for (std::map<Value*,Value*>::iterator it=replacementMap.begin(); it!=replacementMap.end(); ++it) {
					Value* origVal = it->first;
					Value* newVal = it->second;
					updateReferences(ptsToMap, origVal, newVal);
					updateReferences(ptsFromMap, origVal, newVal);
					removedList.insert(origVal);
				}
			}
		}
		for (Value* v: removedList) {
			if (GlobalVariable* gVar = dyn_cast<GlobalVariable>(v)) {
				std::vector<User*> GVarUsers;
				
				for (User* U: gVar->users()) {
					if (U != gVar) {
						GVarUsers.push_back(U);
					}
				}

				if (GVarUsers.size() == 0 ) {
					gVar->eraseFromParent();
				} else {
					for (User* U: GVarUsers) {
						assert(isa<Constant>(U));	
					}
				}
			} else if (Instruction* inst = dyn_cast<Instruction>(v)) {
				inst->eraseFromParent();
			}
			removeFromList(v, SensitiveAllocaList);
		}
	}

	Value* AESBasic::setEncryptedValue(StoreInst* StInst) {
		IRBuilder<> Builder(StInst);

		Value* encryptOperand = StInst->getPointerOperand();
		Value* plainTextValue = StInst->getValueOperand();

		IntegerType* voidTy = IntegerType::get(StInst->getContext(), 8);
		IntegerType* longTy = IntegerType::get(StInst->getContext(), 64);
		PointerType* voidPtrTy = PointerType::get(voidTy, 0);
		// Add a BitCast Instruction to cast it to (void*)
		Value* voidCastPtr = Builder.CreateBitCast(encryptOperand, voidPtrTy);
		// Add a BitCast Instruction to cast the value to i64, if any other sized Integer
		IntegerType* valType = dyn_cast<IntegerType>(plainTextValue->getType());
		if (valType != nullptr && (valType->getBitWidth() != 64)) {
			plainTextValue = Builder.CreateSExtOrBitCast(plainTextValue, longTy);
		}

		// Add call to encrypt_basic
		std::vector<Value*> encryptArgList;
		encryptArgList.push_back(plainTextValue); // Pass the plaintext value here
		encryptArgList.push_back(voidCastPtr); // Pass the actual pointer here
		CallInst* encryptCInst = Builder.CreateCall(this->encryptBasicFunction, encryptArgList);
		return encryptCInst;
	}



	Value* AESBasic::getDecryptedValue(LoadInst* LdInst) {
		IRBuilder<> Builder(LdInst);
		
		Value* returnValue = nullptr;

		Value* decryptOperand = LdInst->getPointerOperand();

		IntegerType* voidTy = IntegerType::get(LdInst->getContext(), 8);
		PointerType* voidPtrTy = PointerType::get(voidTy, 0);
		// Add a BitCast Instruction to cast ptr to (void*)
		Value* voidCastPtr = Builder.CreateBitCast(decryptOperand, voidPtrTy);
		// Add call to decrypt_basic
		std::vector<Value*> decryptArgList;
		decryptArgList.push_back(voidCastPtr);
		CallInst* decryptCInst = Builder.CreateCall(this->decryptBasicFunction, decryptArgList);
		returnValue = decryptCInst;

		// this->decryptBasicFunction returns of type long, so might need to truncate it
		Type* LdPtrType = LdInst->getType();
		if (IntegerType* LdPtrTypeInt = dyn_cast<IntegerType>(LdPtrType)) {
			if (LdPtrTypeInt->getBitWidth() != 64) {
				// Truncate!
				returnValue = Builder.CreateTrunc(decryptCInst, LdPtrTypeInt);
			}
		}

		return returnValue;

	}

}
