#include "HMAC.h"

using namespace llvm;

namespace external {
	
    void HMAC::addExternHMACFuncDecls(Module &M) {
        Type *int32Ty, *int64Ty, *voidTy;
        PointerType  *int8PtrTy;
        int8PtrTy = Type::getInt8PtrTy(M.getContext());
        int64Ty = Type::getInt64Ty(M.getContext());
        int32Ty = Type::getInt32Ty(M.getContext());
        voidTy = Type::getVoidTy(M.getContext());

        // Definitions for creating functions for DFSan set_label and read_label
        const DataLayout &DL = M.getDataLayout();
        Module *Mod;
        LLVMContext *Ctx;
        Mod = &M;
        Ctx = &M.getContext();

        // Add the signatures of the compute and check functions
        voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
        voidType = Type::getVoidTy(M.getContext());

        std::vector<Type*> hmacFuncVec;
        hmacFuncVec.push_back(voidPtrType);
        ArrayRef<Type*> hmacFuncArr(hmacFuncVec);

        FunctionType* hmacFType = FunctionType::get(voidType, hmacFuncArr, false);
        this->computeHMACFunction = Function::Create(hmacFType, Function::ExternalLinkage, "compute_authentication", &M);
        this->checkHMACFunction = Function::Create(hmacFType, Function::ExternalLinkage, "check_authentication", &M);
    }

    void HMAC::initializeHMAC(Module &M) {
        I64Ty = IntegerType::get(M.getContext(), 64);
        I128Ty = IntegerType::get(M.getContext(), 128);
        V512Ty = VectorType::get(I64Ty, 8);
        V768Ty = VectorType::get(I64Ty, 12);
        this->M = &M;
        addExternHMACFuncDecls(M);
    }

    bool HMAC::findTrueOffset(StructType* topLevelType, int topLevelOffset, int* beginOffset, StructType** nestedTypePtr, int* nestedOffsetPtr) {
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
        return false;
    }

    bool HMAC::widenSensitiveComplexType(GepObjPN* gepObjPN) {
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

    bool HMAC::allFieldsSensitive(StructType* stType) {
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

    void HMAC::widenSensitiveAllocationSites(Module &M, std::vector<PAGNode*>& SensitiveAllocaList) {
            for (PAGNode* senNode: SensitiveAllocaList) {
                bool widenedStructType = false;
                // If it is a GepObjPN we need to be careful about what to widen in it
                if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senNode)) {
                    errs() << "This is what I tried to widen: " << *gepNode << " " << gepNode->getLocationSet().getOffset() << "\n";
                    widenedStructType = widenSensitiveComplexType(gepNode);
                } 
                assert(senNode->hasValue());
                // Add padding regardless if we've padded individual fields
                // Easy stuff
                Value* senVal = const_cast<Value*>(senNode->getValue());
                if (AllocaInst* allocInst = dyn_cast<AllocaInst>(senVal)) {
                    // Is an alloca instruction
                    allocInst->setAlignment(16);
                    IRBuilder<> Builder(allocInst);
                    AllocaInst* paddingAllocaInst2 = Builder.CreateAlloca(V768Ty, 0, "padding");
                    MDNode* N2 = MDNode::get(allocInst->getContext(), MDString::get(allocInst->getContext(), "padding"));
                    paddingAllocaInst2->setMetadata("PADDING", N2);

                }
            }

            // As for global variables, just align all of them to a 128 bit boundary
            for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
                if (I->getName() != "llvm.global.annotations") {
                    GlobalVariable* GV = cast<GlobalVariable>(I);
                    GV->setAlignment(16);
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

        Type* HMAC::findBaseType(Type* type) {
            Type* trueType = type;
            while (trueType->isPointerTy()) {
                trueType = trueType->getPointerElementType();
            }
            return trueType;
        }

        void HMAC::insertCheckAuthentication(LoadInst* loadInst) {
            // Need to insert call to check_authentication
            IRBuilder<> Builder(loadInst);
            Value* memOperand = loadInst->getPointerOperand();
            // Check casting
            if (loadInst->getPointerOperand()->getType() != voidPtrType) {
                memOperand = Builder.CreateBitCast(memOperand, voidPtrType);
            }
            // Args
            std::vector<llvm::Value*> argsArr;
            argsArr.push_back(memOperand);
            ArrayRef<Value*> args(argsArr);
            // Insert the call before the load
            Builder.CreateCall(this->checkHMACFunction, args);
        }

        void HMAC::insertComputeAuthentication(StoreInst* storeInst) {
            IRBuilder<> Builder(storeInst);
            Value* memOperand = storeInst->getPointerOperand();
            // Check casting
            if (storeInst->getPointerOperand()->getType() != voidPtrType) {
                memOperand = Builder.CreateBitCast(memOperand, voidPtrType);
            }
            // Args
            std::vector<llvm::Value*> argsArr;
            argsArr.push_back(memOperand);
            ArrayRef<Value*> args(argsArr);
            // Create the call
            CallInst* callInst = CallInst::Create(this->computeHMACFunction, args);
            // Insert the call after the Store
            callInst->insertAfter(storeInst);
        }

    }
