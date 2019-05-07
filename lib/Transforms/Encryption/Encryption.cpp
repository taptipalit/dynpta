#include "EncryptionInternal.h"
#include "ExtLibraryHandler.h"
#include "AES.h"
#include "ASMParser.h"
#include "llvm/Support/Format.h"

#define DEBUG_TYPE "encryption"

#define STORE 1
#define LOAD 2

using namespace llvm;

namespace {

	struct InstructionReplacement {
		Instruction* OldInstruction;
		Instruction* NextInstruction;
		int Type;
	};

	static const char* CallocLikeFunctions[] = {"aes_calloc", "calloc", "pthread_getspecific", "asprintf", "asprintf128", "cloneenv", "strdup", "mmap", "posix_memalign", "readdir", "clonereaddir", nullptr};

	class EncryptionPass : public ModulePass {
		public:
		static char ID;

        static const int SPECIALIZE_THRESHOLD = 50;

		EncryptionPass() : ModulePass(ID) {
            decryptionCount = 0;
            encryptionCount = 0;
			initializeEncryptionPassPass(*PassRegistry::getPassRegistry());
		}

        std::set<Value*> ExtraSensitivePtrs;

        // Statistics
        long decryptionCount;
        long encryptionCount;

        void collectLoadStoreStats(Module&);

		bool runOnModule(Module &M) override;

		private:
		

		//bool DoNullEnc;
		bool DoAESEncCache;

        /*
		std::map<llvm::Value*, std::set<llvm::Value*>>* ptsToMapPtr;
		std::map<llvm::Value*, std::set<llvm::Value*>>* ptsFromMapPtr;
        */

		external::ExtLibraryHandler ExtLibHandler;
		external::AESCache AESCache;
		external::ASMParser asmParser;


		/* Hacky code to handle function pointers */
		std::vector<Function*> MallocFunctions;

		std::vector<Instruction*> InstructionList;
		std::vector<InstructionReplacement*> ReplacementList; // Avoid messing up things while the iterators are running

		std::vector<PAGNode*> SensitiveObjList; // We maintain the PAGNodes here to record field sensitivity

		std::vector<Value*> SensitiveLoadPtrList; // Any pointer that points to sensitive location
		std::vector<Value*> SensitiveLoadList;
		std::vector<Value*> SensitiveInlineAsmCalls;
		std::vector<Value*> SensitiveInlineAsmArgs;
		std::vector<Value*> SensitiveGEPPtrList;

		/* The set equivalents */
		std::set<PAGNode*>* SensitiveObjSet; // PAGNodes to record field sensitivity

		std::set<Value*>* SensitiveLoadPtrSet; // Any pointer that points to sensitive location
		std::set<Value*>* SensitiveLoadSet;
		std::set<Value*>* SensitiveGEPPtrSet;
        std::set<Value*> SensitiveArgSet;

		std::map<Value*, Value*> SensitivePtrValMap;

		std::vector<StoreInst*> SensitiveStoreList;
		std::vector<CallInst*> SensitiveExternalLibCallList;

        // Needed for source-sink data-flow analysis
	    std::set<Value*> AllFunctions;
        std::map<Function*, std::vector<ReturnInst*>> funRetMap;
        std::map<ReturnInst*, std::vector<CallInst*>> retCallMap;

		bool containsSet(llvm::Value*, std::set<llvm::Value*>&);

		bool contains(llvm::Value*, std::vector<llvm::Value*>&);

        PAGNode* getPAGObjNodeFromValue(Value*);
        PAGNode* getPAGValNodeFromValue(Value*);

        void findGepInstFromGepNode(GepObjPN*, std::vector<GetElementPtrInst*>&);
        GepObjPN* getGepOrFINodeFromGEPInst(GetElementPtrInst*);

		bool isSensitiveLoad(Value*);
		bool isSensitiveLoadPtr(Value*);
		bool isSensitiveGEPPtr(Value*);
		bool isSensitiveObj(PAGNode*);

		bool isSensitiveLoadSet(Value*);
		bool isSensitiveLoadPtrSet(Value*);
		bool isSensitiveGEPPtrSet(Value*);
		bool isSensitiveObjSet(PAGNode*);

		bool isSensitivePtrVal(Value*);

		bool isSensitiveArg(Value*,   std::map<PAGNode*, std::set<PAGNode*>>& );
        //bool isSensitiveArg(Value*);


		Instruction* FindNextInstruction(Instruction*);
	

		//void postProcessPointsToGraph(Module&, std::map<llvm::Value*, std::vector<llvm::Value*>>&, std::map<llvm::Value*, std::vector<llvm::Value*>>&);
		void removeAnnotateInstruction(Module& M);

		void collectGlobalSensitiveAnnotations(Module&);
		void collectLocalSensitiveAnnotations(Module&);

        std::vector<Type*> sensitiveTypes;

        bool isaCPointer(Value*);
        bool isaCPointer(Type*);
        Type* findTrueType(Type*, int, int);
        void buildRetCallMap(Module& M);
        void trackExternalFunctionFlows(Value*, std::set<Value*>&);

        bool filterDataFlowPointersByType(Value*);
        void collectSensitiveTypes(Module &);
        void performSourceSinkAnalysis(Module &);
        bool isaConstantValue(Value*);
        void findDirectSinkSites(PAGNode*, std::set<PAGNode*>&);
        void findIndirectSinkSites(PAGNode*, std::set<PAGNode*>&);

        Value* findObjFromCast(Value*);

        Function* findSimpleFunArgFor(Value*);
        void preprocessSensitiveAnnotatedPointers(Module &M);
		void collectSensitivePointsToInfo(Module&, std::map<PAGNode*, std::set<PAGNode*>>&, std::map<PAGNode*, std::set<PAGNode*>>&);
		//void addExternInlineASMHandlers(Module&);

		void initializeSensitiveGlobalVariables(Module&);
		void collectSensitiveLoadInstructions(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);
        void collectSensitiveGEPInstructionsFromLoad(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);
		void collectSensitiveAsmInstructions(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);
		void collectSensitiveGEPInstructions(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);
		void collectSensitiveExternalLibraryCalls(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);

		void buildSets(Module&);
		void unConstantifySensitiveAllocSites(Module&);
		//Value* retPtrIfAny(Function* F);

		void preprocessAllocaAndLoadInstructions(Instruction*);
		void preprocessStoreInstructions(Instruction*);

		void performInstrumentation(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);

		void performXorInstrumentation(Module&);
		void performAesCacheInstrumentation(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);

		//void instrumentInlineAsm(Module&);

		void resetInstructionLists(Function*);

		void instrumentAndAnnotateInst(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);
		void instrumentExternalFunctionCall(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);

		void fixupBrokenFunctionCallsFromWidening(Module&);
        void updateSensitiveState(Value*, Value*, std::map<PAGNode*, std::set<PAGNode*>>&);

		bool isCallocLike(const char* str);
		bool isValueStoredToSensitiveLocation(Value*);

        Type* findBaseType(Type*);
        int getCompositeSzValue(Value*, Module& );

       // int getSzVoidRetVal(Value*, Module&);
        //int getSzVoidArgVal(Value*, Module&);

        void fixupSizeOfOperators(Module&);

        //void collectVoidDataObjects(Module&);

		void getAnalysisUsage(AnalysisUsage& AU) const {
            //AU.addRequired<LibcTransformPass>();
			AU.addRequired<WPAPass>();
			//AU.setPreservesAll();
		}

    };
}

char EncryptionPass::ID = 0;

//cl::opt<bool> NullEnc("null-enc", cl::desc("XOR Encryption"), cl::init(false), cl::Hidden);
cl::opt<bool> AesEncCache("aes-enc-cache", cl::desc("AES Encryption - Cache"), cl::init(false), cl::Hidden);
//cl::opt<bool> SkipVFA("skip-vfa-enc", cl::desc("Skip VFA"), cl::init(false), cl::Hidden);


void EncryptionPass::collectLoadStoreStats(Module& M) {
    int loadCount, storeCount, getDecCount, setEncCount;
    loadCount = storeCount = getDecCount = setEncCount = 0;
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            // Get the local sensitive values
            for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                    //outs() << "Basic block found, name : " << BB->getName() << "\n";
                    for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                        if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                            if (LoadInst* loadInst = dyn_cast<LoadInst>(Inst)) {
                                loadCount++;
                            } else if (StoreInst* storeInst = dyn_cast<StoreInst>(Inst)) {
                                storeCount++;
                            } else if (CallInst* callInst = dyn_cast<CallInst>(Inst)) {
                                Function* fun = callInst->getCalledFunction();
                                if (fun && fun->getName().find("getDec") != StringRef::npos) {
                                    getDecCount++;
                                } else if (fun && fun->getName().find("setEnc") != StringRef::npos) {
                                    setEncCount++;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    errs() << "Statistics: \n";
    errs() << "% of Loads accessing sensitive memory regions: " << format("%.3f\n", ((double)getDecCount)/((double)getDecCount+loadCount)*100.0) << "\n";
    errs() << "% of Stores accessing sensitive memory regions: " << format("%.3f\n", ((double)setEncCount)/((double)(setEncCount+storeCount))*100.0) << "\n";
}

bool EncryptionPass::containsSet(llvm::Value* V, std::set<llvm::Value*>& L) {
	if (std::find(L.begin(), L.end(), V) != L.end()) {
		return true;
	} else {
		return false;
	}
}

bool EncryptionPass::contains(llvm::Value* V, std::vector<llvm::Value*>& L) {
	if (std::find(L.begin(), L.end(), V) != L.end()) {
		return true;
	} else {
		return false;
	}
}

bool EncryptionPass::isSensitiveLoad(Value* Val) {
	if (std::find(SensitiveLoadList.begin(), SensitiveLoadList.end(), Val) != SensitiveLoadList.end()) {
		return true;
	} else {
		return false;
	}
}

bool EncryptionPass::isSensitiveLoadPtr(Value* Val) {
	if (std::find(SensitiveLoadPtrList.begin(), SensitiveLoadPtrList.end(), Val) != SensitiveLoadPtrList.end()) {
		return true;
	} else {
		return false;
	}
}

bool EncryptionPass::isSensitiveGEPPtr(Value* Val) {
	if (std::find(SensitiveGEPPtrList.begin(), SensitiveGEPPtrList.end(), Val) != SensitiveGEPPtrList.end()) {
		return true;
	} else {
		return false;
	}
}

PAGNode* EncryptionPass::getPAGObjNodeFromValue(Value* llvmValue) {
    PAG* pag = getAnalysis<WPAPass>().getPAG();
    assert(pag->hasObjectNode(llvmValue) && "Can't get PAG ObjPN as none exists.");
    return pag->getPAGNode(pag->getObjectNode(llvmValue));

}

PAGNode* EncryptionPass::getPAGValNodeFromValue(Value* llvmValue) {
    PAG* pag = getAnalysis<WPAPass>().getPAG();
    assert(pag->hasValueNode(llvmValue) && "Can't get PAG ValPN as none exists.");
    return pag->getPAGNode(pag->getValueNode(llvmValue));
}

void EncryptionPass::findGepInstFromGepNode(GepObjPN* gepNode, std::vector<GetElementPtrInst*>& gepInstList) {
    /*
    const LocationSet& LS = gepNode->getLocationSet();
    // Location Set (n, o, s) ==> n: name of obj, o: offset, s: stride
    // Location Set for scalar v ==> (v, 0, 0)
    // Location Set for arr elem a[i] ==> (a, 0, s); s: size of elem
    // Location Set for field f in struct S ==> (S, f, 0) 
    // Location Set for set of fields a[i].f ==> (a, f, s); s: size of elem
    // So, the NumStridePair, should be non-zero only in case of fields of an array of struct
    // We don't handle it right now

    const FieldInfo::ElemNumStridePairVec& ns = LS.getNumStridePair();
    for(NodePair np: ns) {
        if ((np.first != 0 || np.second != 0) && LS.getOffset() != 0) {
            assert(false && "We do not handle fields of arrays of struct yet!");
        }
    }

    // Now, we know the offset. Just find the right GEP inst from it
    Value* obj = gepNode->getValue();
    assert((isa<AllocaInst>(obj) || isa<GlobalVariable>(obj) || isa<CallInst>(obj)) && "A GepNode should probably be a stack or global or heap object");
    bool varGep = false;
    // Check if there's a variable gep
    for (Value::user_iterator userItr = obj->user_begin(), userEnd = obj->user_end(); userItr != userEnd; userItr++) {
        if (GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(*userItr)) {
            assert(gepInst->getNumOperands() > 2 && "We do not handle fields of arrays of struct yet!");
            Value* off = gepInst->getOperand(gepInst->getNumOperands() - 1);
            ConstantInt* offInt = dyn_cast<ConstantInt>(off);
            if (!offInt) {
                varGep = true;
            }
        }
    }
    
    if (!varGep) {
        for (Value::user_iterator userItr = obj->user_begin(), userEnd = obj->user_end(); userItr != userEnd; userItr++) {
            if (GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(*userItr)) {
                assert(gepInst->getNumOperands() > 2 && "We do not handle fields of arrays of struct yet!");
                Value* off = gepInst->getOperand(gepInst->getNumOperands() - 1);
                ConstantInt* offInt = dyn_cast<ConstantInt>(off);
                assert(offInt && "We should not see any var geps here any more!");
                int offIntVal = offInt->getLimitedValue();
                if (offIntVal == LS.getOffset()) {
                    gepInstList.push_back(gepInst);
                }
            }
        }
    } else {
        for (Value::user_iterator userItr = obj->user_begin(), userEnd = obj->user_end(); userItr != userEnd; userItr++) {
            if (GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(*userItr)) {
                gepInstList.push_back(gepInst);
            }
        }
    }
    */
}

GepObjPN* EncryptionPass::getGepOrFINodeFromGEPInst(GetElementPtrInst* gepInst) {
    for (int i = 1; i < gepInst->getNumOperands() - 1; i++) {
        Value* off = gepInst->getOperand(i);
        ConstantInt* offInt = dyn_cast<ConstantInt>(off);
        int offset = offInt->getLimitedValue();
        assert(offset == 0 && "We do not handle fields of arrays of struct yet!");
    }
    Value* off = gepInst->getOperand(gepInst->getNumOperands()-1);
    ConstantInt* offInt = dyn_cast<ConstantInt>(off);
    int offset = offInt->getLimitedValue();
    PAG* pag = getAnalysis<WPAPass>().getPAG();
    Value* obj = gepInst->getPointerOperand(); // TODO - is this enough?
    NodeID objID = pag->getObjectNode(obj);
    NodeBS nodeBS = pag->getAllFieldsObjNode(objID);
    
    for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
        PAGNode* fldNode = pag->getPAGNode(*fIt);
        if (GepObjPN* gepNode = dyn_cast<GepObjPN>(fldNode)) {
            if (offset == gepNode->getLocationSet().getOffset()) {
                return gepNode;
            }
        }
    }

    return nullptr;
}

bool EncryptionPass::isSensitiveObj(PAGNode* Val) {
	if (std::find(SensitiveObjList.begin(), SensitiveObjList.end(), Val) != SensitiveObjList.end()) {
		return true;
	} else {
		return false;
	}
}

/* The Set equivalents */
bool EncryptionPass::isSensitiveLoadSet(Value* Val) {
	if (std::find(SensitiveLoadSet->begin(), SensitiveLoadSet->end(), Val) != SensitiveLoadSet->end()) {
		return true;
	} else {
		return false;
	}
}

bool EncryptionPass::isSensitiveLoadPtrSet(Value* Val) {
	if (std::find(SensitiveLoadPtrSet->begin(), SensitiveLoadPtrSet->end(), Val) != SensitiveLoadPtrSet->end()) {
		return true;
	} else {
		return false;
	}
}

bool EncryptionPass::isSensitiveGEPPtrSet(Value* Val) {
	if (std::find(SensitiveGEPPtrSet->begin(), SensitiveGEPPtrSet->end(), Val) != SensitiveGEPPtrSet->end()) {
		return true;
	} else {
		return false;
	}
}

bool EncryptionPass::isSensitiveObjSet(PAGNode* Val) {
	if (std::find(SensitiveObjSet->begin(), SensitiveObjSet->end(), Val) != SensitiveObjSet->end()) {
		return true;
	} else {
		return false;
	}
}

bool EncryptionPass::isSensitivePtrVal(Value* Val) {
	std::map<Value*,Value*>::iterator it = SensitivePtrValMap.find(Val);
	if (it != SensitivePtrValMap.end()) {
		return true;
	} else {
		return false;
	}
}

/* The Set equivalents .... end */

Instruction* EncryptionPass::FindNextInstruction(Instruction* CurrentInstruction) {
	bool RetNext = false;
	for (std::vector<Instruction*>::iterator InstIt = InstructionList.begin() ; InstIt != InstructionList.end(); ++InstIt) {
		if (RetNext == true) {
			return *InstIt;
		}
		if (*InstIt == CurrentInstruction) {
			RetNext = true;
		}
	}
	// Print all list
	/*
	   for (std::vector<Instruction*>::iterator InstIt = InstructionList.begin() ; InstIt != InstructionList.end(); ++InstIt) {
	   dbgs() << **InstIt << "\n";
	   }
	   */
	return nullptr;
}


Value* EncryptionPass::findObjFromCast(Value* castValue) {
    std::vector<Value*> workList;
    assert(isa<CastInst>(castValue) && "Should be a cast instruction!\n");
    workList.push_back(castValue);
    while (!workList.empty()) {
        Value* workNode = workList.back();
        workList.pop_back();
        if (GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(workNode)) {
            return gepInst;
        } else if (CastInst* castInst = dyn_cast<CastInst>(workNode)) {
            if (isa<AllocaInst>(castInst->getOperand(0)) || isa<GlobalVariable>(castInst->getOperand(0)) || isa<CallInst>(castInst->getOperand(0))) {
                return castInst->getOperand(0);
            } else {
                workList.push_back(castInst->getOperand(0));
            }
        } else if (LoadInst* loadInst = dyn_cast<LoadInst>(workNode)) {
            if (isa<AllocaInst>(loadInst->getPointerOperand()) || isa<GlobalVariable>(loadInst->getPointerOperand()) || isa<CallInst>(loadInst->getPointerOperand())) {
                return loadInst->getPointerOperand();
            } else {
                workList.push_back(loadInst->getPointerOperand());
            }
        } else {
            assert(false && "Something other than Gep inst and cast inst here!\n");
        }
    }
    return nullptr;
}

bool EncryptionPass::isaCPointer(Type* type) {
    if (PointerType* ptrType = dyn_cast<PointerType>(type)) {
        if (ptrType->getPointerElementType()->isPointerTy()) {
            return true;
        }
    }
    return false;
}

bool EncryptionPass::isaCPointer(Value* pointer) {
    if (PointerType* ptrType = dyn_cast<PointerType>(pointer->getType())) {
        if (ptrType->getPointerElementType()->isPointerTy()) {
            return true;
        }
    }
    return false;
}

bool EncryptionPass::isaConstantValue(Value* value) {
    if (GlobalVariable* gv = dyn_cast<GlobalVariable>(value)) {
        if (gv->isConstant()) {
            return true;
        }
    }
    return false;
}


void EncryptionPass::findIndirectSinkSites(PAGNode* ptsFrom, std::set<PAGNode*>& sinkSites) {
    // tpalit: There's no difference between a direct and a indirect flow
    // Because in the algorithm for the indirect flow, we only track the Value
    // Flow edges, that capture only the non-pointer flows
    findDirectSinkSites(ptsFrom, sinkSites);
}

/**
 * Find all the sink sites that this value directly flows to
 */
void EncryptionPass::findDirectSinkSites(PAGNode* source, std::set<PAGNode*>& sinkSites) {
    std::map<PAGNode*, std::set<PAGNode*>> ptsToMap = getAnalysis<WPAPass>().getPAGPtsToMap();

    PAG* pag = getAnalysis<WPAPass>().getPAG();

    std::vector<PAGNode*> workList;

    workList.push_back(source);

    // Find the outgoing value flow edges, keep adding them until you find the store edges
    while (!workList.empty()) {
        PAGNode* work = workList.back();
        workList.pop_back();

        for (PAGEdge* outEdge: work->getOutgoingValFlowEdges()) {
            if (StoreValPE* storeValEdge = dyn_cast<StoreValPE>(outEdge)) {
                PAGNode* sinkStorePtr = pag->getPAGNode(storeValEdge->getDstID());
                // Find everything this can point to
                // This will take care of non-pointers too, because
                // non-pointers point to itself
                for (PAGNode* ptsTo: ptsToMap[sinkStorePtr]) {
                    sinkSites.insert(ptsTo);
                }
            } else {
                // Store the destination in the workList
                PAGNode* intermediateNode = pag->getPAGNode(outEdge->getDstID());
                workList.push_back(intermediateNode);
            }
        }
    }
    
}

void EncryptionPass::buildRetCallMap(Module& M) {
    std::map<PAGNode*, std::set<PAGNode*>> ptsToMap = getAnalysis<WPAPass>().getPAGPtsToMap();
	std::map<PAGNode*, std::set<PAGNode*>> ptsFromMap = getAnalysis<WPAPass>().getPAGPtsFromMap();


	// Populate list of all functions
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			if (!F->isDeclaration()) {
				AllFunctions.insert(F);
			}
		}
	}


    // Iterate over each function body, finding return instructions
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            // Get the local sensitive values
            for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                    //outs() << "Basic block found, name : " << BB->getName() << "\n";
                    for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                        if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                            // Check if it's a ReturnInst
                            if (ReturnInst* returnInst = dyn_cast<ReturnInst>(Inst)) {
                                funRetMap[F].push_back(returnInst);
                            }
                        }
                    }
                }
            }
        }
    }
    // Iterate over all instructions, tracking
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            // Get the local sensitive values
            for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                    for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                        if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                            if (CallInst* CInst = dyn_cast<CallInst>(Inst)) {
                                if (CInst->getCalledFunction()) {
                                    if (containsSet(CInst->getCalledFunction(), AllFunctions)) {
                                        // Internal function
                                        // Find the return statements
                                        for (ReturnInst* retInst: funRetMap[CInst->getCalledFunction()]) {
                                            retCallMap[retInst].push_back(CInst);
                                        }
                                    }
                                } else if (ConstantExpr* consExpr = dyn_cast<ConstantExpr>(CInst->getCalledValue())) {
                                    if (containsSet(consExpr->getOperand(0), AllFunctions)) {
                                        // Internal function
                                        // Find the return statements
                                        Function* fun = dyn_cast<Function>(consExpr->getOperand(0));
                                        assert(fun && "Constant expression here should only be a UnaryConstExpr for a Cast operation!");
                                        for (ReturnInst* retInst: funRetMap[fun]) {
                                            retCallMap[retInst].push_back(CInst);
                                        }
                                    }
                                } else {
                                    // Function pointer
                                    Value* calledValue = CInst->getCalledValue();
                                    // Get the PAGNode for calledValue
                                    PAGNode* calledNode = getPAGValNodeFromValue(calledValue);

                                    for (PAGNode* calledFuncNode: ptsToMap[calledNode]) {
                                        Value* calledFuncVal = const_cast<Value*>(calledFuncNode->getValue());
                                        //assert(isa<Function>(calledFuncVal)); // Possible pointer analysis imprecision
                                        if (!isa<Function>(calledFuncVal)) {
                                            continue;
                                        }
                                        Function* calledFunction = dyn_cast<Function>(calledFuncVal);
                                        if (containsSet(calledFunction, AllFunctions)) {
                                            // Internal function
                                            // Find the return statements
                                            for (ReturnInst* retInst: funRetMap[calledFunction]) {
                                                retCallMap[retInst].push_back(CInst);
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

void EncryptionPass::trackExternalFunctionFlows(Value* ptr, std::set<Value*>& sinkSites) {
    std::map<Value*, std::set<Value*>> ptsToMap; // = getAnalysis<WPAPass>().getSensitivePtsToMap(); // TODO
	std::map<Value*, std::set<Value*>> ptsFromMap; // = getAnalysis<WPAPass>().getSensitivePtsFromMap(); // TODO

    // Go through the users of of this pointer, to see if it was used as the source operand in memcpy or strcpy
    for (User* user: ptr->users()) {
        if (Value* userValue = dyn_cast<Value>(user)) {
            if (CallInst* callInst = dyn_cast<CallInst>(userValue)) {
                Function* calledFunction = callInst->getCalledFunction();
                if (calledFunction) {
                    if (calledFunction->getName().equals("memcpy") || calledFunction->getName().equals("strcpy")) {
                        // Is it the source?
                        if (callInst->getOperand(1) == ptr) {
                            // Find everything that the destination pointer can point to
                            Value* destPtr = callInst->getOperand(0);
                            if (filterDataFlowPointersByType(destPtr)) {
                                continue;
                            }

                            for (Value* destPtsToValue: ptsToMap[destPtr]) {
                                sinkSites.insert(destPtsToValue);
                            }
                            /*
                            if (pag->hasValueNode(destPtr)) {
                                PAGNode* destPAGNode = pag->getPAGNode(pag->getValueNode(destPtr));
                                for (PAGNode* destPtsToPAGNode : ptsToMap[destPAGNode]) {
                                    if (destPtsToPAGNode->hasValue()) {
                                        Value* destPtsToValue = destPtsToPAGNode->getValue();
                                        sinkSites.insert(destPtsToValue);
                                    }
                                }
                            }

                            assert(!pag->hasObjectNode(destPtr) && "Destination argument to memcpy/strcpy should be a register");
                            if (pag->hasObjectNode(destPtr)) {
                                PAGNode* destPAGNode = pag->getPAGNode(pag->getObjectNode(destPtr));
                                for (PAGNode* destPtsToPAGNode : ptsToMap[destPAGNode]) {
                                    if (destPtsToPAGNode->hasValue()) {
                                        Value* destPtsToValue = destPtsToPAGNode->getValue();
                                        sinkSites.insert(destPtsToValue);
                                    }
                                }

                            }

                            */

                        }
                    } 
                }

                // @tpalit - Function pointers to access memcpy/strcpy?
            }
        }
    }
}

bool EncryptionPass::filterDataFlowPointersByType(Value* potentialIndirectFlowPointer) {
    if (isa<Function>(potentialIndirectFlowPointer) || isa<CallInst>(potentialIndirectFlowPointer)) { // if it is a malloc, then there will be load instructions that will show up here
        return true;
    }   

    PointerType* ptrType = dyn_cast<PointerType>(potentialIndirectFlowPointer->getType());
    if (!ptrType) {
        return true;
    }

    Type* elementType = ptrType->getPointerElementType();
    // If we get a pointer to a pointer here, too bad, but we must continue
    
    // If the type of the pointer is the same as one of the sensitive types, only then track this data-flow
    if (std::find(sensitiveTypes.begin(), sensitiveTypes.end(), elementType) != sensitiveTypes.end()) {
        return false;
    }

    return true;
}

/**
 * Collect the base types of all the sensitive types
 */
void EncryptionPass::collectSensitiveTypes(Module& M) {
    std::vector<Type*> typeWorkList;
    std::vector<Type*> analyzedList;

    for (PAGNode* sensitiveNode: SensitiveObjList) {
        Value* sensitiveValue = const_cast<Value*>(sensitiveNode->getValue());
        errs() << "Sensitive value: " << *sensitiveValue << "\n";

        typeWorkList.clear();
        Type* sensitiveType = sensitiveValue->getType();
        if (PointerType* ptrType = dyn_cast<PointerType>(sensitiveType)) {
            if (isa<StructType>(sensitiveType->getPointerElementType()))
                continue;
            sensitiveTypes.push_back(sensitiveType->getPointerElementType());
            if (std::find(analyzedList.begin(), analyzedList.end(), sensitiveType->getPointerElementType()) == analyzedList.end()) {
                typeWorkList.push_back(sensitiveType->getPointerElementType());
            }
        } else {
            if (isa<StructType>(sensitiveType))
                continue;
            sensitiveTypes.push_back(sensitiveType);
            if (std::find(analyzedList.begin(), analyzedList.end(), sensitiveType) == analyzedList.end()) {
                typeWorkList.push_back(sensitiveType);
            }
        }

        while (!typeWorkList.empty()) {
            Type* type = typeWorkList.back();
            errs() << "Popped type: " << *type << "\n";
            typeWorkList.pop_back();
            analyzedList.push_back(type);
            if (PointerType* ptrType = dyn_cast<PointerType>(type)) {
                if (!isa<StructType>(ptrType) && !ptrType->getPointerElementType()->isPointerTy()) {
                    sensitiveTypes.push_back(ptrType->getPointerElementType());
                }
                if (std::find(analyzedList.begin(), analyzedList.end(), ptrType->getPointerElementType()) == analyzedList.end()) {
                    typeWorkList.push_back(ptrType->getPointerElementType());
                }
            } else {
                if (isa<StructType>(type))
                    continue;
                sensitiveTypes.push_back(type);
            }
            if (StructType* structType = dyn_cast<StructType>(type)) {
                // All inner types
                int numElems = structType->getNumElements();
                for (int i = 0; i < numElems; i++) {
                    // If we find a pointer, find the pointed to type
                    if (PointerType* ptrType = dyn_cast<PointerType>(structType->getElementType(i))) {
                        // If the pointed to type is also a pointer, forget about it!
                        if (!isa<StructType>(ptrType) && !(ptrType->getPointerElementType()->isPointerTy())) {
                            if (std::find(analyzedList.begin(), analyzedList.end(), ptrType->getPointerElementType()) == analyzedList.end()) {
                                typeWorkList.push_back(ptrType->getPointerElementType());
                            }
                        }
                    } else {
                        if (!isa<FunctionType>(structType->getElementType(i)) && !isa<StructType>(structType->getElementType(i))) {
                            if (std::find(analyzedList.begin(), analyzedList.end(), structType->getElementType(i)) == analyzedList.end()) {
                                typeWorkList.push_back(structType->getElementType(i));
                            }
                        }
                    }
                }
            }
        }
    }

    for (Type* sensType: sensitiveTypes) {
        errs() << "Sensitive type: " << *sensType << "\n";
    }
}

void EncryptionPass::performSourceSinkAnalysis(Module& M) {

    std::map<PAGNode*, std::set<PAGNode*>> ptsFromMap = getAnalysis<WPAPass>().getPAGPtsFromMap();
    PAG* pag = getAnalysis<WPAPass>().getPAG();

    collectSensitiveTypes(M);

    buildRetCallMap(M);

    std::vector<PAGNode*> sinkSites;
    std::vector<PAGNode*> workList; // List of allocation sites for which we still need to perform source-sink analysis
    std::vector<PAGNode*> analyzedList; // List of sites for which we have completed source-sink analysis (item as Source)
    std::vector<PAGNode*> analyzedPtrList; // List of pointers for which we have completed source-sink analysis (item as Source)
    std::set<PAGNode*> tempSinkSites; // Temporary list of sink-sites
    for (PAGNode* sensitiveObjNode: SensitiveObjList) {
        errs() << "Before dataflow, sensitive value: " << *sensitiveObjNode << "\n";
        workList.push_back(sensitiveObjNode);
    }

    while (!workList.empty()) {
        PAGNode* work = workList.back();
        workList.pop_back();

        for (PAGNode* ptsFrom: ptsFromMap[work]) {
            if (!(ptsFrom->vfaVisited)) {
                findIndirectSinkSites(ptsFrom, tempSinkSites);
                ptsFrom->vfaVisited = true;
            }
        }

        findDirectSinkSites(work, tempSinkSites);

        for (PAGNode* sinkSiteNode: tempSinkSites) {
            SensitiveObjList.push_back(sinkSiteNode);
            if (!(work->vfaVisited)) {
                workList.push_back(sinkSiteNode); 
            }
        }
        tempSinkSites.clear();
        work->vfaVisited = true;
    }

    errs() << "After dataflow analysis:\n";
    for (PAGNode* sensValNode: SensitiveObjList) {
        if (GepObjPN* gepObjPN = dyn_cast<GepObjPN>(sensValNode)) {
            errs() << "Sensitive value: " << *gepObjPN << "\n";
        } else {
            errs() << "Sensitive value: " << *sensValNode << "\n";
        }
    }
}


void EncryptionPass::removeAnnotateInstruction(Module& M) {
	GlobalVariable* tobeDeleted = nullptr;
	for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
		if (I->getName() == "llvm.global.annotations") {
			for(Value::user_iterator User = I->user_begin(); User != I->user_end(); ++User) {

				User->dump();
			}

			tobeDeleted = &(*I);
		}
	}

}

void EncryptionPass::collectGlobalSensitiveAnnotations(Module& M) {
	std::vector<StringRef> GlobalSensitiveNameList;
    PAG* pag = getAnalysis<WPAPass>().getPAG();

	// Get the names of the global variables that are sensitive
	if(GlobalVariable* GA = M.getGlobalVariable("llvm.global.annotations")) {
		for (Value *AOp : GA->operands()) {
			if (ConstantArray *CA = dyn_cast<ConstantArray>(AOp)) {
				for (Value *CAOp : CA->operands()) {
					if (ConstantStruct *CS = dyn_cast<ConstantStruct>(CAOp)) {
						if (CS->getNumOperands() < 4) {
							LLVM_DEBUG(dbgs() << "Unexpected number of operands found. Skipping annotation. \n";);
							break;
						}

						Value *CValue = CS->getOperand(0);
						if (ConstantExpr *Cons = dyn_cast<ConstantExpr>(CValue)) {
							GlobalSensitiveNameList.push_back(Cons->getOperand(0)->getName());
						}
					}
				}
			}
		}
	}
	// Add the global variables which are sensitive to the list
	for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
		if (I->getName() != "llvm.global.annotations") {
			GlobalVariable* GV = llvm::cast<GlobalVariable>(I);
			if (std::find(GlobalSensitiveNameList.begin(), GlobalSensitiveNameList.end(), GV->getName()) != GlobalSensitiveNameList.end()) {
                // It might be an object or a pointer, we'll deal with these guys later
                if (pag->hasObjectNode(GV)) {
                    NodeID objID = pag->getObjectNode(GV);
                    PAGNode* objNode = pag->getPAGNode(objID);
				    SensitiveObjList.push_back(objNode);
                    // Find all Field-edges and corresponding field nodes
                    NodeBS nodeBS = pag->getAllFieldsObjNode(objID);
                    for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
                        PAGNode* fldNode = pag->getPAGNode(*fIt);
                        SensitiveObjList.push_back(fldNode);
                    }
                    SensitiveObjList.push_back(objNode);
                } 
                if (pag->hasValueNode(GV)) {
                    SensitiveObjList.push_back(pag->getPAGNode(pag->getValueNode(GV)));
                }
			}
		}
	}
}

void EncryptionPass::collectLocalSensitiveAnnotations(Module &M) {
    PAG* pag = getAnalysis<WPAPass>().getPAG();

	// Do one pass around the program to gather all sensitive values

	// For each function ... 
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			// Get the local sensitive values
			for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
				if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
					//outs() << "Basic block found, name : " << BB->getName() << "\n";
					for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
						if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
							// Check if it's an annotation
							if (isa<CallInst>(Inst)) {
								CallInst* CInst = dyn_cast<CallInst>(Inst);
								// CallInst->getCalledValue() gives us a pointer to the Function
								if (CInst->getCalledValue()->getName().equals("llvm.var.annotation") || CInst->getCalledValue()->getName().startswith("llvm.ptr.annotation")) {
									Value* SV = CInst->getArgOperand(0);
									for (Value::use_iterator useItr = SV->use_begin(), useEnd = SV->use_end(); useItr != useEnd; useItr++) {
										Value* UseValue = dyn_cast<Value>(*useItr);
                                        if (pag->hasObjectNode(UseValue)) {
                                            NodeID objID = pag->getObjectNode(UseValue);
                                            PAGNode* objNode = pag->getPAGNode(objID);
                                            SensitiveObjList.push_back(objNode);
                                            // Find all Field-edges and corresponding field nodes
                                            NodeBS nodeBS = pag->getAllFieldsObjNode(objID);
                                            for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
                                                PAGNode* fldNode = pag->getPAGNode(*fIt);
                                                SensitiveObjList.push_back(fldNode);
                                            }
                                            SensitiveObjList.push_back(objNode);
                                        } 
                                        if (pag->hasValueNode(UseValue)) {
										    SensitiveObjList.push_back(pag->getPAGNode(pag->getValueNode(UseValue)));
                                        }
									}
								}
							}	
						}
					}
				}
			}

			// Check for bitcast versions. This is needed because annotation function calls seem to take 8bit arguments only.
			for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
				if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
					for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
						if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
							if (isa<BitCastInst>(Inst)) {
								BitCastInst* BCInst = dyn_cast<BitCastInst>(Inst);
								Value* RetVal = llvm::cast<Value>(Inst);
								if (isSensitiveObj(getPAGValNodeFromValue(RetVal))) { // A CastInst is a Value not Obj
									// The bitcasted version of this variable was used in the annotation call,
									// So add this variable too to the encrypted list
                                    Value* val = BCInst->getOperand(0);
                                    if (pag->hasObjectNode(val)) {
                                        NodeID objID = pag->getObjectNode(val);
                                        PAGNode* objNode = pag->getPAGNode(objID);
                                        SensitiveObjList.push_back(objNode);
                                        // Find all Field-edges and corresponding field nodes
                                        NodeBS nodeBS = pag->getAllFieldsObjNode(objID);
                                        for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
                                            PAGNode* fldNode = pag->getPAGNode(*fIt);
                                            SensitiveObjList.push_back(fldNode);
                                        }
                                        SensitiveObjList.push_back(objNode);
                                    } 
                                    if (pag->hasValueNode(val)) {
									    SensitiveObjList.push_back(pag->getPAGNode(pag->getValueNode(val)));
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

/*
bool EncryptionPass::isSimpleFun(Function* F) {
    for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
        if (CallInst* cInst = dyn_cast<CallInst>(*I)) {
            Function* calledFunction = cInst->getCalledFunction();
            if (!calledFunction) {
                if (ConstantExpr* constFunExpr = dyn_cast<ConstantExpr>(cInst->getCalledValue())) { // Simple cast
                    calledFunction = dyn_cast<Function>(consExpr->getOperand(0));
                }
            }
            if (calledFunction) {
                if (containsSet(calledFunction, AllFunctions)) {
                    return false;
                }
            }
        }
    }
    return true;
}

void EncryptionPass::buildArgSimpleFunMap(Module& M) {
    // Find the simple functions
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			// Iterate over all instructions in the Function to build the Instruction list
			for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
                if (CallInst* cInst = dyn_cast<CallInst>(*I)) {
                    Function* calledFunction = cInst->getCalledFunction();
                    if (!calledFunction) {
                        if (ConstantExpr* constFunExpr = dyn_cast<ConstantExpr>(cInst->getCalledValue())) { // Simple cast
                            calledFunction = dyn_cast<Function>(consExpr->getOperand(0));
                        }
                    }
                    if (calledFunction) {
                        // Not a function pointer
                        if (isSimpleFun(calledFunction)) {
                            simpleFunList.push_back(calledFunction);
                        }
                    }
                    if (containsSet(calledFunction, AllFunctions)) {
                    }
                }
            }
        }
    }
	
}

*/
Function* EncryptionPass::findSimpleFunArgFor(Value* ptr) {
    // There's a list of Functions that are 'simple' --> simpleFunList
    // There's a map <Value*, Function*> that maps actual parameters to simple functions --> argSimpleFunMap 
    /*
    std::map<Value*, Function*>::iterator it;
    it = argSimpleFunMap.find(ptr);
    if (it == argSimpleFunMap.end()) {
        return nullptr;
    }
    return it->next;
    */
    return nullptr;
}

void EncryptionPass::collectSensitivePointsToInfo(Module &M, 
		std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap,
		std::map<PAGNode*, std::set<PAGNode*>>& ptsFromMap) {

    PAG* pag = getAnalysis<WPAPass>().getPAG();

	std::map<PAGNode*, std::set<PAGNode*>>::iterator ptsToMapIt = ptsToMap.begin();
	bool done = false;

    std::vector<PAGNode*> tempObjList;
    // If there are any pointers in the sensitive object list, we want find their targets right away
    for (PAGNode* senPAGNode: SensitiveObjList) {
        for(PAGNode* ptsToNode: ptsToMap[senPAGNode]) {
            tempObjList.push_back(ptsToNode);
        }
    }
    std::copy(tempObjList.begin(), tempObjList.end(), std::back_inserter(SensitiveObjList));

	// --- We need to keep merging the points-to sets of each pointer that points to sensitive allocation sites
	// Set if off
	std::set<PAGNode*>* allocaSetPtr = new std::set<PAGNode*>(SensitiveObjList.begin(), SensitiveObjList.end()); 
	std::set<PAGNode*>* newObjSetPtr = nullptr;
	std::vector<PAGNode*>* newObjVecPtr = nullptr;
	std::set<PAGNode*>* allAllocSitesSetPtr = nullptr;
    std::set<PAGNode*>* diffSetPtr = nullptr;
    std::set<PAGNode*>* tmpPtr = nullptr;

	while (!done) {
		dbgs() << allocaSetPtr->size() << " New allocation sites found ... \n";
    
		if (allocaSetPtr->size() == 0) break;;

		if (newObjVecPtr) {
			delete newObjVecPtr;
		}
		newObjVecPtr = new std::vector<PAGNode*>();

        int count = 0;

		for (PAGNode* sensitiveObjSite: *allocaSetPtr) {
			// --- Any pointer that points to the sensitiveObjSite also needs to be processed
            for (PAGNode* ptr: ptsFromMap[sensitiveObjSite]) {
                if (ptr->hasValue()) {
                    if (isa<Function>(ptr->getValue()) || isa<CallInst>(ptr->getValue())) {
                        continue;
                    }
                }
                
                // --- All allocation sites this pointer can point to is also sensitive
                std::set<PAGNode*>* s = &ptsToMap[ptr];
                for (PAGNode* obj: *s) {
                    const Value* v = obj->getValue();
                    if (const ConstantArray* carr = dyn_cast<ConstantArray>(v)) {
                        const ArrayType* type = carr->getType();
                        if (type->getNumElements() <= 1) {
                            continue;
                        }
                    }
                    newObjVecPtr->push_back(obj);
                }
                //newObjVecPtr->insert(newObjVecPtr->end(), s->begin(), s->end());


                /*
                for (PAGNode* node: *s) {
                    if (node->getValue()->hasName()) {
                        if (node->getValue()->getName().startswith("argv")) {
                            errs() << "Pointer: " << *(ptr->getValue()) << " points to " << node->getValue()->getName() << "!\n";
                            if (const Argument* arg = dyn_cast<const Argument>(ptr->getValue())) {
                                errs() << " arg " << arg->getName() << " of function: " << arg->getParent()->getName() << " points to opt!\n";
                            }
                            if (const Instruction* inst = dyn_cast<const Instruction>(ptr->getValue())) {
                                errs() << " and this is in function : " << inst->getParent()->getParent()->getName() << "\n";
                            }
                        }
                    }
                }
                */
                /*
                errs() << "Pointer: " << *(ptr->getValue()) << " points to sensitive buffer\n";
                if (const Instruction* inst = dyn_cast<const Instruction>(ptr->getValue())) {
                    errs() << " and this is in function : " << inst->getParent()->getParent()->getName() << "\n";
                }
                errs() << " has points-to set of size: " << s->size() << "\n\n\n";
                */

                /*
                if (const Argument* arg = dyn_cast<const Argument>(ptr->getValue())) {
                    errs() << " arg " << arg->getName() << " of function: " << arg->getParent()->getName() << " became sensitive!\n";
                    for(PAGNode* node: ptsToMap[ptr]) {
                        errs() << "And this points to " << *node << "\n";
                    }
                }
                */

                /*
                if (count == 382 || count == 383) {
                    errs() << "This might be the guy: " << *sensitiveObjSite << "\n";
                }
                */
                // Someone set str.8 as sensitive
                /*
                for (PAGNode* obj: *s) {
                    const Value* v = obj->getValue();
                    if (const Constant* con = dyn_cast<Constant>(v)) {
                        errs() << "The constant " << *con << " became sensitive because of " << *(ptr->getValue()) << " \n";
                    }
                }
                */

                /*
                if (const Instruction* inst = dyn_cast<Instruction>(ptr->getValue())) {
                    if (inst->getName().contains("out_msg")) {
                        // Print out the points-to set
                        for (PAGNode* node: *s) {
                            errs() << " points to ... " << *(node->getValue()) << "\n";
                        }
                    }
                }
                */
                /*
                for (PAGNode* obj: *s) {
                    errs() << "Value: " <<  *(obj->getValue()) << "\n";
                }
                */

                // For every Gep node, add its Field insensitive node too,
                // NOT Needed any more
                /*
                for (PAGNode* node: *s) {
                    errs() << " Points to node: " << *node << "\n";
                    if (GepObjPN* gepNode = dyn_cast<GepObjPN>(node)) {
                        NodeID objID = pag->getObjectNode(gepNode->getValue()); 
                        NodeBS nodeBS = pag->getAllFieldsObjNode(objID);
                        for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
                            PAGNode* fldNode = pag->getPAGNode(*fIt);
                            newObjVecPtr->push_back(fldNode);
                        }
                    }
                }
                */
            }
            errs() << "Processed " << count++ << " site\n";
		}
		// newObjVecPtr has all newly discovered sensitive allocation sites
		// Convert it to set and find difference
		// Free the old guy
		if (newObjSetPtr) {
			delete newObjSetPtr;
		}
		newObjSetPtr = new std::set<PAGNode*>(newObjVecPtr->begin(), newObjVecPtr->end());

		if (allAllocSitesSetPtr) {
			delete allAllocSitesSetPtr;
		}
		allAllocSitesSetPtr = new std::set<PAGNode*>(SensitiveObjList.begin(), SensitiveObjList.end());

        if (diffSetPtr) {
            delete diffSetPtr;
        }
		diffSetPtr = new std::set<PAGNode*>();
		// diff is the new allocation sites that have been found

		set_difference(newObjSetPtr->begin(), newObjSetPtr->end(), allAllocSitesSetPtr->begin(), allAllocSitesSetPtr->end(), inserter(*diffSetPtr, diffSetPtr->begin()));

		if (diffSetPtr->size() == 0) {
			// Nothing new found, done!
			done = true;
		}
      
		SensitiveObjList.insert(SensitiveObjList.end(), diffSetPtr->begin(), diffSetPtr->end());

		allocaSetPtr = diffSetPtr;
	}
}

void EncryptionPass::collectSensitiveGEPInstructions(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
	// Find all the GEP instructions that load IR pointers that point to sensitive locations
	std::map<PAGNode*, std::set<PAGNode*>>::iterator mapIt = ptsToMap.begin();
	for (; mapIt != ptsToMap.end(); ++mapIt) {
        PAGNode* ptrNode = mapIt->first;
        assert(ptrNode->hasValue() && "A PAG node made it so far, it should have a value.");
		if (GetElementPtrInst *GEPInst = dyn_cast<GetElementPtrInst>(const_cast<Value*>(ptrNode->getValue()))) {
			std::set<PAGNode*> pointsToSet = mapIt->second;
			for (PAGNode* ptsToNode: pointsToSet) {
				if (isSensitiveObj(ptsToNode)) {
					//if (GEPInst->getPointerOperand()->getType()->isPointerTy()) { // Changing this not sure why I wanted the Gep to give me a C pointers?: 4/20/2019
						SensitiveGEPPtrList.push_back(GEPInst);
					//}
				}
			}
		}
	}

	LLVM_DEBUG(
	for (Value* GEPInst: SensitiveGEPPtrList) {
		dbgs() << "Sensitive GEP instruction: ";
		GEPInst->dump();
	}
	);

	// Find all Load instructions that load from sensitive locations pointed to by GEP instructions
	for (Value* GEPValue: SensitiveGEPPtrList) {
		// Find all Users of this GEP instruction

		for(Value::user_iterator User = GEPValue->user_begin(); User != GEPValue->user_end(); ++User) {
			if (LoadInst* LdInst = dyn_cast<LoadInst>(*User)) {
				if (!LdInst->getType()->isPointerTy()) {
					// Ignore any pointer assignments here, the pointer analysis will take care of it TODO - Will this break anything?
					if (!LdInst->getType()->isPointerTy()) {
						SensitiveLoadList.push_back(LdInst);
					}
				}
			}
		}

	}
}

void EncryptionPass::collectSensitiveAsmInstructions(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    // @TODO fldsen
	// Find all InlineAsm instructions in the program and decrypt the sensitive operands
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			// Iterate over all instructions in the Function to build the Instruction list
			for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
				CallInst* cInst = dyn_cast<CallInst>(&*I);
				if (cInst) {
					Value* calledValue = cInst->getCalledValue();
					if (calledValue) {
						// Inline assembly?
						InlineAsm* inlineAsm = dyn_cast<InlineAsm>(calledValue);
						if (inlineAsm) {
							for(CallInst::const_op_iterator arg = cInst->arg_begin(), argEnd = cInst->arg_end(); arg != argEnd; ++arg) {
								Value* argVal = dyn_cast<Value>(arg);
								if (isSensitiveObj(getPAGObjNodeFromValue(argVal)) || isSensitiveLoadPtr(argVal) || isSensitiveGEPPtr(argVal)) {
									SensitiveInlineAsmCalls.push_back(cInst);
								}
							}					
						}
					}
				}
			}
		}
	}
    dbgs() << "Sensitive Inline ASM:\n";
    for (Value* asmVal: SensitiveInlineAsmCalls) {
        asmVal->dump();
    }
}
void EncryptionPass::collectSensitiveGEPInstructionsFromLoad(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    for (Value* ldPtrVal: SensitiveLoadPtrList) {

    }
}

void EncryptionPass::collectSensitiveLoadInstructions(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
	// Find all the Load instructions that load IR pointers that point to sensitive locations
	std::map<PAGNode*, std::set<PAGNode*>>::iterator mapIt = ptsToMap.begin();
	for (; mapIt != ptsToMap.end(); ++mapIt) {
        PAGNode* ptr = mapIt->first;
        assert(ptr->hasValue() && "A PAG node made it so far, it should have a value.");
		if (LoadInst *LdInst = dyn_cast<LoadInst>(const_cast<Value*>(ptr->getValue()))) {
			std::set<PAGNode*> pointsToSet = mapIt->second;
			for (PAGNode* ptsToNode: pointsToSet) {
				if (isSensitiveObjSet(ptsToNode)) {
                    SensitiveLoadPtrList.push_back(LdInst);
				}
			}
		} else if (CastInst *CInst = dyn_cast<CastInst>(const_cast<Value*>(ptr->getValue()))) {
			std::set<PAGNode*> pointsToSet = mapIt->second;
			for (PAGNode* ptsToNode: pointsToSet) {
				if (isSensitiveObjSet(ptsToNode)) {
					SensitiveLoadPtrList.push_back(CInst);
				}
			}
		}
	}

	LLVM_DEBUG (
	for (Value* LdInst: SensitiveLoadPtrList) {
		dbgs() << "Sensitive Load Ptr instruction: ";
		LdInst->dump();
	}
	);

	// Find all Load instructions that load sensitive locations from the points to graph and constant expressions
	for (Value* sensitivePtrLoad: SensitiveLoadPtrList) {
		// Find all Users of this Load instruction
		Value* loadValue = dyn_cast<Value>(sensitivePtrLoad);

		for(Value::user_iterator User = loadValue->user_begin(); User != loadValue->user_end(); ++User) {
			if (GetElementPtrInst* GEPInst = dyn_cast<GetElementPtrInst>(*User) ) {
				SensitiveGEPPtrList.push_back(GEPInst);
                SensitiveGEPPtrSet->insert(GEPInst);
			}
		}

	}



	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			// Iterate over all instructions in the Function to build the Instruction list
			for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
				LoadInst* LdInst = dyn_cast<LoadInst>(&*I);
				if (LdInst) {
                    // Is this loading from a Simple object?
                    PAG* pag = getAnalysis<WPAPass>().getPAG();
                    if (pag->hasObjectNode(LdInst->getPointerOperand())) {
                        if (isSensitiveObjSet(getPAGObjNodeFromValue(LdInst->getPointerOperand()))) {
                            SensitiveLoadList.push_back(LdInst);
                        }
                    }
					if (isSensitiveGEPPtrSet(LdInst->getPointerOperand())) {
						SensitiveLoadList.push_back(LdInst);
					}/*
                        // Not needed any more because SVF breaks these guys up anyway.
                        else if (ConstantExpr* CConstExpr = dyn_cast<ConstantExpr>(LdInst->getPointerOperand())) {
						// Fix for Constant Expressions
						ConstantExpr* ConstExpr = const_cast<ConstantExpr*>(CConstExpr);
						if (ConstExpr->getOpcode() == Instruction::GetElementPtr) {
							GEPOperator* GEPOp = dyn_cast<GEPOperator>(ConstExpr);
							if (GEPOp && isSensitiveObj(GEPOp->getPointerOperand())) {
								if (LdInst->getType()->isPointerTy()) {
									SensitiveLoadPtrList.push_back(LdInst);
									SensitiveLoadList.push_back(LdInst);
								} else {
									SensitiveLoadList.push_back(LdInst);
								}
							}
						}
					}
                    */
				}
			}
		}
	}

	// Find all Load instructions that load sensitive locations from the points to graph and constant expressions
	for (Value* sensitivePtrLoad: SensitiveLoadPtrList) {
		// Find all Users of this Load instruction
		Value* loadValue = dyn_cast<Value>(sensitivePtrLoad);

		for(Value::user_iterator User = loadValue->user_begin(); User != loadValue->user_end(); ++User) {
			if (LoadInst* LdInst = dyn_cast<LoadInst>(*User) ) {
				SensitiveLoadList.push_back(LdInst);
			}
		}

	}

	LLVM_DEBUG (
	for (Value* LdInst: SensitiveLoadList) {
		dbgs() << "Sensitive Load instruction: ";
		LdInst->dump();
	}
	);

}

bool EncryptionPass::isCallocLike(const char* str)
{
	for (unsigned i = 0; CallocLikeFunctions[i] != nullptr; ++i)
	{
		if (strcmp(CallocLikeFunctions[i], str) == 0)
			return true;
	}
	return false;
}

bool EncryptionPass::isValueStoredToSensitiveLocation(Value* v) {
    /*
	// Follow use chains, until you find a store
	std::vector<Value*> workList;
	workList.push_back(v);
	for (int i = 0; i < workList.size(); i++) {
		Value* val = workList[i];
		for (Value::user_iterator UserIt = val->user_begin(), UserEnd = val->user_end(); UserIt != UserEnd; ++UserIt) {
			Value* UseValue = dyn_cast<Value>(*UserIt);
			if (CastInst* castInst = dyn_cast<CastInst>(UseValue)) {
				if (castInst != val) {
					workList.push_back(castInst);
				}
			}
			if (StoreInst* storeInst = dyn_cast<StoreInst>(UseValue)) {
				Value* storeLocation = storeInst->getPointerOperand();
				if (isSensitiveObjSet(storeLocation) || isSensitiveGEPPtrSet(storeLocation) || isSensitiveLoadPtrSet(storeLocation)) {
					return true;
				}
			}
		}
	}
    */
	return false;
}

void EncryptionPass::collectSensitiveExternalLibraryCalls(Module& M,  std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
	// Create sets for quicker lookup
	std::set<Value*> SensitiveGEPPtrSet(SensitiveGEPPtrList.begin(), SensitiveGEPPtrList.end());
	std::set<Value*> SensitiveLoadPtrSet(SensitiveLoadPtrList.begin(), SensitiveLoadPtrList.end());

	std::set<Value*> AllFunctions;
	// Populate list of all functions
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			if (!F->isDeclaration()) {
				AllFunctions.insert(F);
			}
		}
	}

	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
				if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
					for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
						if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
							if (CallInst* CInst = dyn_cast<CallInst>(Inst)) {
								if (CInst->getCalledFunction()) {
									// It's not a function pointer
									const char* fNameStr = CInst->getCalledFunction()->getName().data();
									if (isCallocLike(fNameStr)) {
										//if (isValueStoredToSensitiveLocation(CInst)) {
                                        if (isSensitiveObjSet(getPAGObjNodeFromValue(CInst))) {
                                            /*
                                            if (CInst->getCalledFunction()->getName().equals("strlen")) {
                                                errs() << "oops.Strlen with sensitive arg in function : " << CInst->getParent()->getParent()->getName() << "\n";
                                            }
                                            */
                                            SensitiveExternalLibCallList.push_back(CInst);
                                        }
									} else {
										if (!containsSet(CInst->getCalledFunction(), AllFunctions)) {
											bool isSensitiveCall = false;
                                            PAG* pag = getAnalysis<WPAPass>().getPAG();
                                            // Hack!
                                            if (CInst->getCalledFunction()->getName() == "uname" ) {
                                                if (isSensitiveObj(pag->getPAGNode(pag->getObjectNode(CInst->getArgOperand(0))))) {
                                                    isSensitiveCall = true;
                                                }
                                            } else if (CInst->getCalledFunction()->getName() == "epoll_ctl") {
                                                // TODO
                                                /*
                                                // The epoll_event might point to sensitive value in its data filed
                                                // let's ignore that for now!
                                                if (isSensitiveObj(CInst->getArgOperand(3))) {
                                                    SensitiveExternalLibCallList.push_back(CInst);
                                                }
                                                continue;
                                                */
                                            }
                                            if (CInst->getCalledFunction()->getName().equals("bind")) {
                                                // HACK! Why do we need this?
                                                // Get the second operand
                                                Value* val = CInst->getOperand(1);
                                                PAGNode* pagArg = getPAGValNodeFromValue(val);
                                                for (PAGNode* ptsToNode: ptsToMap[pagArg]) {
                                                    PAGNode* valNode = getPAGValNodeFromValue(const_cast<Value*>(ptsToNode->getValue()));
                                                    for (PAGNode* ptsToToNode: ptsToMap[valNode]) {
                                                        if (isSensitiveObj(ptsToToNode)) {
                                                            isSensitiveCall = true;
                                                        }
                                                    }
                                                }

                                            }
                                            // Get the arguments, check if any of them is sensitive 
                                            // and then put code to decrypt them in memory
											int numArgs = CInst->getNumArgOperands();
											for (int i = 0; i < numArgs; i++) {
												Value* value = CInst->getArgOperand(i);
												if (isSensitiveArg(value, ptsToMap)) {
                                                    //SensitiveArgSet.insert(value);
                                                    
													LLVM_DEBUG (
															dbgs() << "Sensitive external library call found: ";
															value->dump();
													      );
													isSensitiveCall = true;
												}
											}
											if (isSensitiveCall) {
												SensitiveExternalLibCallList.push_back(CInst);
											}
										}
									}
								} else {
                                    // Function pointer
                                    PAGNode* calledValueNode = getPAGValNodeFromValue(CInst->getCalledValue());
                                    for (PAGNode* possibleFunNode: ptsToMap[calledValueNode]) {
                                        if (possibleFunNode->hasValue()) {
                                            Value* possibleFun = const_cast<Value*>(possibleFunNode->getValue());
                                            if (Function* function = dyn_cast<Function>(possibleFun)) {
                                                if (!containsSet(function, AllFunctions)) {

                                                    // Get the arguments, check if any of them is sensitive 
                                                    // and then put code to decrypt them in memory
                                                    int numArgs = CInst->getNumArgOperands();
                                                    bool isSensitiveCall = false;
                                                    for (int i = 0; i < numArgs; i++) {
                                                        Value* value = CInst->getArgOperand(i);
                                                        if (isSensitiveArg(value, ptsToMap)) {
                                                            LLVM_DEBUG (
                                                                    dbgs() << "Sensitive external library call found: ";
                                                                    value->dump();
                                                                  );
                                                            isSensitiveCall = true;
                                                        }
                                                    }
                                                    if (isSensitiveCall) {
                                                        SensitiveExternalLibCallList.push_back(CInst);
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
	}
}


void EncryptionPass::preprocessAllocaAndLoadInstructions(Instruction* Inst) {
	// Add the MetaData to the AllocaInst
	// Check if it's an Allocation on the stack
	if (AllocaInst* AInst = dyn_cast<AllocaInst>(Inst)) {
        if (AInst->getName().startswith("padding")) {
            return;
        }
		if (isSensitiveObjSet(getPAGObjNodeFromValue(AInst))) {
			LLVMContext& C = AInst->getContext();
			MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
			AInst->setMetadata("SENSITIVE", N);
		}
	} else if (LoadInst* LdInst = dyn_cast<LoadInst>(Inst)) {					
		if (isSensitiveLoadSet(LdInst)) {
			LLVMContext& C = LdInst->getContext();
			MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
			LdInst->setMetadata("SENSITIVE", N);

			// Find the next instruction
			Instruction* NextInstruction = FindNextInstruction(Inst);
			InstructionReplacement* Replacement = new InstructionReplacement();
			Replacement->OldInstruction = Inst;
			Replacement->NextInstruction = NextInstruction;
			Replacement->Type = LOAD;
			ReplacementList.push_back(Replacement);
		}
	}
}


void EncryptionPass::preprocessStoreInstructions(Instruction* Inst) {
	StoreInst* StInst = dyn_cast<StoreInst>(Inst);
	Value* PointerOperand = StInst->getPointerOperand();
	// Fix for ConstantExpr
	// First check if the Store instruction has GEPConstantExpr
	//bool sensitiveGEPCE = false;
    /*
     * SVF breaks this up anyway
	if (ConstantExpr* CConstExpr = dyn_cast<ConstantExpr>(StInst->getPointerOperand())) {
		// Fix for Constant Expressions
		ConstantExpr* ConstExpr = const_cast<ConstantExpr*>(CConstExpr);
		if (ConstExpr->getOpcode() == Instruction::GetElementPtr) {
			GEPOperator* GEPOp = dyn_cast<GEPOperator>(ConstExpr);
			if (GEPOp && isSensitiveObj(GEPOp->getPointerOperand())) {
				sensitiveGEPCE = true;
			}
		}
	}
    */

    PAG* pag = getAnalysis<WPAPass>().getPAG();
    // We care only if the PointerOperand is a memory location
	if ((pag->hasObjectNode(PointerOperand) && isSensitiveObjSet(getPAGObjNodeFromValue(PointerOperand))) || isSensitiveLoadPtrSet(PointerOperand) || isSensitiveGEPPtrSet(PointerOperand)/* || sensitiveGEPCE*/) {
		LLVMContext& C = StInst->getContext();
		MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
		StInst->setMetadata("SENSITIVE", N);

		InstructionReplacement* Replacement = new InstructionReplacement();
		Replacement->OldInstruction = Inst;
		Replacement->NextInstruction = nullptr; // Don't care about the next, the decryption happens before the store
		Replacement->Type = STORE;
		ReplacementList.push_back(Replacement);
	}
}


void EncryptionPass::updateSensitiveState(Value* oldVal, Value* newVal, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    PAG* pag = getAnalysis<WPAPass>().getPAG();
    PAGNode* oldValNode = getPAGValNodeFromValue(oldVal);
    // Hack, we modify the PAG, but not the underlying SymInfo
    PAGNode* newValNode = pag->getPAGNode(pag->addDummyValNode());
    newValNode->setValue(newVal);
    // If the oldVal belonged to any of the Sensitive lists / sets, then update it
    std::vector<Value*> listlist[] = {
                    SensitiveLoadPtrList,
                    SensitiveLoadList,
                    SensitiveInlineAsmCalls,
                    SensitiveInlineAsmArgs,
                    SensitiveGEPPtrList};
    for (int i = 0; i < 5; i++) {
        if (contains(oldVal, listlist[i])) {
            listlist[i].push_back(newVal);
        }
    }

    std::set<Value*>* setList[] = {SensitiveLoadPtrSet, SensitiveLoadSet, SensitiveGEPPtrSet};

    for (int i = 0; i < 3; i++) {
        if (containsSet(oldVal, *(setList[i]))) {
            setList[i]->insert(newVal);
        }
    }

    // This probably does nothing
    for (PAGNode* ptsToNode: ptsToMap[oldValNode]) {
        ptsToMap[newValNode].insert(ptsToNode);
    }

    ExtraSensitivePtrs.insert(newVal);

}


void EncryptionPass::resetInstructionLists(Function *F) {
	ReplacementList.clear();
	InstructionList.clear();
	// Iterate over all instructions in the Function to build the Instruction list
	for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
		InstructionList.push_back(&*I);
	}

}

void EncryptionPass::performAesCacheInstrumentation(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
	for (std::vector<InstructionReplacement*>::iterator ReplacementIt = ReplacementList.begin() ; ReplacementIt != ReplacementList.end(); ++ReplacementIt) {
		InstructionReplacement* Repl = *ReplacementIt;
		if (Repl->Type == LOAD) {
			IRBuilder<> Builder(Repl->NextInstruction); // Insert before "next" instruction
			LoadInst* LdInst = dyn_cast<LoadInst>(Repl->OldInstruction);

			// Check get the decrypted value
            decryptionCount++;
			Value* decryptedValue = AESCache.getDecryptedValueCached(LdInst);

            updateSensitiveState(LdInst, decryptedValue, ptsToMap);
			// Can't blindly replace all uses of the old loaded value, because it includes the InlineASM
			std::vector<User*> LoadInstUsers;
			for (User *U : LdInst->users()) {
				LoadInstUsers.push_back(U);
			}

			for (User *U: LoadInstUsers) {
				if (U != decryptedValue) {
					int i, NumOperands = U->getNumOperands();
					for (i = 0; i < NumOperands; i++) {
						if (U->getOperand(i) == LdInst) {
							U->setOperand(i, decryptedValue);
						}
					}
				}
			}

			// Remove the Load instruction
			LdInst->eraseFromParent();
		} else	if (Repl->Type == STORE) {
			IRBuilder<> Builder(Repl->OldInstruction); // Insert before the current Store instruction
			StoreInst* StInst = dyn_cast<StoreInst>(Repl->OldInstruction);
			LLVM_DEBUG (
			dbgs() << "Replacing Store Instruction : ";
			StInst->dump();
			);

            encryptionCount++;
			AESCache.setEncryptedValueCached(StInst);
			// Remove the Store instruction
			StInst->eraseFromParent();
		}
	}
}

/*
void EncryptionPass::instrumentInlineAsm(Module& M) {
	PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
	for (Value* sensitiveAsm: SensitiveInlineAsmCalls) {
		CallInst* sensCInst = dyn_cast<CallInst>(sensitiveAsm);
		InlineAsm* inlineAsm = dyn_cast<InlineAsm>(sensCInst->getCalledValue());
		
		int argIndex = 0;
		for(User::op_iterator arg = sensCInst->arg_begin(), argEnd = sensCInst->arg_end(); arg != argEnd; ++arg) {
			argIndex++;
			Value* argVal = dyn_cast<Value>(&*arg);
			if (isSensitiveAlloca(argVal) || isSensitiveLoadPtr(argVal) || isSensitiveGEPPtr(argVal)) {
				// Decrypt before the call
				IRBuilder<> InstBuilder(sensCInst);
				int numBytesToDecrypt = asmParser.findNumBytesAccessed(inlineAsm, argVal, argIndex);
				Function* instrumentFunction = M.getFunction("decryptInMem");
				std::vector<Value*> ArgList;
				if (argVal->getType() != voidPtrType) {
					Value* voidArgVal = InstBuilder.CreateBitCast(argVal, voidPtrType);
					ArgList.push_back(voidArgVal);
				} else {
					ArgList.push_back(argVal);
				}
				ArgList.push_back(ConstantInt::get(IntegerType::get(sensCInst->getContext(), 64), numBytesToDecrypt));
				InstBuilder.CreateCall(instrumentFunction, ArgList);
				
				// Encrypt after the inline assembly call
				Function* encInstFunc = M.getFunction("encryptInMem");
				CallInst* encCInst = CallInst::Create(encInstFunc, ArgList);
				encCInst->insertAfter(sensCInst);
			}
		}
	}
}
*/

void EncryptionPass::performXorInstrumentation(Module& M) {
    /*
	IntegerType* longTy = IntegerType::get(M.getContext(), 64);
	Value* XORResult = nullptr;
	ConstantInt* XORInt = nullptr;
	Value* intValOfPtr = nullptr;
	Value* intXORedPtr = nullptr;

	for (std::vector<InstructionReplacement*>::iterator ReplacementIt = ReplacementList.begin() ; ReplacementIt != ReplacementList.end(); ++ReplacementIt) {
		InstructionReplacement* Repl = *ReplacementIt;
		if (Repl->Type == LOAD) {
			IRBuilder<> Builder(Repl->NextInstruction); // Insert before "next" instruction
			LoadInst* LdInst = dyn_cast<LoadInst>(Repl->OldInstruction);
			// We need to add a XOR instruction after this load
			// Then, we need to update all references to the original virtual register with the new virtreg
			Value* LoadValue = llvm::cast<Value>(LdInst);
			IntegerType* Ty = dyn_cast<IntegerType>(LoadValue->getType());
			PointerType* PTy = dyn_cast<PointerType>(LoadValue->getType());
			if (Ty) {
				switch(Ty->getBitWidth()) {
					case 8:
						XORInt = ConstantInt::get(Ty, 0xAA, true);
						break;
					case 16:
						XORInt = ConstantInt::get(Ty, 0xAAAA, true);
						break;
					case 32:
						XORInt = ConstantInt::get(Ty, 0xAAAAAAAA, true);
						break;
					case 64:
						XORInt = ConstantInt::get(Ty, 0xAAAAAAAAAAAAAAAA, true);
						break;
					default:
						errs() << "Invalid Integer Type!\n";
				}
				
				XORResult = Builder.CreateXor(LoadValue, XORInt);
			} else if (PTy) {
				// The loaded value is a pointer, do a ptrtoint and then xor, then inttoptr
				intValOfPtr = Builder.CreatePtrToInt(LoadValue, longTy);
				XORInt = ConstantInt::get(longTy, 0xAAAAAAAAAAAAAAAA, true);
				intXORedPtr = Builder.CreateXor(intValOfPtr, XORInt);
				XORResult = Builder.CreateIntToPtr(intXORedPtr, PTy);

				// We're replacing a pointer - handle memberships of that pointer
				if (isSensitiveObjSet(LoadValue)) {
					SensitiveObjList.push_back(XORResult);
					SensitiveObjSet->insert(XORResult);
				} 
				if (isSensitiveGEPPtrSet(LoadValue)) {
					SensitiveGEPPtrList.push_back(XORResult);
					SensitiveGEPPtrSet->insert(XORResult);
				}
				if (isSensitiveLoadPtrSet(LoadValue)) {
					SensitiveLoadPtrList.push_back(XORResult);
					SensitiveLoadPtrSet->insert(XORResult);
				}
				if (isSensitiveLoadSet(LoadValue)) {
					SensitiveLoadList.push_back(XORResult);
					SensitiveLoadSet->insert(XORResult);
				}

				// The loaded value is a pointer
				// If this pointer were to be passed to outside libraries, then it must be protected
				for (Value::use_iterator UseIt = LoadValue->use_begin(), UseEnd = LoadValue->use_end(); UseIt != UseEnd; UseIt++) {
					Value* UseValue = dyn_cast<Value>(*UseIt);
					if(LoadInst* loadedFromPtr = dyn_cast<LoadInst>(UseValue)) {
						SensitivePtrValMap[XORResult] = loadedFromPtr->getPointerOperand();
						break;
					}
				}

			} else {
				assert(false);
			}

			Instruction* XORInst = dyn_cast<Instruction>(XORResult);
			if (XORInst) {
				LLVMContext& C = XORInst->getContext();
				MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
				XORInst->setMetadata("SENSITIVE", N);
			}
			// Can't blindly replace all uses of the old loaded value, because it includes the XOR

			std::vector<User*> LoadInstUsers;
			for (User *U : LdInst->users()) {
				LoadInstUsers.push_back(U);
			}
			for (User *U: LoadInstUsers) {
				if ((U != XORInst) && (U != intValOfPtr) && (U != intXORedPtr)) {
					int i, NumOperands = U->getNumOperands();
					for (i = 0; i < NumOperands; i++) {
						if (U->getOperand(i) == LoadValue) {
							U->setOperand(i, XORResult);
						}
					}
				}
			}
		} else	if (Repl->Type == STORE) {
			// Add the XOR instruction before the Store
			IRBuilder<> Builder(Repl->OldInstruction); // Insert before the current Store instruction
			StoreInst* StInst = dyn_cast<StoreInst>(Repl->OldInstruction);
			LLVM_DEBUG (
			dbgs() << "Replacing Store Instruction : ";
			StInst->dump();
			);
			// Get the value operand
			Value* PointerValue = StInst->getValueOperand();
			IntegerType *Ty = dyn_cast<IntegerType>(PointerValue->getType());
			PointerType *PTy = dyn_cast<PointerType>(PointerValue->getType());
			if (Ty) {
				switch(Ty->getBitWidth()) {
					case 8:
						XORInt = ConstantInt::get(Ty, 0xAA, true);
						break;
					case 16:
						XORInt = ConstantInt::get(Ty, 0xAAAA, true);
						break;
					case 32:
						XORInt = ConstantInt::get(Ty, 0xAAAAAAAA, true);
						break;
					case 64:
						XORInt = ConstantInt::get(Ty, 0xAAAAAAAAAAAAAAAA, true);
						break;
					default:
						errs() << "Invalid Integer Type!\n";
				}

				XORResult = Builder.CreateXor(PointerValue, XORInt);
			} else if (PTy) {
				// The loaded value is a pointer, do a ptrtoint and then xor, then inttoptr
				intValOfPtr = Builder.CreatePtrToInt(PointerValue, longTy);
				XORInt = ConstantInt::get(longTy, 0xAAAAAAAAAAAAAAAA, true);
				intXORedPtr = Builder.CreateXor(intValOfPtr, XORInt);
				XORResult = Builder.CreateIntToPtr(intXORedPtr, PTy);
				// We're replacing a pointer - handle memberships of that pointer
				if (isSensitiveObjSet(PointerValue)) {
					SensitiveObjList.push_back(XORResult);
					SensitiveObjSet->insert(XORResult);
				} 
				if (isSensitiveGEPPtrSet(PointerValue)) {
					SensitiveGEPPtrList.push_back(XORResult);
					SensitiveGEPPtrSet->insert(XORResult);
				}
				if (isSensitiveLoadPtrSet(PointerValue)) {
					SensitiveLoadPtrList.push_back(XORResult);
					SensitiveLoadPtrSet->insert(XORResult);
				}
				if (isSensitiveLoadSet(PointerValue)) {
					SensitiveLoadList.push_back(XORResult);
					SensitiveLoadSet->insert(XORResult);
				}
			}

			Instruction* XORInst = dyn_cast<Instruction>(XORResult);
			if (XORInst) {
				LLVMContext& C = XORInst->getContext();
				MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
				XORInst->setMetadata("SENSITIVE", N);
			}
			// Update the Value to store the XORResult
			StInst->setOperand(0, XORResult);
		}
	}
    */


}

void EncryptionPass::performInstrumentation(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    /*
	if (DoNullEnc) {
		performXorInstrumentation(M);
	} else if (DoAESEncCache){
    */
    performAesCacheInstrumentation(M, ptsToMap);
        /*
	}
    */
}


/*
bool EncryptionPass::isSensitiveArg(Value* arg) {
	if (isSensitiveGEPPtrSet(arg) || isSensitiveLoadPtrSet(arg) || isSensitiveObjSet(arg) || isSensitiveConstantExpr(arg)) {
		return true;
	} else {
		// Check if we need to do special handling for call values
		if (CallInst* retVal = dyn_cast<CallInst>(arg)) {
			// TODO Handle function pointers
			Function* calledFunction = retVal->getCalledFunction();
			if (calledFunction) {
				// Check the retmap 
				std::set<Value*> retVals = (*ptsToMapPtr)[calledFunction];
				for (Value* retVal: retVals) {
					if (isSensitiveArg(retVal)) {
						return true;
					}
				}
			}
		}
	}
}
*/

bool EncryptionPass::isSensitiveArg(Value* arg,  std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    PAG* pag = getAnalysis<WPAPass>().getPAG();

    if (std::find(ExtraSensitivePtrs.begin(), ExtraSensitivePtrs.end(), arg) != ExtraSensitivePtrs.end()) {
        return true;
    }

    if (!pag->hasValueNode(arg)) {
        // Constant etc
        return false;
    }

    if (!arg->getType()->isPointerTy()) {
        return false;
    }

    // If this arg points to sensitive stuff, then it is sensitive
    PAGNode* argNode = getPAGValNodeFromValue(arg);
    for (PAGNode* pointedToNode: ptsToMap[argNode]) {
        if (isSensitiveObjSet(pointedToNode)) {
            return true;
        }
    }
    /*
    if (CallInst* retVal = dyn_cast<CallInst>(arg)) {
        // TODO Handle function pointers
        Function* calledFunction = retVal->getCalledFunction();
        PAGNode* calledFunctionNode = getPAGObjNodeFromValue(calledFunction);
        if (calledFunction) {
            // Check the retmap 
            std::set<PAGNode*> retValNodes = ptsToMap[calledFunctionNode];
            for (PAGNode* retValNode: retValNodes) {
                assert(retValNode->hasValue() && "A PAG node made it so far, must have value.");
                Value* retVal = const_cast<Value*>(retValNode->getValue());
                if (isSensitiveArg(retVal, ptsToMap)) {
                    return true;
                }
            }
        }
    }
    */

    return false;
}

Type* EncryptionPass::findBaseType(Type* type) {
    Type* trueType = type;
    while (trueType->isPointerTy()) {
        trueType = trueType->getPointerElementType();
    }
    return trueType;
}

/*
int EncryptionPass::getSzVoidArgVal(Value* voidPtrValue, Module& M) {
    // It's a void argument value
    // It should be bitcasted from something
    if (CastInst* castInst = dyn_cast<CastInst>(voidPtrValue)) {
        Type* trueType = findBaseType(castInst->getSrcTy());
        if (CompositeType* cType = dyn_cast<CompositeType>(trueType)) {
            return M.getDataLayout().getTypeAllocSize(cType);
        } else {
            return -1;
        }
    }
    if (ConstantExpr* unaryConsExpr = dyn_cast<ConstantExpr>(voidPtrValue)) {
        Type* trueType = findBaseType(unaryConsExpr->getOperand(0)->getType());
        if (CompositeType* cType = dyn_cast<CompositeType>(trueType)) {
            return M.getDataLayout().getTypeAllocSize(cType);
        } else {
            return -1;
        }
    }


    for (Value::use_iterator useItr = voidPtrValue->use_begin(),
            useEnd = voidPtrValue->use_end();
            useItr != useEnd;
            useItr++) {
        if (CastInst* castInst = dyn_cast<CastInst>(*useItr)) {
            Type* trueType = findBaseType(castInst->getSrcTy());
            if (CompositeType* cType = dyn_cast<CompositeType>(trueType)) {
                return M.getDataLayout().getTypeAllocSize(cType);
            } else {
                return -1;
            }
        }
    }
    return -1;
}
*/

int EncryptionPass::getCompositeSzValue(Value* value, Module& M) {
    Type* trueType = findBaseType(value->getType());
    if (CompositeType* cType = dyn_cast<CompositeType>(trueType)) {
            return M.getDataLayout().getTypeAllocSize(cType);
    }
    assert(false && "getCompositeSzValue called with a non-composite type!");
}

/*
int EncryptionPass::getSzVoidRetVal(Value* voidPtrValue, Module& M) {
    // It's a return value
    // Eventually, it should be stored somewhere
    std::set<Value*> sinkSites;
    findSinkSites(voidPtrValue, sinkSites, false); // ind = false, because we *are* tracking flow of pointer
    assert(sinkSites.size() == 1 && "Hopefully, the value returned will not be stored at more than one location\n");
    for (Value* sinkSite: sinkSites) {
        assert(sinkSite->getType()->isPointerTy() && "Sink site must be a pointer type!\n");
        Type* trueType = findBaseType(sinkSite->getType());
        if (CompositeType* cType = dyn_cast<CompositeType>(trueType)) {
            return M.getDataLayout().getTypeAllocSize(cType);
        } else {
            return -1; // Fingers crossed that this is a string
        }
    }
}
*/
/**
 * The routine that actual does the instrumentation for external function calls.
 */
void EncryptionPass::instrumentExternalFunctionCall(Module &M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
	std::set<Value*> UnsupportedCallSet;

	std::vector<Value*> sensitivePointerValueList; // List of sensitive pointers (the pointer itself is sensitive)
	/*IntegerType* longTy = IntegerType::get(M.getContext(), 64);*/

	for (CallInst* externalCallInst : SensitiveExternalLibCallList) {
		Function* externalFunction = externalCallInst->getCalledFunction();
        if (!externalFunction) {
            // Was a function pointer.
            std::vector<Function*> possibleFuns;
            PAGNode* fptrNode = getPAGValNodeFromValue(externalCallInst->getCalledValue());
            for (PAGNode* fNode : ptsToMap[fptrNode]) {
                Value* fn = const_cast<Value*>(fNode->getValue());
                if (Function* realFn = dyn_cast<Function>(fn)) {
                    possibleFuns.push_back(realFn);
                }
            }
            if (possibleFuns.size() != 1) {
                errs() << "For call instruction: " << *externalCallInst << " in function " << externalCallInst->getParent()->getParent()->getName() << " found " << possibleFuns.size() << " functions\n";
            }
            assert(possibleFuns.size() == 1 && "Found more than one external function pointer targets. Don't know what to do here.\n");
            externalFunction = possibleFuns[0];
        }
        /*
        if (externalFunction->getName().equals("strlen")) {
            errs() << "1. " << externalCallInst << " : " << *externalCallInst << "\n";
        }
        */
		IRBuilder<> InstBuilder(externalCallInst);

        StringRef annotFn("llvm.var.annotation");
        if (annotFn.equals(externalFunction->getName())) {
            continue;
        }
		int numArgs = externalCallInst->getNumArgOperands();
		/*
		sensitivePointerValueList.clear();
		// Are any of the args in sensitive allocation sites -- do we really need to do this?
		for (int i = 0; i < numArgs; i++) {
			Value* arg = externalCallInst->getArgOperand(i);
			if (isSensitivePtrVal(arg)) {
				// XOR and store
				Value* XORInt = ConstantInt::get(longTy, 0xAAAAAAAAAAAAAAAA, true);
				Value* intValOfPtr = InstBuilder.CreatePtrToInt(arg, longTy);

				Value* XORResult = InstBuilder.CreateXor(intValOfPtr, XORInt);
				Value* destPtr = SensitivePtrValMap[arg];
				Value* XORResultPtr = InstBuilder.CreateIntToPtr(XORResult, destPtr->getType()->getPointerElementType());

				StoreInst* StInst = InstBuilder.CreateStore(XORResultPtr, destPtr);
				sensitivePointerValueList.push_back(arg);
			}
		}
		*/

        // In case of AES cache encryption, write back the cache
        if (DoAESEncCache) {
            AESCache.writeback(externalCallInst);
        }

        if (externalFunction->getName() == "select") {
            // TODO - Handle all arguments
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);

            IRBuilder<> InstBuilder(externalCallInst);
            Value* sensitiveArg = externalCallInst->getOperand(1);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            if (sensitiveArg->getType() != voidPtrType) {
                Value* voidArgVal = InstBuilder.CreateBitCast(sensitiveArg, voidPtrType);
                ArgList.push_back(voidArgVal);
            } else {
                ArgList.push_back(sensitiveArg);
            }
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 128));
            InstBuilder.CreateCall(decryptFunction, ArgList);
            // Encrypt it back
            CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
            encCInst->insertAfter(externalCallInst);
        } else if (externalFunction->getName() == "calloc" || externalFunction->getName() == "aes_calloc") {
			Function* instrumentFunction = M.getFunction("encryptArrayForLibCall");
			std::vector<Value*> ArgList;
			Value* numElements = externalCallInst->getArgOperand(0);
			Value* elemSize = externalCallInst->getArgOperand(1);
			Value* numBytes = InstBuilder.CreateMul(elemSize, numElements, "mul");

			ArgList.push_back(externalCallInst);
			ArgList.push_back(numBytes);
			// Insert call instruction to call the function
			CallInst* CInst = CallInst::Create(instrumentFunction, ArgList);
			CInst->insertAfter(externalCallInst);
		} else if (externalFunction->getName() == "printf") {
			// Get the arguments, check if any of them is sensitive 
			// and then put code to decrypt them in memory
			for (int i = 0; i < numArgs; i++) {
				Value* value = externalCallInst->getArgOperand(i);
				if (isSensitiveArg(value, ptsToMap)) {
					LLVM_DEBUG (
					dbgs() << "Do decryption for print value: ";
					value->dump();
					);
					Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
					std::vector<Value*> ArgList;
					ArgList.push_back(value);
					/*CallInst* CInst = */
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);
				}
			}
        } else if (externalFunction->getName() == "asprintf" || externalFunction->getName() == "asprintf128") {
            // For the first argument which is a pointer to a string
            Value* stringPtr = externalCallInst->getArgOperand(0);
            // stringPtr is a pointer
            // We need to check if it points to sensitive memory objects, and not if it is a sensitive memory object
            if (isSensitiveArg(stringPtr, ptsToMap)) {
                Function* encryptFunction = M.getFunction("encryptStringPtrAfterLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(stringPtr);
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
            for (int i = 1; i < numArgs; i++) {
                Value* value = externalCallInst->getArgOperand(i);
                if (isSensitiveArg(value, ptsToMap)) {
                    LLVM_DEBUG (
                            dbgs() << "Do decryption for print value: ";
                            value->dump();
                          );
                    Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                    std::vector<Value*> ArgList;
                    ArgList.push_back(value);
                    /*CallInst* CInst = */
                    InstBuilder.CreateCall(decryptFunction, ArgList);
                    // Encrypt it back
                    Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                    CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                    encCInst->insertAfter(externalCallInst);
                }
            }
        } else if (externalFunction->getName() == "posix_memalign") {
            errs() << "Sensitive posix_memalign\n";
            Value* memPtr = externalCallInst->getArgOperand(0);
            Value* size = externalCallInst->getArgOperand(2);
            // stringPtr is a pointer
            // We need to check if it points to sensitive memory objects, and not if it is a sensitive memory object
            if (isSensitiveArg(memPtr, ptsToMap)) {
                Function* instrumentFunction = M.getFunction("encryptArrayPtrAfterLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(memPtr);
                ArgList.push_back(size);
                // Insert call instruction to call the function
                CallInst* CInst = CallInst::Create(instrumentFunction, ArgList);
                CInst->insertAfter(externalCallInst);
            }
        } else if (externalFunction->getName() == "cloneenv") {
            //assert(false && "Broke cloneenv!");
            if (isSensitiveObjSet(getPAGObjNodeFromValue(externalCallInst))) {
                std::vector<Value*> ArgList;
                ArgList.push_back(externalCallInst);
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
        } else if (externalFunction->getName() == "poll") {
            IRBuilder<> InstBuilder(externalCallInst);
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);

            // Handle only the pollfd. The nfds will be in register, the timeout better be 0
            Value* pollfdVal = externalCallInst->getArgOperand(0);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            if (isSensitiveArg(pollfdVal, ptsToMap)) {
                std::vector<Value*> ArgList;
                if (pollfdVal->getType() != voidPtrType) {
                    Value* voidArgVal = InstBuilder.CreateBitCast(pollfdVal, voidPtrType);
                    ArgList.push_back(voidArgVal);
                } else {
                    ArgList.push_back(pollfdVal);
                }
                ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 8));
                InstBuilder.CreateCall(decryptFunction, ArgList);
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
		} else if (externalFunction->getName() == "puts") {
			Value* value = externalCallInst->getArgOperand(0);
			if (isSensitiveArg(value, ptsToMap)) {
				LLVM_DEBUG (
				dbgs() << "Do decryption for puts value: ";
				value->dump();
				);
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(value);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
		} else if (externalFunction->getName() == "fgets") {
        	Value* buffer = externalCallInst->getArgOperand(0);
            Value* fileStream0 = externalCallInst->getArgOperand(2);
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Value* fileStream = InstBuilder.CreateBitCast(fileStream0, voidPtrType);

			if (isSensitiveArg(buffer, ptsToMap)) {
				//Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(buffer);
				//InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
			if (isSensitiveArg(fileStream, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(fileStream);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
        } else if (externalFunction->getName() == "fopen" || externalFunction->getName() == "open") {
			Value* fileName = externalCallInst->getArgOperand(0);
			Value* mode = externalCallInst->getArgOperand(1);
			if (isSensitiveArg(fileName, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(fileName);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
			if (isSensitiveArg(mode, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(mode);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
		} else if (externalFunction->getName() == "fprintf") {
			// Variable arg number
			int argNum = externalCallInst->getNumArgOperands();
			// Assuming first arguments, FILE* stream can never be sensitive
			if (argNum > 1) {
				// has varargs
				for (int i = 1; i < argNum; i++) {
					Value* arg = externalCallInst->getArgOperand(i);
					if (isSensitiveArg(arg, ptsToMap) ) {
						Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
						std::vector<Value*> ArgList;
						ArgList.push_back(arg);
						/*CallInst* CInst = */
						InstBuilder.CreateCall(decryptFunction, ArgList);
						// Encrypt it back
						Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
						CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
						encCInst->insertAfter(externalCallInst);

					}
				}
			}
		} else if (externalFunction->getName() == "vsnprintf") {
			// vsnprintf(char* str, size_t size, const char *format, va_list ap);
			int argNum = externalCallInst->getNumArgOperands();
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
                     
            // The first argument -> char *str
            Value* arg = externalCallInst->getArgOperand(0);
            if (isSensitiveArg(arg, ptsToMap)) {
                //Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                std::vector<Value*> ArgList;
                if (arg->getType() != voidPtrType) {
                    arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                }
                ArgList.push_back(arg);
                /*CallInst* CInst = */
                //InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);

            }
            // Second argument is the size, ignore
            // The third argument is the format buffer
            arg = externalCallInst->getArgOperand(2);
            if (isSensitiveArg(arg, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                std::vector<Value*> ArgList;
                if (arg->getType() != voidPtrType) {
                    arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                }
                ArgList.push_back(arg);
                /*CallInst* CInst = */
                InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
            // The fourth argument is the tricky va_list
            arg = externalCallInst->getArgOperand(3);
            if (isSensitiveArg(arg, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptVaArgListBeforeLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(externalCallInst->getArgOperand(2));
                ArgList.push_back(arg);
                InstBuilder.CreateCall(decryptFunction, ArgList);

                std::vector<Value*> vaArgList;
                if (arg->getType() != voidPtrType) {
                    arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                }

                vaArgList.push_back(arg);
                // Before we try to encrypt it back, we need to call a va_end and va_start to reinitialize 
                // the va_list
                Function* vaEndIntrinsicFun = M.getFunction("llvm.va_end");
                CallInst* vaEndCInst = CallInst::Create(vaEndIntrinsicFun, vaArgList);
                vaEndCInst->insertAfter(externalCallInst);

                Function* vaStartIntrinsicFun = M.getFunction("llvm.va_start");
                CallInst* vaStartCInst = CallInst::Create(vaStartIntrinsicFun, vaArgList);
                vaStartCInst->insertAfter(vaEndCInst);

                Function* encryptFunction = M.getFunction("encryptVaArgListAfterLibCall");
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(vaStartCInst);
            }
        } else if (externalFunction->getName() == "vprintf") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
 
            Value* format = externalCallInst->getArgOperand(0);
            Value* vararg = externalCallInst->getArgOperand(1);
            if (isSensitiveArg(format, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                std::vector<Value*> ArgList;
                if (format->getType() != voidPtrType) {
                    format = InstBuilder.CreateBitCast(format, voidPtrType);
                }
                ArgList.push_back(format);
                /*CallInst* CInst = */
                InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
            if (isSensitiveArg(vararg, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptVaArgListBeforeLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(format);
                ArgList.push_back(vararg);
                InstBuilder.CreateCall(decryptFunction, ArgList);

                std::vector<Value*> vaArgList;
                if (vararg->getType() != voidPtrType) {
                    vararg = InstBuilder.CreateBitCast(vararg, voidPtrType);
                }

                vaArgList.push_back(vararg);
                // Before we try to encrypt it back, we need to call a va_end and va_start to reinitialize 
                // the va_list
                Function* vaEndIntrinsicFun = M.getFunction("llvm.va_end");
                CallInst* vaEndCInst = CallInst::Create(vaEndIntrinsicFun, vaArgList);
                vaEndCInst->insertAfter(externalCallInst);

                Function* vaStartIntrinsicFun = M.getFunction("llvm.va_start");
                CallInst* vaStartCInst = CallInst::Create(vaStartIntrinsicFun, vaArgList);
                vaStartCInst->insertAfter(vaEndCInst);

                Function* encryptFunction = M.getFunction("encryptVaArgListAfterLibCall");
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(vaStartCInst);
            }
        } else if (externalFunction->getName() == "sprintf") {
            // Variable arg number
            int argNum = externalCallInst->getNumArgOperands();
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
                     
			for (int i = 0; i < argNum; i++) {
				// has varargs
				Value* arg = externalCallInst->getArgOperand(i);
				if (isSensitiveArg(arg, ptsToMap)) {
					Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
					std::vector<Value*> ArgList;
                    if (arg->getType() != voidPtrType) {
                        arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                    }
					ArgList.push_back(arg);
					/*CallInst* CInst = */
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);

				}
			}
		} else if (externalFunction->getName() == "snprintf") {
			// Variable arg number
			int argNum = externalCallInst->getNumArgOperands();
			// has varargs TODO
			for (int i = 0; i < argNum; i++) {
				if (i == 1) continue; // the size_t size arg
				Value* arg = externalCallInst->getArgOperand(i);
				if (isSensitiveArg(arg, ptsToMap)) {
					Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
					std::vector<Value*> ArgList;
					ArgList.push_back(arg);
					/*CallInst* CInst = */
                    if (i != 0) {
                        // Don't decrypt the first argument, which is the destination.
					    InstBuilder.CreateCall(decryptFunction, ArgList);
                    }
					// Encrypt it back
					Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);

				}
			}
		} else if (externalFunction->getName() == "memcmp") {
			Value* firstBuff = externalCallInst->getArgOperand(0);
			Value* secondBuff = externalCallInst->getArgOperand(1);
			Value* numBytes = externalCallInst->getArgOperand(2);
			bool firstBuffSens = false;
			bool secondBuffSens = false;
			if (isSensitiveArg(firstBuff, ptsToMap)) {
				firstBuffSens = true;
			}
			if (isSensitiveArg(secondBuff, ptsToMap)) {
				secondBuffSens = true;
			}
			Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

			// One of them is sensitive, the other is not
			// If it is the source, then decrypt before the call to memcpy
			// If it is the destination, then decrypt after the call to memcpy

			//if (firstBuffSens xor secondBuffSens) {
				if (firstBuffSens) {
			        std::vector<Value*> ArgList;
					ArgList.push_back(firstBuff);
					ArgList.push_back(numBytes);
					// Insert call instruction to call the function
					IRBuilder<> InstBuilder(externalCallInst);
					/*CallInst* CInst = */
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);

				} 
                if (secondBuffSens) {
                    std::vector<Value*> ArgList;
					ArgList.push_back(secondBuff);
					ArgList.push_back(numBytes);
					// Insert call instruction to call the function
					IRBuilder<> InstBuilder(externalCallInst);
					/*CallInst* CInst = */
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);

				}
			//}
		} else if (externalFunction->getName().find("llvm.memmove") != StringRef::npos) {
			Value* firstBuff = externalCallInst->getArgOperand(0);
			Value* secondBuff = externalCallInst->getArgOperand(1);
			Value* numBytes = externalCallInst->getArgOperand(2);
			bool firstBuffSens = false;
			bool secondBuffSens = false;
			if (isSensitiveArg(firstBuff, ptsToMap)) {
				firstBuffSens = true;
			}
			if (isSensitiveArg(secondBuff, ptsToMap)) {
				secondBuffSens = true;
			}
			Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
			std::vector<Value*> ArgList;

			// One of them is sensitive, the other is not
			// If it is the source, then decrypt before the call to memcpy
			// If it is the destination, then decrypt after the call to memcpy

			if (firstBuffSens xor secondBuffSens) {
				if (firstBuffSens) {
					ArgList.push_back(firstBuff);
					ArgList.push_back(numBytes);
					// Insert call instruction to call the function
					IRBuilder<> InstBuilder(externalCallInst);
					/*CallInst* CInst = */
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);

				} else {
					ArgList.push_back(secondBuff);
					ArgList.push_back(numBytes);
					// Insert call instruction to call the function
					IRBuilder<> InstBuilder(externalCallInst);
					/*CallInst* CInst = */
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);

				}
			}
		} else if (externalFunction->getName() == "opendir") {
			Value* dirName = externalCallInst->getArgOperand(0);
			if (isSensitiveArg(dirName, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(dirName);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
		} else if (externalFunction->getName() == "stat" || externalFunction->getName() == "lstat") {
			Value* pathName = externalCallInst->getArgOperand(0);
			Value* statBuf = externalCallInst->getArgOperand(1);
			if (isSensitiveArg(pathName, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(pathName);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
			if (isSensitiveArg(statBuf, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(statBuf);
				ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 144));
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
		} else if (externalFunction->getName() == "fread") {
			Value* bufferPtr = externalCallInst->getArgOperand(0);
			Value* elemSize = externalCallInst->getArgOperand(1);
			Value* numElements = externalCallInst->getArgOperand(2);
			if (isSensitiveArg(bufferPtr, ptsToMap)) {
				// Insert call instruction to call the function
				Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
				Value* numBytes = InstBuilder.CreateMul(elemSize, numElements, "mul");
				std::vector<Value*> ArgList;
				ArgList.push_back(bufferPtr);
				ArgList.push_back(numBytes);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
		} else if (externalFunction->getName() == "strchr") {
			Value* str = externalCallInst->getArgOperand(0);
			if (isSensitiveArg(str, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(str);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);
			}
		} else if (externalFunction->getName() == "strcmp" || externalFunction->getName() == "strncmp" || externalFunction->getName() == "strncasecmp") {
			Value* string1 = externalCallInst->getArgOperand(0);
			Value* string2 = externalCallInst->getArgOperand(1);
			if (isSensitiveArg(string1, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(string1);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);
			}
			if (isSensitiveArg(string2, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(string2);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
		} else if (externalFunction->getName() == "memchr" || externalFunction->getName() == "memrchr" || 
                externalFunction->getName() == "strtol" || externalFunction->getName() == "unlink") {
            Value* bufferPtr = externalCallInst->getArgOperand(0);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(bufferPtr);
                // Insert call instruction to call the function
                IRBuilder<> InstBuilder(externalCallInst);
                InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);
			}
        } else if (externalFunction->getName().find("strcpy") != StringRef::npos || externalFunction->getName() == "strncpy") {
            Value* destBufferPtr = externalCallInst->getArgOperand(0);
            Value* srcBufferPtr = externalCallInst->getArgOperand(1);

            //Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(srcBufferPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(srcBufferPtr);
                // Insert call instruction to call the function
                //IRBuilder<> InstBuilder(externalCallInst);
                /*CallInst* CInst = */
                //InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);
			}
			if (isSensitiveArg(destBufferPtr, ptsToMap)) {
				std::vector<Value*> ArgList;
				ArgList.push_back(destBufferPtr);
				//IRBuilder<> InstBuilder(externalCallInst);
				//InstBuilder.CreateCall(decryptFunction, ArgList); // Bug Fix - Need to do this for unaligned buffers
				// Can't use IRBuilder, TODO - is this ok to do?
				CallInst* CInst = CallInst::Create(encryptFunction, ArgList);
				CInst->insertAfter(externalCallInst);
			}
		} else if (externalFunction->getName().find("strcasecmp") != StringRef::npos) {
            Value* destBufferPtr = externalCallInst->getArgOperand(0);
            Value* srcBufferPtr = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(srcBufferPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(srcBufferPtr);
                // Insert call instruction to call the function
                IRBuilder<> InstBuilder(externalCallInst);
                /*CallInst* CInst = */
                InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);
			}
			if (isSensitiveArg(destBufferPtr, ptsToMap)) {
				std::vector<Value*> ArgList;
				ArgList.push_back(destBufferPtr);
				IRBuilder<> InstBuilder(externalCallInst);
				InstBuilder.CreateCall(decryptFunction, ArgList); // Bug Fix - Need to do this for unaligned buffers
				// Can't use IRBuilder, TODO - is this ok to do?
				CallInst* CInst = CallInst::Create(encryptFunction, ArgList);
				CInst->insertAfter(externalCallInst);
			}
        } else if (externalFunction->getName() == "strlen") {
			Value* string1 = externalCallInst->getArgOperand(0);
			if (isSensitiveArg(string1, ptsToMap) ) {
                /*
                errs() << "Analysis says string " << *string1 << " is sensitive\n";
                for (Value* val: ptsToMap[string1]) {
                    errs() << "points to ... " << *val << "\n";
                }
                */
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(string1);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);
			}
		} else if (externalFunction->getName() == "strdup") {
            Value* string1 = externalCallInst->getArgOperand(0);
			if (isSensitiveArg(string1, ptsToMap) ) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(string1);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);
			}
            // It allocates and returns memory, is that sensitive?
            if (isSensitiveObjSet(getPAGObjNodeFromValue(externalCallInst))) {
                std::vector<Value*> ArgList;
                ArgList.push_back(externalCallInst);
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);
            }
        } else if (externalFunction->getName() == "strstr" || externalFunction->getName() == "strcasestr") {
			Value* string1 = externalCallInst->getArgOperand(0);
			Value* string2 = externalCallInst->getArgOperand(1);
			if (isSensitiveArg(string1, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(string1);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
			if (isSensitiveArg(string2, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(string2);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
        } else if (externalFunction->getName() == "crypt") {
        	Value* string1 = externalCallInst->getArgOperand(0);
			Value* string2 = externalCallInst->getArgOperand(1);
			if (isSensitiveArg(string1, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(string1);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
			if (isSensitiveArg(string2, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(string2);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}

        } else if (externalFunction->getName() == "cwd") {
            Value* buf = externalCallInst->getArgOperand(0);
            Value* bufLen = externalCallInst->getArgOperand(1);
            // The second argument might be a sensitive buffer
            if (isSensitiveArg(buf, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(buf);
                ArgList.push_back(bufLen);
                /*CallInst* CInst = */
                InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
        } else if (externalFunction->getName() == "syscall") {
                // Only support syscall getRandom at the moment. On current machine it is 318
                if (ConstantInt* syscallNumVal = dyn_cast<ConstantInt>(externalCallInst->getArgOperand(0))) {
                    IntegerType* longType = IntegerType::get(M.getContext(), 64);
                    uint64_t syscallNum = syscallNumVal->getValue().getLimitedValue();
                    if (syscallNum == 318) {
					Value* buf = externalCallInst->getArgOperand(1);
					Value* bufLen = externalCallInst->getArgOperand(2);
                    IntegerType* bufLenWidth = dyn_cast<IntegerType>(bufLen->getType());
                    assert(bufLenWidth && "Buflen should always be an integer!");
                    if (bufLenWidth->getBitWidth() != 64) {
                        // Can only extend, never truncate, as 64 bit
                        bufLen = InstBuilder.CreateSExt(bufLen, longType);
                    }
					// The second argument might be a sensitive buffer
					if (isSensitiveArg(buf, ptsToMap)) {
						Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                        Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
						std::vector<Value*> ArgList;
						ArgList.push_back(buf);
						ArgList.push_back(bufLen);
						/*CallInst* CInst = */
						InstBuilder.CreateCall(decryptFunction, ArgList);
						// Encrypt it back
						CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
						encCInst->insertAfter(externalCallInst);

					}
				} else {
					errs() << "Unsupported syscall found!\n";
					assert(false);
				}
			}
		} else if (externalFunction->getName() == "fwrite") {
			// Get the first operand
			Value* bufferPtr = externalCallInst->getArgOperand(0);
			Value* elemSize = externalCallInst->getArgOperand(1);
			Value* numElements = externalCallInst->getArgOperand(2);
			if (isSensitiveArg(bufferPtr, ptsToMap)) {
				// Insert call instruction to call the function
				Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
				Value* numBytes = InstBuilder.CreateMul(elemSize, numElements, "mul");
				std::vector<Value*> ArgList;
				ArgList.push_back(bufferPtr);
				ArgList.push_back(numBytes);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
		} else if (externalFunction->getName().find("llvm.memcpy") != StringRef::npos) {
			Value* destBufferPtr = externalCallInst->getArgOperand(0);
			Value* srcBufferPtr = externalCallInst->getArgOperand(1);
			Value* numBytes = externalCallInst->getArgOperand(2);
			// If both sensitive, or both not sensitive then do nothing
			/*
			if ((isSensitiveArg(srcBufferPtr, ptsToMap)) 
					xor (isSensitiveArg(destBufferPtr, ptsToMap))) {
					*/
				Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

				// One of them is sensitive, the other is not
				// If it is the source, then decrypt before the call to memcpy
				// If it is the destination, then decrypt after the call to memcpy

				if (isSensitiveArg(srcBufferPtr, ptsToMap)) {
					std::vector<Value*> ArgList;
					ArgList.push_back(srcBufferPtr);
					ArgList.push_back(numBytes);
					// Insert call instruction to call the function
					IRBuilder<> InstBuilder(externalCallInst);
					/*CallInst* CInst = */
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);

				} 
				if (isSensitiveArg(destBufferPtr, ptsToMap)) {
					std::vector<Value*> ArgList;
					ArgList.push_back(destBufferPtr);
					ArgList.push_back(numBytes);
                    IRBuilder<> InstBuilder(externalCallInst);
                    InstBuilder.CreateCall(decryptFunction, ArgList); // Bug Fix - Need to do this for unaligned buffers
					// Can't use IRBuilder, TODO - is this ok to do?
					CallInst* CInst = CallInst::Create(encryptFunction, ArgList);
					CInst->insertAfter(externalCallInst);
				}
				/*
			}
			*/
		} else if (externalFunction->getName() == "bzero") {
            Value *bufferPtr = externalCallInst->getArgOperand(0);
            Value *numBytes = externalCallInst->getArgOperand(1);
        	if (isSensitiveArg(bufferPtr, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
				Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
                IRBuilder<> InstBuilder(externalCallInst);
				std::vector<Value*> ArgList;
				ArgList.push_back(bufferPtr);
				ArgList.push_back(numBytes);
                InstBuilder.CreateCall(decryptFunction, ArgList); // Bug Fix - Need to do this for unaligned buffers
				CallInst* CInst = CallInst::Create(encryptFunction, ArgList);
				CInst->insertAfter(externalCallInst);
			}
        } else if (externalFunction->getName().find("memset") != StringRef::npos) {
			Value *bufferPtr = externalCallInst->getArgOperand(0);
			Value *numBytes = externalCallInst->getArgOperand(2);
			if (isSensitiveArg(bufferPtr, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
				Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
                IRBuilder<> InstBuilder(externalCallInst);
				std::vector<Value*> ArgList;
				ArgList.push_back(bufferPtr);
				ArgList.push_back(numBytes);
                InstBuilder.CreateCall(decryptFunction, ArgList); // Bug Fix - Need to do this for unaligned buffers
				CallInst* CInst = CallInst::Create(encryptFunction, ArgList);
				CInst->insertAfter(externalCallInst);
			}
		} else if (externalFunction->getName().find("llvm.memset") != StringRef::npos) {
			Value *bufferPtr = externalCallInst->getArgOperand(0);
			Value *numBytes = externalCallInst->getArgOperand(2);
			if (isSensitiveArg(bufferPtr, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
				Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
                IRBuilder<> InstBuilder(externalCallInst);
				std::vector<Value*> ArgList;
				ArgList.push_back(bufferPtr);
				ArgList.push_back(numBytes);
                InstBuilder.CreateCall(decryptFunction, ArgList); // Bug Fix - Need to do this for unaligned buffers
				CallInst* CInst = CallInst::Create(encryptFunction, ArgList);
				CInst->insertAfter(externalCallInst);
			}
		} else if (externalFunction->getName() == "read") {
			Value* bufferPtr = externalCallInst->getArgOperand(1);
			Value* numBytes = externalCallInst->getArgOperand(2);
			if (isSensitiveArg(bufferPtr, ptsToMap)) {
				Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
                Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(bufferPtr);
				ArgList.push_back(numBytes);
                InstBuilder.CreateCall(decryptFunction, ArgList);
				CallInst* CInst = CallInst::Create(encryptFunction, ArgList);
				CInst->insertAfter(externalCallInst);
			}
		} else if (externalFunction->getName() == "write") {
			Value* bufferPtr = externalCallInst->getArgOperand(1);
			Value* numBytes = externalCallInst->getArgOperand(2);
			if (isSensitiveArg(bufferPtr, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(bufferPtr);
				ArgList.push_back(numBytes);
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
		} else if (externalFunction->getName() == "bind") {
			/*Value* sockfd = externalCallInst->getArgOperand(0);*/
			Value* sockaddr = externalCallInst->getArgOperand(1);
			Value* socklen = externalCallInst->getArgOperand(2);
			//if (isSensitiveArg(sockaddr, ptsToMap)) {
				PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
				IntegerType* longType = IntegerType::get(M.getContext(), 64);
				// Convert sockaddr* to void*
				Value* voidSockaddrVal = InstBuilder.CreateBitCast(sockaddr, voidPtrType);
				Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(voidSockaddrVal);
				if (IntegerType* socklenType = dyn_cast<IntegerType>(socklen->getType())) {
					if (socklenType->getBitWidth() != 64) {
						Value* longSocklenVal = InstBuilder.CreateSExt(socklen, longType);	
						ArgList.push_back(longSocklenVal);
					} else {
						ArgList.push_back(socklen);
					}
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);
				} else {
					errs() << "Don't know what to do with non-integer type socklen.\n";
					assert(false);
				}
			//}
		} else if (externalFunction->getName() == "connect") {
			// #TODO - Check if required
		} else if (externalFunction->getName() == "getaddrinfo") {
			Value* host = externalCallInst->getArgOperand(0);
			Value* port = externalCallInst->getArgOperand(1);
			Value* addrHints = externalCallInst->getArgOperand(2);
			if (isSensitiveArg(host, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(host);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
			if (isSensitiveArg(port, ptsToMap)) {
				Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
				std::vector<Value*> ArgList;
				ArgList.push_back(port);
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
			if (isSensitiveArg(addrHints, ptsToMap)) {
				PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
				IntegerType* longType = IntegerType::get(M.getContext(), 64);

				Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
				std::vector<Value*> ArgList;
                Value* addrHintsVoidPtr= InstBuilder.CreateBitCast(addrHints, voidPtrType);
				ArgList.push_back(addrHintsVoidPtr);
				ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 48));
				/*CallInst* CInst = */
				InstBuilder.CreateCall(decryptFunction, ArgList);
				// Encrypt it back
				CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
				encCInst->insertAfter(externalCallInst);

			}
        } else if (externalFunction->getName() == "pthread_mutex_lock") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 40));
            /*CallInst* CInst = */
            InstBuilder.CreateCall(decryptFunction, ArgList);
            // Encrypt it back
            CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
            encCInst->insertAfter(externalCallInst);
        } else if (externalFunction->getName() == "pthread_mutex_lock") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 40));
            /*CallInst* CInst = */
            InstBuilder.CreateCall(decryptFunction, ArgList);
            // Encrypt it back
            CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
            encCInst->insertAfter(externalCallInst);

        } else if (externalFunction->getName() == "pthread_mutex_init") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 40));
            /*CallInst* CInst = */
            InstBuilder.CreateCall(decryptFunction, ArgList);
            // Encrypt it back
            CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
            encCInst->insertAfter(externalCallInst);
        } else if (externalFunction->getName() == "pthread_mutex_destroy") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 40));
            /*CallInst* CInst = */
            InstBuilder.CreateCall(decryptFunction, ArgList);
            // Encrypt it back
            CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
            encCInst->insertAfter(externalCallInst);
        } else if (externalFunction->getName() == "pthread_create") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            Value* pthreadTArg = externalCallInst->getArgOperand(0);
            Value* pthreadAttrTArg = externalCallInst->getArgOperand(1);
            if (isSensitiveArg(pthreadTArg, ptsToMap)) {
                std::vector<Value*> ArgList;
                Value* encryptedPtr= InstBuilder.CreateBitCast(pthreadTArg, voidPtrType);
                ArgList.push_back(encryptedPtr);
                ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 8));
                InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
            if (isSensitiveArg(pthreadAttrTArg, ptsToMap)) {
                 std::vector<Value*> ArgList;
                Value* encryptedPtr= InstBuilder.CreateBitCast(pthreadAttrTArg, voidPtrType);
                ArgList.push_back(encryptedPtr);
                ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 56));
                InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
        } else if (externalFunction->getName() == "readdir" || externalFunction->getName() == "clonereaddir") {
            Value* dirp = externalCallInst->getArgOperand(0);
            if (isSensitiveArg(dirp, ptsToMap)) {
                int dirpSize = getCompositeSzValue(dirp, M);
                Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

                std::vector<Value*> ArgList;
                ArgList.push_back(dirp);
                ArgList.push_back(
                        ConstantInt::get(
                            IntegerType::get(externalCallInst->getContext(), 64), 
                            dirpSize
                            )
                        );
                InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
            if (isSensitiveObjSet(getPAGObjNodeFromValue(externalCallInst))) {
                int direntSize = getCompositeSzValue(externalCallInst, M);
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");


                PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
                IntegerType* longType = IntegerType::get(M.getContext(), 64);

                CastInst* castInst = BitCastInst::CreateBitOrPointerCast(externalCallInst, voidPtrType);
                castInst->insertAfter(externalCallInst);

                std::vector<Value*> ArgList;
                ArgList.push_back(castInst);
                ArgList.push_back(
                        ConstantInt::get(
                            IntegerType::get(externalCallInst->getContext(), 64), 
                            direntSize
                            )
                        );
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(castInst);
            }
        } /* else if (externalFunction->getName() == "pthread_setspecific") {
            // int pthread_setspecific(pthread_key_t, const void *value); --> the pthread_key_t is just an integer
            // so only the void* value can be sensitive, it's size is tricky to find
            Value* voidPtrValue = externalCallInst->getArgOperand(1);
            if (isSensitiveArg(voidPtrValue, ptsToMap)) {
                int voidMemObjSize = getSzVoidArgVal(voidPtrValue, M);

                errs() << "For external pthread_setspecific call " << *externalCallInst << " in function " << externalCallInst->getParent()->getParent()->getName() << ", size = " << voidMemObjSize << "\n";
                if (voidMemObjSize == -1) {
                    Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                    Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                     std::vector<Value*> ArgList;
                    ArgList.push_back(externalCallInst->getArgOperand(1));
                    InstBuilder.CreateCall(decryptFunction, ArgList);
                    // Encrypt it back
                    CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                    encCInst->insertAfter(externalCallInst);

                } else {
                    Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                    Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

                    std::vector<Value*> ArgList;
                    ArgList.push_back(externalCallInst->getArgOperand(1));
                    ArgList.push_back(
                            ConstantInt::get(
                                IntegerType::get(externalCallInst->getContext(), 64), 
                                voidMemObjSize 
                                )
                            );
                    InstBuilder.CreateCall(decryptFunction, ArgList);
                    // Encrypt it back
                    CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                    encCInst->insertAfter(externalCallInst);
                }
            }
        } else if (externalFunction->getName() == "pthread_getspecific") {
            Value* voidPtrValue = externalCallInst; // The return value
            int voidMemObjSize = getSzVoidRetVal(voidPtrValue, M);
            errs() << "For external pthread_setspecific call " << *externalCallInst << " in function " << externalCallInst->getParent()->getParent()->getName() << ", size = " << voidMemObjSize << "\n";
            if (voidMemObjSize == -1) {
                Function* instrumentFunction = M.getFunction("encryptStringAfterLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(externalCallInst);
                CallInst* CInst = CallInst::Create(instrumentFunction, ArgList);
                CInst->insertAfter(externalCallInst);
            } else {
                Function* instrumentFunction = M.getFunction("encryptArrayForLibCall");
                std::vector<Value*> ArgList;

                ArgList.push_back(externalCallInst);
                ArgList.push_back(
                            ConstantInt::get(
                                IntegerType::get(externalCallInst->getContext(), 64), 
                                voidMemObjSize 
                                )
                            );
                // Insert call instruction to call the function
                CallInst* CInst = CallInst::Create(instrumentFunction, ArgList);
                CInst->insertAfter(externalCallInst);
            }
        } */
        else if (externalFunction->getName() == "epoll_ctl") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(3), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 12));
            /*CallInst* CInst = */
            InstBuilder.CreateCall(decryptFunction, ArgList);
            // Encrypt it back
            CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
            encCInst->insertAfter(externalCallInst);
        } else if (externalFunction->getName() == "epoll_wait") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(1), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 12));
            /*CallInst* CInst = */
            InstBuilder.CreateCall(decryptFunction, ArgList);
            // Encrypt it back
            CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
            encCInst->insertAfter(externalCallInst);
        } else if (externalFunction->getName() == "uname") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 390));
            /*CallInst* CInst = */
            InstBuilder.CreateCall(decryptFunction, ArgList);
            // Encrypt it back
            CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
            encCInst->insertAfter(externalCallInst);

        } else if (externalFunction->getName() == "mk_string_build") {
			// Variable arg number
			int argNum = externalCallInst->getNumArgOperands();
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
                     
            //char *mk_string_build(char **buffer, unsigned long *len, const char *format, ...);
            Value* returnBufPtr = externalCallInst;
            if (isSensitiveArg(returnBufPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                if (returnBufPtr->getType() != voidPtrType) {
                    returnBufPtr = InstBuilder.CreateBitCast(returnBufPtr, voidPtrType);
                }
                ArgList.push_back(returnBufPtr);
                // Encrypt it back
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);

            }
			for (int i = 2; i < argNum; i++) {
				// has varargs
				Value* arg = externalCallInst->getArgOperand(i);
				if (isSensitiveArg(arg, ptsToMap)) {
					Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
					std::vector<Value*> ArgList;
                    if (arg->getType() != voidPtrType) {
                        arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                    }
					ArgList.push_back(arg);
					/*CallInst* CInst = */
					InstBuilder.CreateCall(decryptFunction, ArgList);
					// Encrypt it back
					Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
					CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
					encCInst->insertAfter(externalCallInst);
				}
			}
		} else {
			UnsupportedCallSet.insert(externalCallInst);
			//errs() << "Unsupported external function: "<<externalFunction->getName() << "\n";
			//assert(false);
		}
		// Add instructions after the externalCallInst
		/*	
		for (Value* sensitivePtrVal: sensitivePointerValueList) {
			// XOR and store
			Value* XORInt = ConstantInt::get(longTy, 0xAAAAAAAAAAAAAAAA, true);
			PtrToIntInst* intValOfPtr = new PtrToIntInst(sensitivePtrVal, longTy);
			intValOfPtr->insertAfter(externalCallInst);

			BinaryOperator* XOROp = BinaryOperator::CreateXor(intValOfPtr, XORInt);
			XOROp->insertAfter(intValOfPtr);
			Value* destPtr = SensitivePtrValMap[sensitivePtrVal];
			if (XOROp->getType() != destPtr->getType()) {
				IntToPtrInst* XORPtr = new IntToPtrInst(XOROp, destPtr->getType()->getPointerElementType());
				XORPtr->insertAfter(XOROp);
				StoreInst* StInst = new StoreInst(XORPtr, destPtr);
				StInst->insertAfter(XORPtr);
			} else {
				StoreInst* StInst = new StoreInst(XOROp, destPtr);
				StInst->insertAfter(XOROp);
			}
		}
		*/
	}
	errs() << "Unsupported Sensitive External Function: \n";
	std::set<Function*> unsupFns;
	for (Value* unsupportedCall: UnsupportedCallSet) {
		CallInst* CInst = dyn_cast<CallInst>(unsupportedCall);
		//dbgs() << "Function call: "<< CInst->getCalledFunction()->getName() << " ";
        if (CInst->getCalledFunction()) {
		    unsupFns.insert(CInst->getCalledFunction());
        } else {
            for (PAGNode* fnNode: ptsToMap[getPAGObjNodeFromValue(CInst->getCalledValue())]) {
                Value* fn = const_cast<Value*>(fnNode->getValue());
                if (Function* realFn = dyn_cast<Function>(fn)) {
                    unsupFns.insert(realFn);
                }
            }
        }
		/*
		for (int i = 0; i < CInst->getNumArgOperands(); i++) {
			Value* argVal = CInst->getArgOperand(i);
			argVal->dump();
		}
		*/
	}
	for (Function* fn: unsupFns) {
        if (fn->getName() == "realloc") {
            dbgs() << "Function: " << fn->getName() << ", can probably do without instrumentation\n";
        } else {
		    dbgs() << "Function: " << fn->getName() << "\n";
        }
	}

    // TODO - Handle ASM calls correctly. Right now only deal with the fd_set call
    for (Value* asmVal: SensitiveInlineAsmCalls) {
        CallInst* inlineAsmCall = dyn_cast<CallInst>(asmVal);
    	PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);

        IRBuilder<> InstBuilder(inlineAsmCall);
        if (inlineAsmCall->getNumArgOperands() < 3) {
            continue;
        }
        Value* sensitiveArg = inlineAsmCall->getOperand(2);
        Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
        Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
        std::vector<Value*> ArgList;
        if (sensitiveArg->getType() != voidPtrType) {
            Value* voidArgVal = InstBuilder.CreateBitCast(sensitiveArg, voidPtrType);
            ArgList.push_back(voidArgVal);
        } else {
            ArgList.push_back(sensitiveArg);
        }
        ArgList.push_back(ConstantInt::get(IntegerType::get(inlineAsmCall->getContext(), 64), 128));
        InstBuilder.CreateCall(decryptFunction, ArgList);
        // Encrypt it back
        CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
        encCInst->insertAfter(inlineAsmCall);
        break; // TODO - Should be only one!
    }
}

/**
 * The routine that instruments and annotates the sensitive Alloca, Load and Store instructions
 * with the encryption/decryption logic and adds the metadata that tells the CodeGen to protect
 * the sensitive virtual registers during Register spills
 */
void EncryptionPass::instrumentAndAnnotateInst(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
	// For each function ... 
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			// For each function
			resetInstructionLists(F);
			// Mark all the Load instructions that need to be instrumented
			for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
				if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
					for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
						if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
							if (isa<LoadInst>(Inst) || isa<AllocaInst>(Inst)) {
								preprocessAllocaAndLoadInstructions(Inst);
							} else if (isa<StoreInst>(Inst)) {
								preprocessStoreInstructions(Inst);
							}
						}
					}
				}
			}

			performInstrumentation(M, ptsToMap);
			resetInstructionLists(F);	
		}
	}

	//instrumentInlineAsm(M);
	instrumentExternalFunctionCall(M, ptsToMap);
}

void EncryptionPass::fixupBrokenFunctionCallsFromWidening(Module &M) {
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
				if (CallInst* callInst = dyn_cast<CallInst>(&(*I))) {
					for (int i = 0; i < callInst->getNumArgOperands(); i++) {
						Value* arg = callInst->getArgOperand(i);
						if (PointerType* valPtrTy = dyn_cast<PointerType>(arg->getType())) {
							IntegerType* valPtrIntTy = dyn_cast<IntegerType>(valPtrTy->getPointerElementType());
							if (valPtrIntTy) {
							 	if (valPtrIntTy->getBitWidth() == 128) {

									Function* f = callInst->getCalledFunction();
									Type* paramType = f->getFunctionType()->getParamType(i);
									// TODO - handle getCalledValue() for function pointers
									// Create a bitcast and pass that as the argument
									IRBuilder<> Builder(callInst);
									Value* bcVal = Builder.CreateBitCast(arg, paramType);
									for (User* U: arg->users()) {
										if (U != bcVal) {
											int i, NumOperands = U->getNumOperands();
											for (i = 0; i < NumOperands; i++) {
												if (U->getOperand(i) == arg) {
													U->setOperand(i, bcVal);
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
}

void EncryptionPass::initializeSensitiveGlobalVariables(Module& M) {

	// Add the extern function
	// Build the signature of the function
	PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
	IntegerType* longType = IntegerType::get(M.getContext(), 64);


	std::vector<Type*> typeVec;
	typeVec.push_back(voidPtrType);
	typeVec.push_back(longType);
	ArrayRef<Type*> paramArgArray(typeVec);

    std::vector<Type*> nullVec;
    ArrayRef<Type*> nullArray(nullVec);

	FunctionType* FTypeDec = FunctionType::get(IntegerType::get(M.getContext(), 64), paramArgArray, false);
    FunctionType* FTypePopKey = FunctionType::get(Type::getVoidTy(M.getContext()), nullArray, false);

	Function* EncryptGlobalFunction = Function::Create(FTypeDec, Function::ExternalLinkage, "encrypt_globals", &M);
    Function* PopulateKeysFunction = Function::Create(FTypePopKey, Function::ExternalLinkage, "populate_keys", &M);

	DataLayout dataLayout = M.getDataLayout();
	// Find the main function
    std::string entryFunctions[] = {"main"};
    Function* mainFunction = nullptr;
    for (std::string entryFunction: entryFunctions) {
        if (M.getFunction(entryFunction)) {
            mainFunction = M.getFunction(entryFunction);
        }
    }
	Instruction* insertionPoint = nullptr;

	if (!mainFunction) {
		errs() << "Library mode.\n";
        return;
	}

	// Find the insertion point in the main function
	for (inst_iterator I = inst_begin(*mainFunction), E = inst_end(*mainFunction); I != E; ++I) {
		Instruction* inst = &*I;
		insertionPoint = inst;
		if (!isa<AllocaInst>(inst)) {
			break;
		}
	}

	IRBuilder<> Builder(insertionPoint);

    // Populate the keys
    std::vector<Value*> EmptyArgs;
    Builder.CreateCall(PopulateKeysFunction, EmptyArgs);

    std::set<PAGNode*> workSet;
    std::set<PAGNode*> gepWorkSet;

    for (PAGNode* sensitiveObjNode: *SensitiveObjSet) {
        if (ObjPN* objNode = dyn_cast<ObjPN>(sensitiveObjNode)) {
            if (!isa<GepObjPN>(objNode)) {
                workSet.insert(objNode);
            }
        }
    }

    for (PAGNode* sensitiveObjNode: *SensitiveObjSet) {
        if (ObjPN* objNode = dyn_cast<ObjPN>(sensitiveObjNode)) {
            if (GepObjPN* gepNode = dyn_cast<GepObjPN>(objNode)) {
                // Check if it's not there already
                bool doInsert = true;
                for (PAGNode* fINode: workSet) {
                    if (fINode->getValue() == gepNode->getValue()) {
                        doInsert = false;
                    }
                }
                if (doInsert) {
                    gepWorkSet.insert(objNode);
                }
            }
        }
    }

    workSet.insert(gepWorkSet.begin(), gepWorkSet.end());

	for (PAGNode* sensitiveObjNode: workSet) {
       
        Value* sensitiveObj = const_cast<Value*>(sensitiveObjNode->getValue());
        Value* gVar = nullptr;
        if (isa<GlobalVariable>(sensitiveObj) || 
                (isa<Constant>(sensitiveObj) && !isa<Function>(sensitiveObj))) {
            gVar = sensitiveObj;
        }
		if (gVar) {
            if (GlobalVariable* gVar2 = dyn_cast<GlobalVariable>(gVar)) {
                StringRef sectionNameSRef = gVar2->getSection();
                StringRef metadataSRef("llvm.metadata");
                if (metadataSRef.equals(sectionNameSRef)) {
                    continue;
                }
            }

            Value* sensitiveValue = nullptr;
            bool handled = false;
            if (GepObjPN* gepObjNode = dyn_cast<GepObjPN>(sensitiveObjNode)) {
                if (isa<StructType>(sensitiveObjNode->getValue()->getType())) {
                    assert(gepObjNode->getLocationSet().isConstantOffset() && "Can't handle global sensitive arrays with partial sensitivity yet!");
                    int offset = gepObjNode->getLocationSet().getOffset();
                    // Create a gep
                    std::vector<Value*> IdxVec;
                    IdxVec.push_back(ConstantInt::get(IntegerType::get(gVar->getContext(), 32), 0));
                    IdxVec.push_back(ConstantInt::get(IntegerType::get(gVar->getContext(), 32), offset));
                    ArrayRef<Value*> IdxArrRef(IdxVec);

                    sensitiveValue = Builder.CreateGEP(gVar, IdxArrRef);
                    handled = true;
                }
            } 
            if (!handled) {
                sensitiveValue = gVar;
            }
            
            //Value* bcVal = Builder.CreateBitCast(sensitiveValue, voidPtrType);
			PointerType* globalTypePtr = dyn_cast<PointerType>(sensitiveValue->getType());
			assert(globalTypePtr);
            if (sensitiveValue->getType() != voidPtrType) {
                sensitiveValue = Builder.CreateBitCast(sensitiveValue, voidPtrType);
            }
            Type* globalType = globalTypePtr->getPointerElementType();
			uint64_t sizeOfGlobalType = dataLayout.getTypeAllocSize(globalType);
			ConstantInt* sizeOfConstant = ConstantInt::get(longType, sizeOfGlobalType, false);
			// Send it off to encryptGlobal routine to encrypt
			std::vector<Value*> encryptGlobalArgs;
			encryptGlobalArgs.push_back(sensitiveValue);
		        encryptGlobalArgs.push_back(sizeOfConstant);
			Value* result = Builder.CreateCall(EncryptGlobalFunction, encryptGlobalArgs);	
		}
	}
}

void EncryptionPass::buildSets(Module &M) {
	SensitiveObjSet = new std::set<PAGNode*>(SensitiveObjList.begin(), SensitiveObjList.end());
	SensitiveLoadPtrSet = new std::set<Value*>(SensitiveLoadPtrList.begin(), SensitiveLoadPtrList.end()); // Any pointer that points to sensitive location
	SensitiveLoadSet = new std::set<Value*>(SensitiveLoadList.begin(), SensitiveLoadList.end());
	SensitiveGEPPtrSet = new std::set<Value*>(SensitiveGEPPtrList.begin(), SensitiveGEPPtrList.end());
}

void EncryptionPass::unConstantifySensitiveAllocSites(Module &M) {
    for (PAGNode* senNode: SensitiveObjList) {
        assert(senNode->hasValue() && "If a PAG node made it so far, it must have a LLVM Value!");
        Value* sensitiveAllocSite = const_cast<Value*>(senNode->getValue());
		if (GlobalVariable* gVar = dyn_cast<GlobalVariable>(sensitiveAllocSite)) {
			if (gVar->isConstant()) {
				gVar->setConstant(false);
			}
		}
	}
}

/*
void EncryptionPass::addExternInlineASMHandlers(Module &M) {
	std::string FunctionNameDec = "decryptInMem";

	// Build the signature of the function
	PointerType* intPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
	IntegerType* intType = IntegerType::get(M.getContext(), 64);

	std::vector<Type*> typeVec;
	typeVec.push_back(intPtrType);
	typeVec.push_back(intType);
	ArrayRef<Type*> paramArgArray(typeVec);

	FunctionType* FTypeDec = FunctionType::get(Type::getVoidTy(M.getContext()), paramArgArray, false);
	Function* decryptInMemFunction = Function::Create(FTypeDec, Function::ExternalLinkage, FunctionNameDec, &M);

	std::string FunctionNameEnc = "encryptInMem";
	// Build the signature of the function
	FunctionType* FTypeEnc = FunctionType::get(Type::getVoidTy(M.getContext()), paramArgArray, false);
	Function* encryptInMemFunction = Function::Create(FTypeEnc, Function::ExternalLinkage, FunctionNameEnc, &M);

}
*/

Type* EncryptionPass::findTrueType(Type* topLevelType0, int topLevelOffset, int beginOffset) {
    StructType* topLevelType = dyn_cast<StructType>(topLevelType0);
    assert(topLevelType && "Top level type is not a struct!\n");
    for (int i = 0; i < topLevelType->getNumElements(); i++) {
        Type* subType = topLevelType->getElementType(i);
        if (beginOffset == topLevelOffset) {
            return subType;
        }
        if (StructType* stSubType = dyn_cast<StructType>(subType)) {
            return findTrueType(stSubType, topLevelOffset, beginOffset);
        }
        beginOffset++;
    }
}

void EncryptionPass::preprocessSensitiveAnnotatedPointers(Module &M) {
	std::map<PAGNode*, std::set<PAGNode*>> ptsToMap = getAnalysis<WPAPass>().getPAGPtsToMap();
    std::map<PAGNode*, std::set<PAGNode*>> ptsFromMap = getAnalysis<WPAPass>().getPAGPtsFromMap();
    PAG* pag = getAnalysis<WPAPass>().getPAG();
    ConstraintGraph* constraintGraph = getAnalysis<WPAPass>().getConstraintGraph();

    std::vector<PAGNode*> workList;
    std::vector<PAGNode*> processedList;

    for (PAGNode* initSensitiveNode: SensitiveObjList) {
        assert(initSensitiveNode->hasValue() && "PAG Node should have a value if it came so far");
        workList.push_back(initSensitiveNode);
    }

    while (!workList.empty()) {
        PAGNode* work = workList.back();
        workList.pop_back();
        if (std::find(processedList.begin(), processedList.end(), work) != processedList.end()) {
            continue;
        }
        processedList.push_back(work);
        // Add whatever this node points to the worklist
        std::copy(ptsToMap[work].begin(), ptsToMap[work].end(), std::back_inserter(workList));
        std::copy(ptsToMap[work].begin(), ptsToMap[work].end(), std::back_inserter(SensitiveObjList));

        if (!isa<ObjPN>(work)) 
            continue;
        // And Child Nodes, and who ever they point to 
        NodeBS nodeBS = constraintGraph->getAllFieldsObjNode(work->getId());

        for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
            // And everything they point to

            PAGNode* fldNode = pag->getPAGNode(*fIt);
            if (isa<GepObjPN>(fldNode)) {
                SensitiveObjList.push_back(fldNode); // Individual fields of the Sensitive object is also sensitive
            }
            std::copy(ptsToMap[fldNode].begin(), ptsToMap[fldNode].end(), std::back_inserter(workList));
            std::copy(ptsToMap[fldNode].begin(), ptsToMap[fldNode].end(), std::back_inserter(SensitiveObjList));
        }

    }

    // Remove all top-level pointers in SensitiveObjList

    std::vector<PAGNode*>::iterator it = SensitiveObjList.begin();
    while (it != SensitiveObjList.end()) {
        PAGNode* sensitiveNode = *it;
        assert(sensitiveNode->hasValue() && "PAG node made it so far, must have value");
        Value* sensitiveValue = const_cast<Value*>(sensitiveNode->getValue());
        if (isaCPointer(sensitiveValue) || isa<CastInst>(sensitiveValue)) {
            it = SensitiveObjList.erase(it);
        } else {
            it++;
        }
    }
}

/*
void EncryptionPass::collectVoidDataObjects(Module &M) {
	// Do Alias Analysis for pointers
	std::map<llvm::Value*, std::set<llvm::Value*>> ptsToMap = getAnalysis<WPAPass>().getPtsToMap();
	std::map<llvm::Value*, std::set<llvm::Value*>> ptsFromMap = getAnalysis<WPAPass>().getPtsFromMap();

	// Find all InlineAsm instructions in the program and decrypt the sensitive operands
	for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
		if (auto *F = dyn_cast<Function>(MIterator)) {
			// Iterate over all instructions in the Function to build the Instruction list
			for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
				CallInst* cInst = dyn_cast<CallInst>(&*I);
				if (cInst) {
                    if (Function* fun = cInst->getCalledFunction()) {
                        if (fun->getName() == "pthread_getspecific") {
                            SensitiveObjList.push_back(cInst);
                        } else if (fun->getName() == "pthread_setspecific") {
                            Value* valuePtr = cInst->getArgOperand(1);
                            for (Value* valueObj: ptsToMap[valuePtr]) {
                                SensitiveObjList.push_back(valueObj);
                            }
                        } else if (fun->getName() == "epoll_ctl") {
                            // Anything that the epoll_event pointer can point to 
                            // should be treated as sensitive because we don't have any idea
                            // when we get it back from epoll library
                            Value* valuePtr = cInst->getArgOperand(3);
                            for (Value* valueObj: ptsToMap[valuePtr]) {
                                SensitiveObjList.push_back(valueObj);
                            }
                        } else if (fun->getName() == "epoll_wait") {
                            // Ditto as epoll_ctl
                            Value* valuePtr = cInst->getArgOperand(1);
                            for (Value* valueObj: ptsToMap[valuePtr]) {
                                SensitiveObjList.push_back(valueObj);
                            }
                        }
                    }
                }
            }
        }
    }
}
*/

void EncryptionPass::fixupSizeOfOperators(Module& M) {
    std::map<std::string, StructType*> structNameTypeMap;
    (const_cast<DataLayout&>(M.getDataLayout())).clear2();
    for (StructType* stType: M.getIdentifiedStructTypes()) {
        structNameTypeMap[stType->getName()] = stType;
    }
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            // Get the local sensitive values
            for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                    //outs() << "Basic block found, name : " << BB->getName() << "\n";
                    for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                        if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                            /*
                            if (StoreInst* SI = dyn_cast<StoreInst>(Inst)) {
                                if (ConstantInt* constInt = dyn_cast<ConstantInt>(SI->getValueOperand())) {
                                    MDNode* numElNode = SI->getMetadata("NUMEL");
                                    MDNode* sizeOfTypeNode = SI->getMetadata("TYPE");
                                    if (numElNode && sizeOfTypeNode) {
                                        MDString* numElNodeStr = cast<MDString>(numElNode->getOperand(0));
                                        MDString* sizeOfTypeNameStr = cast<MDString>(sizeOfTypeNode->getOperand(0));
                                        Type* sizeOfType = SI->getParent()->getParent()->getParent()->getTypeByName(sizeOfTypeNameStr->getString());
                                        int numEl = std::stoi(numElNodeStr->getString());
                                        int updatedSize = M.getDataLayout().getTypeAllocSize(sizeOfType);
                                        ConstantInt* updatedSizeConst = ConstantInt::get(IntegerType::get(M.getContext(), constInt->getBitWidth()), updatedSize*numEl);
                                        SI->setOperand(0, updatedSizeConst);

                                    }
                                }
                            } else */
                            if (CallInst* CI = dyn_cast<CallInst>(Inst)) {
                                MDNode* argIndNode = CI->getMetadata("sizeOfTypeArgNum");
                                MDNode* sizeOfTypeNode = CI->getMetadata("sizeOfTypeName");
                                if (argIndNode && sizeOfTypeNode) {
                                    MDString* argIndexStr = cast<MDString>(argIndNode->getOperand(0));
                                    MDString* sizeOfTypeNameStr = cast<MDString>(sizeOfTypeNode->getOperand(0));
                                    int argIndex = std::stoi(argIndexStr->getString());
                                    Type* sizeOfType = structNameTypeMap[sizeOfTypeNameStr->getString()];
                                    if (!sizeOfType) {
                                        sizeOfType = structNameTypeMap["struct."+sizeOfTypeNameStr->getString().str()];
                                        if (!sizeOfType) {
                                            assert(false && "Cannot find sizeof type");
                                        }
                                    }

                                    errs() << "Should have fixed up callinst: " << *CI << " for type : " << *(sizeOfType) << "\n";
                                    ConstantInt* constInt = dyn_cast<ConstantInt>(CI->getOperand(argIndex));
                                    assert(constInt && "Broken index of sizeof constant in call instruction");
                                    int updatedSize = M.getDataLayout().getTypeAllocSize(sizeOfType);
                                    errs() << "New size = " << updatedSize << "\n";
                                    ConstantInt* updatedSizeConst = ConstantInt::get(IntegerType::get(M.getContext(), constInt->getBitWidth()), updatedSize);
                                    CI->setOperand(argIndex, updatedSizeConst);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

bool EncryptionPass::runOnModule(Module &M) {

    //M.print(errs(), nullptr);
	LLVM_DEBUG (
	dbgs() << "Running Encryption pass\n";
	);

    SensitiveObjSet = nullptr;

	DoAESEncCache = true;
    // Do Alias Analysis for pointers
    getAnalysis<WPAPass>().buildResultMaps();
	std::map<PAGNode*, std::set<PAGNode*>> ptsToMap = getAnalysis<WPAPass>().getPAGPtsToMap();
	std::map<PAGNode*, std::set<PAGNode*>> ptsFromMap = getAnalysis<WPAPass>().getPAGPtsFromMap();

   	dbgs() << "Performed Pointer Analysis\n";

    collectGlobalSensitiveAnnotations(M);
    collectLocalSensitiveAnnotations(M);
    LLVM_DEBUG (
            dbgs() << "Collected sensitive annotations\n";


	for (PAGNode* valNode: SensitiveObjList) {
        assert(valNode->hasValue() && "PAG Node made it so far must have value");
		valNode->getValue()->dump();
	}
	);

    // Remove the annotation instruction because it causes a lot of headache later on
	removeAnnotateInstruction(M);

    preprocessSensitiveAnnotatedPointers(M);
    errs() << "After nested points-to analysis:\n";
    for (PAGNode* senPAGNode: SensitiveObjList) {
        errs() << *senPAGNode << "\n";
        if (GepObjPN* gepNode = dyn_cast<GepObjPN>(senPAGNode)) {
            errs() << "Location: " << gepNode->getLocationSet().getOffset() << "\n";
        }
    }
	

    errs() << "Begin: Perform dataflow analysis\n";

    //if (!SkipVFA) {
    //performSourceSinkAnalysis(M);
    //}

    // Remove duplicates and copy back to SensitiveObjList
	SensitiveObjSet = new std::set<PAGNode*>(SensitiveObjList.begin(), SensitiveObjList.end());
    SensitiveObjList.clear();
    std::copy(SensitiveObjSet->begin(), SensitiveObjSet->end(), std::back_inserter(SensitiveObjList));

    errs() << "End: Perform dataflow analysis: " << SensitiveObjList.size() << " memory objects found\n";
	// Populate the sensitive data types now
	
    for (PAGNode* senPAGNode: SensitiveObjList) {
        errs() << *senPAGNode << "\n";
    }
	
	collectSensitivePointsToInfo(M, ptsToMap, ptsFromMap);

    /*
	dbgs() << "Collected sensitive points-to info (Phase 1) \n";
	LLVM_DEBUG (

	for (PAGNode* sensitivePAGNode: SensitiveObjList) {
		dbgs() << "Sensitive Allocation site: " << *sensitivePAGNode << "\n";
        if (GepObjPN* senGep = dyn_cast<GepObjPN>(sensitivePAGNode)) {
            dbgs() << "Gep offset: " << senGep->getLocationSet().getOffset() << "\n";
            
        }
	}

	);
    */

    if (SensitiveObjSet) {
        delete(SensitiveObjSet);
    }
	SensitiveObjSet = new std::set<PAGNode*>(SensitiveObjList.begin(), SensitiveObjList.end());
    errs() << "Total sensitive allocation sites: " << SensitiveObjSet->size() << "\n";

    for (PAGNode* sensitivePAGNode: *SensitiveObjSet) {
        errs() <<  *sensitivePAGNode << "\n";
        if (GepObjPN* senGep = dyn_cast<GepObjPN>(sensitivePAGNode)) {
            errs() << "Gep offset: " << senGep->getLocationSet().getOffset() << "\n";
            /*
            int Field = senGep->getLocationSet().getOffset();
            Type* baseType = senGep->getValue()->getType();
            if (StructType* stBaseType = dyn_cast<StructType>(baseType)) {
                if (Field < stBaseType->getNumElements()) {
                    dbgs() << "Best guess sub type: " << stBaseType->getElementType(Field) << "\n";
                }

            }
            */
        }
    }

	if (DoAESEncCache) {
		AESCache.initializeAes(M);
		AESCache.widenSensitiveAllocationSites(M, SensitiveObjList, ptsToMap, ptsFromMap);
		dbgs() << "Initialized AES, widened buffers to multiples of 128 bits\n";
	}

	unConstantifySensitiveAllocSites(M);

	//addExternInlineASMHandlers(M);

	initializeSensitiveGlobalVariables(M);

	collectSensitiveGEPInstructions(M, ptsToMap);

	SensitiveGEPPtrSet = new std::set<Value*>(SensitiveGEPPtrList.begin(), SensitiveGEPPtrList.end());

	dbgs() << "Collected sensitive GEP instructions\n";

	collectSensitiveLoadInstructions(M, ptsToMap);

    collectSensitiveGEPInstructionsFromLoad(M, ptsToMap);

	SensitiveLoadPtrSet = new std::set<Value*>(SensitiveLoadPtrList.begin(), SensitiveLoadPtrList.end()); // Any pointer that points to sensitive location
	SensitiveLoadSet = new std::set<Value*>(SensitiveLoadList.begin(), SensitiveLoadList.end());

	//collectSensitiveAsmInstructions(M, ptsToMap);

	dbgs() << "Collected sensitive load instructions\n";

	collectSensitiveExternalLibraryCalls(M, ptsToMap);

	dbgs() << "Collected sensitive External Library calls\n";

	// Build the sets, now that we have the lists
	buildSets(M);

    
    ExtLibHandler.addNullExtFuncHandler(M);
    ExtLibHandler.addAESCacheExtFuncHandler(M);

    //}

	LLVM_DEBUG (
	dbgs() << "Instrumented external function calls\n";
	);

	instrumentAndAnnotateInst(M, ptsToMap);
	LLVM_DEBUG (
	dbgs() << "Instrumented and annotated sensitive Load and Store instructions\n";
	);

   
    fixupSizeOfOperators(M);

    dbgs () << "Inserted " << decryptionCount << " calls to decryption routines.\n";
    dbgs () << "Inserted " << encryptionCount << " calls to encryption routines.\n";

    collectLoadStoreStats(M);
	return true;
}

INITIALIZE_PASS_BEGIN(EncryptionPass, "encryption", "Identify and instrument sensitive variables", false, true)
//INITIALIZE_PASS_DEPENDENCY(LibcTransformPass);
INITIALIZE_PASS_DEPENDENCY(WPAPass);
INITIALIZE_PASS_END(EncryptionPass, "encryption", "Identify and instrument sensitive variables", false, true)

ModulePass* llvm::createEncryptionPass() { return new EncryptionPass(); }


