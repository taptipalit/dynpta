#include "EncryptionInternal.h"
#include "ExtLibraryHandler.h"
#include "AES.h"
#include "HMAC.h"
#include "ASMParser.h"
#include "llvm/Support/Format.h"
#include <llvm/IR/Metadata.h>
#include "llvm/Analysis/LoopInfo.h"
#include <llvm/Transforms/Utils/Cloning.h>
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Constants.h"

#define DEBUG_TYPE "encryption"

#define STORE 1
#define LOAD 2

using namespace llvm;

namespace {
cl::opt<bool> skipVFA("skip-vfa", cl::desc("Skip VFA: debug purposes only"), cl::init(true), cl::Hidden);
cl::opt<int> perLoopHoistLimit("per-loop-hoist-limit", cl::desc("How many individual base memory taint checks can be hoisted per loop"), cl::init(2), cl::Hidden);

    struct InstructionReplacement {
        Instruction* OldInstruction;
        Instruction* NextInstruction;
        int Type;
    };
    static const char* CallocLikeFunctions[] = {"aes_calloc", "calloc", "pthread_getspecific", /*"asprintf", "asprintf128",*/ "cloneenv", "aes_strdup", "mmap", "posix_memalign", "readdir", "clonereaddir", nullptr};
    class EncryptionPass : public ModulePass {
        public:
            //boolpartitioning = false;
            static char ID;

            static const int SPECIALIZE_THRESHOLD = 50;

            int sensitiveValueFlows;
            EncryptionPass() : ModulePass(ID) {
                loadStatCount = 0;
                storeStatCount = 0;
                decStatCount = 0;
                encStatCount = 0;
                sensitiveValueFlows = 0;
                initializeEncryptionPassPass(*PassRegistry::getPassRegistry());
            }

            std::set<Value*> ExtraSensitivePtrs;
            std::vector<string> instrumentedExternalFunctions;

            void addTaintMetaData(Instruction* Inst) {
                if (!skipVFA) {
                    LLVMContext& C = Inst->getContext();
                    MDNode* N = MDNode::get(C, MDString::get(C, "maybe-taint"));
                    Inst->setMetadata("MAYBE-TAINT", N);
                }
            }

            void doVFADirect(Value* work, std::vector<Value*>& sinkSites,
                    std::vector<Value*>& workList, std::vector<Value*>& processedList);

            void doVFAIndirect(Value* work, std::vector<Value*>& sinkSites,
                    std::vector<Value*>& workList, std::vector<Value*>& processedList);


            void handleSink(Value* storePtr, std::vector<Value*>& sinkSites,
                    std::vector<Value*>& workList, std::vector<Value*>& processedList);
            long checkAuthenticationCount;
            long computeAuthenticationCount;

            void collectLoadStoreStats(Module&);

            bool runOnModule(Module &M) override;

        private:

            Module* mod;

            long loadStatCount;
            long storeStatCount;

            long decStatCount;
            long encStatCount;

            external::ExtLibraryHandler ExtLibHandler;
            external::AESCache AESCache;
            external::HMAC HMAC;
            external::ASMParser asmParser;


            std::set<Function*> writebackCacheFunctions;

            /* Hacky code to handle function pointers */
            std::vector<Function*> MallocFunctions;

            std::set<llvm::Function*> CriticalFreeWrapperFunctions;

            std::vector<Instruction*> InstructionList;
            std::vector<InstructionReplacement*> ReplacementList; // Avoid messing up things while the iterators are running
            std::vector<InstructionReplacement*> ReplacementCheckList;

            std::vector<PAGNode*> SensitiveObjList; // We maintain the PAGNodes here to record field sensitivity
            std::set<PAGNode*> InitSensitiveTaintedObjSet;


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

            //Lists needed for adding check for Partitioning
            std::vector<Value*> SensitiveLoadPtrCheckList;
            std::vector<Value*> SensitiveLoadCheckList;
            std::vector<Value*> SensitiveGEPPtrCheckList;

            //Sets needed for adding check for Partitioning
            std::set<Value*>* SensitiveLoadPtrCheckSet;
            std::set<Value*>* SensitiveLoadCheckSet;
            std::set<Value*>* SensitiveGEPPtrCheckSet;


            std::map<Value*, Value*> SensitivePtrValMap;

            std::vector<StoreInst*> SensitiveStoreList;
            std::set<StoreInst*>* SensitiveStoreSet;

            std::vector<CallInst*> SensitiveExternalLibCallList;

            // Needed for source-sink data-flow analysis
            std::set<Value*> AllFunctions;
            std::map<Function*, std::vector<ReturnInst*>> funRetMap;
            std::map<ReturnInst*, std::vector<CallInst*>> retCallMap;

            bool containsSet(llvm::Value*, std::set<llvm::Value*>&);

            bool contains(llvm::Value*, std::vector<llvm::Value*>&);

            void addPAGNodesFromSensitiveObjects(std::vector<Value*>&);

            PAGNode* getPAGObjNodeFromValue(Value*);
            PAGNode* getPAGValNodeFromValue(Value*);

            void findGepInstFromGepNode(GepObjPN*, std::vector<GetElementPtrInst*>&);
            GepObjPN* getGepOrFINodeFromGEPInst(GetElementPtrInst*);


            std::set<PAGNode*> pointsFroms;
            bool isSensitiveLoad(Value*);
            bool isSensitiveLoadPtr(Value*);
            bool isSensitiveGEPPtr(Value*);
            bool isSensitiveObj(PAGNode*);

            bool isSensitiveLoadSet(Value*);
            bool isSensitiveLoadPtrSet(Value*);
            bool isSensitiveGEPPtrSet(Value*);
            bool isSensitiveObjSet(PAGNode*);

            //Functions needed for adding checks
            bool isSensitiveLoadCheckSet(Value*);
            bool isSensitiveLoadPtrCheckSet(Value*);
            bool isSensitiveGEPPtrCheckSet(Value*);

            bool isSensitivePtrVal(Value*);

            bool isSensitiveArg(Value*,   std::map<PAGNode*, std::set<PAGNode*>>& );
            //bool isSensitiveArg(Value*);


            Instruction* FindNextInstruction(Instruction*);

            void getPtsTo(Value*, std::vector<Value*>&);
            void getPtsFrom(Value*, std::vector<Value*>&);

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

            void performAesCacheInstrumentation(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);
            void performHMACInstrumentation(Module& M);

            //void instrumentInlineAsm(Module&);

            void resetInstructionLists(Function*);

            void instrumentAndAnnotateInst(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);
            void instrumentExternalFunctionCall(Module&, std::map<PAGNode*, std::set<PAGNode*>>&);

            void fixupBrokenFunctionCallsFromWidening(Module&);
            void updateSensitiveState(Value*, Value*, std::map<PAGNode*, std::set<PAGNode*>>&);

            bool isCallocLike(const char* str);

            Type* findBaseType(Type*);
            int getCompositeSzValue(Value*, Module& );

            // int getSzVoidRetVal(Value*, Module&);
            //int getSzVoidArgVal(Value*, Module&);

            void fixupSizeOfOperators(Module&);
            //void collectVoidDataObjects(Module&);

            void getAnalysisUsage(AnalysisUsage& AU) const {
                AU.addRequired<SensitiveMemAllocTrackerPass>();
                AU.addRequired<WPAPass>();
                AU.addRequired<ContextSensitivityAnalysisPass>();
                AU.addRequired<LoopInfoWrapperPass>();
                AU.addRequired<DominatorTreeWrapperPass>();
                //AU.setPreservesAll();
            }
            inline void externalFunctionHandlerForPartitioning(Module& , CallInst*, Function*, Function*, Value*, std::vector<Value*>&);
            inline void externalFunctionHandler(Module&, CallInst*, Function*, Function*, std::vector<Value*>&);

            bool isOptimizedOut(Value*, Value*);
            void collectSensitivePointers();
            void collectSensitiveObjectsForWidening();

            void performHoistOptimization();
            bool hasSenBB(Loop*, std::set<BasicBlock*>&);
            bool hasPartialSenMemAccess(BasicBlock*, std::set<Instruction*>&);
            bool hasFunctionCallInBody(Loop*);
            bool allSameMemBase(Loop*, Value**, std::set<Instruction*>&, std::set<Instruction*>&);
            void getMemBases(Loop*, std::set<Instruction*>&, std::map<Value*, std::set<Instruction*>>&, bool);

            bool hasNullCheck(Value*);
            //void performTaintCheckLICM(Module&);

            //void handleLoop(Loop*);

            //bool isInLoopBody(Instruction*);
            Value* getBaseValueForMemOp(Instruction*, Loop*);
            bool sanitizeCandidatesForNullCheck(std::map<Value*, std::set<Instruction*>>&);

            //bool isCandidateForHoisting(Instruction*, Value** baseMemLoc, Loop**, LoopInfo**, DominatorTree**);

            //bool handleTaintCheckInLoop(LoopInfo*, DominatorTree*, Loop*, Instruction*);
            Loop* specializeLoopAndHoist(LoopInfo*, DominatorTree*, Loop*, std::set<Instruction*>&, Value*, std::map<Value*, std::set<Instruction*>>& );
            void loadShadowBase(Module& M);

            BasicBlock* insertNewPH(LLVMContext&, DominatorTree*, LoopInfo*, Loop*, ValueToValueMapTy&);
            Loop* cloneAndInsertLoop(DominatorTree*, LoopInfo*, Loop*, BasicBlock*, ValueToValueMapTy&);
            void addTaintCheck(Loop*, Loop*, BasicBlock*, Value*);

            void transformSensitiveMemInst(Instruction*);

            void updateSensitiveMemLists(std::map<Value*, std::set<Instruction*>>&, Value*, ValueToValueMapTy&);

            void resetInstructions(BasicBlock* bb, ValueToValueMapTy& VMap) {
                for (BasicBlock::iterator BBIterator = bb->begin(); BBIterator != bb->end(); BBIterator++) {
                    if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                        for (int i = 0; i < Inst->getNumOperands(); i++) {
                            Value* op = Inst->getOperand(i);
                            auto it = VMap.find(op);
                            if (it != VMap.end()) {
                                Inst->setOperand(i, it->second);
                            }
                        }
                    }
                }
            }

            void collectInitialLoadStoreStats(Module&);

            void computeTotalValueFlows(Module&);
    };
}

char EncryptionPass::ID = 0;

cl::opt<bool> HoistChecks("hoist-taint-checks", cl::desc("Hoist Taint Checks"), cl::init(false), cl::Hidden);
//cl::opt<bool> NullEnc("null-enc", cl::desc("XOR Encryption"), cl::init(false), cl::Hidden);
cl::opt<bool> Partitioning("partitioning", cl::desc("Partitioning"), cl::init(false), cl::Hidden);
cl::opt<bool> OptimizedCheck("optimized-check", cl::desc("Reduce no of Checks needed"), cl::init(false), cl::Hidden);
cl::opt<bool> ReadFromFile("read-from-file", cl::desc("Read from file"), cl::init(false), cl::Hidden);
cl::opt<bool> WriteToFile("write-from-file", cl::desc("Write to file"), cl::init(false), cl::Hidden);
cl::opt<bool> Integrity("integrity", cl::desc("Integrity only"), cl::init(false), cl::Hidden);
cl::opt<bool> Confidentiality("confidentiality", cl::desc("confidentiality"), cl::init(false), cl::Hidden);

//cl::opt<bool> SkipVFA("skip-vfa-enc", cl::desc("Skip VFA"), cl::init(false), cl::Hidden);

void EncryptionPass::collectInitialLoadStoreStats(Module& M) {
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            // Get the local sensitive values
            for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                    //outs() << "Basic block found, name : " << BB->getName() << "\n";
                    for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                        if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                            if (LoadInst* loadInst = dyn_cast<LoadInst>(Inst)) {
                                loadStatCount++;
                            } else if (StoreInst* storeInst = dyn_cast<StoreInst>(Inst)) {
                                storeStatCount++;
                            } 
                        }
                    }
                }
            }
        }
    }
}

bool EncryptionPass::isOptimizedOut(Value* userVal, Value* ptrVal) {

    if(OptimizedCheck) {
        /* During set Label for context sensitive call, we directly encrypt
         * whatever in the memory. we don't know if memory has
         * been allocated for struct and what are the struct fields. So we
         * can't ignore instrumenting load/store of pointer when these are 
         * users of a gepInst*/
        if(GetElementPtrInst* gepInst = dyn_cast<GetElementPtrInst>(ptrVal)){
            return false;
        } else if(LoadInst* ldInst = dyn_cast<LoadInst>(userVal)){
            /*Skipping all loads that load address from a pointer*/
            if (PointerType* pointerElementType = dyn_cast<PointerType>(ldInst->getPointerOperand()->getType()->getPointerElementType())){
                return true;
            }
        } else if(StoreInst* stInst = dyn_cast<StoreInst>(userVal)){
            /*Skipping all stores that stores address to a pointer*/
            if (PointerType* pointerElementType = dyn_cast<PointerType>(stInst->getPointerOperand()->getType()->getPointerElementType())){
                return true;
            }
        }
    }
    if (isa<GlobalVariable>(ptrVal)){
        if (ptrVal->getName().str().find("stdout") != std::string::npos) {
            return true;
        }
    }
    return false;
}

void EncryptionPass::collectSensitivePointers() {
    if (!ReadFromFile) {
        if (!Partitioning) {
            getAnalysis<WPAPass>().getPtsFromSDD(SensitiveObjList, pointsFroms);
        } else {
            //Skiping Points-to check for now; this phase is taking a lot of time
            //during compilation; 
            //TODO: check if we still need this phase. If we need it, then check if we can optimize it
            /*To find recursive memory allocations, we need pointsTo analysis;
             * we wiil find possibleSensitive allocations from pointsTo analysis
             * and then perform pointsFrom analysis to find the complete set*/
            /*std::vector<PAGNode*> tempSensitiveObjList = SensitiveObjList;
            for (PAGNode* sensitiveNode: SensitiveObjList) {
                for (PAGNode* possibleSensitiveNode: getAnalysis<WPAPass>().pointsToSet(sensitiveNode->getId())) {
                    if (isa<DummyValPN>(possibleSensitiveNode) || isa<DummyObjPN>(possibleSensitiveNode))
                        continue;
                    Value* valNode = const_cast<Value*>(possibleSensitiveNode->getValue());
                    //Since memory allocations can be done via callInst, we will
                    //only consider call instructions as possibleSensitive
                    //allocation
                    if(CallInst* callInst = dyn_cast<CallInst>(valNode)){
                        tempSensitiveObjList.push_back(possibleSensitiveNode);
                    }
                }
            }
            getAnalysis<WPAPass>().getPtsFrom(tempSensitiveObjList, pointsFroms);*/
            getAnalysis<WPAPass>().getPtsFrom(SensitiveObjList, pointsFroms);
        }
        if (WriteToFile) {
            std::ofstream outFile;
            outFile.open("pointsto.results");
            for (PAGNode* pagNode: pointsFroms) {
                outFile << pagNode->getId() << "\n";
            }
            outFile.close();
        }
    } else {
        std::ifstream inFile;
        NodeID sensitivePtrId;
        inFile.open("pointsto.results");
        if (!inFile) {
            assert(false && "Can't open file to read from\n");
        }
        while (inFile >> sensitivePtrId) {
            PAGNode* sensitiveNode = getAnalysis<WPAPass>().getPAG()->getPAGNode(sensitivePtrId);
            pointsFroms.insert(sensitiveNode);
        }
    }
    errs() << "Points from size: " << pointsFroms.size() << "\n";
}

void EncryptionPass::collectLoadStoreStats(Module& M) {
    errs() << "Statistics: \n";
    errs() << "% of Loads accessing sensitive memory regions: " << format("%.3f\n", ((double)decStatCount)/((double)loadStatCount)*100.0) << "\n";
    errs() << "% of Stores accessing sensitive memory regions: " << format("%.3f\n", ((double)encStatCount)/((double)(storeStatCount))*100.0) << "\n";
    long totalMemOpCount = loadStatCount + storeStatCount;
    long totalTransformCount = encStatCount + decStatCount;
    errs() << "% of Mem. Ops instrumented: " << format("%.3f\n", ((double)totalTransformCount/(double)totalMemOpCount)*100.0) << "\n";

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

bool EncryptionPass::isSensitiveLoadCheckSet(Value* Val) {
    if (std::find(SensitiveLoadCheckSet->begin(), SensitiveLoadCheckSet->end(), Val) != SensitiveLoadCheckSet->end()) {
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

bool EncryptionPass::isSensitiveLoadPtrCheckSet(Value* Val) {
    if (std::find(SensitiveLoadPtrCheckSet->begin(), SensitiveLoadPtrCheckSet->end(), Val) != SensitiveLoadPtrCheckSet->end()) {
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

bool EncryptionPass::isSensitiveGEPPtrCheckSet(Value* Val) {
    if (std::find(SensitiveGEPPtrCheckSet->begin(), SensitiveGEPPtrCheckSet->end(), Val) != SensitiveGEPPtrCheckSet->end()) {
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
    /*
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
    */

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
    std::map<Value*, std::set<Value*>> ptsToMap;// = getAnalysis<WPAPass>().getSensitivePtsToMap(); // TODO
    std::map<Value*, std::set<Value*>> ptsFromMap;// = getAnalysis<WPAPass>().getSensitivePtsFromMap(); // TODO

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

void EncryptionPass::doVFAIndirect(Value* work, std::vector<Value*>& sinkSites,
        std::vector<Value*>& workList, std::vector<Value*>& processedList) {
    for (User* user: work->users()) {
        if (LoadInst* loadInst = dyn_cast<LoadInst>(user)) {
            if (isa<PointerType>(loadInst->getType())) 
                continue;
            for (User* loadUser: loadInst->users()) {
                if (StoreInst* storeInst = dyn_cast<StoreInst>(loadUser)) {
                    if (storeInst->getValueOperand() == loadInst) {
                        // This store location *might* be sensitive. 
                        // We can only say for sure, at runtime
                        // Add meta-data and leave it for DFSan to figure it out.
                        addTaintMetaData(storeInst);
                        Value* storeLocation = storeInst->getPointerOperand();
                        handleSink(storeLocation, sinkSites, workList, processedList);
                    }
                }
            }
        }
    }
}

void EncryptionPass::doVFADirect(Value* work, std::vector<Value*>& sinkSites,
        std::vector<Value*>& workList, std::vector<Value*>& processedList) {
    for (User* user: work->users()) {
        if (LoadInst* loadInst = dyn_cast<LoadInst>(user)) {
            // If there's a direct store only then we care
            for (User* loadUser: loadInst->users()) {
                if (StoreInst* storeInst = dyn_cast<StoreInst>(loadUser)) {
                    if (storeInst->getValueOperand() == loadInst) {
                        // This store location *might* be sensitive. 
                        // We can only say for sure, at runtime
                        // Add meta-data and leave it for DFSan to figure it out.
                        addTaintMetaData(storeInst);

                        // Handle different types of sinks
                        Value* storeLocation = storeInst->getPointerOperand();
                        handleSink(storeLocation, sinkSites, workList, processedList);
                    }
                }
            }
        }
    }
}

void EncryptionPass::handleSink(Value* storePtr, std::vector<Value*>& sinkSites,
        std::vector<Value*>& workList, std::vector<Value*>& processedList) {
    if ((isa<AllocaInst>(storePtr) || isa<GlobalVariable>(storePtr))
            && !isa<Constant>(storePtr)) {
        if (((isa<AllocaInst>(storePtr) || isa<GlobalVariable>(storePtr))
                    && !isa<Constant>(storePtr))) {
            if (AllocaInst* allocaInst = dyn_cast<AllocaInst>(storePtr)) {
                if (isa<PointerType>(allocaInst->getAllocatedType())) {
                    return;
                }
            } else {
                if (isa<PointerType>(storePtr->getType())) {
                    return;
                }
            }
            //errs() << "VFA: " << *storePtr << "\n";
            sinkSites.push_back(storePtr);       
            if (std::find(workList.begin(), workList.end(), storePtr) == workList.end()
                    && std::find(processedList.begin(), processedList.end(), storePtr) == processedList.end()) {
                workList.push_back(storePtr);
            }
        }
    }
    sensitiveValueFlows++;
}

void EncryptionPass::getPtsFrom(Value* ptd, std::vector<Value*>& ptsFromVec) {
    PAG* pag = getAnalysis<WPAPass>().getPAG();

    PAGNode* ptdNode = pag->getPAGNode(pag->getObjectNode(ptd));

    std::vector<PAGNode*> pagPtrVec;

    getAnalysis<WPAPass>().getPtsFrom(ptdNode->getId(), pagPtrVec);

    for (PAGNode* possibleNode: pagPtrVec) {
        if (isa<DummyValPN>(possibleNode) || isa<DummyObjPN>(possibleNode))
            continue;
        ptsFromVec.push_back(const_cast<Value*>(possibleNode->getValue()));
    }
}

void EncryptionPass::getPtsTo(Value* ptr, std::vector<Value*>& ptsToVec) {
    PAG* pag = getAnalysis<WPAPass>().getPAG();

    PAGNode* ptrNode = pag->getPAGNode(pag->getValueNode(ptr));

    for (PAGNode* possibleNode: getAnalysis<WPAPass>().pointsToSet(ptrNode->getId())) {
        if (isa<DummyValPN>(possibleNode) || isa<DummyObjPN>(possibleNode))
            continue;
        ptsToVec.push_back(const_cast<Value*>(possibleNode->getValue()));
    }
}

cl::opt<int> VFALimit("vfa-limit", cl::desc("Limit VFA Iterations: debug purposes only"), cl::init(100), cl::Hidden);

void EncryptionPass::performSourceSinkAnalysis(Module& M) {
    PAG* pag = getAnalysis<WPAPass>().getPAG();

    //std::vector<Type*> sensitiveTypes;
    std::vector<Value*> workList; // List of allocation sites for which we still need to perform source-sink analysis
    std::vector<Value*> tempWorkList;
    std::vector<Value*> sinkSites;
    std::vector<Value*> processedList;
    
    for (PAGNode* sensitiveObjNode: SensitiveObjList) {
        workList.push_back(const_cast<Value*>(sensitiveObjNode->getValue()));
    }

    bool done = false;
    int iter = 0;
    do {
        tempWorkList.clear();
        iter ++;
        if ( iter >= VFALimit) {
            break;
        }
        while (!workList.empty()) {
            Value* work = workList.back();
            workList.pop_back();

            processedList.push_back(work);
            // Direct vfa
            doVFADirect(work, sinkSites, tempWorkList, processedList);
            std::vector<Value*> ptsFromVec;
            getPtsFrom(work, ptsFromVec);
            // Indirect vfa 
            for (Value* ptr: ptsFromVec) {
                // It should be a pointer to a pointer? 
                if (ptr->getType() == work->getType()) {
                    doVFAIndirect(ptr, sinkSites, tempWorkList, processedList);
                }
            }
        }
        errs() << "Found " << tempWorkList.size() << " new sites during VFA\n";
        std::copy(tempWorkList.begin(), tempWorkList.end(), std::back_inserter(workList));
        if (workList.empty()) {
            done = true;
        }
    } while (!done);
    errs() << "VFA iter: " << iter << "\n";

    // Put it back in PAG-world
    for (Value* sinkVal: sinkSites) {
        SensitiveObjList.push_back(pag->getPAGNode(pag->getObjectNode(sinkVal)));
    }
    // Set up the writeback functions
    // Pull these from SensitiveObjList not sinkSites because sinkSites don't
    // have the original sensitive objects
    for (PAGNode* pagNode: SensitiveObjList) {
        Value* sensitiveValue = const_cast<Value*>(pagNode->getValue());
        if (AllocaInst* allocInst = dyn_cast<AllocaInst>(sensitiveValue)) {
            writebackCacheFunctions.insert(allocInst->getParent()->getParent());
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
                                if (CInst->getCalledValue()->getName().equals("llvm.var.annotation")) {
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
                                            NodeID objID = pag->getValueNode(UseValue);
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
                                        //SensitiveObjList.push_back(objNode);
                                    } 
                                    /*if(pag->hasValueNode(val)) {
                                      SensitiveObjList.push_back(pag->getPAGNode(pag->getValueNode(val)));
                                      }*/
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
    
    // For sanity, how many pointers point to this memory allocation site?


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
            int size = pointsToSet.size();
            int count = 0;
            bool sensitive = false;
            for (PAGNode* ptsToNode: pointsToSet) {
                if (isSensitiveObj(ptsToNode)) {
                    //SensitiveGEPPtrList.push_back(GEPInst);
                    count++;
                    sensitive = true;
                }
            }
            // check if all the targets are sensitive
            if(count == size && sensitive){
                SensitiveGEPPtrList.push_back(GEPInst);
            }
            else if(sensitive){
                SensitiveGEPPtrCheckList.push_back(GEPInst);
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
    // Do the same for the partially sensititve locations, if any
    for (Value* GEPValue: SensitiveGEPPtrCheckList) {
        // Find all Users of this GEP instruction
        for(Value::user_iterator User = GEPValue->user_begin(); User != GEPValue->user_end(); ++User) {
            if (LoadInst* LdInst = dyn_cast<LoadInst>(*User)) {
                if (!LdInst->getType()->isPointerTy()) {
                    // Ignore any pointer assignments here, the pointer analysis will take care of it TODO - Will this break anything?
                    if (!LdInst->getType()->isPointerTy()) {
                        SensitiveLoadCheckList.push_back(LdInst);
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
            int size = pointsToSet.size();
            int count = 0;
            bool sensitive = false;
            for (PAGNode* ptsToNode: pointsToSet) {
                if (isSensitiveObjSet(ptsToNode)) {
                    count++;
                    sensitive = true;
                }
            }
            if((count == size) && sensitive){
                SensitiveLoadPtrList.push_back(LdInst);
            } else if(sensitive){
                SensitiveLoadPtrCheckList.push_back(LdInst);
            }
        } else if (CastInst *CInst = dyn_cast<CastInst>(const_cast<Value*>(ptr->getValue()))) {
            std::set<PAGNode*> pointsToSet = mapIt->second;
            int size = pointsToSet.size();
            int count = 0;
            bool sensitive = false;
            for (PAGNode* ptsToNode: pointsToSet) {
                if (isSensitiveObjSet(ptsToNode)) {
                    //SensitiveLoadPtrList.push_back(CInst);
                    count++;
                    sensitive = true;
                }
            }
            if(count == size && sensitive){
                SensitiveLoadPtrList.push_back(CInst);
            } else if(sensitive){
                SensitiveLoadPtrCheckList.push_back(CInst);
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
    // Do the same for the partially sensitive locations
    for (Value* sensitivePtrLoad: SensitiveLoadPtrCheckList) {
        // Find all Users of this Load instruction
        Value* loadValue = dyn_cast<Value>(sensitivePtrLoad);

        for(Value::user_iterator User = loadValue->user_begin(); User != loadValue->user_end(); ++User) {
            if (GetElementPtrInst* GEPInst = dyn_cast<GetElementPtrInst>(*User) ) {
                SensitiveGEPPtrCheckList.push_back(GEPInst);
                SensitiveGEPPtrCheckSet->insert(GEPInst);
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
                    }

                    else if (isSensitiveGEPPtrCheckSet(LdInst->getPointerOperand())) {
                        SensitiveLoadCheckList.push_back(LdInst);
                    }
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

    // Do the same for partially sensiitve load ptrs
    for (Value* sensitivePtrLoad: SensitiveLoadPtrCheckList) {
        // Find all Users of this Load instruction
        Value* loadValue = dyn_cast<Value>(sensitivePtrLoad);
        for(Value::user_iterator User = loadValue->user_begin(); User != loadValue->user_end(); ++User) {
            if (LoadInst* LdInst = dyn_cast<LoadInst>(*User) ) {
                SensitiveLoadCheckList.push_back(LdInst);
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

void EncryptionPass::collectSensitiveExternalLibraryCalls(Module& M,  std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    // Create sets for quicker lookup
    std::set<Value*> SensitiveGEPPtrSet(SensitiveGEPPtrList.begin(), SensitiveGEPPtrList.end());
    std::set<Value*> SensitiveLoadPtrSet(SensitiveLoadPtrList.begin(), SensitiveLoadPtrList.end());

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
                                        if (isSensitiveObjSet(getPAGObjNodeFromValue/*getPAGValNodeFromValue*/(CInst))) {
                                            SensitiveExternalLibCallList.push_back(CInst);
                                            //errs()<<"External Calloc:"<<*CInst<<"\n";
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
                                    if (!ReadFromFile) {
                                        for (PAGNode* possibleFunNode: getAnalysis<WPAPass>().pointsToSet(calledValueNode->getId())) {
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
                                    } else {
                                        errs() << "Will skip indirect external function calls in ReadFromFile mode\n";
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
    }
    else if (LoadInst* LdInst = dyn_cast<LoadInst>(Inst)) {					
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
            decStatCount++;
        }
        // Keeping separate ReplacementList where we need to add check
        if(isSensitiveLoadCheckSet(LdInst)) {
            LLVMContext& C = LdInst->getContext();
            MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
            LdInst->setMetadata("SENSITIVE", N);

            Instruction* NextInstruction = FindNextInstruction(Inst);
            InstructionReplacement* Replacement = new InstructionReplacement();
            Replacement->OldInstruction = Inst;
            Replacement->NextInstruction = NextInstruction;
            Replacement->Type = LOAD;
            ReplacementCheckList.push_back(Replacement);
            decStatCount++;
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
        encStatCount++;
        ReplacementList.push_back(Replacement);
    }
    if (/*(pag->hasObjectNode(PointerOperand) && isSensitiveObjSet(getPAGObjNodeFromValue(PointerOperand))) || */isSensitiveLoadPtrCheckSet(PointerOperand) || isSensitiveGEPPtrCheckSet(PointerOperand)/* || sensitiveGEPCE*/) {
        LLVMContext& C = StInst->getContext();
        MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
        StInst->setMetadata("SENSITIVE", N);

        InstructionReplacement* Replacement = new InstructionReplacement();
        Replacement->OldInstruction = Inst;
        Replacement->NextInstruction = nullptr; // Don't care about the next, the decryption happens before the store
        Replacement->Type = STORE;
        encStatCount++;
        ReplacementCheckList.push_back(Replacement);
    }
}


void EncryptionPass::updateSensitiveState(Value* oldVal, Value* newVal, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    // If the newVal is a pointer type, only then need to update anything
    if (!newVal->getType()->isPointerTy()) {
        return;
    }
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
    ReplacementCheckList.clear();

    InstructionList.clear();
    // Iterate over all instructions in the Function to build the Instruction list
    for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
        InstructionList.push_back(&*I);
    }
}

void EncryptionPass::performAesCacheInstrumentation(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    /*
     * ReplacementList contains the sensitive loads/stores that always access sensitive data
     * so we directly add encryption/decryption.
     * ReplacementCheckList is where we need to add check; 
     * so we call encryption/decryption functions which check if the dynamic sensitive label is present
     */
    for (std::vector<InstructionReplacement*>::iterator ReplacementIt = ReplacementList.begin() ; 
            ReplacementIt != ReplacementList.end(); ++ReplacementIt) {
        InstructionReplacement* Repl = *ReplacementIt;
        if (Repl->OldInstruction->getParent()->getParent()->getName() == "apr_thread_create") {
            continue;
        }
        if (Repl->Type == LOAD) {
            IRBuilder<> Builder(Repl->NextInstruction); // Insert before "next" instruction
            LoadInst* LdInst = dyn_cast<LoadInst>(Repl->OldInstruction);

            // Check get the decrypted value
            Value* decryptedValue = nullptr;
            decryptedValue = AESCache.getDecryptedValueCached(LdInst);
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

            AESCache.setEncryptedValueCached(StInst);
            // Remove the Store instruction
            StInst->eraseFromParent();
        }
    }
    // Handle the hoistable taint checks
    if (HoistChecks) {
        performHoistOptimization();
    }

    for (std::vector<InstructionReplacement*>::iterator ReplacementIt = ReplacementCheckList.begin() ;
            ReplacementIt != ReplacementCheckList.end(); ++ReplacementIt) {
        InstructionReplacement* Repl = *ReplacementIt;
        if (Repl->OldInstruction->getParent()->getParent()->getName() == "apr_thread_create"
                || Repl->OldInstruction->getParent()->getParent()->getName() == "CRYPTO_gcm128_encrypt") {
            errs() << "Skipping\n";
            continue;
        }
        
        /*
        LoopInfo* LI = nullptr;
        DominatorTree* DT = nullptr;
        Value* baseMemLoc = nullptr;
        Loop* loop = nullptr;
        if (HoistChecks) {
            bool canHoist = isCandidateForHoisting(Repl->OldInstruction, &baseMemLoc, &loop, &LI, &DT); 
            if (canHoist) {
                if (specializeLoopAndHoist(LI, DT, loop, Repl->OldInstruction, baseMemLoc)) {
                    continue;
                }
            }
        }
        */
 
        if (Repl->Type == LOAD) {
            IRBuilder<> Builder(Repl->NextInstruction); // Insert before "next" instruction
            LoadInst* LdInst = dyn_cast<LoadInst>(Repl->OldInstruction);

            // Check get the decrypted value
            Value* decryptedValue = nullptr;
            if (IntegerType* intType = dyn_cast<IntegerType>(LdInst->getType())) {
                // Fix this
                if (intType->getBitWidth() > 64) {
                    continue;
                }
            }
            decryptedValue = AESCache.getDecryptedValueCachedDfsan(LdInst);
            PHINode* phi = dyn_cast<PHINode>(decryptedValue);
            if (phi) {
                addTaintMetaData(phi);
            }

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
        } else  if (Repl->Type == STORE) {
            IRBuilder<> Builder(Repl->OldInstruction); // Insert before the current Store instruction
            StoreInst* StInst = dyn_cast<StoreInst>(Repl->OldInstruction);
            LLVM_DEBUG (
                    dbgs() << "Replacing Store Instruction : ";
                    StInst->dump();
                    );

            AESCache.setEncryptedValueCachedDfsan(StInst);

            // Remove the Store instruction
            StInst->eraseFromParent();
        }
    }

    AESCache.clearLabelForSensitiveObjects(M, SensitiveObjList);
}

void EncryptionPass::performInstrumentation(Module& M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    if (Confidentiality) {
        performAesCacheInstrumentation(M, ptsToMap);
    } else {
        performHMACInstrumentation(M);
    }
}


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
    return (std::find(pointsFroms.begin(), pointsFroms.end(), argNode) != pointsFroms.end());
}

Type* EncryptionPass::findBaseType(Type* type) {
    Type* trueType = type;
    while (trueType->isPointerTy()) {
        trueType = trueType->getPointerElementType();
    }
    return trueType;
}

int EncryptionPass::getCompositeSzValue(Value* value, Module& M) {
    Type* trueType = findBaseType(value->getType());
    if (CompositeType* cType = dyn_cast<CompositeType>(trueType)) {
        return M.getDataLayout().getTypeAllocSize(cType);
    }
    assert(false && "getCompositeSzValue called with a non-composite type!");
}

inline void EncryptionPass::externalFunctionHandlerForPartitioning(Module &M, CallInst* externalCallInst, Function* decryptFunction, Function* encryptFunction,
        Value* addrForReadLabel, std::vector<Value*>& ArgList){
    IRBuilder<> Builder(externalCallInst);


    // Check that the ArgList has the correct types (void*)
    // If not, type-cast it
    Type* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
    std::vector<Value*> fixedArgList;

    Value* argument = ArgList[0];
    /*if (isa<PHINode>(argument))
        return; // TODO: handle PHINode
    */
    if (argument->getType() != voidPtrType) {
        fixedArgList.push_back(Builder.CreateBitCast(argument, voidPtrType));
    } else {
        fixedArgList.push_back(argument);
    }

    for (int i = 1; i < ArgList.size(); i++) {
        fixedArgList.push_back(ArgList[i]);
    }

    const DataLayout &DL = M.getDataLayout();
    LLVMContext *Ctx;
    Ctx = &M.getContext();
    IntegerType* ShadowTy = IntegerType::get(*Ctx, 8);
    IntegerType* IntptrTy = DL.getIntPtrType(*Ctx);
    Type *DFSanReadLabelArgs[2] = { Type::getInt8PtrTy(*Ctx), IntptrTy };
    FunctionType* FTypeReadLabel = FunctionType::get(ShadowTy, DFSanReadLabelArgs, false);

    //InlineAsm* DFSanReadLabelFn = InlineAsm::get(FTypeReadLabel, "movq %mm0, %rax\n\t and %rax, $1 \n\t movb ($1), $0", "=r,r,r,~{rax}", true, false);
    Function* DFSanReadLabelFn = M.getFunction("dfsan_read_label");
    if (externalCallInst->getParent()->getParent()->getName() == "apr_thread_create") {
        return;
    }
    errs() << "Inserting dfsan_read_label for function: " << externalCallInst->getParent()->getParent()->getName() << "\n";

    CallInst* readLabel = nullptr;
    ConstantInt* noOfByte = Builder.getInt64(1);
    ConstantInt *One = Builder.getInt8(1);

    // tpalit -- this assertion makes no sense. Who added it and why? 
    //assert(DFSanReadLabelFn->getType()->isPointerTy() && "We shouldn't be dealing with virtual register values here");
    /* If it's not a i8* cast it */

    Type* readLabelPtrElemType = addrForReadLabel->getType()->getPointerElementType();
    IntegerType* intType = dyn_cast<IntegerType>(readLabelPtrElemType);
    if (!(intType && intType->getBitWidth() == 8)) {
        // Create the cast
        Type* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
        addrForReadLabel = Builder.CreateBitCast(addrForReadLabel, voidPtrType);
    }


    readLabel = Builder.CreateCall(DFSanReadLabelFn,{addrForReadLabel , noOfByte});
    readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

    Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
    Instruction* SplitBefore = cast<Instruction>(externalCallInst);
    TerminatorInst* ThenTerm = SplitBlockAndInsertIfThen(cmpInst, SplitBefore, false);

    Builder.SetInsertPoint(ThenTerm);
    CallInst* decryptArray = Builder.CreateCall(decryptFunction, fixedArgList);
    
    Builder.SetInsertPoint(SplitBefore);
    Instruction* SplitBeforeNew = cast<Instruction>(externalCallInst->getNextNode());
    ThenTerm  = SplitBlockAndInsertIfThen(cmpInst, SplitBeforeNew, false);
    Builder.SetInsertPoint(ThenTerm);

    CallInst* enecryptArray = Builder.CreateCall(encryptFunction, fixedArgList);
    Builder.SetInsertPoint(SplitBeforeNew);
}


inline void EncryptionPass::externalFunctionHandler(Module &M, CallInst* externalCallInst, Function* decryptFunction, Function* encryptFunction, std::vector<Value*>& ArgList){
    
    IRBuilder<> Builder(externalCallInst);
    Builder.CreateCall(decryptFunction, ArgList); // Bug Fix - Need to do this for unaligned buffers
    CallInst* CInst = CallInst::Create(encryptFunction, ArgList);
    CInst->insertAfter(externalCallInst);
}

/**
 * The routine that actual does the instrumentation for external function calls.
 */
void EncryptionPass::instrumentExternalFunctionCall(Module &M, std::map<PAGNode*, std::set<PAGNode*>>& ptsToMap) {
    std::set<Value*> UnsupportedCallSet;

    std::vector<Value*> sensitivePointerValueList; // List of sensitive pointers (the pointer itself is sensitive)
    /*IntegerType* longTy = IntegerType::get(M.getContext(), 64);*/
    const DataLayout &DL = M.getDataLayout();
    LLVMContext *Ctx;
    Ctx = &M.getContext();
    IntegerType* ShadowTy = IntegerType::get(*Ctx, 8);
    IntegerType* IntptrTy = DL.getIntPtrType(*Ctx);
    Type *DFSanReadLabelArgs[2] = { Type::getInt8PtrTy(*Ctx), IntptrTy };
    FunctionType* FTypeReadLabel = FunctionType::get(ShadowTy, DFSanReadLabelArgs, false);

    InlineAsm* DFSanReadLabelFn = InlineAsm::get(FTypeReadLabel, "movq %mm0, %rax\n\t and %rax, $1 \n\t movb ($1), $0", "=r,r,r,~{rax}", true, false);


    for (CallInst* externalCallInst : SensitiveExternalLibCallList) {
        /*
        if (isInLoopBody(externalCallInst)) {
            continue;
        }
        */
        //errs()<<"CallInst "<<*externalCallInst<<"\n";
        Function* externalFunction = externalCallInst->getCalledFunction();
        //errs()<< "Function Name "<<externalFunction->getName()<<"\n";
        if (!externalFunction) {
            // Was a function pointer.
            std::set<Function*> possibleFuns;
            // Skip it, if the PAG node is missing. This can happen due to PHI
            // nodes
            PAG* pag = getAnalysis<WPAPass>().getPAG();
            if(!pag->hasValueNode(externalCallInst->getCalledValue())) {
                continue;
            }
            PAGNode* fptrNode = getPAGValNodeFromValue(externalCallInst->getCalledValue());
            for (PAGNode* fNode : getAnalysis<WPAPass>().pointsToSet(fptrNode->getId())) {
                if (!fNode->hasValue())
                    continue;
                Value* fn = const_cast<Value*>(fNode->getValue());
                if (Function* realFn = dyn_cast<Function>(fn)) {
                    // This is a hack -- if the target can be both an internal
                    // and external function, then we don't know if we should
                    // decrypt or not before the call.
                    if (std::find(AllFunctions.begin(), AllFunctions.end(), realFn) == AllFunctions.end()) {
                        // External function, but is this one that needs
                        // special handling?
                        if (std::find(instrumentedExternalFunctions.begin(), instrumentedExternalFunctions.end(), realFn->getName()) != instrumentedExternalFunctions.end()) {
                            possibleFuns.insert(realFn);
                        }
                    }
                }
            }
            if (possibleFuns.size() > 1) {
                for (Function* possibleFun: possibleFuns) {
                    if (std::find(AllFunctions.begin(), AllFunctions.end(), possibleFun) == AllFunctions.end()) {
                        errs() << "External function: " << possibleFun->getName() << "\n";
                    }
                }
                errs() << "For call instruction: " << *externalCallInst << " in function " << externalCallInst->getParent()->getParent()->getName() << " found " << possibleFuns.size() << " functions\n";
            }
            assert(possibleFuns.size() <= 1 && "Found more than one external function pointer targets. Don't know what to do here.\n");
            for (Function* possFun: possibleFuns) {
                externalFunction = possFun;
                break;
            }
        } else {
            if (std::find(instrumentedExternalFunctions.begin(), instrumentedExternalFunctions.end(), externalFunction->getName()) == instrumentedExternalFunctions.end()) {
                if (!externalFunction->getName().startswith("llvm.memcpy") && !externalFunction->getName().startswith("llvm.memset") && !externalFunction->getName().startswith("llvm.memmove")) {
                    continue;
                }
            }
        }
        
        /*
           if (externalFunction->getName().equals("strlen")) {
           errs() << "1. " << externalCallInst << " : " << *externalCallInst << "\n";
           }
           */
        IRBuilder<> InstBuilder(externalCallInst);

        StringRef annotFn("llvm.var.annotation");
        if (!externalFunction) {
            // Can happen if the pointer isn't initialized anywhere (in case
            // of libraries)
            continue;
        }
        if (annotFn.equals(externalFunction->getName())) {
            continue;
        }
        int numArgs = externalCallInst->getNumArgOperands();

        // In case of AES cache encryption, write back the cache
        AESCache.writeback(externalCallInst);

        if (externalFunction->getName() == "select") {
            // TODO - Handle all arguments
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);

            IRBuilder<> InstBuilder(externalCallInst);
            Value* sensitiveArg = externalCallInst->getOperand(1);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* arg;
            if (sensitiveArg->getType() != voidPtrType) {
                Value* voidArgVal = InstBuilder.CreateBitCast(sensitiveArg, voidPtrType);
                ArgList.push_back(voidArgVal);
                arg = voidArgVal;
            } else {
                ArgList.push_back(sensitiveArg);
                arg = sensitiveArg;
            }
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 128));

            if (Partitioning){
                externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg, ArgList);
            } else {
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }
            //externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
        } else if (externalFunction->getName() == "calloc" || externalFunction->getName() == "aes_calloc" ) {
            /*
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
            */
        } /*else if (externalFunction->getName() == "realloc" ) {
            Function* instrumentFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* numElements = externalCallInst->getArgOperand(1);
            ArgList.push_back(externalCallInst);
            ArgList.push_back(numElements);
            // Insert call instruction to call the function
            CallInst* CInst = CallInst::Create(instrumentFunction, ArgList);
            CInst->insertAfter(externalCallInst);
        }*/ else if (externalFunction->getName() == "printf") {
            // Get the arguments, check if any of them is sensitive 
            // and then put code to decrypt them in memory
            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            for (int i = 0; i < numArgs; i++) {
                Value* value = externalCallInst->getArgOperand(i);
                 
                std::vector<Value*> ArgList;
                ArgList.push_back(value);

                if (isSensitiveArg(value, ptsToMap)){
                    if (Partitioning){
                        externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, value, ArgList);
                    } else {
                        externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                    }
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

                if (Partitioning){

                    IRBuilder<> Builder(externalCallInst);

                    CallInst* readLabel = nullptr;
                    ConstantInt* noOfByte = Builder.getInt64(1);
                    ConstantInt *One = Builder.getInt8(1);
                    errs()<<"StringPtr "<<*stringPtr<<"\n";

                    IntegerType* voidType = IntegerType::get(externalCallInst->getContext(), 8);
                    PointerType* voidPtrType = PointerType::get(voidType, 0);
                    // The bitcast
                    Value* bcVal = Builder.CreateBitCast(stringPtr, voidPtrType);
                    readLabel = Builder.CreateCall(DFSanReadLabelFn,{bcVal , noOfByte});
                    readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

                    Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
                    Instruction* SplitBeforeNew = cast<Instruction>(externalCallInst->getNextNode());
                    TerminatorInst* ThenTerm  = SplitBlockAndInsertIfThen(cmpInst, SplitBeforeNew, false);
                    Builder.SetInsertPoint(ThenTerm);

                    CallInst* enecryptArray = Builder.CreateCall(encryptFunction, ArgList);
                    Builder.SetInsertPoint(SplitBeforeNew);
                } else {
                    CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                    encCInst->insertAfter(externalCallInst);
                }
            }
            for (int i = 1; i < numArgs; i++) {
                Value* value = externalCallInst->getArgOperand(i);

                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

                if (isSensitiveArg(value, ptsToMap)) {
                    LLVM_DEBUG (
                            dbgs() << "Do decryption for print value: ";
                            value->dump();
                            );
                    std::vector<Value*> ArgList;
                    ArgList.push_back(value);

                    if (Partitioning){
                        externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, value, ArgList);
                    } else {
                        externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                    }
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
                Value* arg;
                if (pollfdVal->getType() != voidPtrType) {
                    Value* voidArgVal = InstBuilder.CreateBitCast(pollfdVal, voidPtrType);
                    ArgList.push_back(voidArgVal);
                    arg = voidArgVal;
                } else {
                    ArgList.push_back(pollfdVal);
                    arg = pollfdVal;
                }
                ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 8));

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "puts") {
            Value* value = externalCallInst->getArgOperand(0);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(value, ptsToMap)) {
                LLVM_DEBUG (
                    dbgs() << "Do decryption for puts value: ";
                    value->dump();
                );
                std::vector<Value*> ArgList;
                ArgList.push_back(value);
               
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, value, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "stat64") {
            IRBuilder<> InstBuilder(externalCallInst);
            Value* arg1 = externalCallInst->getArgOperand(0);
            Value* arg2 = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(arg1, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(arg1);
               
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg1, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
            if (isSensitiveArg(arg2, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(arg2);
               
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg2, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "fgets") {
            Value* buffer = externalCallInst->getArgOperand(0);
            Value* size = externalCallInst->getArgOperand(1);
            Value* fileStream0 = externalCallInst->getArgOperand(2);
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Value* fileStream = InstBuilder.CreateBitCast(fileStream0, voidPtrType);

            if (isSensitiveArg(buffer, ptsToMap)) {

                IRBuilder<> Builder(externalCallInst);
                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(buffer);
                ArgList.push_back(Builder.CreateSExtOrBitCast(size, longType));
                //InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

                if (Partitioning){


                    CallInst* readLabel = nullptr;
                    ConstantInt* noOfByte = Builder.getInt64(1);
                    ConstantInt *One = Builder.getInt8(1);

                    readLabel = Builder.CreateCall(DFSanReadLabelFn,{buffer , noOfByte});
                    readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

                    Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
                    Instruction* SplitBeforeNew = cast<Instruction>(externalCallInst->getNextNode());
                    TerminatorInst* ThenTerm  = SplitBlockAndInsertIfThen(cmpInst, SplitBeforeNew, false);
                    Builder.SetInsertPoint(ThenTerm);

                    CallInst* enecryptArray = Builder.CreateCall(encryptFunction, ArgList);
                    Builder.SetInsertPoint(SplitBeforeNew);
                } else {
                    CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                    encCInst->insertAfter(externalCallInst);
                }

            }
            if (isSensitiveArg(fileStream, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(fileStream);
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, fileStream, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }

            }
        } else if (externalFunction->getName() == "fopen" || externalFunction->getName() == "open" || externalFunction->getName() == "open64" ) {
            Value* fileName = externalCallInst->getArgOperand(0);
            Value* mode = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(fileName, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(fileName);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, fileName, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
            if (isSensitiveArg(mode, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(mode);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, mode, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "fprintf") {
            // Variable arg number
            int argNum = externalCallInst->getNumArgOperands();
            // Assuming first arguments, FILE* stream can never be sensitive
            if (argNum > 1) {
                // has varargs
                for (int i = 1; i < argNum; i++) {
                    Value* arg = externalCallInst->getArgOperand(i);
                    Type* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
                    if(arg->getType() != voidPtrType){
                        continue;
                    }

                    Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                    Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

                    if (isSensitiveArg(arg, ptsToMap) ) {
                        std::vector<Value*> ArgList;
                        ArgList.push_back(arg);
                        if (Partitioning){
                            externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg, ArgList);
                        } else {
                            externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                        }
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
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                std::vector<Value*> ArgList;

                if (arg->getType() != voidPtrType) {
                    arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                }
                ArgList.push_back(arg);

                if (Partitioning){

                    IRBuilder<> Builder(externalCallInst);

                    CallInst* readLabel = nullptr;
                    ConstantInt* noOfByte = Builder.getInt64(1);
                    ConstantInt *One = Builder.getInt8(1);

                    readLabel = Builder.CreateCall(DFSanReadLabelFn,{arg , noOfByte});
                    readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

                    Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
                    Instruction* SplitBeforeNew = cast<Instruction>(externalCallInst->getNextNode());
                    TerminatorInst* ThenTerm  = SplitBlockAndInsertIfThen(cmpInst, SplitBeforeNew, false);
                    Builder.SetInsertPoint(ThenTerm);

                    CallInst* enecryptArray = Builder.CreateCall(encryptFunction, ArgList);
                    Builder.SetInsertPoint(SplitBeforeNew);
                } else {
                    CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                    encCInst->insertAfter(externalCallInst);
                }

            }
            // Second argument is the size, ignore
            // The third argument is the format buffer
            arg = externalCallInst->getArgOperand(2);
            if (isSensitiveArg(arg, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                std::vector<Value*> ArgList;
                if (arg->getType() != voidPtrType) {
                    arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                }
                ArgList.push_back(arg);
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
            // The fourth argument is the tricky va_list
            // We skip the fourth argument for now TODO: handle fourth argument for partitioning
            /*arg = externalCallInst->getArgOperand(3);
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
            }*/
        } else if (externalFunction->getName() == "vprintf") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);

            Value* format = externalCallInst->getArgOperand(0);
            Value* vararg = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(format, ptsToMap)) {
                std::vector<Value*> ArgList;
                if (format->getType() != voidPtrType) {
                    format = InstBuilder.CreateBitCast(format, voidPtrType);
                }
                ArgList.push_back(format);
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
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

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            for (int i = 0; i < argNum; i++) {
                // has varargs
                Value* arg = externalCallInst->getArgOperand(i);
				if (!arg->getType()->isPointerTy())
					continue;

                IRBuilder<> InstBuilder(externalCallInst);
                if (arg->getType() != voidPtrType) {
                    arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                }
                std::vector<Value*> ArgList;
                ArgList.push_back(arg);

                if (isSensitiveArg(arg, ptsToMap)) {
                    if (Partitioning) {
                        externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg, ArgList);
                    } else {
                        externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                    }
                }
            }
        } else if (externalFunction->getName() == "snprintf") {
            // Variable arg number
            int argNum = externalCallInst->getNumArgOperands();
            // has varargs TODO
            for (int i = 0; i < argNum; i++) {
                if (i == 1) continue; // the size_t size arg
                Value* arg = externalCallInst->getArgOperand(i); 

                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

                std::vector<Value*> ArgList;
                ArgList.push_back(arg);

                if (Partitioning){
                    if (isSensitiveArg(arg, ptsToMap) ) {

                        IRBuilder<> Builder(externalCallInst);

                        CallInst* readLabel = nullptr;
                        ConstantInt* noOfByte = Builder.getInt64(1);
                        ConstantInt *One = Builder.getInt8(1);

                        readLabel = Builder.CreateCall(DFSanReadLabelFn,{arg , noOfByte});
                        readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

                        Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");
                        TerminatorInst* ThenTerm;
                        if(i != 0){
                            Instruction* SplitBefore = cast<Instruction>(externalCallInst);
                            ThenTerm = SplitBlockAndInsertIfThen(cmpInst, SplitBefore, false);

                            Builder.SetInsertPoint(ThenTerm);
                            CallInst* decryptArray = Builder.CreateCall(decryptFunction, ArgList);

                            Builder.SetInsertPoint(SplitBefore);
                        }
                        Instruction* SplitBeforeNew = cast<Instruction>(externalCallInst->getNextNode());
                        ThenTerm  = SplitBlockAndInsertIfThen(cmpInst, SplitBeforeNew, false);
                        Builder.SetInsertPoint(ThenTerm);

                        CallInst* enecryptArray = Builder.CreateCall(encryptFunction, ArgList);
                        Builder.SetInsertPoint(SplitBeforeNew);
                    }
                } else if (isSensitiveArg(arg, ptsToMap)) {
                    if (i != 0) {
                        // Don't decrypt the first argument, which is the destination.
                        InstBuilder.CreateCall(decryptFunction, ArgList);
                    }
                    CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                    encCInst->insertAfter(externalCallInst);
                }
            }
        } else if (externalFunction->getName() == "memcmp" || externalFunction->getName() == "crypto_sign_verify_detached") {
            Value* firstBuff = externalCallInst->getArgOperand(0);
            Value* secondBuff = externalCallInst->getArgOperand(1);
            Value* numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(firstBuff);
            firstArgList.push_back(numBytes);

            std::vector<Value*> secondArgList;
            secondArgList.push_back(secondBuff);
            secondArgList.push_back(numBytes);

            if (isSensitiveArg(firstBuff, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, firstBuff, firstArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
            }
            if (isSensitiveArg(secondBuff, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, secondBuff, secondArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, secondArgList);
                }
            }

        } else if (externalFunction->getName() == "crypto_generichash_update" || externalFunction->getName() == "crypto_generichash_final") {
            Value* firstBuff = externalCallInst->getArgOperand(1);
            Value* numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(firstBuff);
            firstArgList.push_back(numBytes);


            if (isSensitiveArg(firstBuff, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, firstBuff, firstArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
            }

        } else if (externalFunction->getName() == "randombytes_buf") {
            Value* firstBuff = externalCallInst->getArgOperand(0);
            Value* numBytes = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(firstBuff);
            firstArgList.push_back(numBytes);


            if (isSensitiveArg(firstBuff, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, firstBuff, firstArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
            }
        } else if (externalFunction->getName() == "crypto_pwhash_scryptsalsa208sha256" ) {
            Value* arg = externalCallInst->getArgOperand(4);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            IRBuilder<> Builder(externalCallInst);
            std::vector<Value*> ArgList;
            ArgList.push_back(arg);
            ArgList.push_back(Builder.getInt64(32));

            if (isSensitiveArg(arg, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }

        } else if (externalFunction->getName() == "crypto_sign_detached") {
            Value* arg = externalCallInst->getArgOperand(4);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            
            IRBuilder<> Builder(externalCallInst); 
            std::vector<Value*> ArgList;
            ArgList.push_back(arg);
            ArgList.push_back(Builder.getInt64(64));

            if (isSensitiveArg(arg, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName().find("llvm.memmove") != StringRef::npos) {

            Value* destBufferPtr = externalCallInst->getArgOperand(0);
            Value* srcBufferPtr = externalCallInst->getArgOperand(1);
            Value* numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(destBufferPtr);
            firstArgList.push_back(numBytes);

            std::vector<Value*> secondArgList;
            secondArgList.push_back(srcBufferPtr);
            secondArgList.push_back(numBytes);
        
            //errs() << "memmove function call: " << *externalCallInst<<"and parent "<<externalCallInst->getParent()->getParent()->getName() << "\n";
        
            if (isSensitiveArg(destBufferPtr, ptsToMap)) {
                //errs()<<"Sensitive dest buffer "<<*destBufferPtr<<"\n";
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, destBufferPtr, firstArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
            } 
            if (isSensitiveArg(srcBufferPtr, ptsToMap)) {
                //errs()<<"Sensitive src buffer "<<*srcBufferPtr<<"\n";
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, srcBufferPtr, secondArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, secondArgList);
                }
            }
            /*Value* firstBuff = externalCallInst->getArgOperand(0);
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

            if (firstBuffSens xor secondBuffSens) {
                if (firstBuffSens) {
                    ArgList.push_back(firstBuff);
                    ArgList.push_back(numBytes);
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                } else {
                    ArgList.push_back(secondBuff);
                    ArgList.push_back(numBytes);
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }*/
        } else if (externalFunction->getName() == "opendir") {
            Value* dirName = externalCallInst->getArgOperand(0);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            std::vector<Value*> ArgList;
            ArgList.push_back(dirName);

            if (isSensitiveArg(dirName, ptsToMap) ) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, dirName, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }

        } else if (externalFunction->getName() == "stat" || externalFunction->getName() == "lstat") {
            Value* pathName = externalCallInst->getArgOperand(0);
            Value* statBuf = externalCallInst->getArgOperand(1);
            if (isSensitiveArg(pathName, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(pathName);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, pathName, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
            if (isSensitiveArg(statBuf, ptsToMap)) {
                Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
                Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(statBuf);
                ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 144));

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, statBuf, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "fread") {
            Value* bufferPtr = externalCallInst->getArgOperand(0);
            Value* elemSize = externalCallInst->getArgOperand(1);
            Value* numElements = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                Value* numBytes = InstBuilder.CreateMul(elemSize, numElements, "mul");
                std::vector<Value*> ArgList;
                ArgList.push_back(bufferPtr);
                ArgList.push_back(numBytes);
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {  
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "strcmp" || externalFunction->getName() == "strcpy" || externalFunction->getName() =="strcat"
                || externalFunction->getName() == "strcasecmp" || externalFunction->getName() == "strstr" || externalFunction->getName() == "strcasestr") {
            if (externalCallInst->getNumOperands() < 3) 
                continue;
            Value* string1 = externalCallInst->getArgOperand(0);
            Value* string2 = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(string1);

            std::vector<Value*> secondArgList;
            secondArgList.push_back(string2);

            if (isSensitiveArg(string1, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, string1, firstArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
            }
            if (isSensitiveArg(string2, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, string2, secondArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, secondArgList);
                }
            }

        } else if (externalFunction->getName() == "strncmp" || externalFunction->getName() == "strncpy" || externalFunction->getName() =="strncat" 
                || externalFunction->getName() == "strncasecmp") {
            Value* firstBuff = externalCallInst->getArgOperand(0);
            Value* secondBuff = externalCallInst->getArgOperand(1);
            Value* numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(firstBuff);
            firstArgList.push_back(numBytes);

            std::vector<Value*> secondArgList;
            secondArgList.push_back(secondBuff);
            secondArgList.push_back(numBytes);

            if (isSensitiveArg(firstBuff, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, firstBuff, firstArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
            }
            if (isSensitiveArg(secondBuff, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, secondBuff, secondArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, secondArgList);
                }
            }
        } else if (externalFunction->getName() == "memchr" || externalFunction->getName() == "memrchr" || 
                externalFunction->getName() == "unlink") {
            Value* bufferPtr = externalCallInst->getArgOperand(0);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(bufferPtr);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName().find("strcasecmp") != StringRef::npos) {
            Value* destBufferPtr = externalCallInst->getArgOperand(0);
            Value* srcBufferPtr = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(srcBufferPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(srcBufferPtr);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, srcBufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
            if (isSensitiveArg(destBufferPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(destBufferPtr);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, destBufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "strlen" || externalFunction->getName() == "strrchr" || externalFunction->getName() == "strchr" || externalFunction->getName() == "strtol" ) {
            Value* string1 = externalCallInst->getArgOperand(0);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            std::vector<Value*> ArgList;
            ArgList.push_back(string1);

            if (isSensitiveArg(string1, ptsToMap) ) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, string1, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "aes_strdup") {
            Value* string1 = externalCallInst->getArgOperand(0);
            if (isSensitiveArg(string1, ptsToMap) ) {
                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                std::vector<Value*> ArgList;
                ArgList.push_back(string1);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, string1, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
            // It allocates and returns memory, is that sensitive?
            if (isSensitiveObjSet(getPAGObjNodeFromValue(externalCallInst))) {
                std::vector<Value*> ArgList;
                ArgList.push_back(externalCallInst);
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);
            }
        } else if (externalFunction->getName() == "crypt") {
            Value* string1 = externalCallInst->getArgOperand(0);
            Value* string2 = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            if (isSensitiveArg(string1, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(string1);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, string1, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
            if (isSensitiveArg(string2, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(string2);
                
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, string2, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }

        } else if (externalFunction->getName() == "cwd") {
            Value* buf = externalCallInst->getArgOperand(0);
            Value* bufLen = externalCallInst->getArgOperand(1);
            // The second argument might be a sensitive buffer
            
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            if (isSensitiveArg(buf, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(buf);
                ArgList.push_back(bufLen);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, buf, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
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

                        if (Partitioning){
                            externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, buf, ArgList);
                        } else {
                            externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                        }
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

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName().find("llvm.memcpy") != StringRef::npos) {
            if (externalCallInst->getParent()->getParent()->getName() == "apr_random_add_entropy" ||
                    externalCallInst->getParent()->getParent()->getName() == "event_open_logs") {
                continue;
            }
            Value* destBufferPtr = externalCallInst->getArgOperand(0);
            Value* srcBufferPtr = externalCallInst->getArgOperand(1);
            Value* numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(destBufferPtr);
            firstArgList.push_back(numBytes);

            std::vector<Value*> secondArgList;
            secondArgList.push_back(srcBufferPtr);
            secondArgList.push_back(numBytes);
        
            //errs() << "memcpy function call: " << *externalCallInst<<"and parent "<<externalCallInst->getParent()->getParent()->getName() << "\n";
        
            if (isSensitiveArg(destBufferPtr, ptsToMap)) {
                //errs()<<"Sensitive dest buffer "<<*destBufferPtr<<"\n";
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, destBufferPtr, firstArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
            } 
            if (isSensitiveArg(srcBufferPtr, ptsToMap)) {
                //errs()<<"Sensitive src buffer "<<*srcBufferPtr<<"\n";
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, srcBufferPtr, secondArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, secondArgList);
                }
            }
        } else if (externalFunction->getName() == "bzero") {
            Value *bufferPtr = externalCallInst->getArgOperand(0);
            Value *numBytes = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(bufferPtr);
                ArgList.push_back(numBytes);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "getcwd") {
            Value *bufferPtr = externalCallInst->getArgOperand(0);
            Value *numBytes = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                std::vector<Value*> ArgList;
                ArgList.push_back(bufferPtr);
                ArgList.push_back(numBytes);

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName().find("memset") != StringRef::npos) {
            Value *bufferPtr = externalCallInst->getArgOperand(0);
            Value *numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> ArgList;
            ArgList.push_back(bufferPtr);
            ArgList.push_back(numBytes);

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName().find("llvm.memset") != StringRef::npos) {
            Value *bufferPtr = externalCallInst->getArgOperand(0);
            Value *numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> ArgList;
            ArgList.push_back(bufferPtr);
            ArgList.push_back(numBytes);

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "read" || externalFunction->getName() == "pread" || externalFunction->getName() == "pread64") {
            Value* bufferPtr = externalCallInst->getArgOperand(1);
            Value* numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> ArgList;
            ArgList.push_back(bufferPtr);
            ArgList.push_back(numBytes);

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }

        } else if (externalFunction->getName() == "sodium_memzero") {
            Value* bufferPtr = externalCallInst->getArgOperand(0);
            Value* numBytes = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> ArgList;
            ArgList.push_back(bufferPtr);
            ArgList.push_back(numBytes);

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }
        } else if (externalFunction->getName() == "write") {
            Value* bufferPtr = externalCallInst->getArgOperand(1);
            Value* numBytes = externalCallInst->getArgOperand(2);

            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> ArgList;
            ArgList.push_back(bufferPtr);
            ArgList.push_back(numBytes);

            if (isSensitiveArg(bufferPtr, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, bufferPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
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
                /*InstBuilder.CreateCall(decryptFunction, ArgList);
                // Encrypt it back
                CallInst* encCInst = CallInst::Create(encryptFunction, ArgList);
                encCInst->insertAfter(externalCallInst);*/
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, voidSockaddrVal, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }

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

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            Function* decryptFunctionArray = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunctionArray = M.getFunction("encryptArrayForLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(host);

            std::vector<Value*> secondArgList;
            secondArgList.push_back(port);


            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);

            if (Partitioning){
                /*if (isSensitiveArg(host, ptsToMap)) {
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, host, firstArgList);
                }
                if (isSensitiveArg(port, ptsToMap)) {
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, port, secondArgList);
                }
                if (isSensitiveArg(addrHints, ptsToMap)) {
                    std::vector<Value*> ArgList;
                    Value* addrHintsVoidPtr= InstBuilder.CreateBitCast(addrHints, voidPtrType);
                    ArgList.push_back(addrHintsVoidPtr);
                    ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 48));
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunctionArray, encryptFunctionArray, addrHintsVoidPtr, ArgList);
                }*/

            }else{
                if (isSensitiveArg(host, ptsToMap)) {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
                if (isSensitiveArg(port, ptsToMap)) {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, secondArgList);
                }
                if (isSensitiveArg(addrHints, ptsToMap)) {
                    std::vector<Value*> ArgList;
                    Value* addrHintsVoidPtr= InstBuilder.CreateBitCast(addrHints, voidPtrType);
                    ArgList.push_back(addrHintsVoidPtr);
                    ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 48));
                    externalFunctionHandler(M, externalCallInst, decryptFunctionArray, encryptFunctionArray, ArgList);
                }
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

            if (Partitioning){
                externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
            } else {
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }
            //externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
        } else if (externalFunction->getName() == "pthread_mutex_unlock") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 40));

            if (Partitioning){
                externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
            } else {
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }
            //externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
        } else if (externalFunction->getName() == "pthread_mutex_init") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 40));

            if (Partitioning){
                externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
            } else {
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }
            //externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
        } else if (externalFunction->getName() == "pthread_mutex_destroy") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 40));

            if (Partitioning){
                externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
            } else {
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }
            //externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
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

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
                //externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }
            if (isSensitiveArg(pthreadAttrTArg, ptsToMap)) {
                std::vector<Value*> ArgList;
                Value* encryptedPtr= InstBuilder.CreateBitCast(pthreadAttrTArg, voidPtrType);
                ArgList.push_back(encryptedPtr);
                ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 56));

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
                //externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
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

                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, dirp, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
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
        } else if (externalFunction->getName() == "epoll_ctl") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(3), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 12));

            if (Partitioning){
                externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
            } else {
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }

        } else if (externalFunction->getName() == "epoll_wait") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(1), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 12));
            
            if (Partitioning){
                externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
            } else {
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }

        } else if (externalFunction->getName() == "uname") {
            PointerType* voidPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
            IntegerType* longType = IntegerType::get(M.getContext(), 64);
            Function* decryptFunction = M.getFunction("decryptArrayForLibCall");
            Function* encryptFunction = M.getFunction("encryptArrayForLibCall");
            std::vector<Value*> ArgList;
            Value* encryptedPtr= InstBuilder.CreateBitCast(externalCallInst->getArgOperand(0), voidPtrType);
            ArgList.push_back(encryptedPtr);
            ArgList.push_back(ConstantInt::get(IntegerType::get(externalCallInst->getContext(), 64), 390));
            
            if (Partitioning){
                externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, encryptedPtr, ArgList);
            } else {
                externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
            }

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

                Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
                Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

                if (isSensitiveArg(arg, ptsToMap)) {
                    std::vector<Value*> ArgList;
                    if (arg->getType() != voidPtrType) {
                        arg = InstBuilder.CreateBitCast(arg, voidPtrType);
                    }
                    ArgList.push_back(arg);

                    if (Partitioning){
                        externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, arg, ArgList);
                    } else {
                        externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                    }
                }
            }
        /*}else if (externalFunction->getName() == "atoi" ) {
            Value* str = externalCallInst->getArgOperand(0);
            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            std::vector<Value*> ArgList;
            ArgList.push_back(str);

            if (isSensitiveArg(str, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, str, ArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, ArgList);
                }
            }*/
        } else if (externalFunction->getName() == "fopen64") {
            Value* string1 = externalCallInst->getArgOperand(0);
            Value* string2 = externalCallInst->getArgOperand(1);

            Function* decryptFunction = M.getFunction("decryptStringBeforeLibCall");
            Function* encryptFunction = M.getFunction("encryptStringAfterLibCall");

            std::vector<Value*> firstArgList;
            firstArgList.push_back(string1);

            std::vector<Value*> secondArgList;
            secondArgList.push_back(string2);

            if (isSensitiveArg(string1, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, string1, firstArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, firstArgList);
                }
            }
            if (isSensitiveArg(string2, ptsToMap)) {
                if (Partitioning){
                    externalFunctionHandlerForPartitioning(M, externalCallInst, decryptFunction, encryptFunction, string2, secondArgList);
                } else {
                    externalFunctionHandler(M, externalCallInst, decryptFunction, encryptFunction, secondArgList);
                }
            }
        } else {
            UnsupportedCallSet.insert(externalCallInst);
        }
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

    const DataLayout& dataLayout = M.getDataLayout();
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
            errs() << "size of global type: " << *globalType << ": " << sizeOfGlobalType << "\n";
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
    SensitiveLoadPtrCheckSet = new std::set<Value*>(SensitiveLoadPtrCheckList.begin(), SensitiveLoadPtrCheckList.end());
    SensitiveLoadCheckSet = new std::set<Value*>(SensitiveLoadCheckList.begin(), SensitiveLoadCheckList.end());
    SensitiveGEPPtrCheckSet = new std::set<Value*>(SensitiveGEPPtrCheckList.begin(), SensitiveGEPPtrCheckList.end());

    SensitiveStoreSet = new std::set<StoreInst*>(SensitiveStoreList.begin(), SensitiveStoreList.end());
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
    return nullptr;
}

void EncryptionPass::preprocessSensitiveAnnotatedPointers(Module &M) {
    std::map<PAGNode*, std::set<PAGNode*>> ptsToMap = getAnalysis<WPAPass>().getPAGPtsToMap();
    std::map<PAGNode*, std::set<PAGNode*>> ptsFromMap = getAnalysis<WPAPass>().getPAGPtsFromMap();
    PAG* pag = getAnalysis<WPAPass>().getPAG();
    ConstraintGraph* constraintGraph = getAnalysis<WPAPass>().getConstraintGraph();

    std::vector<PAGNode*> workList;
    std::vector<PAGNode*> processedList;

    for (PAGNode* initSensitiveNode: SensitiveObjList) {
        errs() << "initSensitiveNode: "<<initSensitiveNode->getId()<<"\n";
        assert(initSensitiveNode->hasValue() && "PAG Node should have a value if it came so far");
        workList.push_back(initSensitiveNode);
    }
    /*errs()<<"PointsFromNodes for sensitive obj \n";
    PAGNode* work1 = workList.back();
    std::copy(ptsFromMap[work1].begin(), ptsFromMap[work1].end(), std::back_inserter(workList));
    for (PAGNode* fromNode: workList) {
        errs()<<"PointsFromNode "<<*fromNode->getValue()<<"\n";
    }
    return;*/
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

        //next if added for test purpose; should be removed later
        /*if (isa<GepObjPN>(work))
          continue;*/
        /*if(Partitioning){
            if (isa<GepObjPN>(work)){
                errs()<<"Work id :"<<work->getId()<<"\n";
                errs()<<"Base Id "<<constraintGraph->getBaseObjNode(work->getId())<<"\n";
            }

        }*/
        // And Child Nodes, and who ever they point to 
        NodeBS nodeBS = constraintGraph->getAllFieldsObjNode(work->getId());
        /*if(work->getId() != constraintGraph->getBaseObjNode(work->getId()))
            continue;*/

        for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
            // And everything they point to

            PAGNode* fldNode = pag->getPAGNode(*fIt);
            /*errs()<<"FLDNode "<<fldNode->getId()<<" ";
            if (isa<GepObjPN>(fldNode)) {
                SensitiveObjList.push_back(fldNode);
               errs()<<"Pushed "<<fldNode->getId()<<" "; // Individual fields of the Sensitive object is also sensitive
            }*/
            std::copy(ptsToMap[fldNode].begin(), ptsToMap[fldNode].end(), std::back_inserter(workList));
            std::copy(ptsToMap[fldNode].begin(), ptsToMap[fldNode].end(), std::back_inserter(SensitiveObjList));
        }
        //errs()<<"\n";
    }

    // Remove all top-level pointers in SensitiveObjList

    std::vector<PAGNode*>::iterator it = SensitiveObjList.begin();
    while (it != SensitiveObjList.end()) {
        PAGNode* sensitiveNode = *it;
        assert(sensitiveNode->hasValue() && "PAG node made it so far, must have value");
        Value* sensitiveValue = const_cast<Value*>(sensitiveNode->getValue());
        if (isaCPointer(sensitiveValue) || isa<CastInst>(sensitiveValue)) {
            errs()<<"Erased "<<*sensitiveValue<<"\n";
            it = SensitiveObjList.erase(it);
        } else {
            it++;
        }
    }
}


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
                                            //assert(false && "Cannot find sizeof type");
                                            errs() << "Couldn't find sizeof type for " << *CI << " in function: " << F->getName() << "\n";
                                            continue;
                                        }
                                    }

                                    errs() << "Should have fixed up callinst: " << *CI << " for type : " << *(sizeOfType) << "\n";
                                    ConstantInt* constInt = dyn_cast<ConstantInt>(CI->getOperand(argIndex));
                                    if (constInt) {
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
}

void EncryptionPass::addPAGNodesFromSensitiveObjects(std::vector<Value*>& sensitiveMemAllocCalls) {

    PAG* pag = getAnalysis<WPAPass>().getPAG();

    for (Value* sensitiveAlloc: sensitiveMemAllocCalls) {
        NodeID objID = pag->getObjectNode(sensitiveAlloc);
        NodeBS nodeBS = pag->getAllFieldsObjNode(objID);

        for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
            PAGNode* fldNode = pag->getPAGNode(*fIt);
            if (GepObjPN* gepNode = dyn_cast<GepObjPN>(fldNode)) {
                // If this is a pointer type, then just skip it
                int index = gepNode->getLocationSet().getOffset();
                // Get the value, and check the type
                Value* sensitiveValue = const_cast<Value*>(gepNode->getValue());
                if (StructType* senStType = dyn_cast<StructType>(sensitiveValue->getType()->getPointerElementType())) {
                    Type* subType = senStType->getElementType(index);
                    // If this is a sub-type struct, then we have a problem and should
                    // abort
                    assert(!isa<StructType>(subType) && "Don't support structs in a sensitive struct yet");
                    /*
                    if (isa<PointerType>(subType) || isa<ArrayType>(subType)) {
                        // Skip!
                        continue;
                    }
                    */
                }
                SensitiveObjList.push_back(fldNode);
            } else {
                SensitiveObjList.push_back(fldNode);
            }
        }
    }

    /* This is integrity stuff -- commenting it out on this branch to prevent
     * breaking - TODO @tpalit
    // Figure this out baby
	for (Module::iterator MIterator = mod->begin(); MIterator != mod->end(); MIterator++) {
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
								if (CInst->getCalledValue()->getName().startswith("llvm.ptr.annotation")) {
									Value* SV = CInst->getArgOperand(0);
                                    if (BitCastInst* bcInst = dyn_cast<BitCastInst>(SV)) {
                                        // The first operand is a Gep? 
                                        Value* operand = bcInst->getOperand(0);
                                        if (GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(operand)) {
                                            ConstantInt* constantInt = dyn_cast<ConstantInt>(gep->getOperand(2));
                                            int sensitiveIndex = constantInt->getZExtValue();
                                            // Find the gep node
                                            NodeID objID = pag->getObjectNode(gep->getPointerOperand());
                                            NodeBS nodeBS = pag->getAllFieldsObjNode(objID);

                                            for (NodeBS::iterator fIt = nodeBS.begin(), fEit = nodeBS.end(); fIt != fEit; ++fIt) {
                                                PAGNode* fldNode = pag->getPAGNode(*fIt);
                                                if (GepObjPN* gepNode = dyn_cast<GepObjPN>(fldNode)) {
                                                    // If this is a pointer type, then just skip it
                                                    int gepObjIndex = gepNode->getLocationSet().getOffset();
                                                    if (sensitiveIndex == gepObjIndex) { 
                                                        SensitiveObjList.push_back(fldNode);
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
    */
}

void EncryptionPass::performHMACInstrumentation(Module& M) {
    // For HMAC, the instrumentation is simpler compared to AES encryption
    // We don't really replace anything here. Our work is purely computing the
    // authentication code and storing it immediately before the address being
    // accessed (starting at (address - 32) (for SHA-256)
    for (std::vector<InstructionReplacement*>::iterator ReplacementIt = ReplacementList.begin() ; 
            ReplacementIt != ReplacementList.end(); ++ReplacementIt) {
        InstructionReplacement* Repl = *ReplacementIt;
        if (Repl->Type == LOAD) {
            IRBuilder<> Builder(Repl->NextInstruction); // Insert before "next" instruction
            LoadInst* LdInst = dyn_cast<LoadInst>(Repl->OldInstruction);

            // Call the authentication routine
            HMAC.insertCheckAuthentication(LdInst);
            checkAuthenticationCount++;
        } else	if (Repl->Type == STORE) {
            IRBuilder<> Builder(Repl->OldInstruction); // Insert before the current Store instruction
            StoreInst* StInst = dyn_cast<StoreInst>(Repl->OldInstruction);
            
            // Call the hmac computation and update route
            HMAC.insertComputeAuthentication(StInst);
            computeAuthenticationCount++;
        }
    }
}

void EncryptionPass::collectSensitiveObjectsForWidening() {
    if (!Partitioning) {
        // For each of the pointers in pointsFrom, whatever they can point to will
        // have to be widened
        for (PAGNode* ptrNode: pointsFroms) {
            // What it points to
            for (PAGNode* ptd: getAnalysis<WPAPass>().pointsToSet(ptrNode->getId())) {
                if (isa<DummyValPN>(ptd) || isa<DummyObjPN>(ptd))
                    continue;
                if (isa<ObjPN>(ptd)) {
                    SensitiveObjList.push_back(ptd);
                }
            }
        }
    }
}

/**
 * Find the base of the memory operation operand
 * that is outside the Loop
 */
Value* EncryptionPass::getBaseValueForMemOp(Instruction* inst, Loop* loop) {
    GetElementPtrInst* gep = nullptr;

    if (LoadInst* ldInst = dyn_cast<LoadInst>(inst)) {
        gep = dyn_cast<GetElementPtrInst>(ldInst->getPointerOperand());
    } else if (StoreInst* stInst = dyn_cast<StoreInst>(inst)) {
        gep = dyn_cast<GetElementPtrInst>(stInst->getPointerOperand());
    }
    assert(gep && "Can't get base value of anything other than geps");
    Value* gepBase = gep->getPointerOperand();

    // The pointer element should not be a struct type
    if (isa<StructType>(findBaseType(gepBase->getType()))) {
        return nullptr;
    }
    Value* trueBase = nullptr;
    // We handle two cases --
    // 1. Where the base is a local operand be it a pointer or a variable
    // 2. Where the base is an argument
    if (Argument* arg = dyn_cast<Argument>(gepBase)) {
        trueBase = arg;
    } else if (LoadInst* loadInst = dyn_cast<LoadInst>(gepBase)){
        trueBase = loadInst->getPointerOperand();
    } else if (AllocaInst* allocInst = dyn_cast<AllocaInst>(gepBase)) {
        trueBase = allocInst;
    }
    if (trueBase) {
        // Verify that this trueBase is outside of the loop
        bool inLoop = false;
        if (Instruction* trueBaseInst = dyn_cast<Instruction>(trueBase)) {
            BasicBlock* trueBaseBB = trueBaseInst->getParent();
            for (BasicBlock* bb: loop->getBlocks()) {
                if (bb == trueBaseBB) {
                    inLoop = true;
                    break;
                }            
            }
            if (inLoop) {
                return nullptr;
            } else {
                return trueBase;
            }
        } else {
            // If it's an argument or a global variable, it is outside the
            // loop anyway
            return trueBase;
        }

    }
    return nullptr;
}

BasicBlock* EncryptionPass::insertNewPH(LLVMContext& ctx, DominatorTree* DT, LoopInfo* LI, Loop* loop, ValueToValueMapTy& VMap) {
    BasicBlock* oldPH = loop->getLoopPredecessor();
    BasicBlock* loopHeader = loop->getHeader();

    // Create a new preheader, where we'll stick our if checks
    BasicBlock* NewPH = BasicBlock::Create(ctx, "hoist.PH", oldPH->getParent(), loopHeader);
    Loop* ParentLoop = loop->getParentLoop();
    if (ParentLoop) {
        ParentLoop->addBasicBlockToLoop(NewPH, *LI);
    }
    // the oldPH should lead to NewPH
    Instruction* termInst = oldPH->getTerminator();
    BranchInst* branchInst = dyn_cast<BranchInst>(termInst);
    assert(branchInst && "Can't handle anything but branch instruction here");
    for (int i = 0; i < branchInst->getNumSuccessors(); i++) {
        if (branchInst->getSuccessor(i) == loopHeader) {
            branchInst->setSuccessor(i, NewPH); 
        }
    }

//    VMap[oldPH] = NewPH; // Needed to update the dominator relationships.
//    Not needed any more. Will update the newloop's header manually
    DT->addNewBlock(NewPH, oldPH);
    DT->changeImmediateDominator(NewPH, oldPH);
    DT->changeImmediateDominator(loop->getHeader(), NewPH);
    return NewPH;
}

void EncryptionPass::addTaintCheck(Loop* OrigLoop, Loop* NewLoop, BasicBlock* NewPH, Value* baseMemLoc) {
    Value* addrForReadLabel = baseMemLoc;
    IRBuilder<> Builder(NewPH);

    LLVMContext& Ctx = baseMemLoc->getContext();
    IntegerType* ShadowTy = IntegerType::get(Ctx, 8);
    IntegerType* IntptrTy = IntegerType::get(Ctx, 64);
    Type *DFSanReadLabelArgs[2] = { Type::getInt8PtrTy(Ctx), IntptrTy };
    FunctionType* FTypeReadLabel = FunctionType::get(ShadowTy, DFSanReadLabelArgs, false);

    InlineAsm* DFSanReadLabelFn = InlineAsm::get(FTypeReadLabel, "movq %mm0, %rax\n\t and %rax, $1 \n\t movb ($1), $0", "=r,r,r,~{rax}", true, false);

    CallInst* readLabel = nullptr;
    ConstantInt* noOfByte = Builder.getInt64(1);
    ConstantInt *One = Builder.getInt8(1);

    // If it's not a i8* cast it

    Type* readLabelPtrElemType = addrForReadLabel->getType()->getPointerElementType();
    IntegerType* intType = dyn_cast<IntegerType>(readLabelPtrElemType);

    if (readLabelPtrElemType->isPointerTy()) {
        // Create a Load to load the IR pointer
        addrForReadLabel = Builder.CreateLoad(readLabelPtrElemType, addrForReadLabel);
    }

    if (!(intType && intType->getBitWidth() == 8)) {
        // Create the cast
        Type* voidPtrType = PointerType::get(IntegerType::get(Ctx, 8), 0);
        addrForReadLabel = Builder.CreateBitCast(addrForReadLabel, voidPtrType);
    }

    readLabel = Builder.CreateCall(DFSanReadLabelFn,{addrForReadLabel , noOfByte});
    readLabel->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);

    Value* cmpInst = Builder.CreateICmpEQ(readLabel, One, "cmp");

    BranchInst* branchInst = Builder.CreateCondBr(cmpInst, OrigLoop->getHeader(), NewLoop->getHeader());
}

Loop* EncryptionPass::cloneAndInsertLoop(DominatorTree* DT, LoopInfo* LI, Loop* loop, BasicBlock* NewPH,
        ValueToValueMapTy& VMap) {
    // Clone the loop
    Loop* OrigLoop = loop;
    Function *F = OrigLoop->getHeader()->getParent();

    // Create new loop
    BasicBlock* Before = loop->getHeader();
    assert(Before && "Should have a header!");
    Loop* ParentLoop = OrigLoop->getParentLoop();
    Loop *NewLoop = LI->AllocateLoop();
    if (ParentLoop)
        ParentLoop->addChildLoop(NewLoop);
    else
        LI->addTopLevelLoop(NewLoop);

    for (BasicBlock *BB : OrigLoop->getBlocks()) {
        // Store it all in VMap, because the PHINode is weird
        //ValueToValueMapTy VMap2;
        BasicBlock *NewBB = CloneBasicBlock(BB, VMap, "", F);
       
        resetInstructions(NewBB, VMap);

        VMap[BB] = NewBB;
        /*
        errs() << "Cloned bb is: \n";
        NewBB->dump();
        */

        // Update LoopInfo.
        NewLoop->addBasicBlockToLoop(NewBB, *LI);

        // Add DominatorTree node. After seeing all blocks, update to correct IDom.
        // Except for the new loop header. The new loop's header is the NewPH
        DT->addNewBlock(NewBB, NewPH);

    }


    for (BasicBlock *BB : OrigLoop->getBlocks()) {
        // We have already adjusted the DomTree for the headers
        if (BB == OrigLoop->getHeader()) {
            continue;
        }
        // Update DominatorTree.
        BasicBlock *IDomBB = DT->getNode(BB)->getIDom()->getBlock();
        DT->changeImmediateDominator(cast<BasicBlock>(VMap[BB]),
                cast<BasicBlock>(VMap[IDomBB]));
    }

    // Move them physically from the end of the block list.
    F->getBasicBlockList().splice(Before->getIterator(), F->getBasicBlockList(),
            NewPH);
    F->getBasicBlockList().splice(Before->getIterator(), F->getBasicBlockList(),
            NewLoop->getHeader()->getIterator(), F->end());

    // Now, let's reset the instructions on the parent
    for (BasicBlock* newBB: NewLoop->getBlocks()) {
        for (BasicBlock::iterator BBIterator = newBB->begin(); BBIterator != newBB->end(); BBIterator++) {
            if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                if (PHINode* phi = dyn_cast<PHINode>(Inst)) {
                    for (int i = 0; i < phi->getNumIncomingValues(); i++) {
                        BasicBlock* orig = phi->getIncomingBlock(i);
                        if (VMap.find(orig) != VMap.end()) {
                            phi->setIncomingBlock(i, cast<BasicBlock>(VMap[orig]));
                        }
                        Value* val = phi->getIncomingValue(i);
                        if (VMap.find(val) != VMap.end()) {
                            phi->setIncomingValue(i, VMap[val]);
                        }
                    }

                } else {
                    for (int i = 0; i < Inst->getNumOperands(); i++) {
                        Value* op = Inst->getOperand(i);
                        if (VMap.find(op) != VMap.end()) {
                            Inst->setOperand(i, VMap[op]);
                        }
                    }
                }
            }
        }
    }
    return NewLoop;
}


bool EncryptionPass::hasPartialSenMemAccess(BasicBlock* bb, std::set<Instruction*>& candidateInsns) {
    for (BasicBlock::iterator BBIterator = bb->begin(); BBIterator != bb->end(); BBIterator++) {
        if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
            if (std::find(candidateInsns.begin(), candidateInsns.end(), Inst) != candidateInsns.end()) {
                return true;
            }
        }
    }
    return false;
}

bool EncryptionPass::hasFunctionCallInBody(Loop* loop) {
    for (BasicBlock* bb: loop->getBlocks()) {
        //if (bb != loop->getHeader() && bb != loop->getExitingBlock()) {
            for (BasicBlock::iterator BBIterator = bb->begin(); BBIterator != bb->end(); BBIterator++) {
                if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                    if (CallInst* callInst = dyn_cast<CallInst>(Inst)) {
                        if (callInst->getCalledFunction() && callInst->getCalledFunction()->getName() == "printf") {
                            continue;
                        }
                        return true;
                    }
                }
            }
        //}
    }
    return false;
}

bool EncryptionPass::hasSenBB(Loop* loop, std::set<BasicBlock*>& senBBs) {
    for (BasicBlock* bb: loop->getBlocks()) {
        if (std::find(senBBs.begin(), senBBs.end(), bb) != senBBs.end()) {
            return true;
        }
    }
    return false;
}

bool EncryptionPass::sanitizeCandidatesForNullCheck(std::map<Value*, std::set<Instruction*>>& baseMemInsnMap) {
    std::map<Value*, std::set<Instruction*>>::iterator baseMapIt = baseMemInsnMap.begin();
    if (baseMapIt == baseMemInsnMap.end()) {
        return false;
    }

    do
    {
        Value* baseMemLoc = baseMapIt->first;
        if (hasNullCheck(baseMemLoc)) {
            // Remove it
            baseMapIt = baseMemInsnMap.erase(baseMapIt);
            if (baseMapIt == baseMemInsnMap.end()) {
                break;
            }
        }
        baseMapIt++;
    } while (baseMapIt != baseMemInsnMap.end());

    if (baseMemInsnMap.size() == 0) {
        return false;
    }
    return true;
}

void EncryptionPass::getMemBases(Loop* loop, std::set<Instruction*>& candidateInsns, std::map<Value*, std::set<Instruction*>>& baseMemInsnMap, bool aggressive) {
    for (BasicBlock* bb: loop->getBlocks()) {
        if (!aggressive) {
            if (bb == loop->getHeader() || bb == loop->getExitingBlock()) {
                continue;
            }
        }
        for (BasicBlock::iterator BBIterator = bb->begin(); BBIterator != bb->end(); BBIterator++) {
            if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                if (std::find(candidateInsns.begin(), candidateInsns.end(), Inst) != candidateInsns.end()) {
                    // If one of these is not a gep instruction, then return
                    // false. Too much work to continue this
                    GetElementPtrInst* gep = nullptr;
                    if (LoadInst* ldInst = dyn_cast<LoadInst>(Inst)) {
                        gep = dyn_cast<GetElementPtrInst>(ldInst->getPointerOperand());
                        if (aggressive) {
                            if (LoadInst* ldPtrInst = dyn_cast<LoadInst>(ldInst->getPointerOperand())) {
                                // Who's the base of this? 
                                Value* baseValue = ldPtrInst->getPointerOperand();
                                if (isa<AllocaInst>(baseValue)) {
                                    baseMemInsnMap[baseValue].insert(Inst);
                                }
                                continue;
                            }
                        } else {
                            if (!gep) {
                                continue;
                            }
                        }
                    }
                    if (StoreInst* stInst = dyn_cast<StoreInst>(Inst)) {
                        gep = dyn_cast<GetElementPtrInst>(stInst->getPointerOperand());
                        if (aggressive) {
                            if (LoadInst* ldPtrInst = dyn_cast<LoadInst>(stInst->getPointerOperand())) {
                                // Who's the base of this? 
                                Value* baseValue = ldPtrInst->getPointerOperand();
                                if (isa<AllocaInst>(baseValue)) {
                                    baseMemInsnMap[baseValue].insert(Inst);
                                }
                                continue;
                            }
                        } if (!gep) {
                            continue;
                        }
                    }
                    // This is a sensitive memory location
                    Value* baseMemLoc = getBaseValueForMemOp(Inst, loop);
                    if (baseMemLoc) {
                        baseMemInsnMap[baseMemLoc].insert(Inst);
                    }
                }
            }
        }
    }

}

bool EncryptionPass::allSameMemBase(Loop* loop, Value** baseMemLoc, std::set<Instruction*>& candidateInsns, std::set<Instruction*>& outInsns) {
    *baseMemLoc = nullptr;
    for (BasicBlock* bb: loop->getBlocks()) {
        if (bb == loop->getHeader() || bb == loop->getExitingBlock()) {
            continue;
        }
        for (BasicBlock::iterator BBIterator = bb->begin(); BBIterator != bb->end(); BBIterator++) {
            if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                if (std::find(candidateInsns.begin(), candidateInsns.end(), Inst) != candidateInsns.end()) {
                    // If one of these is not a gep instruction, then return
                    // false. Too much work to continue this
                    GetElementPtrInst* gep = nullptr;
                    if (LoadInst* ldInst = dyn_cast<LoadInst>(Inst)) {
                        gep = dyn_cast<GetElementPtrInst>(ldInst->getPointerOperand());
                        if (!gep) {
                            return false;
                        }
                    }
                    if (StoreInst* stInst = dyn_cast<StoreInst>(Inst)) {
                        gep = dyn_cast<GetElementPtrInst>(stInst->getPointerOperand());
                        if (!gep) {
                            return false;
                        }
                    }
                    // This is a sensitive memory location
                    Value* thisBaseMem = getBaseValueForMemOp(Inst, loop);
                    if ((*baseMemLoc != nullptr) && (thisBaseMem != *baseMemLoc)) {
                        return false;
                    }
                    outInsns.insert(Inst);
                    *baseMemLoc = thisBaseMem;
                }
            }
        }
    }
    if (*baseMemLoc) {
        return true;
    } else {
        return false;
    }
}

void EncryptionPass::performHoistOptimization() {
    std::set<Function*> candidateFns;
    std::set<BasicBlock*> candidateBBs;
    std::set<Instruction*> candidateInsns;

    for (std::vector<InstructionReplacement*>::iterator ReplacementIt = ReplacementCheckList.begin() ;
            ReplacementIt != ReplacementCheckList.end(); ++ReplacementIt) {
        InstructionReplacement* Repl = *ReplacementIt;
        Instruction* partiallySenMemInst = Repl->OldInstruction;
        candidateFns.insert(partiallySenMemInst->getParent()->getParent());
        candidateBBs.insert(partiallySenMemInst->getParent());
        candidateInsns.insert(partiallySenMemInst);
    }

    bool aggressive = false;
    // Now, for each function, find the Loops in it
    for (Function* candidateFn: candidateFns) {
        if (candidateFn->getName().startswith("tlibc_internal")) {
            aggressive = true;
        } else {
            aggressive = false;
        }
        if (candidateFn->getName() == "cfbr_encrypt_block") {
            continue;
        }
        /*
        if (candidateFn->getName() == "stream_ref.257") {
            errs() << "Found stream_ref.257\n";
        }
        */
        std::set<Loop*> candidateLoops;
        // We care about only tightloops, that run multiple times 
        LoopInfo* LI = &(getAnalysis<LoopInfoWrapperPass>(*candidateFn).getLoopInfo());
        DominatorTree* DT = &(getAnalysis<DominatorTreeWrapperPass>(*candidateFn).getDomTree());

        std::vector<Loop*> loopsInPreorder;
        for (Loop* loop: LI->getLoopsInPreorder()) {
            loopsInPreorder.push_back(loop);
        }
        for (Loop* loop: loopsInPreorder) {
            // Can handle only innermost loops that are safe to clone, and
            // have a preheader.
            // Important: We don't want to deal with loops without preheaders
            // at this stage. Though later, when handling multiple sensitive
            // arrays, we *do* handle loops that don't have a preheader
            //
            // From llvm:  A preheader is a (singular) loop predecessor which
            // ends in an unconditional transfer of control to the loop
            // header.
            if (!loop->empty() || !loop->isSafeToClone() || (loop->getLoopPreheader() == nullptr)) {
                continue;
            }
            BasicBlock* header = loop->getHeader();
            Function* function = header->getParent();
            BasicBlock* exitingBlock = loop->getExitingBlock();
            // Check that this loop has a single exit block for now
            // TODO -- do we need this? 
            if (!aggressive) {
                if (!loop->getExitingBlock()) {
                    continue;
                }
            }

            // Check that this is a loop that is interesting
            if (!hasSenBB(loop, candidateBBs)) {
                continue;
            }

            // @tpalit: This isn't needed, right? 
            // Check that the header and the exit condition doesn't have any
            // partially sensitive memory access
            /*
            if (hasPartialSenMemAccess(header, candidateInsns) || hasPartialSenMemAccess(exitingBlock, candidateInsns)) {
                continue;
            }
            */

            if (hasFunctionCallInBody(loop)) {
                continue;
            }

            Value* baseMem = nullptr;
            std::map<Value*, std::set<Instruction*>> baseMemInsnMap;

            getMemBases(loop, candidateInsns, baseMemInsnMap, aggressive);
            
            errs() << "Number of independent taint-tracked base memory addresses: " << baseMemInsnMap.size() <<"\n";
            if (baseMemInsnMap.size() > perLoopHoistLimit) {
                continue;
            }
            errs() << "Proceeding ... \n";
            if (!sanitizeCandidatesForNullCheck(baseMemInsnMap)) {
                continue;
            }
            /*
            if (!allSameMemBase(loop, &baseMem, candidateInsns, partiallySenMemInsts)) {
                continue;
            }
            */

            std::map<Value*, std::set<Instruction*>>::iterator baseMapIt = baseMemInsnMap.begin();

            std::vector<Loop*> clonedLoops;
            clonedLoops.push_back(loop);

            for (; baseMapIt != baseMemInsnMap.end(); baseMapIt++) {
                Value* baseMem = baseMapIt->first;
                std::set<Instruction*>& partiallySenMemInsts = baseMapIt->second;

                // Do this transformation for each of the cloned Loops
                std::vector<Loop*> tempClonedLoops;
                for (Loop* clonedLoop: clonedLoops) { 
                    Loop* newLoop = specializeLoopAndHoist(LI, DT, clonedLoop, partiallySenMemInsts, baseMem, baseMemInsnMap);
                    tempClonedLoops.push_back(newLoop);

                    // Remove the handled partially sensitive mem instructions
                    for (Instruction* inst: partiallySenMemInsts) {
                        std::vector<InstructionReplacement*>::iterator ReplacementIt = ReplacementCheckList.begin();
                        while (ReplacementIt != ReplacementCheckList.end()) {
                            InstructionReplacement* Repl = *ReplacementIt;
                            Instruction* partiallySenMemInst = Repl->OldInstruction;
                            if (partiallySenMemInst == inst) {
                                ReplacementIt = ReplacementCheckList.erase(ReplacementIt);
                                if (ReplacementIt == ReplacementCheckList.end()) {
                                    break; // done
                                }
                            } else {
                                ReplacementIt++;
                            }
                        }
                    }
                    errs() << "Specialized loop and hoisted check in function: " << candidateFn->getName() << "\n";
                    //errs() << "Dumping function: "<< *function << "\n";
                }
                //clonedLoops.clear();
                // Copy the tempClonedLoops into clonedLoops
                std::copy(tempClonedLoops.begin(), tempClonedLoops.end(), std::back_inserter(clonedLoops));
                //clonedLoops.begin(), clonedLoops.end(), std::back_inserter(tempClonedLoops));
            }
        }
    }
}


/* Go over every instruction in VMap. If the source is in
 * baseMemInsMap for *other* basememlocs then, add then to the
 * corresponding sensitive list.
 */
void EncryptionPass::updateSensitiveMemLists(std::map<Value*, std::set<Instruction*>>& baseMemInsMap, Value* baseMemLoc, ValueToValueMapTy& VMap) {
    std::map<Value*, std::set<Instruction*>>::iterator baseMapIt = baseMemInsMap.begin();
    std::vector<Instruction*> tempList; // list to temporarily store the cloned objects

    for(; baseMapIt != baseMemInsMap.end(); baseMapIt++) {
        Value* mapBaseMem = baseMapIt->first;
        if (mapBaseMem != baseMemLoc) {
            tempList.clear();
            std::set<Instruction*>& partiallySenMemList = baseMapIt->second;
            // Go over the VMap, updating the tempList
            for (Instruction* partiallySenMemInst: partiallySenMemList) {
                auto it = VMap.find(partiallySenMemInst);
                if (it != VMap.end()) {
                    Instruction* inst = dyn_cast<Instruction>(VMap[partiallySenMemInst]);
                    assert(inst && "This should be an instruction");
                    tempList.push_back(inst);
                }
            } 
            std::copy(tempList.begin(), tempList.end(), std::inserter(partiallySenMemList, partiallySenMemList.begin()));
        }
    }
}

/*
 * LI: LoopInfo to maintain sanity
 * DT: DominatorTree to maintain sanity
 * Loop: The original Loop being cloned
 * partiallySenMemInstSet: The set of partially sensitive memory instructions
 *                          corresponding to baseMemLoc
 * baseMemLoc: The base memory
 *
 * baseMemInsnMap: To insert the sensitive memory instructions from the cloned
 * loops
 */
Loop* EncryptionPass::specializeLoopAndHoist(LoopInfo* LI, DominatorTree* DT, Loop* OrigLoop, std::set<Instruction*>& partiallySenMemInstSet, Value* baseMemLoc, std::map<Value*, std::set<Instruction*>>& baseMemInsMap) {
    LLVMContext& ctx = baseMemLoc->getContext();

    // Following conditions should've been checked already
    assert(OrigLoop->empty() && "Can only handle innermost loops");
    assert(OrigLoop->isSafeToClone() && "Can't clone loop");
    // We do handle loops without preheaders
    //assert(OrigLoop->getLoopPreheader() && "loop doesn't have a preheader");
    
    ValueToValueMapTy VMap;

    BasicBlock* NewPH = insertNewPH(ctx, DT, LI, OrigLoop, VMap);

    Loop* NewLoop = cloneAndInsertLoop(DT, LI, OrigLoop, NewPH, VMap);

    assert(DT->getNode(OrigLoop->getHeader())->getIDom()->getBlock() == NewPH && "Inconsistent Dom Tree (orig loop)");
    assert(DT->getNode(NewLoop->getHeader())->getIDom()->getBlock() == NewPH && "Inconsistent Dom Tree (new loop)");
    
    updateSensitiveMemLists(baseMemInsMap, baseMemLoc, VMap);

    // Now, retrieve the sensitive pointer and call dfsan_read_label
    // If taint present, then branch to OrigLoop, if not, branch toNewLoop
    addTaintCheck(OrigLoop, NewLoop, NewPH, baseMemLoc);

    for (Instruction* partiallySenMemInst: partiallySenMemInstSet) {
        bool contains = false;
        for (BasicBlock* bb: OrigLoop->blocks()) {
            if (bb == partiallySenMemInst->getParent()) {
                contains = true;
                break;
            } 
        }
        if (contains) {
            transformSensitiveMemInst(partiallySenMemInst);
        }
    }
    return NewLoop;
}

void EncryptionPass::transformSensitiveMemInst(Instruction* partiallySenMemInst) {
    std::map<PAGNode*, std::set<PAGNode*>> ptsToMap = getAnalysis<WPAPass>().getPAGPtsToMap();

    if (LoadInst* LdInst = dyn_cast<LoadInst>(partiallySenMemInst)) {
        IRBuilder<> Builder(LdInst); // Insert before "next" instruction
        // Check get the decrypted value
        Value* decryptedValue = nullptr;
        decryptedValue = AESCache.getDecryptedValueCached(LdInst);
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
    } else	if (StoreInst* StInst = dyn_cast<StoreInst>(partiallySenMemInst)) {
        IRBuilder<> Builder(StInst);

        LLVM_DEBUG (
                dbgs() << "Replacing Store Instruction : ";
                StInst->dump();
                );
        AESCache.setEncryptedValueCached(StInst);
        // Remove the Store instruction
        StInst->eraseFromParent();
    }

}

void EncryptionPass::loadShadowBase(Module& M) {
    const DataLayout &DL = M.getDataLayout();
    LLVMContext *Ctx;
    Ctx = &M.getContext();
    FunctionType* FTypeInit = FunctionType::get(Type::getVoidTy(*Ctx), false);

    Function* loadShadowBaseFn = Function::Create(FTypeInit, Function::ExternalLinkage, "load_shadow_base", &M);

    //InlineAsm* loadMM0Asm = InlineAsm::get(FTypeInit, "movq $$0xffff8fffffffffff, %mm0\n\t", "", true, false);

    Function* mainFunction = M.getFunction("main");
    Instruction* insertionPoint = nullptr;
    
    for (inst_iterator I = inst_begin(*mainFunction), E = inst_end(*mainFunction); I != E; ++I) {
        Instruction* inst = &*I;
        insertionPoint = inst;
        if (!isa<AllocaInst>(inst)) {
            break;
        }
    }

    IRBuilder<> Builder(insertionPoint);
    Builder.CreateCall(loadShadowBaseFn);

}

bool EncryptionPass::hasNullCheck(Value* baseMem) {
    for (User* user: baseMem->users()) {
        if (LoadInst* loadInst = dyn_cast<LoadInst>(user)) {
            for (User* ldUser: loadInst->users()) {
                if (ICmpInst* icmp = dyn_cast<ICmpInst>(ldUser)) {
                    for (int i = 0; i < icmp->getNumOperands(); i++) {
                        Value* op = icmp->getOperand(i);
                        if (ConstantPointerNull* nullptrVal = dyn_cast<ConstantPointerNull>(op)) {
                            return true;
                        }
                    }
                }
            }
        }
        if (ICmpInst* icmp = dyn_cast<ICmpInst>(user)) {
            for (int i = 0; i < icmp->getNumOperands(); i++) {
                Value* op = icmp->getOperand(i);
                if (ConstantPointerNull* nullptrVal = dyn_cast<ConstantPointerNull>(op)) {
                    return true;
                }
            }
        }
    }
    return false;
}
void EncryptionPass::computeTotalValueFlows (Module& M) {
    std::vector<Instruction*> workList;
    long totalValueFlowCount = 0;
    // find all Load instructions
    for (Module::iterator MIterator = M.begin(); MIterator != M.end(); MIterator++) {
        if (auto *F = dyn_cast<Function>(MIterator)) {
            for (Function::iterator FIterator = F->begin(); FIterator != F->end(); FIterator++) {
                if (auto *BB = dyn_cast<BasicBlock>(FIterator)) {
                    for (BasicBlock::iterator BBIterator = BB->begin(); BBIterator != BB->end(); BBIterator++) {
                        if (auto *Inst = dyn_cast<Instruction>(BBIterator)) {
                            if (LoadInst* loadInst = dyn_cast<LoadInst>(Inst)) {
                                if (!loadInst->getType()->isPointerTy()) {
                                    workList.push_back(loadInst);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    while (!workList.empty()){
        Instruction* inst = workList.back();
        workList.pop_back();
        //errs()<< " worklist "<< *inst << "\n";
        for (User* instUser: inst->users()) {
            // direct store
            if (StoreInst* storeInst = dyn_cast<StoreInst>(instUser)) {
                if (storeInst->getValueOperand() == inst) {
                    //errs()<< " Store " << *storeInst << "\n";
                    totalValueFlowCount++;
                }
            }
            // look for type casts
            else if (BitCastInst* bcInst = dyn_cast<BitCastInst>(instUser)){
                workList.push_back(bcInst);
            }
            else if (SExtInst* sextInst = dyn_cast<SExtInst>(instUser)){
                workList.push_back(sextInst);
            }
            else if (TruncInst* truncInst = dyn_cast<TruncInst>(instUser)){
                workList.push_back(truncInst);
            }
            else if (ZExtInst* zextInst = dyn_cast<ZExtInst>(instUser)){
                workList.push_back(zextInst);
            }
            else if (PtrToIntInst* ptrtointInst = dyn_cast<PtrToIntInst>(instUser)){
                workList.push_back(ptrtointInst);
            }
            else if (IntToPtrInst* inttoptrInst = dyn_cast<IntToPtrInst>(instUser)){
                workList.push_back(inttoptrInst);
            }
        }
    }
    errs() << "Total Value Flow Count is " << totalValueFlowCount << "\n";
}

bool EncryptionPass::runOnModule(Module &M) {
    this->mod = &M;
    checkAuthenticationCount = 0;
    computeAuthenticationCount = 0;

    collectInitialLoadStoreStats(M);
    computeTotalValueFlows(M);

    // Check soundness of config options
    assert(!(Integrity && Confidentiality) && "Can't support both integrity and confidentiality right now");
    assert((Integrity || Confidentiality) && "Need to select at least one -- integrity or confidentiality");

    // Set up the widening / aligning bytes
    if (Confidentiality) {
        const_cast<DataLayout&>(M.getDataLayout()).setWidenSensitiveBytes(16);
        M.addModuleFlag(llvm::Module::Warning, StringRef("auth_mode"), (uint32_t)0);
    } else {
        const_cast<DataLayout&>(M.getDataLayout()).setWidenSensitiveBytes(98); // [ 256 (hmac) : 512 (data) ]
        M.addModuleFlag(llvm::Module::Warning, StringRef("auth_mode"), (uint32_t)1);
    }

    PAG* pag = getAnalysis<WPAPass>().getPAG();
    // Set up the external functions handled

    instrumentedExternalFunctions.push_back("strtol");
    instrumentedExternalFunctions.push_back("strcpy");
    instrumentedExternalFunctions.push_back("strncpy");
    instrumentedExternalFunctions.push_back("strcmp");
    instrumentedExternalFunctions.push_back("strcasecmp");
    instrumentedExternalFunctions.push_back("strlen");
    instrumentedExternalFunctions.push_back("strrchr");
    instrumentedExternalFunctions.push_back("aes_strdup");
    instrumentedExternalFunctions.push_back("strstr");
    instrumentedExternalFunctions.push_back("strcasestr");

    instrumentedExternalFunctions.push_back("llvm.memcpy");
    instrumentedExternalFunctions.push_back("bzero");
    instrumentedExternalFunctions.push_back("llvm.memset");
    instrumentedExternalFunctions.push_back("memset");

    instrumentedExternalFunctions.push_back("memcmp");
    instrumentedExternalFunctions.push_back("memchr");
    instrumentedExternalFunctions.push_back("memrchr");
    instrumentedExternalFunctions.push_back("llvm.memmove");
    instrumentedExternalFunctions.push_back("fgets");
    instrumentedExternalFunctions.push_back("read");
    instrumentedExternalFunctions.push_back("pread");
    instrumentedExternalFunctions.push_back("pread64");
    instrumentedExternalFunctions.push_back("strncmp");


    //============== break

    instrumentedExternalFunctions.push_back("select");
    instrumentedExternalFunctions.push_back("calloc");
    instrumentedExternalFunctions.push_back("aes_calloc");
    instrumentedExternalFunctions.push_back("printf");
    instrumentedExternalFunctions.push_back("asprintf");
    instrumentedExternalFunctions.push_back("asprintf128");

    instrumentedExternalFunctions.push_back("posix_memalign");

    instrumentedExternalFunctions.push_back("cloneenv");
    instrumentedExternalFunctions.push_back("poll");

    instrumentedExternalFunctions.push_back("puts");
    instrumentedExternalFunctions.push_back("fgets");
    instrumentedExternalFunctions.push_back("fopen");
    instrumentedExternalFunctions.push_back("open");

    instrumentedExternalFunctions.push_back("fprintf");
    instrumentedExternalFunctions.push_back("vsnprintf");
    instrumentedExternalFunctions.push_back("sprintf");
    instrumentedExternalFunctions.push_back("snprintf");

    instrumentedExternalFunctions.push_back("memcmp");
    instrumentedExternalFunctions.push_back("opendir");
    instrumentedExternalFunctions.push_back("memcmp");

    instrumentedExternalFunctions.push_back("stat");
    instrumentedExternalFunctions.push_back("lstat");
    instrumentedExternalFunctions.push_back("fread");
    
    instrumentedExternalFunctions.push_back("strchr");
    instrumentedExternalFunctions.push_back("strncmp");
    instrumentedExternalFunctions.push_back("strncasecmp");

    instrumentedExternalFunctions.push_back("memchr");
    instrumentedExternalFunctions.push_back("memrchr");

    instrumentedExternalFunctions.push_back("strtol");
    instrumentedExternalFunctions.push_back("strcpy");
    instrumentedExternalFunctions.push_back("strncpy");
    instrumentedExternalFunctions.push_back("strcasecmp");
    instrumentedExternalFunctions.push_back("strlen");
    instrumentedExternalFunctions.push_back("strrchr");
    instrumentedExternalFunctions.push_back("aes_strdup");
    instrumentedExternalFunctions.push_back("strstr");
    instrumentedExternalFunctions.push_back("strcasestr");

    instrumentedExternalFunctions.push_back("crypt");
    instrumentedExternalFunctions.push_back("cwd");
    instrumentedExternalFunctions.push_back("syscall");

    instrumentedExternalFunctions.push_back("fwrite");
    instrumentedExternalFunctions.push_back("llvm.memcpy");
    instrumentedExternalFunctions.push_back("bzero");
    instrumentedExternalFunctions.push_back("llvm.memset");
    instrumentedExternalFunctions.push_back("memset");

    instrumentedExternalFunctions.push_back("read");
    instrumentedExternalFunctions.push_back("write");
    instrumentedExternalFunctions.push_back("bind");
    instrumentedExternalFunctions.push_back("connect");
    instrumentedExternalFunctions.push_back("getaddrinfo");

    instrumentedExternalFunctions.push_back("pthread_mutex_lock");
    instrumentedExternalFunctions.push_back("pthread_mutex_unlock");
    instrumentedExternalFunctions.push_back("pthread_mutex_init");
    instrumentedExternalFunctions.push_back("pthread_mutex_destroy");
    instrumentedExternalFunctions.push_back("pthread_create");

    instrumentedExternalFunctions.push_back("readdir");
    instrumentedExternalFunctions.push_back("clonereaddir");
    instrumentedExternalFunctions.push_back("epoll_ctl");
    instrumentedExternalFunctions.push_back("epoll_wait");
    instrumentedExternalFunctions.push_back("uname");
    instrumentedExternalFunctions.push_back("mk_string_build");
    instrumentedExternalFunctions.push_back("fopen64");

    //M.print(errs(), nullptr);
    LLVM_DEBUG (
            dbgs() << "Running Encryption pass\n";
            );
    // Store the struct types here, because later things get hairy when we add
    // the AES functions with 128 bit integer arguments
    std::vector<llvm::Value*> sensitiveMemAllocCalls;

    SensitiveObjSet = nullptr;

    // Do Alias Analysis for pointers
    std::map<PAGNode*, std::set<PAGNode*>> ptsToMap = getAnalysis<WPAPass>().getPAGPtsToMap();
    std::map<PAGNode*, std::set<PAGNode*>> ptsFromMap = getAnalysis<WPAPass>().getPAGPtsFromMap();

    dbgs() << "Performed Pointer Analysis\n";

    // The SensitiveMemAllocTracker has
    // identified the sensitive memory allocations
    for (Value* sensitiveMem: getAnalysis<SensitiveMemAllocTrackerPass>().getSensitiveMemAllocCalls()) {
        if (AllocaInst* allocInst = dyn_cast<AllocaInst>(sensitiveMem)) {
            if (pag->isIncludedFunction(allocInst->getParent()->getParent())) {
                sensitiveMemAllocCalls.push_back(allocInst);
            }
        } else if (CallInst* callInst = dyn_cast<CallInst>(sensitiveMem)) {
            if (pag->isIncludedFunction(callInst->getParent()->getParent())) {
                Function* function = callInst->getCalledFunction();
                if (!function) {
                    // TODO: Handle Funtion Pointer returned from SensitiveMemAllocTrackerPass 
                    errs() << "Function Pointer "<<*callInst<<"\n";
                    continue;
                }
                sensitiveMemAllocCalls.push_back(callInst);
            }
        } else {
            sensitiveMemAllocCalls.push_back(sensitiveMem);
        }
    }

    // Critical Free Functions
    errs()<<"Critical Free Functions in Encryption Pass are:\n";
    for (Function* freeFunction : getAnalysis<ContextSensitivityAnalysisPass>().getCriticalFreeFunctions()){
        errs()<<"Function name is: " << freeFunction->getName() << "\n";
        CriticalFreeWrapperFunctions.insert(freeFunction);
    }

    for (AllocaInst* allocaInst: getAnalysis<SensitiveMemAllocTrackerPass>().getSensitiveAllocaInsts()) {
        if (!isaCPointer(allocaInst)) {
            sensitiveMemAllocCalls.push_back(allocaInst);
        }
    }

    for (Value* val: sensitiveMemAllocCalls) {
        if (Instruction* inst = dyn_cast<Instruction>(val)) {
            errs() << "Sensitive mem alloc function call: " << *inst << " in function " << inst->getParent()->getParent()->getName() << "\n";
        }
    }

    LLVM_DEBUG (
            dbgs() << "Collected sensitive annotations\n";
            for (PAGNode* valNode: SensitiveObjList) {
            assert(valNode->hasValue() && "PAG Node made it so far must have value");
            valNode->getValue()->dump();
            }	
            );

    // Remove the annotation instruction because it causes a lot of headache later on
    removeAnnotateInstruction(M);

    addPAGNodesFromSensitiveObjects(sensitiveMemAllocCalls);

    for (PAGNode* node: SensitiveObjList) {
        InitSensitiveTaintedObjSet.insert(node);
    }

    if (!skipVFA) {
        performSourceSinkAnalysis(M);
    }

    errs() << "Sensitive value flows: " << sensitiveValueFlows << "\n";
    if (SensitiveObjSet) {
        delete(SensitiveObjSet);
    }

    SensitiveObjSet = new std::set<PAGNode*>(SensitiveObjList.begin(), SensitiveObjList.end());
    errs() << "Total sensitive allocation sites: " << SensitiveObjSet->size() << "\n";
    for (PAGNode* sensitiveNode: *SensitiveObjSet) {
        errs() << "Sensitive node: " << *(sensitiveNode->getValue()) << "\n";
        if (const Instruction* inst = dyn_cast<Instruction>(sensitiveNode->getValue())) {
            errs() << "Function: " << inst->getParent()->getParent()->getName() << "\n";
        }
    }
    SensitiveObjList.clear();
    std::copy(SensitiveObjSet->begin(), SensitiveObjSet->end(), std::back_inserter(SensitiveObjList));
    errs() << "After collectSensitivePointsToInfo: " << SensitiveObjList.size() << " memory objects found\n";

    collectSensitivePointers();

    // Check for the LoadInsts and StoreInsts that use the sensitive
    // memory
    for (PAGNode* sensitivePtrNode: pointsFroms) {
        if (!sensitivePtrNode->hasValue()) {
            continue;
        }
        Value* ptrVal = const_cast<Value*>(sensitivePtrNode->getValue());

        for (User* user: ptrVal->users()) {
            if (user == ptrVal) 
                continue;
            if (LoadInst* ldInst = dyn_cast<LoadInst>(user)) {
                if (ldInst->getPointerOperand() == ptrVal) {
                    /*
                    if (ldInst->getType()->isPointerTy()) {
                        continue;
                    }
                    */
                    if (isOptimizedOut(ldInst, ptrVal)) {
                        continue;
                    }
                    SensitiveLoadList.push_back(ldInst);
                }
            } else if (StoreInst* stInst = dyn_cast<StoreInst>(user)) {
                if (stInst->getPointerOperand() == ptrVal) {
                    /*
                    if (stInst->getValueOperand()->getType()->isPointerTy()) {
                        continue;
                    }
                    */
 
                    if (isOptimizedOut(stInst, ptrVal)) {
                        continue;
                    }
                    SensitiveStoreList.push_back(stInst);
                }
            }
        }
    }

    collectSensitiveObjectsForWidening();

    if (SensitiveObjSet) {
        delete(SensitiveObjSet);
    }

    if (Confidentiality) {
        AESCache.initializeAes(M, skipVFA, writebackCacheFunctions);
        AESCache.widenSensitiveAllocationSites(M, SensitiveObjList, ptsToMap, ptsFromMap);
    }

    if (Integrity) {
        HMAC.initializeHMAC(M);
        HMAC.widenSensitiveAllocationSites(M, SensitiveObjList);
    }


    SensitiveObjSet = new std::set<PAGNode*>(SensitiveObjList.begin(), SensitiveObjList.end());
    errs() << "Total sensitive allocation sites after pointsFromSet: " << SensitiveObjSet->size() << "\n";
    SensitiveObjList.clear();
    std::copy(SensitiveObjSet->begin(), SensitiveObjSet->end(), std::back_inserter(SensitiveObjList));
    errs() << "After adding sensitive objects from PointsFromSet: " << SensitiveObjList.size() << " memory objects found\n";

    if (!Partitioning) {
        for (PAGNode* sensitiveNode: *SensitiveObjSet) {
            errs() << "After points-from analysis ensitive node: " << *sensitiveNode << "\n";
        }
    }

    if(Partitioning){
        //Set Labels for Sensitive objects
        //AESCache.setLabelsForSensitiveObjects(M, &InitSensitiveTaintedObjSet, ptsToMap, ptsFromMap);
        //AESCache.trackDownAllRecursiveSensitiveAllocations(M);
        //AESCache.unsetLabelsForCriticalFreeWrapperFunctions(M, CriticalFreeWrapperFunctions);
    }
    dbgs() << "Initialized AES, widened buffers to multiples of 128 bits\n";

    buildSets(M);

    // Just do track them
    for (Value* LdVal: *SensitiveLoadSet) {
        LoadInst* LdInst = dyn_cast<LoadInst>(LdVal);
		// Temporarily ignore anything that's not an integer
        /*
		if (!LdInst->getType()->isIntegerTy())
			continue;
		IntegerType* intType = dyn_cast<IntegerType>(LdInst->getType());
		if (intType->getBitWidth() > 8)
			continue;
            */

        LLVMContext& C = LdInst->getContext();
        MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
        LdInst->setMetadata("SENSITIVE", N);

        // Find the next instruction
        Instruction* NextInstruction = LdInst->getNextNode();
        InstructionReplacement* Replacement = new InstructionReplacement();
        Replacement->OldInstruction = LdInst;
        Replacement->NextInstruction = NextInstruction;
        Replacement->Type = LOAD;
        decStatCount++;
        if(Partitioning){
            ReplacementCheckList.push_back(Replacement);
        } else {
            ReplacementList.push_back(Replacement);
        }
    }

    for (StoreInst* StInst: *SensitiveStoreSet) {

        LLVMContext& C = StInst->getContext();
		MDNode* N = MDNode::get(C, MDString::get(C, "sensitive"));
        /*
		if (!StInst->getValueOperand()->getType()->isIntegerTy())
		*/
        StInst->setMetadata("SENSITIVE", N);

        InstructionReplacement* Replacement = new InstructionReplacement();
        Replacement->OldInstruction = StInst;
        Replacement->NextInstruction = nullptr; // Don't care about the next, the decryption happens before the store
        Replacement->Type = STORE;
        encStatCount++;
        if(Partitioning){
            ReplacementCheckList.push_back(Replacement);
        } else {
            ReplacementList.push_back(Replacement);
        }

    }

    if (Confidentiality) {
        loadShadowBase(M);
        unConstantifySensitiveAllocSites(M);
        initializeSensitiveGlobalVariables(M);
        collectSensitiveExternalLibraryCalls(M, ptsToMap);
    }

    dbgs() << "Collected sensitive External Library calls\n";
    errs() << "External Library Call List Size: " << SensitiveExternalLibCallList.size() << "\n";


    ExtLibHandler.addNullExtFuncHandler(M); // This includes the decryptStringForLibCall and decryptArrayForLibCall
    ExtLibHandler.addAESCacheExtFuncHandler(M);


    performInstrumentation(M, ptsToMap);
    if (Confidentiality) {
        instrumentExternalFunctionCall(M, ptsToMap);
    }
    fixupSizeOfOperators(M);


    if (Confidentiality) {

        collectLoadStoreStats(M);
    } else {
        dbgs() << "Inserted " << checkAuthenticationCount << " calls to check-authentication routines.\n";
        dbgs() << "Inserted " << computeAuthenticationCount << " calls to compute-authentication routines.\n";
    }

    if (skipVFA) {
        errs() << "************* STOP!!!!!!!!!!!!! ANALYZED WITH VALUE FLOW ANALYSIS SKIPPED! *********************\n";
    }

    //performTaintCheckLICM(M);
    //    M.dump();
    return true;
}

INITIALIZE_PASS_BEGIN(EncryptionPass, "encryption", "Identify and instrument sensitive variables", false, true)
INITIALIZE_PASS_DEPENDENCY(SensitiveMemAllocTrackerPass);
INITIALIZE_PASS_DEPENDENCY(WPAPass);
INITIALIZE_PASS_DEPENDENCY(LoopInfoWrapperPass);
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass);
INITIALIZE_PASS_END(EncryptionPass, "encryption", "Identify and instrument sensitive variables", false, true)

ModulePass* llvm::createEncryptionPass() { return new EncryptionPass(); }


