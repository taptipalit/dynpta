#ifndef CSA_H_
#define CSA_H_

#include <utility>      // std::pair, std::make_pair
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include "llvm/Support/CommandLine.h"
#include <llvm/IR/Module.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/Support/raw_ostream.h>
#include <vector>
#include <set>
#include <map>
#include "llvm/Analysis/CFLSteensAliasAnalysis.h"

class ContextSensitivityAnalysisPass: public llvm::ModulePass {

public:
    /// Pass ID
    static char ID;

    /// Constructor needs TargetLibraryInfo to be passed to the AliasAnalysis
    ContextSensitivityAnalysisPass() : llvm::ModulePass(ID), CFLAA(nullptr) {

    }

    /// Destructor
    ~ContextSensitivityAnalysisPass() { }

    /// LLVM analysis usage
    virtual inline void getAnalysisUsage(llvm::AnalysisUsage &au) const {
        // declare your dependencies here.
        /// do not intend to change the IR in this pass,
        au.setPreservesAll();
        au.addRequiredTransitive<llvm::CFLSteensAAWrapperPass>();
    }

    virtual bool runOnModule(llvm::Module& module);

    bool recompute(llvm::Module&, int, int); 

    std::vector<llvm::Function*>& getCriticalFunctions() {
        return criticalFunctions;
    }

    std::vector<llvm::Function*>& getCriticalFreeFunctions() {
        return criticalFreeFunctions;
    }

    std::vector<llvm::Function*>& getTop10CriticalFunctions() {
        return top10CriticalFunctions;
    }

    llvm::Value* getReturnedAllocation(llvm::Function* func) {
        for (auto pair: funcRetPairList) {
            if (pair.first == func) {
                return pair.second;
            }
        }
        return nullptr;
    }

private:
    std::map<llvm::Function*, int> funcCallNumMap; // A map between a function and how many times they're called
    std::vector<std::pair<llvm::Function*, int>> mallocWrapperCallNumMap;
    std::vector<std::pair<llvm::Function*, int>> freeWrapperCallNumMap;

    std::set<llvm::Function*> mallocWrappers;
    std::set<llvm::Function*> freeWrappers;

    std::set<llvm::Function*> newFreeWrappers; // the free wrappers that are found, like CRYPTO_free

    std::set<llvm::GlobalVariable*> globalMallocWrapperPtrs; // these are simple global function pointers
    std::set<llvm::GlobalVariable*> globalFreeWrapperPtrs; // these are simple global function pointers to free

    std::vector<llvm::Function*> criticalFunctions;
    std::vector<llvm::Function*> criticalFreeFunctions;

    std::vector<llvm::Function*> top10CriticalFunctions;

    std::vector<std::pair<llvm::Function*, llvm::Value*>> funcRetPairList;

    llvm::CFLSteensAAResult* CFLAA;
    void profileFuncCalls(llvm::Module&);
    void handleGlobalFunctionPointersForMallocWrappers(llvm::Module&);
    void handleGlobalFunctionPointersForFreeWrappers(llvm::Module&);
    bool returnsAllocedMemory(llvm::Function*);
    bool freesPassedMemory(llvm::Function*);
    bool isReturningUnwrittenMallockedPtr(llvm::ReturnInst*, std::vector<llvm::Value*>&);
    //void findSinks(llvm::Value*, std::vector<llvm::Value*>&);

    bool findNumFuncRooted(llvm::Function*, int&);
};

namespace llvm {
    class ModulePass;
    class Module;

    ModulePass *createContextSensitivityAnalysisPass();
}

#endif /* CSA_H_ */
