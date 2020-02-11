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


class ContextSensitivityAnalysisPass: public llvm::ModulePass {

public:
    /// Pass ID
    static char ID;

    /// Constructor needs TargetLibraryInfo to be passed to the AliasAnalysis
    ContextSensitivityAnalysisPass() : llvm::ModulePass(ID) {

    }

    /// Destructor
    ~ContextSensitivityAnalysisPass() { }

    /// LLVM analysis usage
    virtual inline void getAnalysisUsage(llvm::AnalysisUsage &au) const {
        // declare your dependencies here.
        /// do not intend to change the IR in this pass,
        au.setPreservesAll();
    }

    virtual bool runOnModule(llvm::Module& module);

    std::vector<llvm::Function*>& getCriticalFunctions() {
        return criticalFunctions;
    }

    std::vector<llvm::Function*>& getTop10CriticalFunctions() {
        return top10CriticalFunctions;
    }

private:
    std::map<llvm::Function*, int> funcCallNumMap; // A map between a function and how many times they're called
    std::vector<std::pair<llvm::Function*, int>> mallocWrapperCallNumMap;

    std::set<llvm::Function*> mallocWrappers;

    std::set<llvm::GlobalVariable*> globalMallocWrapperPtrs; // these are simple global function pointers

    std::vector<llvm::Function*> criticalFunctions;
    std::vector<llvm::Function*> top10CriticalFunctions;

    void profileFuncCalls(llvm::Module&);
    void handleGlobalFunctionPointers(llvm::Module&);
    bool returnsAllocedMemory(llvm::Function*);
    bool isReturningMallockedPtr(llvm::ReturnInst*, std::vector<llvm::Value*>&);
    llvm::Value* findSink(llvm::Value*);

    bool findNumFuncRooted(llvm::Function*, int&);
};

namespace llvm {
    class ModulePass;
    class Module;

    ModulePass *createContextSensitivityAnalysisPass();
}

#endif /* CSA_H_ */