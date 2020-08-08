#ifndef SMAT_H_
#define SMAT_H_

#include <utility>      // std::pair, std::make_pair
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include "llvm/Support/CommandLine.h"
#include <llvm/IR/Module.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Analysis/ContextSensitivityAnalysis.h>
#include <vector>
#include <set>
#include <map>


class SensitiveMemAllocTrackerPass: public llvm::ModulePass {

public:
    /// Pass ID
    static char ID;

    /// Constructor needs TargetLibraryInfo to be passed to the AliasAnalysis
    SensitiveMemAllocTrackerPass() : llvm::ModulePass(ID) {

    }

    /// Destructor
    ~SensitiveMemAllocTrackerPass() { }

    /// LLVM analysis usage
    virtual inline void getAnalysisUsage(llvm::AnalysisUsage &au) const {
        // declare your dependencies here.
        /// do not intend to change the IR in this pass,
        au.addRequired<ContextSensitivityAnalysisPass>();
        au.setPreservesAll();
    }

    virtual bool runOnModule(llvm::Module& module);

    std::vector<llvm::CallInst*>& getSensitiveMemAllocCalls() {
        return sensitiveMemAllocCalls;
    }

    std::vector<llvm::AllocaInst*>& getSensitiveAllocaInsts() {
        return sensitiveAllocaPtrs;
    }

private:

    llvm::Module* mod;

    std::map<llvm::Type*, std::vector<llvm::Value*>> gepMap;

    std::set<llvm::Function*> mallocRoutines;

    std::vector<llvm::AllocaInst*> sensitiveAllocaPtrs;
    std::vector<llvm::GetElementPtrInst*> sensitiveGepPtrs;

    std::vector<llvm::StoreInst*> storesAtSensitivePtrs;

    std::vector<llvm::CallInst*> sensitiveMemAllocCalls;

    void collectLocalSensitiveAnnotations(llvm::Module&);

    void findAllSensitiveGepPtrs(llvm::Value*);

    void findStoresAtSensitivePtrs();

    void findMemAllocsReachingSensitivePtrs();

    std::vector<llvm::Value*>& findAllGepBases(llvm::Value* gepBase);

};

namespace llvm {
    class ModulePass;
    class Module;

    ModulePass *createSensitiveMemAllocTrackerPass();
}

#endif
