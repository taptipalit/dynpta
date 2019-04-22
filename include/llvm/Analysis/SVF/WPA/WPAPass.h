//===- WPAPass.h -- Whole program analysis------------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013-2017>  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===----------------------------------------------------------------------===//


/*
 * @file: WPA.h
 * @author: yesen
 * @date: 10/06/2014
 * @version: 1.0
 *
 * @section LICENSE
 *
 * @section DESCRIPTION
 *
 */


#ifndef WPA_H_
#define WPA_H_

#include "llvm/Analysis/SVF/MemoryModel/PointerAnalysis.h"
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Pass.h>
#include "llvm/Analysis/SVF/Util/SVFModule.h"
#include "llvm/Analysis/SVF/WPA/Andersen.h"
#include "llvm/Analysis/SVF/WPA/FlowSensitive.h"
#include <llvm/Support/CommandLine.h>
#include <iostream>
using namespace std;
using namespace llvm;

class SVFModule;

/*!
 * Whole program pointer analysis.
 * This class performs various pointer analysis on the given module.
 */
// excised ", public llvm::AliasAnalysis" as that has a very light interface
// and I want to see what breaks.
class WPAPass: public llvm::ModulePass {
    typedef std::vector<PointerAnalysis*> PTAVector;

public:
    /// Pass ID
    static char ID;
    
    std::map<llvm::Value*, std::set<llvm::Value*>> ptsToMap;
    std::map<llvm::Value*, std::set<llvm::Value*>> ptsFromMap;

    std::map<PAGNode*, std::set<PAGNode*>> pagPtsToMap;
    std::map<PAGNode*, std::set<PAGNode*>> pagPtsFromMap;

    
    enum AliasCheckRule {
        Conservative,	///< return MayAlias if any pta says alias
        Veto,			///< return NoAlias if any pta says no alias
        Precise			///< return alias result by the most precise pta
    };

    /// Constructor needs TargetLibraryInfo to be passed to the AliasAnalysis
    WPAPass() : llvm::ModulePass(ID) {
	initializeWPAPassPass(*PassRegistry::getPassRegistry());

    }

    /// Destructor
    ~WPAPass();

    /// LLVM analysis usage
    virtual inline void getAnalysisUsage(llvm::AnalysisUsage &au) const {
        // declare your dependencies here.
        /// do not intend to change the IR in this pass,
        au.setPreservesAll();
    }

    /// Get adjusted analysis for alias analysis
    virtual inline void* getAdjustedAnalysisPointer(llvm::AnalysisID id) {
        return this;
    }

    /// Interface expose to users of our pointer analysis, given Location infos
    virtual inline llvm::AliasResult alias(const llvm::MemoryLocation  &LocA, const llvm::MemoryLocation  &LocB) {
        return alias(LocA.Ptr, LocB.Ptr);
    }

    /// Interface expose to users of our pointer analysis, given Value infos
    virtual llvm::AliasResult alias(const llvm::Value* V1,	const llvm::Value* V2);

    /// We start from here
    virtual bool runOnModule(llvm::Module& module);// {
	/*dbgs() << "1";
        return runOnModule(module);
    }*/

    /// Run pointer analysis on SVFModule
    void runOnModule(SVFModule svfModule);
    //virtual bool runOnModule(SVFModule svfModule);

    /// PTA name
    virtual inline llvm::StringRef getPassName() const {
        return "WPAPass";
    }

    virtual PointerAnalysis* getPTA(); 

    virtual PAG* getPAG();

    virtual ConstraintGraph* getConstraintGraph();

    virtual std::map<PAGNode*, std::set<PAGNode*>>& getPAGPtsToMap() {
        return pagPtsToMap;
    }

    virtual std::map<PAGNode*, std::set<PAGNode*>>& getPAGPtsFromMap() {
        return pagPtsFromMap;
    }

    virtual void buildResultMaps(); 
    
     virtual std::map<llvm::Value*, std::set<llvm::Value*>>& getPtsToMap() {
        return ptsToMap;
    }

    virtual std::map<llvm::Value*, std::set<llvm::Value*>>& getPtsFromMap() {
        return ptsFromMap;
    }
private:
    /// Create pointer analysis according to specified kind and analyze the module.
    void runPointerAnalysis(SVFModule svfModule, u32_t kind);
    //void runPointerAnalysis(llvm::Module& svfModule, u32_t kind);

    PTAVector ptaVector;	///< all pointer analysis to be executed.
    PointerAnalysis* _pta;	///<  pointer analysis to be executed.
};

namespace llvm {
	class ModulePass;
	class Module;

	ModulePass *createWPAPass();
}

#endif /* WPA_H_ */
