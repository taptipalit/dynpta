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

#include "MemoryModel/PointerAnalysis.h"
#include "MemoryModel/ConsG.h"
#include "WPA/Andersen.h"
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Pass.h>
#include <llvm/Analysis/ContextSensitivityAnalysis.h>

#include <vector>
#include <set>
#include <map>

class SVFModule;

/*!
 * Whole program pointer analysis.
 * This class performs various pointer analysis on the given module.
 */
// excised ", public llvm::AliasAnalysis" as that has a very light interface
// and I want to see what breaks.
class WPAPass: public llvm::ModulePass {
    typedef std::vector<PointerAnalysis*> PTAVector;
    typedef FIFOWorkList<NodeID> WorkList;

public:
    /// Pass ID
    static char ID;

    enum AliasCheckRule {
        Conservative,	///< return MayAlias if any pta says alias
        Veto,			///< return NoAlias if any pta says no alias
        Precise			///< return alias result by the most precise pta
    };

    /// Constructor needs TargetLibraryInfo to be passed to the AliasAnalysis
    WPAPass() : llvm::ModulePass(ID) {

    }

    /// Destructor
    ~WPAPass();

    /// LLVM analysis usage
    virtual inline void getAnalysisUsage(llvm::AnalysisUsage &au) const {
        // declare your dependencies here.
        au.addRequired<ContextSensitivityAnalysisPass>();
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
    virtual bool runOnModule(llvm::Module& module) {
        contextSensitivityPass = &(getAnalysis<ContextSensitivityAnalysisPass>());
        SVFModule *svfModule = new SVFModule(module);
        runOnModule(*svfModule);
        delete svfModule;
        return false;
    }

    /// Run pointer analysis on SVFModule
    void runOnModule(SVFModule svfModule);

    void performLayeredPointerAnalysis(SVFModule svfModule, llvm::Module*);

    bool isPointsToNodes(NodeID, std::vector<NodeID>&);
    std::vector<PAGNode*> pointsToSet(NodeID);
    void getPtsFrom(NodeID ptd, std::vector<PAGNode*>& pointsFrom);
    void getPtsFrom(std::vector<PAGNode*>& sensitiveNodes,
                    std::set<PAGNode*>& pointsFrom);
    void getPtsFromSDD(NodeID ptd, std::vector<PAGNode*>& pointsFrom);
    void getPtsFromSDD(std::vector<PAGNode*>& sensitiveNodes,
                    std::set<PAGNode*>& pointsFrom);

 
    /// PTA name
    virtual inline llvm::StringRef getPassName() const {
        return "WPAPass";
    }

    void collectLocalSensitiveAnnotations(llvm::Module&);

    void collectGlobalSensitiveAnnotations(llvm::Module&);

    void computeSubGraph(std::set<PAGNode*>&, ConstraintGraph*); 

    ConstraintGraph* computeSteensSubGraph();

    bool isSensitiveObj(PAGNode*);

    PAGNode* getPAGValNodeFromValue(llvm::Value*);

    PAG* getPAG() {
        return _pta->getPAG();
    }

    ConstraintGraph* getConstraintGraph() {
        if (Andersen* aa = llvm::dyn_cast<Andersen>(_pta)) {
            return aa->getConstraintGraph();
        }
        return nullptr;
    }

    virtual std::map<PAGNode*, std::set<PAGNode*>>& getPAGPtsToMap() {
        return pagPtsToMap;
    }

    virtual std::map<PAGNode*, std::set<PAGNode*>>& getPAGPtsFromMap() {
        return pagPtsFromMap;
    }

    virtual void buildResultMaps(); 

    void findDirectSinkSites(PAGNode*, std::set<PAGNode*>&);
    void findIndirectSinkSites(PAGNode*, std::set<PAGNode*>&);
    void performSourceSinkAnalysis(llvm::Module&);

    void doSteensPostProcessing();

    void doAndersenPostProcessing();
private:
    /// Create pointer analysis according to specified kind and analyze the module.
    void runPointerAnalysis(SVFModule svfModule, u32_t kind);

    PTAVector ptaVector;	///< all pointer analysis to be executed.
    PointerAnalysis* _pta;	///<  pointer analysis to be executed.

    std::vector<PAGNode*> SensitiveObjList;
    std::map<PAGNode*, std::set<PAGNode*>> pagPtsToMap;
    std::map<PAGNode*, std::set<PAGNode*>> pagPtsFromMap;

    ContextSensitivityAnalysisPass* contextSensitivityPass;
};

namespace llvm {
    class ModulePass;
    class Module;

    ModulePass *createWPAPass();
}

#endif /* WPA_H_ */
