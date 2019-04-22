//===- WPAPass.cpp -- Whole program analysis pass------------------------------//
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
//===-----------------------------------------------------------------------===//

/*
 * @file: WPA.cpp
 * @author: yesen
 * @date: 10/06/2014
 * @version: 1.0
 *
 * @section LICENSE
 *
 * @section DESCRIPTION
 *
 */


#include "llvm/Analysis/SVF/Util/SVFModule.h"
#include "llvm/Analysis/SVF/MemoryModel/PointerAnalysis.h"
#include "llvm/Analysis/SVF/WPA/WPAPass.h"
#include "llvm/Analysis/SVF/WPA/Andersen.h"
#include "llvm/Analysis/SVF/WPA/FlowSensitive.h"
#include <llvm/Support/CommandLine.h>
#include <iostream>
using namespace std;
using namespace llvm;

char WPAPass::ID = 0;
/*
static RegisterPass<WPAPass> WHOLEPROGRAMPA("wpa",
        "Whole Program Pointer Analysis Pass");
*/
/// register this into alias analysis group
///static RegisterAnalysisGroup<AliasAnalysis> AA_GROUP(WHOLEPROGRAMPA);

static cl::bits<PointerAnalysis::PTATY> PASelected(cl::desc("Select pointer analysis"),
        cl::values(
            clEnumValN(PointerAnalysis::Andersen_WPA, "nander", "Standard inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenLCD_WPA, "lander", "Lazy cycle detection inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenWave_WPA, "wander", "Wave propagation inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenWaveDiff_WPA, "ander", "Diff wave propagation inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenWaveDiffWithType_WPA, "andertype", "Diff wave propagation with type inclusion-based analysis"),
            clEnumValN(PointerAnalysis::FSSPARSE_WPA, "fspta", "Sparse flow sensitive pointer analysis")
        ));


static cl::bits<WPAPass::AliasCheckRule> AliasRule(cl::desc("Select alias check rule"),
        cl::values(
            clEnumValN(WPAPass::Conservative, "conservative", "return MayAlias if any pta says alias"),
            clEnumValN(WPAPass::Veto, "veto", "return NoAlias if any pta says no alias")
        ));

cl::opt<bool> anderSVFG("svfg", cl::init(false),
                        cl::desc("Generate SVFG after Andersen's Analysis"));

cl::opt<bool> fullAnders("fullanders", cl::init(false), cl::desc("Perform the full Anderson's analysis"));

/// Constructor
//WPAPass::WPAPass() : llvm::ModulePass(ID) {

  //  initializeWPAPassPass(*PassRegistry::getPassRegistry());
//}
/*!
 * Destructor
 */
WPAPass::~WPAPass() {
    PTAVector::const_iterator it = ptaVector.begin();
    PTAVector::const_iterator eit = ptaVector.end();
    for (; it != eit; ++it) {
        PointerAnalysis* pta = *it;
        delete pta;
    }
    ptaVector.clear();
}

/*!
 * We start from here
 */
    //virtual bool runOnModule(llvm::Module& module) {
    //void runOnModule(SVFModule svfModule);
void WPAPass::runOnModule(SVFModule svfModule) {
    if (fullAnders) {
        _pta = new Andersen();
        _pta->analyze(svfModule);
    } else {
        /*
        errs() << "Started running AndersenCFG\n";
        AndersenCFG* awcfg = new AndersenCFG();
        _pta = awcfg;
        awcfg->analyze(svfModule);
        errs() << "Finished running AndersenCFG\n";

        errs() << "Started running AndersenDD\n";
        PAG::CallSiteToFunPtrMap& callSiteToFunPtrMap = const_cast<PAG::CallSiteToFunPtrMap&>(awcfg->getIndirectCallsites());
        AndersenDD* anderdd = new AndersenDD();
        _pta = anderdd;
        // Glue start
        // The constraint Graph supplied by AndersenCFG has the complete CFG
        anderdd->setConstraintGraph(awcfg->getConstraintGraph());
        anderdd->setPAG(awcfg->getPAG());
        anderdd->setCallSiteToFunPtrMap(&callSiteToFunPtrMap);
        //anderdd->updateCallGraph(callSiteToFunPtrMap);
        // Glue end
        anderdd->analyze(svfModule);
        errs() << "Ended running AndersenDD\n";
        */
        errs() << "Started running AndersenWaveDiff\n";
        Andersen* aa = new Andersen();
        _pta = aa;
        aa->analyze(svfModule);
        errs() << "Finished running AndersenWaveDiff\n";
    }
}

bool WPAPass::runOnModule(llvm::Module& module) {
 /*   for (u32_t i = 0; i< PointerAnalysis::Default_PTA; i++) {
        if (PASelected.isSet(i))
            runPointerAnalysis(svfModule, i);
    }*/
	//cout << "WPA\n";
    module.dump();
    for (StructType* stType: module.getIdentifiedStructTypes()) {
        errs() << "Num elements: " << stType->getNumElements() << " for " << stType->getName() << " is literal?" << stType->isLiteral() << "\n";
    }
	SVFModule *svfModule = new SVFModule(module);
	runOnModule(*svfModule);
	//_pta = new Andersen();
	//_pta->analyze(svfModule);
	delete svfModule;
	return false;
}

PAG* WPAPass::getPAG() {
	return _pta->getPAG();
}

ConstraintGraph* WPAPass::getConstraintGraph() {
    if (Andersen* aa = dyn_cast<Andersen>(_pta)) {
        return aa->getConstraintGraph();
    }
    return nullptr;
}

PointerAnalysis* WPAPass::getPTA() {
	return _pta;
}

void WPAPass::buildResultMaps(void) {
    PAG* pag = _pta->getPAG();
    for (PAG::iterator it = pag->begin(), eit = pag->end(); it != eit; it++) {
        NodeID ptr = it->first;
        PointsTo pts = _pta->getPts(it->first);
        PAGNode* node = pag->getPAGNode(ptr);
        if (isa<DummyValPN>(node) || isa<DummyObjPN>(node)) {
            continue;
        }

        for (NodeBS::iterator ptIt = pts.begin(), ptEit = pts.end(); ptIt != ptEit; ++ptIt) {
            PAGNode* ptNode = pag->getPAGNode(*ptIt);
            if (!isa<ObjPN>(ptNode)) {
                continue;
            }
            if (isa<DummyValPN>(ptNode) || isa<DummyObjPN>(ptNode)) {
                continue;
            }
            // The PAG equivalents
    //std::map<llvm::Value*, std::set<llvm::Value*>> ptsToMap;
    //std::map<llvm::Value*, std::set<llvm::Value*>> ptsFromMap;

    //std::map<PAGNode*, std::set<PAGNode*>> pagPtsToMap;
    //std::map<PAGNode*, std::set<PAGNode*>> pagPtsFromMap;

            if (node != ptNode) {
                pagPtsToMap[node].insert(ptNode);
                //pagPtsToMap[node] = ptNode;
                //std::map<llvm::Value*, std::set<llvm::Value*>> ptsToMap;
                pagPtsFromMap[ptNode].insert(node);
            }
           // pagPtsFromMap.insert(ptNode, node);
           /*

            if (node->getValue() != ptNode->getValue()) {
		        llvm::Value* a = const_cast<Value*>(node->getValue());
                ptsToMap[(llvm::Value*)(a)].insert((std::set<llvm::Value*>)(const_cast<Value*>(ptNode->getValue())));
                //ptsToMap.insert(pair<llvm::Value*, std::set<llvm::Value*>>(a, ptNode->getValue()));
                //ptsFromMap[ptNode->getValue()].insert(node->getValue());
                ptsFromMap.insert(ptNode->getValue(), node->getValue());
            }
            */
        }
    }
}
	
/*!
 * Create pointer analysis according to a specified kind and then analyze the module.
 */
void WPAPass::runPointerAnalysis(SVFModule svfModule, u32_t kind)
{
    /// Initialize pointer analysis.
    switch (kind) {
    case PointerAnalysis::Andersen_WPA:
        _pta = new Andersen();
        break;
    case PointerAnalysis::AndersenLCD_WPA:
        _pta = new AndersenLCD();
        break;
    case PointerAnalysis::AndersenWave_WPA:
        _pta = new AndersenWave();
        break;
    case PointerAnalysis::AndersenWaveDiff_WPA:
        _pta = new AndersenWaveDiff();
        break;
    case PointerAnalysis::AndersenWaveDiffWithType_WPA:
        _pta = new AndersenWaveDiffWithType();
        break;
    case PointerAnalysis::FSSPARSE_WPA:
        _pta = new FlowSensitive();
        break;
    default:
        llvm::outs() << "This pointer analysis has not been implemented yet.\n";
        break;
    }

    ptaVector.push_back(_pta);
    _pta->analyze(svfModule);
    if (anderSVFG) {
        SVFGBuilder memSSA(true);
        SVFG *svfg = memSSA.buildSVFG((BVDataPTAImpl*)_pta);
        svfg->dump("ander_svfg");
    }
}



/*!
 * Return alias results based on our points-to/alias analysis
 * TODO: Need to handle PartialAlias and MustAlias here.
 */
llvm::AliasResult WPAPass::alias(const Value* V1, const Value* V2) {

    llvm::AliasResult result = MayAlias;

    PAG* pag = _pta->getPAG();

    /// TODO: When this method is invoked during compiler optimizations, the IR
    ///       used for pointer analysis may been changed, so some Values may not
    ///       find corresponding PAG node. In this case, we only check alias
    ///       between two Values if they both have PAG nodes. Otherwise, MayAlias
    ///       will be returned.
    if (pag->hasValueNode(V1) && pag->hasValueNode(V2)) {
        /// Veto is used by default
        if (AliasRule.getBits() == 0 || AliasRule.isSet(Veto)) {
            /// Return NoAlias if any PTA gives NoAlias result
            result = MayAlias;

            for (PTAVector::const_iterator it = ptaVector.begin(), eit = ptaVector.end();
                    it != eit; ++it) {
                if ((*it)->alias(V1, V2) == NoAlias)
                    result = NoAlias;
            }
        }
        else if (AliasRule.isSet(Conservative)) {
            /// Return MayAlias if any PTA gives MayAlias result
            result = NoAlias;

            for (PTAVector::const_iterator it = ptaVector.begin(), eit = ptaVector.end();
                    it != eit; ++it) {
                if ((*it)->alias(V1, V2) == MayAlias)
                    result = MayAlias;
            }
        }
    }

    return result;
}

ModulePass* llvm::createWPAPass() {
    dbgs() << "createWPAPass";
    dbgs() << "createWPAPass";
    return new WPAPass();
}
INITIALIZE_PASS_BEGIN(WPAPass, "wpa", "Whole Program Analysis", true, true);
INITIALIZE_PASS_END(WPAPass, "wpa", "Whole Program Analysis", true, true);
