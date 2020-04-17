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


#include "Util/SVFModule.h"
#include "MemoryModel/PointerAnalysis.h"
#include "WPA/WPAPass.h"
#include "WPA/Andersen.h"
#include "WPA/FlowSensitive.h"
#include "WPA/TypeAnalysis.h"
#include <llvm/Support/CommandLine.h>

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
	        clEnumValN(PointerAnalysis::Steensgard_WPA, "steens", "Standard unification-based analysis"),
            clEnumValN(PointerAnalysis::SteensgaardFast_WPA, "steens-fast", "Fast unification-based analysis"),
            clEnumValN(PointerAnalysis::AndersenLCD_WPA, "lander", "Lazy cycle detection inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenWave_WPA, "wander", "Wave propagation inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenWaveDiff_WPA, "ander", "Diff wave propagation inclusion-based analysis"),
            clEnumValN(PointerAnalysis::AndersenWaveDiffWithType_WPA, "andertype", "Diff wave propagation with type inclusion-based analysis"),
            clEnumValN(PointerAnalysis::FSSPARSE_WPA, "fspta", "Sparse flow sensitive pointer analysis"),
			clEnumValN(PointerAnalysis::TypeCPP_WPA, "type", "Type-based fast analysis for Callgraph, PAG and CHA"),
            clEnumValN(PointerAnalysis::Layered_WPA, "layered", "Layered pointer analysis with unification based approach, followed by inclusion based approach")
        ));


static cl::bits<WPAPass::AliasCheckRule> AliasRule(cl::desc("Select alias check rule"),
        cl::values(
            clEnumValN(WPAPass::Conservative, "conservative", "return MayAlias if any pta says alias"),
            clEnumValN(WPAPass::Veto, "veto", "return NoAlias if any pta says no alias")
        ));

cl::opt<bool> anderSVFG("svfg", cl::init(false),
                        cl::desc("Generate SVFG after Andersen's Analysis"));

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

void WPAPass::performLayeredPointerAnalysis(SVFModule svfModule, Module* M) {
	outs() << "Started running Steensgaard analysis:\n";
    outs() << "TODO: layered analysis still needs to be context sensitive\n";
	SteensgaardFast* steens = new SteensgaardFast();
    _pta = steens;
    steens->analyze(svfModule);
    outs() << "Ended running Steensgaard anlaysis:\n";

    // Gather the sensitive annotated values
	collectGlobalSensitiveAnnotations(*M);
    collectLocalSensitiveAnnotations(*M);

	ConstraintGraph* subGraph = computeSteensSubGraph();
    outs() << "Retained constraint graph has : " << subGraph->getTotalNodeNum() << "\n";
    subGraph->dump("consCG_subgraph");

    PAG::CallSiteToFunPtrMap& callSiteToFunPtrMap = const_cast<PAG::CallSiteToFunPtrMap&>(steens->getIndirectCallsites());

    outs() << "Started running Andersen analysis:\n";
    AndersenWaveDiff* ander = new AndersenWaveDiff();
    _pta = ander;
    // Glue start
    // The constraint Graph supplied by AndersenCFG has the complete CFG
    ander->setPAG(steens->getPAG());
    ander->setCHGraph(steens->getCHGraph());
    ander->setTypeSystem(const_cast<TypeSystem*>(steens->getTypeSystem()));
    ander->setPTACallGraph(steens->getPTACallGraph());
    ander->setConstraintGraph(subGraph);
    ander->updateCallGraph(callSiteToFunPtrMap);
    // Glue end
    ander->analyzeSubgraph(svfModule); // Skip initialize
    outs() << "Ended running Andersens analysis:\n";
}

/*!
 * We start from here
 */
void WPAPass::runOnModule(SVFModule svfModule) {
    if (!PASelected.isSet(PointerAnalysis::Layered_WPA)) {
        for (u32_t i = 0; i<= PointerAnalysis::Default_PTA; i++) {
            if (PASelected.isSet(i))
                runPointerAnalysis(svfModule, i);
        }
    } else {
        Module* M = svfModule.getModule(0);
        performLayeredPointerAnalysis(svfModule, M);
    }
}

void WPAPass::performSourceSinkAnalysis(Module& M) {

    PAG* pag = _pta->getPAG();


    std::vector<PAGNode*> sinkSites;
    std::vector<PAGNode*> workList; // List of allocation sites for which we still need to perform source-sink analysis
    std::vector<PAGNode*> analyzedList; // List of sites for which we have completed source-sink analysis (item as Source)
    std::vector<PAGNode*> analyzedPtrList; // List of pointers for which we have completed source-sink analysis (item as Source)
    std::set<PAGNode*> tempSinkSites; // Temporary list of sink-sites
    for (PAGNode* sensitiveObjNode: SensitiveObjList) {
        outs() << "Before dataflow, sensitive value: " << *sensitiveObjNode << "\n";
        workList.push_back(sensitiveObjNode);
    }

    while (!workList.empty()) {
        PAGNode* work = workList.back();
        workList.pop_back();

        for (PAGNode* ptsFrom: pagPtsFromMap[work]) {
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

    outs() << "After dataflow analysis:\n";
    for (PAGNode* sensValNode: SensitiveObjList) {
        if (GepObjPN* gepObjPN = dyn_cast<GepObjPN>(sensValNode)) {
            outs() << "Sensitive value: " << *gepObjPN << "\n";
        } else {
            outs() << "Sensitive value: " << *sensValNode << "\n";
        }
    }
}


void WPAPass::findIndirectSinkSites(PAGNode* ptsFrom, std::set<PAGNode*>& sinkSites) {
    // tpalit: There's no difference between a direct and a indirect flow
    // Because in the algorithm for the indirect flow, we only track the Value
    // Flow edges, that capture only the non-pointer flows
    findDirectSinkSites(ptsFrom, sinkSites);
}

/**
 * Find all the sink sites that this value directly flows to
 */
void WPAPass::findDirectSinkSites(PAGNode* source, std::set<PAGNode*>& sinkSites) {

/*

    PAG* pag = _pta->getPAG();

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
                for (PAGNode* ptsTo: pagPtsToMap[sinkStorePtr]) {
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

ConstraintGraph* WPAPass::computeSteensSubGraph() {
    PAG* pag = _pta->getPAG();
    int totalNumSets = 0;
    int totalRetainedNodes = 0;

    ConstraintGraph* consCG = nullptr;
    if (Andersen* anders = dyn_cast<Andersen>(_pta)) {
        consCG = anders->getConstraintGraph();
    }


    SteensgaardFast* steens = dyn_cast<SteensgaardFast>(_pta);

    std::set<NodeID> sensitiveNodeIds;
    std::set<SetID> setSet;
    for (PAGNode* senPAGNode: SensitiveObjList) {
        sensitiveNodeIds.insert(senPAGNode->getId());
    }

    // Add the nodes to the WorkList
    WorkList workList;

    steens->findPointsToFromChain(sensitiveNodeIds, setSet, totalNumSets, totalRetainedNodes, workList);

    outs() << "Total number of sensitive sets: " << setSet.size() << "\n";
    outs() << "Total number of sets: " << totalNumSets << "\n";
    outs() << "Total number of sensitive nodes: " << totalRetainedNodes << "\n";
    outs() << "Total node num: " << consCG->getTotalNodeNum() << "\n";

    /*
    std::vector<int> senIds{10,100,1020,1021,1022,1023,1024,1025,1026,1027,1028,1029,103,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,106,109,1125,1126,1138,1139,1151,1152,1158,1159,11727,12116,12564,12746,12761,12907,12919,12931,13049,13816,15562,15564,15687,1690,1704,1705,1708,1711,17355,17446,18341,18343,1885,1895,1897,1899,1901,1903,1907,1909,1910,1911,1913,1915,20082,20335,20337,20339,20345,21003,21186,21266,21274,21276,21278,21359,21965,22039,22188,22194,22196,22455,22568,22697,22699,22807,22879,22938,23172,25856,26638,27097,27149,27174,27208,27391,27830,27982,28921,28976,29053,29245,29323,29374,29509,29764,30817,31127,31129,31169,31171,31223,31225,31519,32037,32039,33555,34018,34020,34070,34072,34310,34312,34314,34316,34318,3498,35870,35872,35874,35876,36746,36748,36794,36796,36798,36963,37030,37032,37034,37036,37038,37040,37042,37044,37046,372,37707,38669,387,38747,38778,38821,3884,38846,38871,38879,38898,3891,38913,38938,38963,38994,39037,39062,39087,39095,39113,39128,39159,39202,39227,39252,39260,39279,39331,39407,39521,39523,39525,39527,39533,39786,40019,40111,40115,4017,4019,4029,4032,40329,4034,40402,41238,41395,41419,41559,43160,43314,43316,43436,43438,43563,43726,43789,44250,44448,44450,44555,44826,45043,47642,47656,47711,47722,47745,47762,47768,47779,47792,47810,47827,47838,47861,47878,47884,47896,47909,47927,47946,47957,47980,47997,48019,48025,48037,48050,48070,48089,48100,49400,49769,50068,50070,50133,50135,50199,50201,50270,50272,51339,51358,51374,51464,51541,51613,51688,51708,51714,51728,51743,51852,51998,52216,52218,52224,52428,52430,52432,52580,52711,52915,53033,53035,541,54503,54608,54610,54612,54614,54616,54618,54620,54622,54628,54630,55430,556,557,558,559,560,56093,561,56104,562,565,56632,56638,598,601,604,61275,61289,622,627,64713,652,653,65721,6841,6843,68448,68450,68714,68716,68832,68834,69013,69015,69229,6943,6948,6953,7,7534,7536,7540,7809,7811,7875,7877,7879,8734,882,889,91,94,9651,9653,97,9924}; 

    */

    ConstraintGraph* newConsG = new ConstraintGraph(consCG->getPAG(), true);
    
    newConsG->createSubGraphReachableFrom(consCG, workList);

    /*
    for (int senId: senIds) {
        if (!newConsG->hasGNode(senId)) {
            // Not found node
            errs() << "NOT FOUND NODE: " << senId << "\n";
        }
    }
    errs() << "========================= DONE CHECK==========================\n";
    */
    outs() << "New constraint graph with : " << newConsG->getTotalNodeNum() << " nodes created\n";

    
    
    return newConsG;
}

void WPAPass::doSteensPostProcessing() {
    PAG* pag = _pta->getPAG();
    std::vector<PAGNode*> tempObjList;

    SteensgaardFast* steens = dyn_cast<SteensgaardFast>(_pta);
    assert(steens && "Should only pass a steensgaard-fast instance here");
    int countSensitivePointers = 0;
    std::set<NodeID> sensitiveNodeIds;
    std::set<PAGNode*> nodeSet;
    for (PAGNode* senPAGNode: SensitiveObjList) {
        for (PAGNode* ptsToNode: pagPtsToMap[senPAGNode]) {
            tempObjList.push_back(ptsToNode);
        }
    }
    // Remove duplicates
    std::set<PAGNode*> sensitiveObjSet(tempObjList.begin(), tempObjList.end());

    outs() << "Number of objects pointed to by the sensitive annotated pointers : " << sensitiveObjSet.size() << "\n";

}

void WPAPass::doAndersenPostProcessing() {
    PAG* pag = _pta->getPAG();

    ConstraintGraph* consCG = nullptr;
    if (Andersen* anders = dyn_cast<Andersen>(_pta)) {
        consCG = anders->getConstraintGraph();
    }

    // Check how many objects are pointed to by the SensitiveObjList
    std::vector<PAGNode*> tempObjList;
    for (PAGNode* senPAGNode: SensitiveObjList) {
        // Find their representative node
        PAGNode* repNode = pag->getPAGNode(consCG->getRep(senPAGNode->getId()));
        for(PAGNode* ptsToNode: pagPtsToMap[repNode]) {
            tempObjList.push_back(ptsToNode);
            for (NodeID subNodeId: consCG->getNode(ptsToNode->getId())) {
                PAGNode* subPtsToNode = pag->getPAGNode(subNodeId);
                tempObjList.push_back(subPtsToNode);
            }
        }
    }
    // Remove duplicates
    std::set<PAGNode*> sensitiveObjSet(tempObjList.begin(), tempObjList.end());

    outs() << "Number of objects pointed to by the sensitive annotated pointers : " << sensitiveObjSet.size() << "\n";
}

void WPAPass::computeSubGraph(std::set<PAGNode*>& initSet, ConstraintGraph* constraintGraph) {
    llvm::SparseBitVector<> fullyProcessedConsNodeList; // Nodes whose edges are fully processed

    WorkList workList;

    std::set<NodeID> finalSet;
    std::set<ConstraintNode*> finalConsSet;

    for (PAGNode* node: initSet) {
        workList.push(node->getId());
        finalSet.insert(node->getId());
        finalConsSet.insert(constraintGraph->getConstraintNode(node->getId()));
    }

    while (!workList.empty()) {
        NodeID nodeId = workList.pop();
        ConstraintNode* node =  constraintGraph->getConstraintNode(nodeId);

        if (!fullyProcessedConsNodeList.test(nodeId)) {
            // Find all incoming Addr edges for this node
            for (ConstraintNode::const_iterator it = node->incomingAddrsBegin(),
                    eit = node->incomingAddrsEnd(); it != eit; ++it) {
                workList.push((*it)->getSrcID());
                finalSet.insert((*it)->getSrcID());
                finalConsSet.insert(constraintGraph->getConstraintNode((*it)->getSrcID()));
            }

			// Find all outgoing Addr edges for this node.
            for (ConstraintNode::const_iterator it = node->outgoingAddrsBegin(),
                    eit = node->outgoingAddrsEnd(); it != eit; ++it) {
                workList.push((*it)->getDstID());
                finalSet.insert((*it)->getDstID());
                finalConsSet.insert(constraintGraph->getConstraintNode((*it)->getDstID()));
            }
		
			// Find all incoming Copy edges for this node. (Actually Copy and Gep, only there's no Gep)
            for (ConstraintNode::const_iterator it = node->directInEdgeBegin(),
                    eit = node->directInEdgeEnd(); it != eit; ++it) {
                workList.push((*it)->getSrcID());
                finalSet.insert((*it)->getSrcID());
                finalConsSet.insert(constraintGraph->getConstraintNode((*it)->getSrcID()));
            }

			// Find all outgoing Copy edges for this node.
            for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(),
                    eit = node->directOutEdgeEnd(); it != eit; ++it) {
                workList.push((*it)->getDstID());
                finalSet.insert((*it)->getDstID());
                finalConsSet.insert(constraintGraph->getConstraintNode((*it)->getDstID()));
            }

			// Add all the nodes, for which this node is a representative of.
            for (NodeID subNodeId: constraintGraph->getNode(nodeId)) {
                finalSet.insert(subNodeId);
                finalConsSet.insert(constraintGraph->getConstraintNode(subNodeId));
            }
            fullyProcessedConsNodeList.set(nodeId);
        }
    }

    outs() << "Total node num: " << constraintGraph->getTotalNodeNum() << "\n";
    outs() << "Retained nodes: " << finalSet.size() << "\n";

    // Good, now we must make sure that we're not counting Constants because
    // they typically don't flow anywhere and are removed a lot in the pruning
    // part

    PAG* pag = constraintGraph->getPAG();

    int nonConstantValues = 0;

    for(PAG::iterator it = pag->begin(), eit = pag->end(); it!=eit; it++) { 
        NodeID id = it->first;
        PAGNode* pagNode = pag->getPAGNode(id);
        if (pagNode->hasValue()) {
            Value* value = const_cast<Value*>(pagNode->getValue());
            if (!isa<Constant>(value)) {
                nonConstantValues ++; 
            }
        }
    }

    outs() << "Total number of non-constant nodes: " << nonConstantValues << "\n";

}

void WPAPass::collectGlobalSensitiveAnnotations(Module& M) {
	std::vector<StringRef> GlobalSensitiveNameList;
    PAG* pag = _pta->getPAG();

	// Get the names of the global variables that are sensitive
	if(GlobalVariable* GA = M.getGlobalVariable("llvm.global.annotations")) {
		for (Value *AOp : GA->operands()) {
			if (ConstantArray *CA = dyn_cast<ConstantArray>(AOp)) {
				for (Value *CAOp : CA->operands()) {
					if (ConstantStruct *CS = dyn_cast<ConstantStruct>(CAOp)) {
						if (CS->getNumOperands() < 4) {
							dbgs() << "Unexpected number of operands found. Skipping annotation. \n";
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

void WPAPass::collectLocalSensitiveAnnotations(Module &M) {
    PAG* pag = _pta->getPAG();

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

bool WPAPass::isSensitiveObj(PAGNode* Val) {
    if (std::find(SensitiveObjList.begin(), SensitiveObjList.end(), Val) != SensitiveObjList.end()) {
        return true;
    } else {
        return false;
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
    case PointerAnalysis::Steensgard_WPA:
        _pta = new Steensgard();
        break;
    case PointerAnalysis::SteensgaardFast_WPA:
        _pta = new SteensgaardFast();
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
    case PointerAnalysis::TypeCPP_WPA:
		_pta = new TypeAnalysis();
		break;
    default:
        assert(false && "This pointer analysis has not been implemented yet.\n");
        return;
    }

   Module* M = svfModule.getModule(0);
   contextSensitivityPass->recompute(*M, 5, 2);
    _pta->setContextCriticalFunctions(contextSensitivityPass->getTop10CriticalFunctions());
    ptaVector.push_back(_pta);
    _pta->analyze(svfModule);
    if (anderSVFG) {
        SVFGBuilder memSSA(true);
        assert(isa<Andersen>(_pta) && "supports only andersen for pre-computed SVFG");
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


bool WPAPass::isPointsToNodes(NodeID ptrNodeId, std::vector<NodeID>& sensitiveNodeIds) {
    SteensgaardFast* steens = dyn_cast<SteensgaardFast>(_pta);
    assert(steens && "getPtsFrom works only on Steensgaard");
    
    for (NodeID ptsId: steens->getPts(ptrNodeId)) {
        if (std::find(sensitiveNodeIds.begin(), sensitiveNodeIds.end(), ptsId) != sensitiveNodeIds.end()) {
            return true;
        }
    }
    return false;
}


std::vector<PAGNode*> WPAPass::pointsToSet(NodeID ptrNodeId) {
    SteensgaardFast* steens = dyn_cast<SteensgaardFast>(_pta);
    assert(steens && "getPtsFrom works only on Steensgaard");
    
    PAG* pag = _pta->getPAG();
    std::vector<PAGNode*> sensitiveNodeIdForPointsToSet;
    for (NodeID ptsId: steens->getPts(ptrNodeId)) {
            sensitiveNodeIdForPointsToSet.push_back(pag->getPAGNode(ptsId));
   }
    return sensitiveNodeIdForPointsToSet;
}

void WPAPass::getPtsFrom(std::vector<PAGNode*>& sensitiveNodes,
                    std::set<PAGNode*>& pointsFrom) {
    PAG* pag = _pta->getPAG();

    SteensgaardFast* steens = dyn_cast<SteensgaardFast>(_pta);
    assert(steens && "getPtsFrom works only on Steensgaard");
    

    for (PAGNode* sensitiveNode: sensitiveNodes) {
        PointsTo ptsFrom = steens->getPtsFrom(sensitiveNode->getId());
        for (NodeBS::iterator ptIt = ptsFrom.begin(), ptEit = ptsFrom.end(); ptIt != ptEit; ++ptIt) {
            PAGNode* ptNode = pag->getPAGNode(*ptIt);
            pointsFrom.insert(ptNode);
        }
    }
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
            if (node != ptNode) {
                pagPtsToMap[node].insert(ptNode);
                //pagPtsToMap[node] = ptNode;
                //std::map<llvm::Value*, std::set<llvm::Value*>> ptsToMap;
                pagPtsFromMap[ptNode].insert(node);
            }
        }
    }
}

PAGNode* WPAPass::getPAGValNodeFromValue(Value* llvmValue) {
    PAG* pag = _pta->getPAG();
    assert(pag->hasValueNode(llvmValue) && "Can't get PAG ValPN as none exists.");
    return pag->getPAGNode(pag->getValueNode(llvmValue));
}

ModulePass* llvm::createWPAPass() {
    dbgs() << "createWPAPass";
    return new WPAPass();
}

INITIALIZE_PASS_BEGIN(WPAPass, "wpa", "Whole Program Analysis", true, true);
INITIALIZE_PASS_DEPENDENCY(ContextSensitivityAnalysisPass);
INITIALIZE_PASS_END(WPAPass, "wpa", "Whole Program Analysis", true, true);
