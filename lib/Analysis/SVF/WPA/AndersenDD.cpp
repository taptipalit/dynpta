//===- AndersenDD.cpp -- Demand driven, field-sensitive Andersen's analysis-------------------//
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
 * AndersenDD.cpp
 *
 *  Created on: Nov 11, 2018
 *      Author: Tapti Palit
 */

#include "llvm/Analysis/SVF/MemoryModel/PAG.h"
#include "llvm/Analysis/SVF/WPA/Andersen.h"
#include "llvm/Analysis/SVF/Util/AnalysisUtil.h"

#include <llvm/Support/CommandLine.h> // for tool output file

using namespace llvm;
using namespace analysisUtil;


#define DEBUG_TYPE "andersendd"

bool AndersenDD::updateCallGraph(const CallSiteToFunPtrMap& callsites) {
    CallEdgeMap newEdges;
    onTheFlyCallGraphSolve(callsites,newEdges);
    NodePairSet cpySrcNodes;	/// nodes as a src of a generated new copy edge
    for(CallEdgeMap::iterator it = newEdges.begin(), eit = newEdges.end(); it!=eit; ++it ) {
        llvm::CallSite cs = it->first;
        for(FunctionSet::iterator cit = it->second.begin(), ecit = it->second.end(); cit!=ecit; ++cit) {
            consCG->connectCaller2CalleeParams(cs,*cit,cpySrcNodes);
        }
    }

    // We're not doing this on-the-fly, so this should be okay here
    /*
    for(NodePairSet::iterator it = cpySrcNodes.begin(), eit = cpySrcNodes.end(); it!=eit; ++it) {
        pushIntoWorklist(it->first);
    }
    */

    if(!newEdges.empty())
        return true;
    return false;

}

ConstraintGraph*  AndersenDD::findSensitiveSubGraph(ConstraintGraph* fullGraph) {
    ConstraintGraph* sensitiveSubGraph = new ConstraintGraph(fullGraph->getPAG(), true);
    NodeStack& nodeStack = SCCDetect();

    WorkList sensitiveWork;
    // Find the sensitive nodes
    while (!nodeStack.empty()) {
        NodeID nodeId = nodeStack.top();
        nodeStack.pop();
        if (isSensitiveObj(nodeId)) {
            sensitiveWork.push(nodeId);
        }
    }

    /*
    errs() << "================== Full Constraint Graph =======================\n";
    errs() << "Number of nodes: " << fullGraph->getTotalNodeNum() << "\n";
    errs() << "Number of edges: " << fullGraph->getTotalEdgeNum() << "\n";
    errs() << "Number of Variant Gep edges: " << fullGraph->getVariableGepEdgeNum() << "\n";
    errs() << "Number of Normal Gep edges: " << fullGraph->getNormalGepEdgeNum() << "\n";
    */

    sensitiveSubGraph->createSubGraphReachableFrom(fullGraph, sensitiveWork);

    errs() << "================== Selective Constraint Graph =======================\n";
    errs() << "Number of nodes: " << sensitiveSubGraph->getTotalNodeNum() << "\n";
    errs() << "Number of edges: " << sensitiveSubGraph->getTotalEdgeNum() << "\n";
    errs() << "Number of Variant Gep edges: " << sensitiveSubGraph->getVariableGepEdgeNum() << "\n";
    errs() << "Number of Normal Gep edges: " << sensitiveSubGraph->getNormalGepEdgeNum() << "\n";

    return sensitiveSubGraph;

}

void AndersenDD::analyze(SVFModule svfModule) {
    Size_t prevIterationSensitiveCopyEdges = 0;
    /// Initialization for the Solver
    initialize(svfModule);
    // AnderDD depends on the resolution of the function pointers from the
    // AnderCFG
    assert(callSiteToFunPtrMap && "AnderCFG should have resolved the function pointers");
    updateCallGraph(*callSiteToFunPtrMap);
    //sensitiveOnly = false;

    DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Start Solving Constraints\n"));

    errs() << "Preprocessing all addresses: start\n";
    preprocessAllAddr();
    errs() << "Preprocessing all addresses: end\n";

    errs() << "Solve:start\n";
    solve();
    errs() << "Solve:end\n";
    
    DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Finish Solving Constraints\n"));

    /// finalize the analysis
    finalize();

    errs() << "Number of Positive Weight Cycles: " << problematicPWC << "\n";
}


/*!
 * Start constraint solving
 */
void AndersenDD::processNode(NodeID nodeId) {

    //errs() << "Processing node: " << nodeId << "\n";
    numOfIteration++;
    if (0 == numOfIteration % OnTheFlyIterBudgetForStat) {
        dumpStat();
    }

    ConstraintNode* node = consCG->getConstraintNode(nodeId);

    node->incNumTimesVisited();
    //errs() << "Node getId(): " << node->getId() << " nodeId: " << nodeId << " for node: " << node <<  " visited " << node->getNumTimesVisited() << "\n";

    for (ConstraintNode::const_iterator it = node->outgoingAddrsBegin(), eit =
                node->outgoingAddrsEnd(); it != eit; ++it) {
        processAddr(cast<AddrCGEdge>(*it));
    }

    for (PointsTo::iterator piter = getPts(nodeId).begin(), epiter =
                getPts(nodeId).end(); piter != epiter; ++piter) {
        NodeID ptd = *piter;
        // handle load
        for (ConstraintNode::const_iterator it = node->outgoingLoadsBegin(),
                eit = node->outgoingLoadsEnd(); it != eit; ++it) {
            if (processLoad(ptd, *it))
                pushIntoWorklist(ptd);
        }

        // handle store
        for (ConstraintNode::const_iterator it = node->incomingStoresBegin(),
                eit = node->incomingStoresEnd(); it != eit; ++it) {
            if (processStore(ptd, *it))
                pushIntoWorklist((*it)->getSrcID());
        }
    }

    // handle copy, call, return, gep
    for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(), eit =
                node->directOutEdgeEnd(); it != eit; ++it) {
        if (GepCGEdge* gepEdge = llvm::dyn_cast<GepCGEdge>(*it))
            processGep(nodeId, gepEdge);
        else

            processCopy(nodeId, *it);
    }
}

void AndersenDD::preprocessAllAddr() {
    for (ConstraintGraph::const_iterator nodeIt = consCG->begin(), nodeEit = consCG->end(); nodeIt != nodeEit; nodeIt++) {
        ConstraintNode * cgNode = nodeIt->second;
        for (ConstraintNode::const_iterator it = cgNode->incomingAddrsBegin(), eit = cgNode->incomingAddrsEnd();
                it != eit; ++it) {
            numOfProcessedAddr++;
            AddrCGEdge* addr = cast<AddrCGEdge>(*it);
            NodeID dst = addr->getDstID();
            NodeID src = addr->getSrcID();
            bool updated = addPts(dst,src);
            if (updated) {
                if (isSensitiveObj(src) || isSensitiveObj(dst)) {
                    pushIntoWorklist(dst);
                } 
            }
        }
    }
}
