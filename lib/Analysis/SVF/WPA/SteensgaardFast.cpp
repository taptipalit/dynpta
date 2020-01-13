//===- SteensgaardFast.cpp -- Field-insensitive Steensgaard Analysis -------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2019-2020>  <Tapti Palit>
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
 * SteensgaardFast.cpp
 *
 *  Created on: Oct 27, 2019
 *      Author: Tapti Palit
 */

#include "MemoryModel/PAG.h"
#include "WPA/Andersen.h"
#include "Util/AnalysisUtil.h"
#include <vector>
#include <llvm/Support/CommandLine.h> // for tool output file

using namespace llvm;
using namespace analysisUtil;

/*!
 * Process address edges. Same as Andersen's, but doesn't push anything into a
 * worklist
 */
void SteensgaardFast::processAddr(const AddrCGEdge* addr) {
    NodeID dst = addr->getDstID();
    NodeID src = addr->getSrcID();
    addPts(dst,src);
}

void SteensgaardFast::analyze(SVFModule svfModule) {
    /// Initialization for the Solver
    double steensAnalysisTime;

    initialize(svfModule);
    processAllAddr();

    // Now, initialize and build the initial points-to graph
    ptgraph = new PTG(pag, consCG, getPTDataTy());
	double timeStart, timeEnd;
	timeStart = CLOCK_IN_MS();

    ptgraph->solve();

    // Update the callgraph
    // If this creates new copy edges, then we record that
    // We solve only for the new copy edges
    // We repeat till we find new edges
    std::vector<ConstraintEdge*> newCopyEdges;
    outs() << "Total number of indirect call sites: " << getIndirectCallsites().size() << "\n";
    updateCallGraph(getIndirectCallsites(), newCopyEdges);
    while (!newCopyEdges.empty()) {
        DBOUT(DSTEENS, outs() << "Solving for new " << newCopyEdges.size() << " edges\n";);
        outs() << "Solving for new " << newCopyEdges.size() << " edges\n";
        ptgraph->solve(newCopyEdges);
        newCopyEdges.clear();
        updateCallGraph(getIndirectCallsites(), newCopyEdges);
    }

    finalize();
	timeEnd = CLOCK_IN_MS();
	steensAnalysisTime = (timeEnd - timeStart) / TIMEINTERVAL;

    outs() << "Steensgaard Analysis took: " << (long)steensAnalysisTime << " seconds.\n";


    //ptgraph->dumpMaps();
}

/**
 * This function updates the constraint graph with the new points-to edges
 * found.
 *
 * It uses the getPts() implementation from SteensgaardFast to update the
 * state. SteensgaardFast's getPts() implementation uses the information in
 * the PTG to compute the pts to sets.
 *
 * Then, it returns the copyEdges inserted, because we must process them
 * again.
 */
bool SteensgaardFast::updateCallGraph(const CallSiteToFunPtrMap& callsites, std::vector<ConstraintEdge*>& copyEdges) {
    // Solve the callgraph, using SteensgaardFast's getPts() implementation
    CallEdgeMap newEdges;
    onTheFlyCallGraphSolve(callsites,newEdges);
    NodePairSet cpySrcNodes;	/// nodes as a src of a generated new copy edge
    for(CallEdgeMap::iterator it = newEdges.begin(), eit = newEdges.end(); it!=eit; ++it ) {
        llvm::CallSite cs = it->first;
        for(FunctionSet::iterator cit = it->second.begin(), ecit = it->second.end(); cit!=ecit; ++cit) {
            consCG->connectCaller2CalleeParams(cs,*cit,cpySrcNodes);
        }
    }
    for(NodePairSet::iterator it = cpySrcNodes.begin(), eit = cpySrcNodes.end(); it!=eit; ++it) {
        NodeID srcId = it->first;
        NodeID dstId = it->second;
        // Now, find that copy edge
        ConstraintEdge* edge = consCG->getCopyEdge(srcId, dstId);
        copyEdges.push_back(edge);
    }
    if(!newEdges.empty())
        return true;
    return false;
}

void SteensgaardFast::findPointsToFromChain(std::set<NodeID>& senIDs, std::set<SetID>& setSet, 
        int& totalNumSets, int& totalRetainedNodeNum, WorkList& retainedNodeList) {
    std::vector<SetID> workList;
    std::vector<SetID> checkedList;

    PTG::PtdMapTy& ptdMap = ptgraph->getPtdMap();
    PTG::PtdRevMapTy& ptdRevMap = ptgraph->getPtdRevMap();
    PTG::PtsToSetMapTy& ptsToSetMap = ptgraph->getPtsToSetMap();
    PTG::PtsFromSetMapTy& ptsFromSetMap = ptgraph->getPtsFromSetMap();

    totalNumSets = ptsToSetMap.size();

    // Which sets to the sensitive NodeIDs belong to?
    for (NodeID id: senIDs) {
        SetID setId = ptdRevMap[id];
        workList.push_back(setId);
        setSet.insert(setId);
    }

    // Now get all of the pts-to and pts-from sets of these guys
    while (!workList.empty()) {
        SetID sId = workList.back();
        workList.pop_back();
        setSet.insert(sId);
        auto iter = ptgraph->getPtsToSetMap().find(sId);
        if (iter != ptgraph->getPtsToSetMap().end()) {
            if (std::find(checkedList.begin(), checkedList.end(), iter->second) == checkedList.end()) {
                checkedList.push_back(iter->second);
                workList.push_back(iter->second);
            }
            
        }
        iter = ptgraph->getPtsFromSetMap().find(sId);
        if (iter != ptgraph->getPtsFromSetMap().end()) {
            if (std::find(checkedList.begin(), checkedList.end(), iter->second) == checkedList.end()) {
                checkedList.push_back(iter->second);
                workList.push_back(iter->second);
            }
        }
    }

    errs() << "Sensitive sets\n";
    for (SetID setID: setSet) {
        errs() << "Set ID: " << setID << "\n";
        for (SparseBitVector<>::iterator it = ptdMap[setID]->begin(), eit = ptdMap[setID]->end(); it != eit; it++) {
            NodeID nodeId = *it;
            retainedNodeList.push(nodeId);
        }
        totalRetainedNodeNum += ptdMap[setID]->count();
    }
}
