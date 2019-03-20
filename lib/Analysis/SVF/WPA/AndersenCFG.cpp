//===- AndersenCFG.cpp -- Control Flow Graph Andersen's analysis-------------------//
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
 * AndersenCFG.cpp
 *
 *  Created on: Nov 21, 2018
 *      Author: Tapti Palit
 */

#include "llvm/Analysis/SVF/MemoryModel/PAG.h"
#include "llvm/Analysis/SVF/WPA/Andersen.h"
#include "llvm/Analysis/SVF/Util/AnalysisUtil.h"

#include <llvm/Support/CommandLine.h> // for tool output file

using namespace llvm;
using namespace analysisUtil;


#define DEBUG_TYPE "andersencfg"

void AndersenCFG::processNode(NodeID nodeId) {
    // Filter out stuff that isn't a function pointer
    //
    PAGNode* pagNode = pag->getPAGNode(nodeId);
    if (!pagNode->hasValue())
        return;
    Value* value = const_cast<Value*>(pagNode->getValue());
    Type* type = value->getType();

    if (!sensitiveHelper->isFunctionPtrType(dyn_cast<PointerType>(type)))
        return;

    numOfIteration++;
    if (0 == numOfIteration % OnTheFlyIterBudgetForStat) {
        dumpStat();
    }

    ConstraintNode* node = consCG->getConstraintNode(nodeId);

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

void AndersenCFG::processAllAddr() {
    errs() << "AndersenCFG\n";
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
                PAGNode* srcNode = pag->getPAGNode(src);
                PAGNode* dstNode = pag->getPAGNode(dst);
                if (srcNode->hasValue() && dstNode->hasValue()) {
                    Value* srcValue = const_cast<Value*>(srcNode->getValue());
                    Value* dstValue = const_cast<Value*>(dstNode->getValue());
                    Type* srcType = srcValue->getType();
                    Type* dstType = dstValue->getType();
                    //if (isSensitiveObj(src) || isSensitiveObj(dst)) {
                    if (sensitiveHelper->isFunctionPtrType(dyn_cast<PointerType>(srcType)) 
                            || sensitiveHelper->isFunctionPtrType(dyn_cast<PointerType>(dstType))) {
                        //errs() << "Pushed " << dst << " to work list at processAllAddr\n";
                        pushIntoWorklist(dst);
                    } 
                } /*else {
                    pushIntoWorklist(dst);
                }*/
            }
        }
    }
}

bool AndersenCFG::updateCallGraph(const CallSiteToFunPtrMap& callsites) {
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
        // Only process these if these are potentially function pointer types
        PAGNode* srcNode = pag->getPAGNode(it->first);
        if (srcNode->hasValue()) {
            Value* srcValue = const_cast<Value*>(srcNode->getValue());
            Type* srcType = srcValue->getType();
            if (sensitiveHelper->isFunctionPtrType(dyn_cast<PointerType>(srcType))) {
                pushIntoWorklist(it->first);
            }
        }
    }
    if(!newEdges.empty())
        return true;
    return false;

}
