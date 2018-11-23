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

void AndersenDD::analyze(SVFModule svfModule) {
    Size_t prevIterationSensitiveCopyEdges = 0;
    /// Initialization for the Solver
    initialize(svfModule);
    updateCallGraph(*(getCallSiteToFunPtrMap()));
    sensitiveOnly = false;


    DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Start Solving Constraints\n"));

    preprocessAllAddr();

    do {
        numOfIteration++;

        if(0 == numOfIteration % OnTheFlyIterBudgetForStat) {
            dumpStat();
        }

        reanalyze = false;

        /// Start solving constraints
        solve();

        double cgUpdateStart = stat->getClk();
        if (updateCallGraph(getIndirectCallsites()))
            reanalyze = true;
        double cgUpdateEnd = stat->getClk();
        timeOfUpdateCallGraph += (cgUpdateEnd - cgUpdateStart) / TIMEINTERVAL;

    } while (reanalyze);

    DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Finish Solving Constraints\n"));

    /// finalize the analysis
    finalize();
}


/*!
 * Start constraint solving
 */
void AndersenDD::processNode(NodeID nodeId) {

    numOfIteration++;
    if (0 == numOfIteration % OnTheFlyIterBudgetForStat) {
        dumpStat();
    }

    ConstraintNode* node = consCG->getConstraintNode(nodeId);

    for (ConstraintNode::const_iterator it = node->outgoingAddrsBegin(), eit =
                node->outgoingAddrsEnd(); it != eit; ++it) {
        processAddr(cast<AddrCGEdge>(*it));
    }

    // Demand driven 
    // If we're storing something to another location
    // We need to process the other location as well
    for (ConstraintNode::const_iterator it = node->outgoingStoresBegin(),
            eit = node->outgoingStoresEnd(); it != eit; ++it) {
        NodeID src = nodeId;
        NodeID dst = (*it)->getDstID();
        ConstraintNode* dstNode = consCG->getConstraintNode(dst);
        /*
        // We could be doing either of two things -- storing to a Value Node 
        // In that case, we need to figure out what it could point to
        for (PointsTo::iterator piter = getPts(dst).begin(), epiter = 
        getPts(dst).end(); piter != epiter; ++piter) {
        NodeID ptd = *piter;
        errs() << "SRC = " << src << " DST = " << dst << " PTD = " << ptd << "\n";
        if (processStore(ptd, *it)) {
        pushIntoWorklist(dst);
        }
        }
        */
        // We need to process this node too
        // If this is a GepObjPN, then find it's original FI node
        /*
           PAGNode* pagNode = pag->getPAGNode(dst);
           if (GepObjPN* gepObjPN = dyn_cast<GepObjPN>(pagNode)) {
           NodeID fiObjID = getFIObjNode(dst);
           pushIntoWorklist(fiObjID);
           } else {
           pushIntoWorklist(dst);
           }
           */
        // Check if this is a constraint node corresponding to a
        // field-sensitive PAG node
        for (ConstraintNode::const_iterator it = dstNode->directInEdgeBegin(), eit =
                dstNode->directInEdgeEnd(); it != eit; ++it) {
            if (GepCGEdge* gepEdge = llvm::dyn_cast<GepCGEdge>(*it)) {
                pushIntoWorklist(gepEdge->getSrcID());
            }
        }
        pushIntoWorklist(dst);
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
