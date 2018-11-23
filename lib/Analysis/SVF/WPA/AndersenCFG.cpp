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

void AndersenCFG::processAllAddr() {
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
                Value* srcValue = srcNode->getValue();
                Value* dstValue = dstNode->getValue();
                Type* srcType = srcValue->getType();
                Type* dstType = dstValue->getType();
                //if (isSensitiveObj(src) || isSensitiveObj(dst)) {
                if (sensitiveHelper->isFunctionPtrType(dyn_cast<PointerType>(srcType)) 
                        || sensitiveHelper->isFunctionPtrType(dyn_cast<PointerType>(dstType)))
                    pushIntoWorklist(dst);
                } 
            }
        }
    }
}
