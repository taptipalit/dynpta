//===- ConsG.cpp -- Constraint graph representation-----------------------------//
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
 * ConstraintGraph.cpp
 *
 *  Created on: Oct 14, 2013
 *      Author: Yulei Sui
 */

#include "llvm/Analysis/SVF/MemoryModel/ConsG.h"
#include "llvm/Analysis/SVF/Util/AnalysisUtil.h"
#include "llvm/Analysis/SVF/Util/GraphUtil.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace analysisUtil;

#define DEBUG_TYPE "svf"

static cl::opt<bool> ConsCGDotGraph("dump-consG", cl::init(true),
                                    cl::desc("Dump dot graph of Constraint Graph"));


void ConstraintGraph::cloneAddrEdge(ConstraintEdge* edge) {
    NodeID srcID = edge->getSrcID();
    NodeID dstID = edge->getDstID();
    addAddrCGEdge(srcID, dstID);
    LLVM_DEBUG(dbgs() << "Cloning addr edge: " << srcID << " --> " << dstID << "\n";);
}

void ConstraintGraph::cloneStoreValEdge(ConstraintEdge* edge) {
    NodeID srcID = edge->getSrcID();
    NodeID dstID = edge->getDstID();
    addStoreValCGEdge(srcID, dstID);
    LLVM_DEBUG(dbgs() << "Cloning store value edge: " << srcID << " --> " << dstID << "\n";);
}

void ConstraintGraph::cloneStoreEdge(ConstraintEdge* edge) {
    NodeID srcID = edge->getSrcID();
    NodeID dstID = edge->getDstID();
    addStoreCGEdge(srcID, dstID);
    LLVM_DEBUG(dbgs() << "Cloning store edge: " << srcID << " --> " << dstID << "\n";);
}

void ConstraintGraph::cloneLoadValEdge(ConstraintEdge* edge) {
    NodeID srcID = edge->getSrcID();
    NodeID dstID = edge->getDstID();
    addLoadValCGEdge(srcID, dstID);
    LLVM_DEBUG(dbgs() << "Cloning load value edge: " << srcID << " --> " << dstID << "\n";);
}

void ConstraintGraph::cloneLoadEdge(ConstraintEdge* edge) {
    NodeID srcID = edge->getSrcID();
    NodeID dstID = edge->getDstID();
    addLoadCGEdge(srcID, dstID);
    LLVM_DEBUG(dbgs() << "Cloning load edge: " << srcID << " --> " << dstID << "\n";);
}

void ConstraintGraph::cloneCallValEdge(ConstraintEdge* edge) {
    NodeID srcID = edge->getSrcID();
    NodeID dstID = edge->getDstID();
    addCallValCGEdge(srcID, dstID);
}

void ConstraintGraph::cloneRetValEdge(ConstraintEdge* edge) {
    NodeID srcID = edge->getSrcID();
    NodeID dstID = edge->getDstID();
    addRetValCGEdge(srcID, dstID);
}

void ConstraintGraph::cloneDirectEdge(ConstraintEdge* edge) {
    NodeID srcID = edge->getSrcID();
    NodeID dstID = edge->getDstID();
    if (VariantGepCGEdge* vgepCGEdge = dyn_cast<VariantGepCGEdge>(edge)) {
        addVariantGepCGEdge(srcID, dstID);
        LLVM_DEBUG(dbgs() << "Cloning vgep edge: " << srcID << " --> " << dstID << "\n";);
    } else if (NormalGepCGEdge* ngepCGEdge = dyn_cast<NormalGepCGEdge>(edge)) {
        addNormalGepCGEdge(srcID, dstID, ngepCGEdge->getLocationSet());
        LLVM_DEBUG(dbgs() << "Cloning ngep edge: " << srcID << " --> " << dstID << "\n";);
    } else {
        addCopyCGEdge(srcID, dstID);
        LLVM_DEBUG(dbgs() << "Cloning copy edge: " << srcID << " --> " << dstID << "\n";);
    }
}

void ConstraintGraph::testAndAddNode(NodeID nodeID, llvm::SparseBitVector<>& addedNodes) {
    if (!addedNodes.test(nodeID)) {
        addConstraintNode(new ConstraintNode(nodeID), nodeID);
        addedNodes.set(nodeID);
        LLVM_DEBUG(dbgs() << "Cloning node: " << nodeID << "\n";);
    }
}


void ConstraintGraph::pruneNonSensitiveEdges(ConstraintGraph* oldCG, WorkList& workList) {
    llvm::SparseBitVector<> addedConsNodeList;          // Nodes which are just added to the constraint graph
    llvm::SparseBitVector<> fullyProcessedConsNodeList; // Nodes whose edges are fully processed
    std::list<NormalGepCGEdge*> ngepList;
    while (!workList.empty()) {
        NodeID nodeId = workList.pop();
        ConstraintNode* node = oldCG->getConstraintNode(nodeId);
        if (!fullyProcessedConsNodeList.test(nodeId)) {
           // Outgoing Gep/copy edges
            for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(),
                    eit = node->directOutEdgeEnd(); it != eit; ++it) {
                if (NormalGepCGEdge* ngep = dyn_cast<NormalGepCGEdge>(*it)) {
                    Value* gepBase = const_cast<Value*>(pag->getPAGNode(node->getId())->getValue());
                    // Can filter only leaf-geps, so gepBase should be the
                    // base of an object
                    if (Type* ptrType = gepBase->getType()->getPointerElementType()) {
                        if (!ptrType->isPointerTy()) {
                            Type* baseType = findBaseType(gepBase->getType());
                            if(isPrunedType(baseType) && !isSensitiveField(baseType, ngep->getLocationSet().getOffset()) ) {
                                ngepList.push_back(ngep);
                
                            }                               
                        }
                    }
                }
            }
            for (NormalGepCGEdge* ngep: ngepList) {
                // Remove the outgoing gep edge
                node->removeOutgoingDirectEdge(ngep);
                if (node->hasNoOutEdges()) {
                    // Remove the incoming edges for this
                    // node, and any other nodes that become
                    // free
                    removePrunedNodes(node, oldCG);
                }
            }
            ngepList.clear();

            fullyProcessedConsNodeList.set(nodeId);
        }
    }
}

void ConstraintGraph::removePrunedNodes(ConstraintNode* node, ConstraintGraph* oldCG) {
    WorkList workList;
    workList.push(node->getId());

    while (!workList.empty()) {
        NodeID nodeId = workList.pop();
        if (oldCG->hasConstraintNode(nodeId)) {
            ConstraintNode* work = oldCG->getConstraintNode(nodeId);
            if (work->hasNoOutEdges()) {
                oldCG->removeAllIncomingEdges(work, workList);
            }
        }
    }
}

void ConstraintGraph::removeAllIncomingEdges(ConstraintNode* node, WorkList& workList) {
    std::list<ConstraintEdge*> InEdgeList;
    for (ConstraintEdge* edge: node->getInEdges()) {
        InEdgeList.push_back(edge);
    }

    // All the types
    for (ConstraintEdge* edge: InEdgeList) {
        ConstraintNode* sNode = getConstraintNode(edge->getSrcID());
        ConstraintNode* dNode = getConstraintNode(edge->getDstID());

        workList.push(sNode->getId());

        if (AddrCGEdge* addrEdge = dyn_cast<AddrCGEdge>(edge)) {
            dNode->removeIncomingAddrEdge(addrEdge);
            sNode->removeOutgoingAddrEdge(addrEdge);
        } else if (LoadCGEdge* loadEdge = dyn_cast<LoadCGEdge>(edge)) {
            dNode->removeIncomingLoadEdge(loadEdge);
            sNode->removeOutgoingLoadEdge(loadEdge);
        } else if (StoreCGEdge* storeEdge = dyn_cast<StoreCGEdge>(edge)) {
            dNode->removeIncomingStoreEdge(storeEdge);
            sNode->removeOutgoingStoreEdge(storeEdge);
        } else if (GepCGEdge* gepEdge = dyn_cast<GepCGEdge>(edge)) {
            dNode->removeIncomingDirectEdge(gepEdge);
            sNode->removeOutgoingDirectEdge(gepEdge);
        } else if (CopyCGEdge* copyEdge = dyn_cast<CopyCGEdge>(edge)) {
            dNode->removeIncomingDirectEdge(copyEdge);
            sNode->removeOutgoingDirectEdge(copyEdge);
        } else if (LoadValCGEdge* loadValEdge = dyn_cast<LoadValCGEdge>(edge)) {
            dNode->removeIncomingLoadValEdge(loadValEdge);
            sNode->removeOutgoingLoadValEdge(loadValEdge);
        } else if (StoreValCGEdge* storeValEdge = dyn_cast<StoreValCGEdge>(edge)) {
            dNode->removeIncomingStoreValEdge(storeValEdge);
            sNode->removeOutgoingStoreValEdge(storeValEdge);
        } else if (CallValCGEdge* callValEdge = dyn_cast<CallValCGEdge>(edge)) {
            dNode->removeIncomingCallValEdge(callValEdge);
            sNode->removeOutgoingCallValEdge(callValEdge);
        } else if (RetValCGEdge* retValEdge = dyn_cast<RetValCGEdge>(edge)) {
            dNode->removeIncomingRetValEdge(retValEdge);
            sNode->removeOutgoingRetValEdge(retValEdge);
        }
    }
}

void ConstraintGraph::populatePrunedFlattenedFieldOffsets(ConstraintGraph* oldCG) {
    PAG* pag = oldCG->getPAG();
    Module* mod = pag->getModule().getModule(0);
    SymbolTableInfo* symbTblInfo = SymbolTableInfo::Symbolnfo();

    bool changed = true;

    while (changed) {
        changed = false;

        for (StructType* stType: mod->getIdentifiedStructTypes()) {
            /*
            if (stType->getName() == "cert_pkey_st") {
                appendSensitiveField(stType, 1);
            }
            */
            int offset = 0;
            for (Type* subType: stType->elements()) {
                // Is this a nested type?
                if (isa<StructType>(subType) || isa<ArrayType>(subType)) {
                    StInfo* subStinfo = symbTblInfo->getStructInfo(subType);
                    int fieldSize = subStinfo->getFlattenFieldInfoVec().size();
                    if (ArrayType* arrTy = dyn_cast<ArrayType>(subType)) {
                        if (StructType* stArrTy = dyn_cast<StructType>(arrTy->getElementType())) {
                            if (isPrunedType(stArrTy) || isSensitiveType(stArrTy)) {
                                // If the array elements are pruned or
                                // explicitly sensitive structs
                                int indOffset = offset;
                                for (int i = 0; i < stArrTy->getNumElements(); i++) {
                                    if (!isSensitiveField(stType, indOffset)) {
                                        changed = true;
                                        appendSensitiveField(stType, indOffset);
                                        indOffset++;
                                    }
                                }
                            }
                        }
                    }
                    offset += fieldSize;
                    // This is not a pointer, so no need to track sensitive
                    // indirect flows
                } else {
                    // Track sensitive indirect flows via pointers to structs
                    Type* baseType = findBaseType(subType);
                    if (StructType* stSubType = dyn_cast<StructType>(baseType)) {
                        if (isPrunedType(stSubType) || isSensitiveType(stSubType)) {
                            if (!isSensitiveField(stType, offset)) {
                                changed = true;
                                appendSensitiveField(stType, offset);
                            }
                        }
                    }
                    offset++;
                }
            }
        }
    }

}

Type* ConstraintGraph::findBaseType(Type* type) {
    Type* trueType = type;
    while (trueType->isPointerTy()) {
        trueType = trueType->getPointerElementType();
    }
    return trueType;
}

void ConstraintGraph::annotateGraphWithSensitiveFlows(ConstraintGraph* oldCG, WorkList& initList) {}

void ConstraintGraph::createMinSubGraphReachableFrom(ConstraintGraph* oldCG, WorkList& initList) {
    WorkList initList2;
    WorkList initList3;

    WorkList workList;
    WorkList::copyWorkList(initList, initList2);
    WorkList::copyWorkList(initList, initList3);

    oldCG->getAllNodes(workList);
    while (!initList2.empty()) {
        NodeID senId = initList2.pop();
        PAGNode* pnode = pag->getPAGNode(senId);
        Type* baseType = findBaseType(pnode->getValue()->getType());
        addExplicitSensitiveType(baseType);
    }

    populatePrunedFlattenedFieldOffsets(oldCG);
    printPrunedTypes();
    pruneNonSensitiveEdges(oldCG, workList);


    llvm::SparseBitVector<> addedConsNodeList;          // Nodes which are just added to the constraint graph
    llvm::SparseBitVector<> fullyProcessedConsNodeList; // Nodes whose edges are fully processed

    while (!initList3.empty()) {
        NodeID nodeId = initList3.pop();
        ConstraintNode* node = oldCG->getConstraintNode(nodeId);
        if (!fullyProcessedConsNodeList.test(nodeId)) {

            testAndAddNode(nodeId, addedConsNodeList);

            // Find all incoming edges for this node
            for (ConstraintNode::const_iterator it = node->incomingAddrsBegin(),
                    eit = node->incomingAddrsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                cloneAddrEdge(*it);
                initList3.push((*it)->getSrcID());
            }

            // Incoming stores
            for (ConstraintNode::const_iterator it = node->incomingStoresBegin(),
                    eit = node->incomingStoresEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                cloneStoreEdge(*it);
                initList3.push((*it)->getSrcID());
            }


            // Incoming loads
            for (ConstraintNode::const_iterator it = node->incomingLoadsBegin(),
                    eit = node->incomingLoadsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                cloneLoadEdge(*it);
                initList3.push((*it)->getSrcID());
            }

            // Gep/copy edges
            for (ConstraintNode::const_iterator it = node->directInEdgeBegin(),
                    eit = node->directInEdgeEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                cloneDirectEdge(*it);
                initList3.push((*it)->getSrcID());
            }

            // Find all outgoing edges for this node
            for (ConstraintNode::const_iterator it = node->outgoingAddrsBegin(),
                    eit = node->outgoingAddrsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneAddrEdge(*it); 
                initList3.push((*it)->getDstID());
            }

            // Outgoing stores
            for (ConstraintNode::const_iterator it = node->outgoingStoresBegin(),
                    eit = node->outgoingStoresEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneStoreEdge(*it); 
                initList3.push((*it)->getDstID());
            }

            // Outgoing store vals
            for (ConstraintNode::const_iterator it = node->outgoingStoreValsBegin(),
                    eit = node->outgoingStoreValsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneStoreValEdge(*it); 
                initList3.push((*it)->getDstID());
            }

            // Outgoing call values
            for (ConstraintNode::const_iterator it = node->outgoingCallValsBegin(),
                    eit = node->outgoingCallValsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneCallValEdge(*it);
                initList3.push((*it)->getDstID());
            }


            // Outgoing loads
            for (ConstraintNode::const_iterator it = node->outgoingLoadsBegin(),
                    eit = node->outgoingLoadsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneLoadEdge(*it); 
                initList3.push((*it)->getDstID());
            }

            // Outgoing load vals
            for (ConstraintNode::const_iterator it = node->outgoingLoadValsBegin(),
                    eit = node->outgoingLoadValsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneLoadValEdge(*it); 
                initList3.push((*it)->getDstID());
            }

            // Outgoing return values
            for (ConstraintNode::const_iterator it = node->outgoingRetValsBegin(),
                    eit = node->outgoingRetValsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneRetValEdge(*it);
                initList3.push((*it)->getDstID());
            }


            for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(),
                    eit = node->directOutEdgeEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneDirectEdge(*it); 
                initList3.push((*it)->getDstID());
            }

            fullyProcessedConsNodeList.set(nodeId);
        }
    }

}

/*
void ConstraintGraph::createMinSubGraphReachableFrom(ConstraintGraph* oldCG, WorkList& initList) {
    // Annotate the graph with the sensitive flows to consider
    WorkList initList2;
    WorkList::copyWorkList(initList, initList2);
    annotateGraphWithSensitiveFlows(oldCG, initList2);

    // Now, start with the initList
    // Follow the edge only if the edge is marked as sensitive
    llvm::SparseBitVector<> addedConsNodeList;          // Nodes which are just added to the constraint graph
    llvm::SparseBitVector<> fullyProcessedConsNodeList; // Nodes whose edges are fully processed
    while (!initList.empty()) {
        NodeID nodeId = initList.pop();
        ConstraintNode* node = oldCG->getConstraintNode(nodeId);
        if (!fullyProcessedConsNodeList.test(nodeId)) {

            testAndAddNode(nodeId, addedConsNodeList);

            // Find all incoming edges for this node
            for (ConstraintNode::const_iterator it = node->incomingAddrsBegin(),
                    eit = node->incomingAddrsEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                    cloneAddrEdge(*it);
                    initList.push((*it)->getSrcID());
                }
            }

            // Incoming stores
            for (ConstraintNode::const_iterator it = node->incomingStoresBegin(),
                    eit = node->incomingStoresEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                    cloneStoreEdge(*it);
                    initList.push((*it)->getSrcID());
                }
            }


            // Incoming loads
            for (ConstraintNode::const_iterator it = node->incomingLoadsBegin(),
                    eit = node->incomingLoadsEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                    cloneLoadEdge(*it);
                    initList.push((*it)->getSrcID());
                }
            }

            // Gep/copy edges
            for (ConstraintNode::const_iterator it = node->directInEdgeBegin(),
                    eit = node->directInEdgeEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                    cloneDirectEdge(*it);
                    initList.push((*it)->getSrcID());
                }
            }

            // Find all outgoing edges for this node
            for (ConstraintNode::const_iterator it = node->outgoingAddrsBegin(),
                    eit = node->outgoingAddrsEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getDstID(), addedConsNodeList);
                    cloneAddrEdge(*it); 
                    initList.push((*it)->getDstID());
                }
            }

            // Outgoing stores
            for (ConstraintNode::const_iterator it = node->outgoingStoresBegin(),
                    eit = node->outgoingStoresEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getDstID(), addedConsNodeList);
                    cloneStoreEdge(*it); 
                    initList.push((*it)->getDstID());
                }
            }

            // Outgoing store vals
            for (ConstraintNode::const_iterator it = node->outgoingStoreValsBegin(),
                    eit = node->outgoingStoreValsEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getDstID(), addedConsNodeList);
                    cloneStoreValEdge(*it); 
                    initList.push((*it)->getDstID());
                }
            }

            // Outgoing call values
            for (ConstraintNode::const_iterator it = node->outgoingCallValsBegin(),
                    eit = node->outgoingCallValsEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getDstID(), addedConsNodeList);
                    cloneCallValEdge(*it);
                    initList.push((*it)->getDstID());
                }
            }


            // Outgoing loads
            for (ConstraintNode::const_iterator it = node->outgoingLoadsBegin(),
                    eit = node->outgoingLoadsEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getDstID(), addedConsNodeList);
                    cloneLoadEdge(*it); 
                    initList.push((*it)->getDstID());
                }
            }

            // Outgoing load vals
            for (ConstraintNode::const_iterator it = node->outgoingLoadValsBegin(),
                    eit = node->outgoingLoadValsEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getDstID(), addedConsNodeList);
                    cloneLoadValEdge(*it); 
                    initList.push((*it)->getDstID());
                }
            }

            // Outgoing return values
            for (ConstraintNode::const_iterator it = node->outgoingRetValsBegin(),
                    eit = node->outgoingRetValsEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getDstID(), addedConsNodeList);
                    cloneRetValEdge(*it);
                    initList.push((*it)->getDstID());
                }
            }


            for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(),
                    eit = node->directOutEdgeEnd(); it != eit; ++it) {
                if ((*it)->isSensitive()) {
                    testAndAddNode((*it)->getDstID(), addedConsNodeList);
                    cloneDirectEdge(*it); 
                    initList.push((*it)->getDstID());
                }
            }

            fullyProcessedConsNodeList.set(nodeId);
        }
    }
}*/

void ConstraintGraph::createSubGraphReachableFrom(ConstraintGraph* oldCG, WorkList& workList) {
    llvm::SparseBitVector<> addedConsNodeList;          // Nodes which are just added to the constraint graph
    llvm::SparseBitVector<> fullyProcessedConsNodeList; // Nodes whose edges are fully processed
    while (!workList.empty()) {
        NodeID nodeId = workList.pop();
        ConstraintNode* node = oldCG->getConstraintNode(nodeId);
        if (!fullyProcessedConsNodeList.test(nodeId)) {

            testAndAddNode(nodeId, addedConsNodeList);

            // Find all incoming edges for this node
            for (ConstraintNode::const_iterator it = node->incomingAddrsBegin(),
                    eit = node->incomingAddrsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                cloneAddrEdge(*it);
                workList.push((*it)->getSrcID());
            }

            // Incoming stores
            for (ConstraintNode::const_iterator it = node->incomingStoresBegin(),
                    eit = node->incomingStoresEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                cloneStoreEdge(*it);
                workList.push((*it)->getSrcID());
            }


            // Incoming loads
            for (ConstraintNode::const_iterator it = node->incomingLoadsBegin(),
                    eit = node->incomingLoadsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                cloneLoadEdge(*it);
                workList.push((*it)->getSrcID());
            }

            // Gep/copy edges
            for (ConstraintNode::const_iterator it = node->directInEdgeBegin(),
                    eit = node->directInEdgeEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getSrcID(), addedConsNodeList);
                cloneDirectEdge(*it);
                workList.push((*it)->getSrcID());
            }

            // Find all outgoing edges for this node
            for (ConstraintNode::const_iterator it = node->outgoingAddrsBegin(),
                    eit = node->outgoingAddrsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneAddrEdge(*it); 
                workList.push((*it)->getDstID());
            }

            // Outgoing stores
            for (ConstraintNode::const_iterator it = node->outgoingStoresBegin(),
                    eit = node->outgoingStoresEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneStoreEdge(*it); 
                workList.push((*it)->getDstID());
            }

            // Outgoing store vals
            for (ConstraintNode::const_iterator it = node->outgoingStoreValsBegin(),
                    eit = node->outgoingStoreValsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneStoreValEdge(*it); 
                workList.push((*it)->getDstID());
            }

            // Outgoing call values
            for (ConstraintNode::const_iterator it = node->outgoingCallValsBegin(),
                    eit = node->outgoingCallValsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneCallValEdge(*it);
                workList.push((*it)->getDstID());
            }


            // Outgoing loads
            for (ConstraintNode::const_iterator it = node->outgoingLoadsBegin(),
                    eit = node->outgoingLoadsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneLoadEdge(*it); 
                workList.push((*it)->getDstID());
            }

            // Outgoing load vals
            for (ConstraintNode::const_iterator it = node->outgoingLoadValsBegin(),
                    eit = node->outgoingLoadValsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneLoadValEdge(*it); 
                workList.push((*it)->getDstID());
            }

            // Outgoing return values
            for (ConstraintNode::const_iterator it = node->outgoingRetValsBegin(),
                    eit = node->outgoingRetValsEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneRetValEdge(*it);
                workList.push((*it)->getDstID());
            }


            for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(),
                    eit = node->directOutEdgeEnd(); it != eit; ++it) {
                testAndAddNode((*it)->getDstID(), addedConsNodeList);
                cloneDirectEdge(*it); 
                workList.push((*it)->getDstID());
            }

            fullyProcessedConsNodeList.set(nodeId);
        }
    }
}

/*!
 * Start building constraint graph
 */
void ConstraintGraph::buildCG() {

    // initialize nodes
    for(PAG::iterator it = pag->begin(), eit = pag->end(); it!=eit; ++it) {
        addConstraintNode(new ConstraintNode(it->first),it->first);
    }

    // initialize edges
    PAGEdge::PAGEdgeSetTy& addrs = pag->getEdgeSet(PAGEdge::Addr);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = addrs.begin(), eiter =
                addrs.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addAddrCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& copys = pag->getEdgeSet(PAGEdge::Copy);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = copys.begin(), eiter =
                copys.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addCopyCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& calls = pag->getEdgeSet(PAGEdge::Call);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = calls.begin(), eiter =
                calls.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addCopyCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& rets = pag->getEdgeSet(PAGEdge::Ret);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = rets.begin(), eiter =
                rets.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addCopyCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& tdfks = pag->getEdgeSet(PAGEdge::ThreadFork);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = tdfks.begin(), eiter =
                tdfks.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addCopyCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& tdjns = pag->getEdgeSet(PAGEdge::ThreadJoin);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = tdjns.begin(), eiter =
                tdjns.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addCopyCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& ngeps = pag->getEdgeSet(PAGEdge::NormalGep);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = ngeps.begin(), eiter =
                ngeps.end(); iter != eiter; ++iter) {
        NormalGepPE* edge = cast<NormalGepPE>(*iter);
        addNormalGepCGEdge(edge->getSrcID(),edge->getDstID(),edge->getLocationSet());
    }

    PAGEdge::PAGEdgeSetTy& vgeps = pag->getEdgeSet(PAGEdge::VariantGep);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = vgeps.begin(), eiter =
                vgeps.end(); iter != eiter; ++iter) {
        VariantGepPE* edge = cast<VariantGepPE>(*iter);
        addVariantGepCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& stores = pag->getEdgeSet(PAGEdge::Load);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = stores.begin(), eiter =
                stores.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addLoadCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& loads = pag->getEdgeSet(PAGEdge::Store);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = loads.begin(), eiter =
                loads.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addStoreCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& storeVals = pag->getEdgeSet(PAGEdge::StoreVal);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = storeVals.begin(), eiter =
                storeVals.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addStoreValCGEdge(edge->getSrcID(),edge->getDstID());
    }

    PAGEdge::PAGEdgeSetTy& loadVals = pag->getEdgeSet(PAGEdge::LoadVal);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = loadVals.begin(), eiter =
                loadVals.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addLoadValCGEdge(edge->getSrcID(),edge->getDstID());
    }

    // Call Values
    PAGEdge::PAGEdgeSetTy& callVals = pag->getEdgeSet(PAGEdge::CallVal);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = callVals.begin(), eiter = 
            callVals.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addCallValCGEdge(edge->getSrcID(), edge->getDstID());
    }

    // Return Values
    PAGEdge::PAGEdgeSetTy& retVals = pag->getEdgeSet(PAGEdge::RetVal);
    for (PAGEdge::PAGEdgeSetTy::iterator iter = retVals.begin(), eiter = 
            retVals.end(); iter != eiter; ++iter) {
        PAGEdge* edge = *iter;
        addRetValCGEdge(edge->getSrcID(), edge->getDstID());
    }

    errs() << "================== Full Constraint Graph =======================\n";
    errs() << "Number of nodes: " << this->getTotalNodeNum() << "\n";
    errs() << "Number of edges: " << this->getTotalEdgeNum() << "\n";
    errs() << "Number of Variant Gep edges: " << this->getVariableGepEdgeNum() << "\n";
    errs() << "Number of Normal Gep edges: " << this->getNormalGepEdgeNum() << "\n";

}


/*!
 * Memory has been cleaned up at GenericGraph
 */
void ConstraintGraph::destroy() {
}

/*!
 * Constructor for address constraint graph edge
 */
AddrCGEdge::AddrCGEdge(ConstraintNode* s, ConstraintNode* d, EdgeID id)
    : ConstraintEdge(s,d,Addr,id) {
    PAGNode* node = PAG::getPAG()->getPAGNode(s->getId());
    assert(!llvm::isa<DummyValPN>(node) && "a dummy node??");
}

/*!
 * Add an address edge
 */
bool ConstraintGraph::addAddrCGEdge(NodeID src, NodeID dst) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::Addr))
        return false;
    AddrCGEdge* edge = new AddrCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = AddrCGEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingAddrEdge(edge);
    dstNode->addIncomingAddrEdge(edge);
    return added;
}

/*!
 * Add Copy edge
 */
bool ConstraintGraph::addCopyCGEdge(NodeID src, NodeID dst) {

    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::Copy)
            || srcNode == dstNode)
        return false;

    CopyCGEdge* edge = new CopyCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = directEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingCopyEdge(edge);
    dstNode->addIncomingCopyEdge(edge);
    return added;
}


/*!
 * Add Gep edge
 */
bool ConstraintGraph::addNormalGepCGEdge(NodeID src, NodeID dst, const LocationSet& ls) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::NormalGep))
        return false;

    NormalGepCGEdge* edge = new NormalGepCGEdge(srcNode, dstNode,ls, edgeIndex++);
    bool added = directEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingGepEdge(edge);
    dstNode->addIncomingGepEdge(edge);
    return added;
}

/*!
 * Add variant gep edge
 */
bool ConstraintGraph::addVariantGepCGEdge(NodeID src, NodeID dst) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::VariantGep))
        return false;

    VariantGepCGEdge* edge = new VariantGepCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = directEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingGepEdge(edge);
    dstNode->addIncomingGepEdge(edge);
    return added;
}

/*!
 * Add Load edge
 */
bool ConstraintGraph::addLoadCGEdge(NodeID src, NodeID dst) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::Load))
        return false;

    LoadCGEdge* edge = new LoadCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = LoadCGEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingLoadEdge(edge);
    dstNode->addIncomingLoadEdge(edge);
    return added;
}

/*!
 * Add Load Val edge
 */
bool ConstraintGraph::addLoadValCGEdge(NodeID src, NodeID dst) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::LoadVal))
        return false;

    LoadValCGEdge* edge = new LoadValCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = LoadValCGEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingLoadValEdge(edge);
    dstNode->addIncomingLoadValEdge(edge);
    return added;
}

/*!
 * Add Call Val edge
 */
bool ConstraintGraph::addCallValCGEdge(NodeID src, NodeID dst) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::CallVal))
        return false;

    CallValCGEdge* edge = new CallValCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = CallValCGEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingCallValEdge(edge);
    dstNode->addIncomingCallValEdge(edge);
    return added;
}

/*!
 * Add Return Val edge
 */
bool ConstraintGraph::addRetValCGEdge(NodeID src, NodeID dst) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::RetVal))
        return false;

    RetValCGEdge* edge = new RetValCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = RetValCGEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingRetValEdge(edge);
    dstNode->addIncomingRetValEdge(edge);
    return added;
}

/*!
 * Add Store edge
 */
bool ConstraintGraph::addStoreCGEdge(NodeID src, NodeID dst) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::Store))
        return false;

    StoreCGEdge* edge = new StoreCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = StoreCGEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingStoreEdge(edge);
    dstNode->addIncomingStoreEdge(edge);
    return added;
}

/*!
 * Add Store Val edge
 */
bool ConstraintGraph::addStoreValCGEdge(NodeID src, NodeID dst) {
    ConstraintNode* srcNode = getConstraintNode(src);
    ConstraintNode* dstNode = getConstraintNode(dst);
    if(hasEdge(srcNode,dstNode,ConstraintEdge::StoreVal))
        return false;

    StoreValCGEdge* edge = new StoreValCGEdge(srcNode, dstNode, edgeIndex++);
    bool added = StoreValCGEdgeSet.insert(edge).second;
    assert(added && "not added??");
    srcNode->addOutgoingStoreValEdge(edge);
    dstNode->addIncomingStoreValEdge(edge);
    return added;
}

/*!
 * Re-target dst node of an edge
 *
 * (1) Remove edge from old dst target,
 * (2) Change edge dst id and
 * (3) Add modifed edge into new dst
 */
void ConstraintGraph::reTargetDstOfEdge(ConstraintEdge* edge, ConstraintNode* newDstNode) {
    NodeID newDstNodeID = newDstNode->getId();
    NodeID srcId = edge->getSrcID();
    if(LoadCGEdge* load = dyn_cast<LoadCGEdge>(edge)) {
        removeLoadEdge(load);
        addLoadCGEdge(srcId,newDstNodeID);
    }
    else if(StoreCGEdge* store = dyn_cast<StoreCGEdge>(edge)) {
        removeStoreEdge(store);
        addStoreCGEdge(srcId,newDstNodeID);
    }
    else if(CopyCGEdge* copy = dyn_cast<CopyCGEdge>(edge)) {
        removeDirectEdge(copy);
        addCopyCGEdge(srcId,newDstNodeID);
    }
    else if(NormalGepCGEdge* gep = dyn_cast<NormalGepCGEdge>(edge)) {
        const LocationSet ls = gep->getLocationSet();
        removeDirectEdge(gep);
        addNormalGepCGEdge(srcId,newDstNodeID,ls);
    }
    else if(VariantGepCGEdge* gep = dyn_cast<VariantGepCGEdge>(edge)) {
        removeDirectEdge(gep);
        addVariantGepCGEdge(srcId,newDstNodeID);
    }
    /// Address edge is removed directly, because it won't participate in solving further
    /// To be noted: it can not retarget the address edge to newSrc, otherwise it might lead
    /// non object node flows to points-to set of a pointer (src of the edge maybe non object node after scc)
    else if(AddrCGEdge* addr = dyn_cast<AddrCGEdge>(edge)) {
        removeAddrEdge(addr);
    } else if (LoadValCGEdge* loadval = dyn_cast<LoadValCGEdge>(edge)) {
        removeLoadValEdge(loadval);
        addLoadValCGEdge(srcId,newDstNodeID);
    } else if (StoreValCGEdge* storeval = dyn_cast<StoreValCGEdge>(edge)) {
        removeStoreValEdge(storeval);
        addStoreValCGEdge(srcId,newDstNodeID);
    } else if (CallValCGEdge* callval = dyn_cast<CallValCGEdge>(edge)) {
        removeCallValEdge(callval);
        addCallValCGEdge(srcId,newDstNodeID);
    } else if (RetValCGEdge* retval = dyn_cast<RetValCGEdge>(edge)) {
        removeRetValEdge(retval);
        addRetValCGEdge(srcId,newDstNodeID);
    }
    else
        assert(false && "no other edge type!!");
}

/*!
 * Re-target src node of an edge
 * (1) Remove edge from old src target,
 * (2) Change edge src id and
 * (3) Add modified edge into new src
 */
void ConstraintGraph::reTargetSrcOfEdge(ConstraintEdge* edge, ConstraintNode* newSrcNode) {
    NodeID newSrcNodeID = newSrcNode->getId();
    NodeID dstId = edge->getDstID();
    if(LoadCGEdge* load = dyn_cast<LoadCGEdge>(edge)) {
        removeLoadEdge(load);
        addLoadCGEdge(newSrcNodeID,dstId);
    }
    else if(StoreCGEdge* store = dyn_cast<StoreCGEdge>(edge)) {
        removeStoreEdge(store);
        addStoreCGEdge(newSrcNodeID,dstId);
    }
    else if(CopyCGEdge* copy = dyn_cast<CopyCGEdge>(edge)) {
        removeDirectEdge(copy);
        addCopyCGEdge(newSrcNodeID,dstId);
    }
    else if(NormalGepCGEdge* gep = dyn_cast<NormalGepCGEdge>(edge)) {
        const LocationSet ls = gep->getLocationSet();
        removeDirectEdge(gep);
        addNormalGepCGEdge(newSrcNodeID,dstId,ls);
    }
    else if(VariantGepCGEdge* gep = dyn_cast<VariantGepCGEdge>(edge)) {
        removeDirectEdge(gep);
        addVariantGepCGEdge(newSrcNodeID,dstId);
    }
    /// Address edge is removed directly, because it won't participate in solving further
    /// To be noted: it can not retarget the address edge to newSrc, otherwise it might lead
    /// non object node flows to points-to set of a pointer (src of the edge maybe non object node after scc)
    else if(AddrCGEdge* addr = dyn_cast<AddrCGEdge>(edge)) {
        removeAddrEdge(addr);
    } else if (LoadValCGEdge* loadval = dyn_cast<LoadValCGEdge>(edge)) {
        removeLoadValEdge(loadval);
        addLoadValCGEdge(newSrcNodeID, dstId);
    } else if (StoreValCGEdge* storeval = dyn_cast<StoreValCGEdge>(edge)) {
        removeStoreValEdge(storeval);
        addStoreValCGEdge(newSrcNodeID, dstId);
    } else if (CallValCGEdge* callval = dyn_cast<CallValCGEdge>(edge)) {
        removeCallValEdge(callval);
        addCallValCGEdge(newSrcNodeID, dstId);
    } else if (RetValCGEdge* retval = dyn_cast<RetValCGEdge>(edge)) {
        removeRetValEdge(retval);
        addRetValCGEdge(newSrcNodeID, dstId);
    }
    else
        assert(false && "no other edge type!!");
}

/*!
 * Remove addr edge from their src and dst edge sets
 */
void ConstraintGraph::removeAddrEdge(AddrCGEdge* edge) {
    getConstraintNode(edge->getSrcID())->removeOutgoingAddrEdge(edge);
    getConstraintNode(edge->getDstID())->removeIncomingAddrEdge(edge);
    Size_t num = AddrCGEdgeSet.erase(edge);
    delete edge;
    assert(num && "edge not in the set, can not remove!!!");
}

/*!
 * Remove load edge from their src and dst edge sets
 */
void ConstraintGraph::removeLoadEdge(LoadCGEdge* edge) {
    getConstraintNode(edge->getSrcID())->removeOutgoingLoadEdge(edge);
    getConstraintNode(edge->getDstID())->removeIncomingLoadEdge(edge);
    Size_t num = LoadCGEdgeSet.erase(edge);
    delete edge;
    assert(num && "edge not in the set, can not remove!!!");
}

/*!
 * Remove store edge from their src and dst edge sets
 */
void ConstraintGraph::removeStoreEdge(StoreCGEdge* edge) {
    getConstraintNode(edge->getSrcID())->removeOutgoingStoreEdge(edge);
    getConstraintNode(edge->getDstID())->removeIncomingStoreEdge(edge);
    Size_t num = StoreCGEdgeSet.erase(edge);
    delete edge;
    assert(num && "edge not in the set, can not remove!!!");
}

/*!
 * Remove load value edge from their src and dst edge sets
 */
void ConstraintGraph::removeLoadValEdge(LoadValCGEdge* edge) {
    getConstraintNode(edge->getSrcID())->removeOutgoingLoadValEdge(edge);
    getConstraintNode(edge->getDstID())->removeIncomingLoadValEdge(edge);
    Size_t num = LoadValCGEdgeSet.erase(edge);
    delete edge;
    assert(num && "edge not in the set, can not remove!!!");
}

/*!
 * Remove store value edge from their src and dst edge sets
 */
void ConstraintGraph::removeStoreValEdge(StoreValCGEdge* edge) {
    getConstraintNode(edge->getSrcID())->removeOutgoingStoreValEdge(edge);
    getConstraintNode(edge->getDstID())->removeIncomingStoreValEdge(edge);
    Size_t num = StoreValCGEdgeSet.erase(edge);
    delete edge;
    assert(num && "edge not in the set, can not remove!!!");
}

/*!
 * Remove call value edge from their src and dst edge sets
 */
void ConstraintGraph::removeCallValEdge(CallValCGEdge* edge) {
    getConstraintNode(edge->getSrcID())->removeOutgoingCallValEdge(edge);
    getConstraintNode(edge->getDstID())->removeIncomingCallValEdge(edge);
    Size_t num = CallValCGEdgeSet.erase(edge);
    delete edge;
    assert(num && "edge not in the set, can not remove!!!");
}

/*!
 * Remove return value edge from their src and dst edge sets
 */
void ConstraintGraph::removeRetValEdge(RetValCGEdge* edge) {
    getConstraintNode(edge->getSrcID())->removeOutgoingRetValEdge(edge);
    getConstraintNode(edge->getDstID())->removeIncomingRetValEdge(edge);
    Size_t num = RetValCGEdgeSet.erase(edge);
    delete edge;
    assert(num && "edge not in the set, can not remove!!!");
}
/*!
 * Remove edges from their src and dst edge sets
 */
void ConstraintGraph::removeDirectEdge(ConstraintEdge* edge) {

    getConstraintNode(edge->getSrcID())->removeOutgoingDirectEdge(edge);
    getConstraintNode(edge->getDstID())->removeIncomingDirectEdge(edge);
    Size_t num = directEdgeSet.erase(edge);

    assert(num && "edge not in the set, can not remove!!!");
    delete edge;
}

/*!
 * Move incoming direct edges of a sub node which is outside SCC to its rep node
 * Remove incoming direct edges of a sub node which is inside SCC from its rep node
 */
bool ConstraintGraph::moveInEdgesToRepNode(ConstraintNode* node, ConstraintNode* rep ) {
    std::vector<ConstraintEdge*> sccEdges;
    std::vector<ConstraintEdge*> nonSccEdges;
    for (ConstraintNode::const_iterator it = node->InEdgeBegin(), eit = node->InEdgeEnd(); it != eit;
            ++it) {
        ConstraintEdge* subInEdge = *it;
        if(sccRepNode(subInEdge->getSrcID()) != rep->getId())
            nonSccEdges.push_back(subInEdge);
        else {
            sccEdges.push_back(subInEdge);
        }
    }
    // if this edge is outside scc, then re-target edge dst to rep
    while(!nonSccEdges.empty()) {
        ConstraintEdge* edge = nonSccEdges.back();
        nonSccEdges.pop_back();
        reTargetDstOfEdge(edge,rep);
    }

    bool criticalGepInsideSCC = false;
    // if this edge is inside scc, then remove this edge and two end nodes
    while(!sccEdges.empty()) {
        ConstraintEdge* edge = sccEdges.back();
        sccEdges.pop_back();
        /// only copy and gep edge can be removed
        if(isa<CopyCGEdge>(edge))
            removeDirectEdge(edge);
        else if (isa<GepCGEdge>(edge)) {
            removeDirectEdge(edge);
            // If the GEP is critical (i.e. may have a non-zero offset),
            // then it brings impact on field-sensitivity.
            if (!isZeroOffsettedGepCGEdge(edge)) {
                criticalGepInsideSCC = true;
            }
        }
        else if(isa<LoadCGEdge>(edge) || isa<StoreCGEdge>(edge))
            reTargetDstOfEdge(edge,rep);
        else if(AddrCGEdge* addr = dyn_cast<AddrCGEdge>(edge)) {
            removeAddrEdge(addr);
        }
        else
            assert(false && "no such edge");
    }
    return criticalGepInsideSCC;
}

/*!
 * Move outgoing direct edges of a sub node which is outside SCC to its rep node
 * Remove outgoing direct edges of a sub node which is inside SCC from its rep node
 */
bool ConstraintGraph::moveOutEdgesToRepNode(ConstraintNode*node, ConstraintNode* rep ) {

    std::vector<ConstraintEdge*> sccEdges;
    std::vector<ConstraintEdge*> nonSccEdges;

    for (ConstraintNode::const_iterator it = node->OutEdgeBegin(), eit = node->OutEdgeEnd(); it != eit;
            ++it) {
        ConstraintEdge* subOutEdge = *it;
        if(sccRepNode(subOutEdge->getDstID()) != rep->getId())
            nonSccEdges.push_back(subOutEdge);
        else {
            sccEdges.push_back(subOutEdge);
        }
    }
    // if this edge is outside scc, then re-target edge src to rep
    while(!nonSccEdges.empty()) {
        ConstraintEdge* edge = nonSccEdges.back();
        nonSccEdges.pop_back();
        reTargetSrcOfEdge(edge,rep);
    }
    bool criticalGepInsideSCC = false;
    // if this edge is inside scc, then remove this edge and two end nodes
    while(!sccEdges.empty()) {
        ConstraintEdge* edge = sccEdges.back();
        sccEdges.pop_back();
        /// only copy and gep edge can be removed
        if(isa<CopyCGEdge>(edge))
            removeDirectEdge(edge);
        else if (isa<GepCGEdge>(edge)) {
            removeDirectEdge(edge);
            // If the GEP is critical (i.e. may have a non-zero offset),
            // then it brings impact on field-sensitivity.
            if (!isZeroOffsettedGepCGEdge(edge)) {
                criticalGepInsideSCC = true;
            }
        }
        else if(isa<LoadCGEdge>(edge) || isa<StoreCGEdge>(edge))
            reTargetSrcOfEdge(edge,rep);
        else if(AddrCGEdge* addr = dyn_cast<AddrCGEdge>(edge)) {
            removeAddrEdge(addr);
        }
        else
            assert(false && "no such edge");
    }
    return criticalGepInsideSCC;
}

/*!
 * Connect formal and actual parameters for indirect callsites
 */
void ConstraintGraph::connectCaller2CalleeParams(llvm::CallSite cs, const llvm::Function *F,
        NodePairSet& cpySrcNodes) {

    assert(F);

    DBOUT(DAndersen, outs() << "connect parameters from indirect callsite " << *cs.getInstruction() << " to callee " << *F << "\n");

    if (pag->funHasRet(F) && pag->callsiteHasRet(cs)) {
        const PAGNode* cs_return = pag->getCallSiteRet(cs);
        const PAGNode* fun_return = pag->getFunRet(F);
        if (cs_return->isPointer() && fun_return->isPointer()) {
            NodeID dstrec = sccRepNode(cs_return->getId());
            NodeID srcret = sccRepNode(fun_return->getId());
            if(addCopyCGEdge(srcret, dstrec)) {
                cpySrcNodes.insert(std::make_pair(srcret,dstrec));
            }
        }
        else {
            NodeID dstrec = sccRepNode(cs_return->getId());
            NodeID srcret = sccRepNode(fun_return->getId());

            addRetValCGEdge(srcret, dstrec);
            //DBOUT(DAndersen, outs() << "not a pointer ignored\n");
        }
    }

    if (pag->hasCallSiteArgsMap(cs) && pag->hasFunArgsMap(F)) {

        // connect actual and formal param
        const PAG::PAGNodeList& csArgList = pag->getCallSiteArgsList(cs);
        const PAG::PAGNodeList& funArgList = pag->getFunArgsList(F);
        //Go through the fixed parameters.
        DBOUT(DPAGBuild, outs() << "      args:");
        PAG::PAGNodeList::const_iterator funArgIt = funArgList.begin(), funArgEit = funArgList.end();
        PAG::PAGNodeList::const_iterator csArgIt  = csArgList.begin(), csArgEit = csArgList.end();
        for (; funArgIt != funArgEit; ++csArgIt, ++funArgIt) {
            //Some programs (e.g. Linux kernel) leave unneeded parameters empty.
            if (csArgIt  == csArgEit) {
                DBOUT(DAndersen, outs() << " !! not enough args\n");
                break;
            }
            const PAGNode *cs_arg = *csArgIt ;
            const PAGNode *fun_arg = *funArgIt;

            if (cs_arg->isPointer() && fun_arg->isPointer()) {
                DBOUT(DAndersen, outs() << "process actual parm  " << *(cs_arg->getValue()) << " \n");
                NodeID srcAA = sccRepNode(cs_arg->getId());
                NodeID dstFA = sccRepNode(fun_arg->getId());
                if(addCopyCGEdge(srcAA, dstFA)) {
                    cpySrcNodes.insert(std::make_pair(srcAA,dstFA));
                }
            } else {
                NodeID srcAA = sccRepNode(cs_arg->getId());
                NodeID dstFA = sccRepNode(fun_arg->getId());
                addCallValCGEdge(srcAA, dstFA);
            }
        }

        //Any remaining actual args must be varargs.
        if (F->isVarArg()) {
            NodeID vaF = sccRepNode(getVarargNode(F));
            DBOUT(DPAGBuild, outs() << "\n      varargs:");
            for (; csArgIt != csArgEit; ++csArgIt) {
                const PAGNode *cs_arg = *csArgIt;
                if (cs_arg->isPointer()) {
                    NodeID vnAA = sccRepNode(cs_arg->getId());
                    if (addCopyCGEdge(vnAA,vaF)) {
                        cpySrcNodes.insert(std::make_pair(vnAA,vaF));
                    }
                }
            }
        }
        if(csArgIt != csArgEit) {
            wrnMsg("too many args to non-vararg func.");
            wrnMsg("(" + getSourceLoc(cs.getInstruction()) + ")");
        }
    }
}

/*!
 * Dump constraint graph
 */
void ConstraintGraph::dump() {
    if(ConsCGDotGraph) {
        if (selective) {
            GraphPrinter::WriteGraphToFile(llvm::outs(), "consCG_selective_final", this);
        } else {
            GraphPrinter::WriteGraphToFile(llvm::outs(), "consCG_final", this);
        }
    }
}

void ConstraintGraph::dumpSensitiveGraph() {
    GraphPrinter::WriteGraphToFile(llvm::outs(), "consCG_sensitive_presolving", this);
}

/*!
 * GraphTraits specialization for constraint graph
 */
namespace llvm {
template<>
struct DOTGraphTraits<ConstraintGraph*> : public DOTGraphTraits<PAG*> {

    typedef ConstraintNode NodeType;
    DOTGraphTraits(bool isSimple = false) :
        DOTGraphTraits<PAG*>(isSimple) {
    }

    /// Return name of the graph
    static std::string getGraphName(ConstraintGraph *graph) {
        return "ConstraintG";
    }

    /// Return label of a VFG node with two display mode
    /// Either you can choose to display the name of the value or the whole instruction
    static std::string getNodeLabel(NodeType *n, ConstraintGraph *graph) {
        PAGNode* node = PAG::getPAG()->getPAGNode(n->getId());
        bool briefDisplay = true;
        bool nameDisplay = true;
        std::string str;
        raw_string_ostream rawstr(str);

        if (briefDisplay) {
            if (isa<ValPN>(node)) {
                if (nameDisplay)
                    rawstr << node->getId() << ":" << node->getValueName();
                else
                    rawstr << node->getId();
            } else
                rawstr << node->getId();
        } else {
            // print the whole value
            if (!isa<DummyValPN>(node) && !isa<DummyObjPN>(node))
                rawstr << *node->getValue();
            else
                rawstr << "";

        }

        return rawstr.str();
    }

    static std::string getNodeAttributes(NodeType *n, ConstraintGraph *graph) {
        PAGNode* node = PAG::getPAG()->getPAGNode(n->getId());

        if (isa<ValPN>(node)) {
            if(isa<GepValPN>(node))
                return "shape=hexagon";
            else if (isa<DummyValPN>(node))
                return "shape=diamond";
            else
                return "shape=circle";
        } else if (isa<ObjPN>(node)) {
            if(isa<GepObjPN>(node))
                return "shape=doubleoctagon";
            else if(isa<FIObjPN>(node))
                return "shape=septagon";
            else if (isa<DummyObjPN>(node))
                return "shape=Mcircle";
            else
                return "shape=doublecircle";
        } else if (isa<RetPN>(node)) {
            return "shape=Mrecord";
        } else if (isa<VarArgPN>(node)) {
            return "shape=octagon";
        } else {
            assert(0 && "no such kind node!!");
        }
        return "";
    }

    template<class EdgeIter>
    static std::string getEdgeAttributes(NodeType *node, EdgeIter EI, ConstraintGraph *pag) {
        ConstraintEdge* edge = *(EI.getCurrent());
        assert(edge && "No edge found!!");
        if (edge->getEdgeKind() == ConstraintEdge::Addr) {
            return "color=green";
        } else if (edge->getEdgeKind() == ConstraintEdge::Copy) {
            return "color=black";
        } else if (edge->getEdgeKind() == ConstraintEdge::NormalGep
                   || edge->getEdgeKind() == ConstraintEdge::VariantGep) {
            return "color=purple";
        } else if (edge->getEdgeKind() == ConstraintEdge::Store) {
            return "color=blue";
        } else if (edge->getEdgeKind() == ConstraintEdge::Load) {
            return "color=red";
        } else if (edge->getEdgeKind() == ConstraintEdge::LoadVal) {
            return "color=yellow";
        } else if (edge->getEdgeKind() == ConstraintEdge::StoreVal) {
            return "color=grey";
        } else if (edge->getEdgeKind() == ConstraintEdge::CallVal) {
            return "color=blue,style=dotted";
        } else if (edge->getEdgeKind() == ConstraintEdge::RetVal) {
            return "color=green,style=dotted";
        } else {
            assert(0 && "No such kind edge!!");
        }
        return "";
    }

    template<class EdgeIter>
    static std::string getEdgeSourceLabel(NodeType *node, EdgeIter EI) {
        return "";
    }
};
}
