//===- PTG.cpp -- Points To Graph representation-----------------------------//
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
 * PTG.cpp
 *
 *  Created on: Oct 27, 2019
 *      Author: Tapti Palit
 */

#include "MemoryModel/PTG.h"
#include "Util/AnalysisUtil.h"
#include "Util/GraphUtil.h"
#include <llvm/ADT/SparseBitVector.h>

using namespace llvm;
using namespace analysisUtil;

/*!
 * Start building the data structures associated with the graph
 */
void PTG::buildPTG() {
    buildInitialPtdMaps();
    buildInitialPtsToMaps();
}

void PTG::dumpMaps() {

    outs() << "\n.......... Dumping maps\n";
    // The ptdMap
    outs() << "The elements in each set\n";
    for (PtdMapTyIt iter = ptdMap.begin(), eiter = ptdMap.end(); iter != eiter; iter++) {
        SetID setId = iter->first;
        outs() << "Set ID : " << setId << " : ";
        for (SparseBitVector<>::iterator it = iter->second->begin(), eit = iter->second->end(); it != eit; it++) {
            NodeID nodeId = *it;
            outs() << nodeId << " ";
        }
        outs() << "\n";
    }

    /*
    outs() << "The values in each set\n";
    for (PtdMapTyIt iter = ptdMap.begin(), eiter = ptdMap.end(); iter != eiter; iter++) {
        SetID setId = iter->first;
        outs() << "Set ID : " << setId << " : " << "\n";
        for (SparseBitVector<>::iterator it = iter->second->begin(), eit = iter->second->end(); it != eit; it++) {
            NodeID nodeId = *it;
            outs() << nodeId << "\n";
            PAGNode* node = pag->getPAGNode(nodeId);
            if (node->hasValue()) {
                outs() << *(node->getValue()) << "\n";
            }
        }
        outs() << "\n";
    }
    */


    outs() << "The pts-to relationships among sets:\n";
    // The ptsTo Map
    for (PtsToSetMapTyIt iter = ptsToSetMap.begin(), eiter = ptsToSetMap.end(); iter != eiter; iter++) {
        SetID ptrSetId = iter->first;
        SetID ptdSetId = iter->second;
        outs() << ptrSetId << " : " << ptdSetId << "\n";
    }

    outs() << "The pts-from relationships among sets:\n";
    // The ptsTo Map
    for (PtsToSetMapTyIt iter = ptsFromSetMap.begin(), eiter = ptsFromSetMap.end(); iter != eiter; iter++) {
        SetID ptrSetId = iter->first;
        SetID ptdSetId = iter->second;
        outs() << ptrSetId << " <--- " << ptdSetId << "\n";
    }


}


/**
 * Build the initial ptdMap and ptdRevMap
 */
void PTG::buildInitialPtdMaps(void) {
    // Create the empty set
    SetID setId = currSetId++;
    EMPTYSET = setId;
    ptdMap[setId] = new SparseBitVector<>();
    ptdRevMap[pag->getNullPtr()] = setId; // This should never be used ever

    // Go over the constraint graph nodes and insert 
    for(ConstraintGraph::iterator it = consG->begin(), eit = consG->end(); it != eit; it++) {
        NodeID nodeId = it->first;

        setId = currSetId++;
        DBOUT(DSTEENS, outs() << "Node " << nodeId << " is in set " << setId << "\n";);
        // Initially every node is its own set
        ptdMap[setId] = new SparseBitVector<>();
        ptdMap[setId]->set(nodeId);
        ptdRevMap[nodeId] = setId;
    }
}

/**
 * Builds the ptsToSetMap, and ptsFromSetMap
 */
void PTG::buildInitialPtsToMaps() {
    // Go over the points to sets and build the initial maps
    for (PAG::iterator it = pag->begin(), eit = pag->end(); it != eit; it++) {
        NodeID ptr = it->first;

        PointsTo pts = ptDataTy->getPts(it->first);

        assert(pts.count() <= 1 && "At this stage, we've processed only the address edges, so we should have only one element in the pts-to set at most");

        PAGNode* node = pag->getPAGNode(ptr);
        if (isa<DummyValPN>(node) || isa<DummyObjPN>(node)) {
            continue;
        }

        if (pts.count() > 0) {
            NodeID ptID = pts.find_first(); // We should have only 1
            PAGNode* ptNode = pag->getPAGNode(ptID);
            if (!isa<ObjPN>(ptNode)) {
                continue;
            }
            if (isa<DummyValPN>(ptNode) || isa<DummyObjPN>(ptNode)) {
                continue;
            }

            // We use the find operation to find the set-membership for the 
            SetID ptrSetID = find(ptr);
            SetID ptdSetID = find(ptID);

            ptsToSetMap.insert(SetPair(ptrSetID, ptdSetID));
            ptsFromSetMap.insert(SetPair(ptdSetID, ptrSetID));
        } /*else {
            // The ptr points to EMPTYSET. We don't care about pts-from
            // We use the find operation to find the set-membership for the 
            SetID ptrSetID = find(ptr);
            ptsToSetMap[ptrSetID] = EMPTYSET;
        }
        */
    }
}

void PTG::initializeCollapsedSet(SetID collapsedSetID, std::set<SetID>& collapsedList) {
    for (SetID inCycleSetID: collapsedList) {
        *ptdMap[collapsedSetID] |= *ptdMap[inCycleSetID];
        // Update the ptdRevMap
        for (SparseBitVector<>::iterator it = ptdMap[inCycleSetID]->begin(), eit = ptdMap[inCycleSetID]->end(); it != eit; it++) {
            NodeID nodeId = *it;
            DBOUT(DSTEENS, outs() << "Seting set: " << collapsedSetID << " for node " << nodeId << "\n";);
            ptdRevMap[nodeId] = collapsedSetID;
        }
    }

    // Now, add the points-to set, and points-from set
    ptsToSetMap.insert(SetPair(collapsedSetID, collapsedSetID));
    ptsFromSetMap.insert(SetPair(collapsedSetID, collapsedSetID));
}

/**
 * Find the points-to and points-from chains for Set s
 * And return all the sets in setSet (ran out of creativity)
 */
/*
void PTG::findPointerChain(SetID s, std::set<SetID>& setSet) {
    setSet.insert(s);
    // The pts-to chain
    PtsToSetMapTyIt iter = ptsToSetMap.find(s);
    while (iter != ptsToSetMap.end()) {
        setSet.insert(iter->second);
        // Cycle?
        if (iter->first == iter->second) 
            break;
        iter = ptsToSetMap.find(iter->second);
    }

    // The pts-from chain
    PtsFromSetMapTyIt iterPtsFrom = ptsFromSetMap.find(s);
    while (iterPtsFrom != ptsFromSetMap.end()) {
        setSet.insert(iterPtsFrom->second);
        // Cycle?
        if (iterPtsFrom->first == iterPtsFrom->second)
            break;
        iterPtsFrom = ptsFromSetMap.find(iterPtsFrom->second);
    }
}
*/

/*
void PTG::deleteCollapsedSet(std::set<SetID>& collapsedSet) {
    for (SetID setID: collapsedSet) {
        delete(ptdMap[setID]);
        ptdMap.erase(setID);
    }
}
*/

void PTG::solveCopyConstraints() {
    for (ConstraintEdge* copyEdge: consG->getDirectCGEdges()) {
        NodeID srcId = copyEdge->getSrcID();
        NodeID dstId = copyEdge->getDstID();
        // Ignore nullptrnode in the source or dest
        if (pag->isNullPtr(srcId) || pag->isNullPtr(dstId))
            continue;
        SetID setDst = find(dstId);
        SetID setSrc = find(srcId);
        SetID ptsSet1 = find_pts(setDst);
        SetID ptsSet2 = find_pts(find(srcId));
        // No need to check any cycles, because copy constraints are processed
        // first, and a simple copy can't cause any cycles
        unify(ptsSet1, ptsSet2);
    }
}

// Load Edges
// p = *q
void PTG::solveDerefConstraints() {
    for (ConstraintEdge* loadEdge: consG->getLoadCGEdges()) {
        NodeID srcId = loadEdge->getSrcID();
        NodeID dstId = loadEdge->getDstID();
        // Ignore nullptrnode in the source (can't be in the dest)
        if (pag->isNullPtr(srcId))
            continue;
        SetID setDst = find(dstId);
        SetID setSrc = find_pts(find(srcId));
        SetID ptsSet1 = find_pts(setDst);
        SetID ptsSet2 = find_pts(setSrc);
        // set-of(dstId) -- points-to --> points-to-set(set-of(srcId)). Will this cause a cycle?
        //outs() << "Going to add load edge " << srcId << " to " << dstId << "\n";
        unify(ptsSet1, ptsSet2);
    }
}

// Store Edges
// *p = q
void PTG::solveAssignConstraints() {
    for (ConstraintEdge* storeEdge: consG->getStoreCGEdges()) {
        NodeID srcId = storeEdge->getSrcID();
        NodeID dstId = storeEdge->getDstID();
        // Ignore nullptrnode in the source (can't be in the dest)
        if (pag->isNullPtr(srcId))
            continue;
        PAGNode* srcNode = pag->getPAGNode(srcId);
        PAGNode* dstNode = pag->getPAGNode(dstId);
        DBOUT(DSTEENS, outs() << "Before unify and find_pts / create empty pts\n";);
        //dumpMaps();
        DBOUT(DSTEENS, outs() << "srcId : " << srcId << "\n";);
        DBOUT(DSTEENS, outs() << "dstId : " << dstId << "\n";);
        DBOUT(DSTEENS, outs() << "Store edge: src: " << *(srcNode->getValue()) << "\n";);
        DBOUT(DSTEENS, outs() << "Store edge: dst: " << *(dstNode->getValue()) << "\n";);
        SetID dstSet = find_pts(find(dstId));
        SetID srcSet = find(srcId);
        SetID ptsSet1 = find_pts(dstSet);
        SetID ptsSet2 = find_pts(srcSet);
        DBOUT(DSTEENS, outs() << "After find_pts/create empty pts\n";);
        //dumpMaps();
        DBOUT(DSTEENS, outs() << "Src pts to set id: " << ptsSet2 << "\n";);
        DBOUT(DSTEENS, outs() << "Dst pts to set id: " << ptsSet1 << "\n";);
        //outs() << "Going to add store edge " << srcId << " to " << dstId << "\n";
        unify(ptsSet1, ptsSet2);
        DBOUT(DSTEENS, outs() << "After unify\n";);
        //dumpMaps();
    }
}


// Go over the SteensgaardFast datastructures to get the points to set
PointsTo& PTG::getPts(NodeID nodeID) {
    // Find the setID for the nodeID belongs to
    SetID parentSetID = ptdRevMap[nodeID];
    // Find the setID for the points-to set for the above setID
    SetID ptsToSetID = getPtsToSetMap(parentSetID);
    // Return the members of that set
    return *(ptdMap[ptsToSetID]);
}

// Which pts-to set does NodeID BELONG to
SetID PTG::find(NodeID nodeId) {
    PtdRevMapTyIt iter = ptdRevMap.find(nodeId);
    assert(iter != ptdRevMap.end() && "We should never try to find a node that doesn't exist");
    return iter->second;
}

SetID PTG::createEmptyPtsToSet() {
    SetID setId = currSetId++;
    ptdMap[setId] = new SparseBitVector<>();
    return setId;
}

SetID PTG::createEmptyPtsToSet(SetID ownerSetId) {
    SetID setId = currSetId++;
    ptdMap[setId] = new SparseBitVector<>();
    DBOUT(DSTEENS, outs() << "Created new pts to set with ownerSetId: " << ownerSetId << "\n";);

    ptsToSetMap.insert(SetPair(ownerSetId, setId));
    ptsFromSetMap.insert(SetPair(setId, ownerSetId));
    return setId;
}

// The unify operation needs the points-to set or a src or target
// Which pts-to set does the input set id point to?
// If it doesn't exist, then create a set and add it
SetID PTG::find_pts(SetID setId) {
    if (setId == EMPTYSET) 
        return EMPTYSET;
    SetID ptsToSetId = -1;
    DBOUT(DSTEENS, outs() << "Find pts for owner set Id: " << setId << "\n";);
    PtsToSetMapTyIt iter = ptsToSetMap.find(setId);
    if (iter != ptsToSetMap.end()) 
        ptsToSetId = iter->second;
    else {
        ptsToSetId = createEmptyPtsToSet(setId);
    }
    DBOUT(DSTEENS, outs() << "Returning pts to set Id: " << ptsToSetId << "\n";);
    return ptsToSetId;
}

/**
 * Which sets point to s1 and s2?
 * We need to unify them, and set the ptsToSetMap and ptsFromSetMap to s3
 *
 * Also, if no unification is needed, we just need to update them.
 */
SetID PTG::unifyBackward(SetID s3) {
    std::set<SetID> unifySet;
    SetID unifiedID = -1;
    bool cycle = false;

    auto range = ptsFromSetMap.equal_range(s3);
    for (auto it = range.first; it != range.second; it++) {
        unifySet.insert(it->second);
    }
    // Need to unify only if there are more than one set pointing to s3
    int numPtsFrom = unifySet.size();
    if (numPtsFrom > 1) {
        DBOUT(DSTEENS, outs() << "Unifying backward\n";);
        std::vector<SetID> unifyVec(unifySet.begin(), unifySet.end());
        assert(unifyVec.size() && "Shouldn't try to backward unify more than two sets");
        if (unifyVec[0] == s3 || unifyVec[1] == s3) {
            cycle = true;
        }
        unifiedID = unify(unifyVec[0], unifyVec[1], false, true);
    }

    if (cycle)
        return unifiedID;
    else
        return s3;
}

/**
 * Unify the pts-to sets of s3
 *
 * Returns the newly created set in case of cycles
 * Returns s3 in case of no cycles
 */
SetID PTG::unifyForward(SetID s3) {
    std::set<SetID> unifySet;
    SetID unifiedID = -1;
    bool cycle = false;
    auto range = ptsToSetMap.equal_range(s3);
    for (auto it = range.first; it != range.second; it++) {
        unifySet.insert(it->second);
    }
    // Need to unify only if there are more than one set pointing to s3
    int numPtsTo = unifySet.size();
    if (numPtsTo > 1) {
        DBOUT(DSTEENS, outs() << "Unifying forward\n";);
        std::vector<SetID> unifyVec(unifySet.begin(), unifySet.end());
        assert(unifyVec.size() && "Shouldn't try to forward unify more than two sets");
        if (unifyVec[0] == s3 || unifyVec[1] == s3) {
            cycle = true;
        }
        unifiedID = unify(unifyVec[0], unifyVec[1], true, false);
    }

    if (cycle) 
        return unifiedID;
    else
        return s3;
}

SetID PTG::unifyBitVectors(SetID s1, SetID s2) {
    // Union the sets
    PtdMapTyIt iterSet1 = ptdMap.find(s1);
    DBOUT(DSTEENS, outs() << s1 << "\n";);
    assert(iterSet1 != ptdMap.end() && "We should never try to find a set that doesn't exist");
    SparseBitVector<>* bv1 = iterSet1->second;

    PtdMapTyIt iterSet2 = ptdMap.find(s2);
    DBOUT(DSTEENS, outs() << s2 << "\n";);
    assert(iterSet2 != ptdMap.end() && "We should never try to find a set that doesn't exist");
    SparseBitVector<>* bv2 = iterSet2->second;

    *bv1 |= *bv2;

    SparseBitVector<>* resultBV = new SparseBitVector<>(*bv1);
    delete(bv1);
    delete(bv2);

    // We got ourselves a new set after the collapse 
    SetID s3 = currSetId++;
    // Add it to ptdMap
    ptdMap[s3] = resultBV;

    DBOUT(DSTEENSCOARSE, outs() << "Calling unify with " << s1 << " and " << s2  << " into set " << s3 << "\n";);
    // Update the ptdRevMap
    for (SparseBitVector<>::iterator it = resultBV->begin(), eit = resultBV->end(); it != eit; it++) {
        NodeID nodeId = *it;
        DBOUT(DSTEENS, outs() << "Seting set: " << s3 << " for node " << nodeId << "\n";);
        ptdRevMap[nodeId] = s3;
    }
    return s3;
}


/**
 * If s1 --points-to--> a, then s3 should also --points-to--> a
 * Same with s2
 * However, if s1 --points-to--> s2, then we need a self-edge
 * s3 --points-to--> s3
 * Ditto with s2.
 *
 * Returns if a cycle was introduced in s3.
 */
bool PTG::insertPtsToRelationships(SetID s1, SetID s2, SetID s3) {
    auto s1PtsToIter = ptsToSetMap.equal_range(s1);
    std::set<SetID> s1Vec;
    std::set<SetID> s2Vec;
    bool cycle = false;

    for (auto it = s1PtsToIter.first; it != s1PtsToIter.second; ++it) {
        s1Vec.insert(it->second);
    }

    for (SetID s1PtsTo: s1Vec) {
        if (s1PtsTo == s1 || s1PtsTo == s2) {
            s1PtsTo = s3;
            cycle = true;
        }
        checkAndInsertPtsTo(s3, s1PtsTo);
        //ptsFromSetMap.insert(SetPair(s1PtsTo, s3));
        checkAndInsertPtsFrom(s1PtsTo, s3);
    }

    // s2 points to B
    auto s2PtsToIter = ptsToSetMap.equal_range(s2);
    for (auto it = s2PtsToIter.first; it != s2PtsToIter.second; ++it) {
        // s3 points to B
        s2Vec.insert(it->second);
    }

    for (SetID s2PtsTo: s2Vec) {
        if (s2PtsTo == s1 || s2PtsTo == s2) {
            s2PtsTo = s3;
            cycle = true;
        }
        checkAndInsertPtsTo(s3, s2PtsTo);
        //ptsFromSetMap.insert(SetPair(s2PtsTo, s3));
        checkAndInsertPtsFrom(s2PtsTo, s3);
    }
    return cycle;
}

/**
 * Same as insertPtsToRelationships, but for the ptsFrom Relationsips
 * a --> s1, b --> s2, etc
 *
 * Returns if a cycle was introduced in s3;
 */
bool PTG::insertPtsFromRelationships(SetID s1, SetID s2, SetID s3) {
    auto s1PtsFromIter = ptsFromSetMap.equal_range(s1);
    std::vector<SetID> s1Vec;
    std::vector<SetID> s2Vec;
    bool cycle = false;

    // A points to s1
    for (auto it = s1PtsFromIter.first; it != s1PtsFromIter.second; ++it) {
        // A points to s3
        s1Vec.push_back(it->second);
    }

    for (SetID ptsFromS1: s1Vec) {
        if (ptsFromS1 == s1 || ptsFromS1 == s2) {
            ptsFromS1 = s3;
            cycle = true;
        }
        //ptsToSetMap.insert(SetPair(ptsFromS1, s3));
        checkAndInsertPtsTo(ptsFromS1, s3);
        checkAndInsertPtsFrom(s3, ptsFromS1);
    }

    auto s2PtsFromIter = ptsFromSetMap.equal_range(s2);
    // B points to s2
    for (auto it = s2PtsFromIter.first; it != s2PtsFromIter.second; ++it) {
        // B points to s3
        s2Vec.push_back(it->second);
    }

    for (SetID ptsFromS2: s2Vec) {
        if (ptsFromS2 == s1 || ptsFromS2 == s2) {
            ptsFromS2 = s3;
            cycle = true;
        }
        //ptsToSetMap.insert(SetPair(ptsFromS2, s3));
        checkAndInsertPtsTo(ptsFromS2, s3);
        checkAndInsertPtsFrom(s3, ptsFromS2);
    }
    return cycle;
}

/**
 * s1 and s2 can point to other stuff, delete those edges in the pts-to and
 * pts-from maps
 */
void PTG::deleteStalePtsToRelationships(SetID s1, SetID s2, SetID s3) {
    auto s1PtsToIter = ptsToSetMap.equal_range(s1);
    std::set<SetID> s1Vec;
    std::set<SetID> s2Vec;

    for (auto it = s1PtsToIter.first; it != s1PtsToIter.second; ++it) {
        s1Vec.insert(it->second);
    }

    // s2 points to B
    auto s2PtsToIter = ptsToSetMap.equal_range(s2);
    for (auto it = s2PtsToIter.first; it != s2PtsToIter.second; ++it) {
        // s3 points to B
        s2Vec.insert(it->second);
    }

    ptsToSetMap.erase(s1);
    ptsToSetMap.erase(s2);

    for (SetID s: s1Vec) {
        // Get the points from relation
        auto ptsFromIter = ptsFromSetMap.equal_range(s);
        auto it = ptsFromIter.first;
        while (it != ptsFromIter.second) {
            if (it->second == s1) {
                it = ptsFromSetMap.erase(it);
            } else {
                it++;
            }
        }
    }
    for (SetID s: s2Vec) {
        // Get the points from relation
        auto ptsFromIter = ptsFromSetMap.equal_range(s);
        auto it = ptsFromIter.first;
        while (it != ptsFromIter.second) {
            if (it->second == s2) {
                it = ptsFromSetMap.erase(it);
            } else {
                it++;
            }
        }
    }
}

void PTG::deleteStalePtsFromRelationships(SetID s1, SetID s2, SetID s3) {
    auto s1PtsFromIter = ptsFromSetMap.equal_range(s1);
    std::set<SetID> s1Vec;
    std::set<SetID> s2Vec;

    for (auto it = s1PtsFromIter.first; it != s1PtsFromIter.second; ++it) {
        s1Vec.insert(it->second);
    }

    auto s2PtsFromIter = ptsFromSetMap.equal_range(s2);
    for (auto it = s2PtsFromIter.first; it != s2PtsFromIter.second; ++it) {
        s2Vec.insert(it->second);
    }

    ptsFromSetMap.erase(s1);
    ptsFromSetMap.erase(s2);

    for (SetID s: s1Vec) {
        // Get the points to relation
        auto ptsToIter = ptsToSetMap.equal_range(s);
        auto it = ptsToIter.first;
        while (it != ptsToIter.second) {
            if (it->second == s1) {
                it = ptsToSetMap.erase(it);
            } else {
                it++;
            }
        }
    }
    for (SetID s: s2Vec) {
        // Get the points from relation
        auto ptsToIter = ptsToSetMap.equal_range(s);
        auto it = ptsToIter.first;
        while (it != ptsToIter.second) {
            if (it->second == s2) {
                it = ptsToSetMap.erase(it);
            } else {
                it++;
            }
        }
    }
}

bool PTG::adjustPointsToRelationships(SetID s1, SetID s2, SetID s3) {
    //outs() << "Before adjusting pointers: unifying " << s1 << " and " << s2 << " into " << s3 << "\n";
    //dumpMaps();
    bool isCycle = false;
    isCycle = insertPtsToRelationships(s1, s2, s3);
    isCycle |= insertPtsFromRelationships(s1, s2, s3);
    deleteStalePtsToRelationships(s1, s2, s3);
    deleteStalePtsFromRelationships(s1, s2, s3);
    //outs() << "After adjusting pointers: unifying " << s1 << " and " << s2 << " into " << s3 << "\n";
    //dumpMaps();
    return isCycle;
}

SetID PTG::unify(SetID s1, SetID s2, bool forwardUnify, bool backwardUnify) {
    if (s1 == s2)
        return s1;

    // Create a set with the unified bitvector
    SetID s3 = unifyBitVectors(s1, s2);

    bool cycle = adjustPointsToRelationships(s1, s2, s3);

    // Now, we should unify forwards and backwards
    //
    // Note that if we're unifying the points-to sets, we can skip unifying
    // backwards (because we've already unified them). The exception to this
    // is when the forward unification causes a cycle. Then you have to do
    // backwards too
    if (forwardUnify || cycle) {
        s3 = unifyForward(s3);
    }

    if (backwardUnify || cycle) {
        s3 = unifyBackward(s3);
    }

    // Done with s1 and s2
    if (s1 != EMPTYSET) {
        ptdMap.erase(s1);
    }
    if (s2 != EMPTYSET) {
        ptdMap.erase(s2);
    }

    /*
    SetID sarr[] = {s1, s2, s3};
    for (SetID s: sarr) {
        if (ptsToSetMap.count(s) > 1) {
            errs() << "PtsToSet got screwed up for set ID: " << s << " ended up with : " << ptsToSetMap.count(s) << " items \n";
        }

        if (ptsFromSetMap.count(s) > 1) {
            errs() << "PtsFromSet got screwed up for set ID: " << s << " ended up with : " << ptsFromSetMap.count(s) << " items \n";
        }
    }

    if (s3 == 113712) {
        // Check that there are no dangling pointers
        errs() << "S3: Points-to set: " << ptsToSetMap.count(s3) << "\n";
        errs() << "S3: Points-from set: " << ptsFromSetMap.count(s3) << "\n";
    }

    if (s1 == 113712) {
        // Check that there are no dangling pointers
        errs() << "S1: Points-to set: " << ptsToSetMap.count(s1) << "\n";
        errs() << "S1: Points-from set: " << ptsFromSetMap.count(s1) << "\n";
    }

    if (s2 == 113712) {
        // Check that there are no dangling pointers
        errs() << "S2: Points-to set: " << ptsToSetMap.count(s2) << "\n";
        errs() << "S2: Points-from set: " << ptsFromSetMap.count(s2) << "\n";
    }
    */
    return s3;
}

// Unify
/*
SetID PTG::unify(SetID s1, SetID s2, bool forwardUnify, bool backwardUnify) {
    if (s1 == s2)
        return s1;

    // Union the sets
    PtdMapTyIt iterSet1 = ptdMap.find(s1);
    DBOUT(DSTEENS, outs() << s1 << "\n";);
    assert(iterSet1 != ptdMap.end() && "We should never try to find a set that doesn't exist");
    SparseBitVector<>* bv1 = iterSet1->second;

    PtdMapTyIt iterSet2 = ptdMap.find(s2);
    DBOUT(DSTEENS, outs() << s2 << "\n";);
    assert(iterSet2 != ptdMap.end() && "We should never try to find a set that doesn't exist");
    SparseBitVector<>* bv2 = iterSet2->second;

    *bv1 |= *bv2;

    SparseBitVector<>* resultBV = new SparseBitVector<>(*bv1);

    // We got ourselves a new set after the collapse 
    SetID s3 = currSetId++;
    // Add it to ptdMap
    ptdMap[s3] = resultBV;

    DBOUT(DSTEENSCOARSE, outs() << "Calling unify with " << s1 << " and " << s2 << " and " << forwardUnify << " and " << backwardUnify << " into set " << s3 << "\n";);
    // Update the ptdRevMap
    for (SparseBitVector<>::iterator it = resultBV->begin(), eit = resultBV->end(); it != eit; it++) {
        NodeID nodeId = *it;
        DBOUT(DSTEENS, outs() << "Seting set: " << s3 << " for node " << nodeId << "\n";);
        ptdRevMap[nodeId] = s3;
    }

    if (backwardUnify) {
        // According to Data Randomization paper (R. Sekar), we unify the sets who
        // point to s1 and s2
        unifyBackward(s1, s2, s3);
    }

    if (forwardUnify) {
        // We unify the points-to sets
        // So, which are the sets that points to s1, and s2?
        unifyForward(s1, s2, s3);
    }

    // Remove the old sets
    if (s1 != EMPTYSET) {
        DBOUT(DSTEENSCOARSE, outs() << "Deleting set " << s1 << " replaced by " << s3 << "\n";);
        delete(bv1);
        ptdMap.erase(s1);
    }
    if (s2 != EMPTYSET) {
        DBOUT(DSTEENSCOARSE, outs() << "Deleting set " << s2 << " replaced by " << s3 << "\n";);
        delete(bv2);
        ptdMap.erase(s2);
    }

    //dumpMaps();
    return s3;
}
*/

void PTG::solve(std::vector<ConstraintEdge*>& newlyInsertedEdges) {
    outs() << "Solving new copy edges after solving for callgraph\n";
    for (ConstraintEdge* copyEdge: newlyInsertedEdges) {
        assert(copyEdge->getEdgeKind() == ConstraintEdge::Copy && "Should only find Copy Edges while solving Steensgaard algorithm");

        NodeID srcId = copyEdge->getSrcID();
        NodeID dstId = copyEdge->getDstID();
        // Ignore nullptrnode in the source or dest
        if (pag->isNullPtr(srcId) || pag->isNullPtr(dstId))
            continue;
        SetID setDst = find(dstId);
        SetID setSrc = find(srcId);
        SetID ptsSet1 = find_pts(setDst);
        SetID ptsSet2 = find_pts(setSrc);
        unify(ptsSet1, ptsSet2);
    }  
}

void PTG::solve() {
    outs() << "Number of copy edges: " << consG->getDirectCGEdges().size() << "\n";
    outs() << "Number of deref edges: " << consG->getLoadCGEdges().size() << "\n";
    outs() << "Number of assign edges: " << consG->getStoreCGEdges().size() << "\n";
    // Solve 
    // Copy edges
    solveCopyConstraints();
    outs() << "Handled copy edges\n";
    // Load edges
    solveDerefConstraints();
    outs() << "Handled deref edges\n";
    // Store edges
    solveAssignConstraints();
    outs() << "Handled assign edges\n";
}

void PTG::destroy() {
    // Go over the bitvectors and delete them
    for (PtdMapTyIt it = ptdMap.begin(), eit = ptdMap.end(); it != eit; it++) {
        delete(it->second);
    }
}
