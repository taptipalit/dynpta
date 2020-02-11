//===- PTG.h -- The points-to graph representation-----------------------------//
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
 * PTG.h
 *
 *  Created on: Oct 27, 2019
 *      Author: Tapti Palit
 */

#ifndef PTG_H_
#define PTG_H_

// We use the Constraint Node and Constraint Edges here too
#include "MemoryModel/ConsG.h"
#include "MemoryModel/ConsGEdge.h"
#include "MemoryModel/ConsGNode.h"
#include "MemoryModel/PointerAnalysis.h"
#include <llvm/ADT/SparseBitVector.h>
#include <unordered_map>
//#include <llvm/Support/raw_ostream.h>


/*!
 * Points-to graph for Steensgard's analysis.
 * It doesn't inherit from SVF's GenericGraph because the goal is to do away
 * with the complicated addition and deletion operations and replace them with
 * quick hashmap lookups. 
 *
 * The data-structures maintained --
 *
 * 1. In order to make the union-find operations fast, 
 * the points-to sets are represented by two Maps, PtdMap, and PtdRevMap, that maps the setID to the
 * contents of that points to set, in a bitvector.
 *
 * 2. The points-to mapping is represented by a Map, PtsToSetMap, that maps the setID to
 * the points-to set id.
 *
 * 3. The points-from mapping is represented by a Map, PtsFromSetMap, that maps the points-to
 * set id to the setID of the pointer set.
 *
 * All program IR statements are maintained in the constraint graph
 * 4) Copy edges represent the copy constraints
 * 5) Load edges represent constraints
 * 6) Store edges represent constraints
 *
 * There are actually two kinds of find operation
 *
 * find_pts(e1)
 *      set_id = lookup(PtdRevMap, e1)
 *      ptr_set_id = lookup(PtsToSetMap, set_id)
 *      return ptr_set_id
 *
 * find(e1)
 *      set_id = lookup(PtdRevMap, e1)
 *      return set_id
 *
 * The union operation, when applied to sets, with id s1, s2
 *
 * unify(s1, s2)
 *      if (s1 == s2)
 *          return
 *      s3 = s1 U s2
 *      Insert s3 in PtdMap, PtdRevMap
 *      Remove s2 and s1 from PtdMap, PtdRevMap
 *      Update all PtsToSetMap for s1 and s2 to s3. 
 *      Update all PtsFromSetMap for s1 and s2 to s3.
 *      
 * The join algorithm (from
 * https://www.cs.cmu.edu/~aldrich/courses/15-819O-13sp/resources/pointer.pdf)
 * Here e1 and e2 are the set ids of pts to sets
 *
 * join(e1, e2)
 *      if (e1 == e2)
 *          return
 *      e1next = find_pts(e1) // Find the sets
 *      e2next = find_pts(e2)
 *      unify(e1, e2)           // Union the sets
 *      join (e1next, e2next)
 *
 * The Algorithm proceeds like this -- 
 * 1. For each copy edge, ir_ptr = ir_qtr,              join(*ir_ptr, *ir_qtr) 
 * 2. For each load edge, ir_qtr = load *ir_ptr,        join(*ir_ptr, **ir_qtr)
 * 3. For each store edge, store ir_qtr, * ir_ptr       join(**ir_ptr,*ir_qtr)
 */
class PTG {

public:

    typedef llvm::DenseMap<SetID, llvm::SparseBitVector<>*> PtdMapTy;
    typedef PtdMapTy::iterator PtdMapTyIt;

    typedef llvm::DenseMap<NodeID, SetID> PtdRevMapTy;
    typedef PtdRevMapTy::iterator PtdRevMapTyIt;

    typedef std::unordered_multimap<SetID, SetID> PtsToSetMapTy;
    typedef PtsToSetMapTy::iterator PtsToSetMapTyIt;

    typedef std::unordered_multimap<SetID, SetID> PtsFromSetMapTy;
    typedef PtsFromSetMapTy::iterator PtsFromSetMapTyIt;

    typedef std::pair<SetID, SetID> SetPair;

private:
    typedef std::vector<SetID>::iterator VecIter;

    SetID currSetId;

    PAG*pag;

    ConstraintGraph* consG;

    SetID EMPTYSET;

    // The points-to set
    BVDataPTAImpl::PTDataTy* ptDataTy;

    // Establish pts-to set membership
    // (Given a set ID, look up which nodes belong to that set)
    PtdMapTy ptdMap;

    // Reverse look up pts-to set membership
    // (Given a node ID, look up which set it belongs to)
    PtdRevMapTy ptdRevMap;

    PtsToSetMapTy ptsToSetMap;
    PtsFromSetMapTy ptsFromSetMap;
    
    void buildPTG();

    void buildInitialPtdMaps();
    void buildInitialPtsToMaps();

    void destroy();

    SetID unify(SetID, SetID, bool forwardUnify = true, bool backwardUnify = true);
    SetID unifyBitVectors(SetID, SetID);
    SetID unifyBackward(SetID);
    SetID unifyForward(SetID);

    // Which set does the input set point to?
    SetID find_pts(SetID);

    // Which pts-to set does NodeID BELONG to
    SetID find(NodeID);

    SetID createEmptyPtsToSet();
    SetID createEmptyPtsToSet(SetID owner);

//    void collapseCyclesAndUnify(SetID, SetID);
    //bool detectAndCollapseCycles(SetID, SetID);
    //void handleCycleAt(SetID, SetID);
    void findPointerChain(SetID, std::set<SetID>&);
    void initializeCollapsedSet(SetID, std::set<SetID>&);
    
    void solveCopyConstraints();
    void solveDerefConstraints();
    void solveAssignConstraints();

    bool adjustPointsToRelationships(SetID, SetID, SetID); 
    bool insertPtsToRelationships(SetID, SetID, SetID); 
    bool insertPtsFromRelationships(SetID, SetID, SetID);
    void deleteStalePtsToRelationships(SetID, SetID, SetID);
    void deleteStalePtsFromRelationships(SetID, SetID, SetID);


public:
    PAG* getPAG() {
        return pag;
    }

    ConstraintGraph* getConsG() {
        return consG;
    }

    /// Constructor
    PTG(PAG* p, ConstraintGraph* c, BVDataPTAImpl::PTDataTy* ptdty): pag(p), consG(c), ptDataTy(ptdty), currSetId(0) {
        buildPTG();
    }

    /// Destructor
    virtual ~PTG() {
        destroy();
    }

    void solve(std::vector<ConstraintEdge*>&);
    void solve();

    virtual PointsTo& getPts(NodeID);

    virtual PointsTo& getPtsFrom(NodeID);

    void dumpMaps();

    PtdMapTy& getPtdMap() {
        return ptdMap;
    }

    PtdRevMapTy& getPtdRevMap() {
        return ptdRevMap;
    }

    PtsToSetMapTy& getPtsToSetMap() {
        return ptsToSetMap;
    }

    PtsFromSetMapTy& getPtsFromSetMap() {
        return ptsFromSetMap;
    }

    // Helper functions that return the first match from the ptsTo and ptsFrom
    // sets
    inline SetID getPtsToSetMap(SetID setId) {
        PtsToSetMapTyIt iter = ptsToSetMap.find(setId);
        //llvm::errs() << "Points to sets size: " << ptsToSetMap.count(setId) << "\n";
        if (iter == ptsToSetMap.end()) {
            return EMPTYSET;
        }
        return iter->second;
    }

    inline SetID getPtsFromSetMap(SetID setId) {
        PtsFromSetMapTyIt iter = ptsFromSetMap.find(setId);
        if (iter == ptsFromSetMap.end()) {
            return EMPTYSET;
        }
        return iter->second;
    }
    
    inline void setPtsToSetMap(SetID srcID, SetID dstID) {
        // Replace, not append
        auto rangeIt = ptsToSetMap.equal_range(srcID);
        for (auto it = rangeIt.first; it != rangeIt.second; ++it) {
            it->second = dstID;
        }
    }

    inline void setPtsFromSetMap(SetID srcID, SetID dstID) {
        // Replace, not append
        auto rangeIt = ptsFromSetMap.equal_range(srcID);
        for (auto it = rangeIt.first; it != rangeIt.second; ++it) {
            it->second = dstID;
        }
    }

    inline void checkAndInsertPtsTo(SetID s1, SetID s2) {
        auto range = ptsToSetMap.equal_range(s1);
        for (auto it = range.first; it != range.second; ++it) {
            if (it->second == s2) {
                return;
            }
        }
        ptsToSetMap.insert(SetPair(s1, s2));
    }

    inline void checkAndInsertPtsFrom(SetID s1, SetID s2) {
        auto range = ptsFromSetMap.equal_range(s1);
        for (auto it = range.first; it != range.second; ++it) {
            if (it->second == s2) {
                return;
            }
        }
        ptsFromSetMap.insert(SetPair(s1, s2));
    }
};

#endif /* PTG_H_ */
