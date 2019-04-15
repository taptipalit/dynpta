//===- ConsGNode.h -- Constraint graph node-----------------------------------//
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
 * ConsGNode.h
 *
 *  Created on: Mar 19, 2014
 *      Author: Yulei Sui
 */

#ifndef CONSGNODE_H_
#define CONSGNODE_H_

#include <llvm/ADT/BitVector.h>
/*!
 * Constraint node
 */
typedef GenericNode<ConstraintNode,ConstraintEdge> GenericConsNodeTy;
class ConstraintNode : public GenericConsNodeTy {

public:
    typedef ConstraintEdge::ConstraintEdgeSetTy::iterator iterator;
    typedef ConstraintEdge::ConstraintEdgeSetTy::const_iterator const_iterator;
    typedef FIFOWorkList<NodeID> WorkList;

private:
    static const int MAX_FIELDS = 120;
    bool _isPWCNode;

    int numTimesVisited;

    int numOutEdges;

    class SensitiveFlowBV;

    class SensitiveFlowBV {
        public:
            llvm::BitVector sensitiveFieldFlows; // A short-cut to avoid traversing the individual lists in the nested struct
            SensitiveFlowBV* nestedSensitiveFieldFlows[MAX_FIELDS];


            /*
             * Should be used only at the beginning to mark everything
             * sensitive
             */
            void setAllSensitiveFieldFlows() {
                sensitiveFieldFlows.set();
            }

            bool setSensitiveFieldFlow(int field) {
                if (!sensitiveFieldFlows.test(field)) {
                    nestedSensitiveFieldFlows[field] = new SensitiveFlowBV();
                    sensitiveFieldFlows.set(field);
                    return true;
                } else {
                    return false;
                }
            }

            bool unionBV(llvm::BitVector& newBV) {
                llvm::BitVector oldBV(sensitiveFieldFlows);
                sensitiveFieldFlows |= newBV;
                if (sensitiveFieldFlows != oldBV) {
                    return true;
                } else {
                    return false;
                }
            }

            llvm::BitVector& getSensitiveFieldFlows() {
                return sensitiveFieldFlows;
            }

            bool isSensitiveFieldFlow(int field) {
                return sensitiveFieldFlows.test(field);
            }

            SensitiveFlowBV* getChildSfbv(int offset) {
                assert(offset < MAX_FIELDS);
                return nestedSensitiveFieldFlows[offset];
            }

            SensitiveFlowBV(): sensitiveFieldFlows(MAX_FIELDS, false) {
                for (int i = 0; i < MAX_FIELDS; i++) {
                    nestedSensitiveFieldFlows[i] = nullptr;
                }
            }
    };

    SensitiveFlowBV* sensitiveFlowBV;

    ConstraintEdge::ConstraintEdgeSetTy loadInEdges; ///< all incoming load edge of this node
    ConstraintEdge::ConstraintEdgeSetTy loadOutEdges; ///< all outgoing load edge of this node
    
    ConstraintEdge::ConstraintEdgeSetTy loadValInEdges; ///< all incoming load value edge of this node
    ConstraintEdge::ConstraintEdgeSetTy loadValOutEdges; ///< all outgoing load value edge of this node


    ConstraintEdge::ConstraintEdgeSetTy storeInEdges; ///< all incoming store edge of this node
    ConstraintEdge::ConstraintEdgeSetTy storeValInEdges;
    ConstraintEdge::ConstraintEdgeSetTy storeOutEdges; ///< all outgoing store edge of this node
    ConstraintEdge::ConstraintEdgeSetTy storeValOutEdges; // <out outgoing store value edge of this node

    ConstraintEdge::ConstraintEdgeSetTy callValInEdges;
    ConstraintEdge::ConstraintEdgeSetTy callValOutEdges;

    ConstraintEdge::ConstraintEdgeSetTy retValInEdges;
    ConstraintEdge::ConstraintEdgeSetTy retValOutEdges;

    /// Copy/call/ret/gep incoming edge of this node,
    /// To be noted: this set is only used when SCC detection, and node merges
    ConstraintEdge::ConstraintEdgeSetTy directInEdges;
    ConstraintEdge::ConstraintEdgeSetTy directOutEdges;

    ConstraintEdge::ConstraintEdgeSetTy addressInEdges; ///< all incoming address edge of this node
    ConstraintEdge::ConstraintEdgeSetTy addressOutEdges; ///< all outgoing address edge of this node

public:

    ConstraintNode(NodeID i): GenericConsNodeTy(i,0), _isPWCNode(false), numTimesVisited(0) {
        sensitiveFlowBV = new SensitiveFlowBV();
    }

    void setSensitiveFlowBV(SensitiveFlowBV* sensitiveFlowBV) {
        this->sensitiveFlowBV = sensitiveFlowBV;
    }

    SensitiveFlowBV* getSensitiveFlowBV() {
        return sensitiveFlowBV;
    }

    
    /*
     * Invoked by the target of an incoming field sensitive edge
     * Propagate the sensitivity
     */
    inline bool appendFieldSensitivePath(int idx, SensitiveFlowBV* incomingSfbv) {
        bool changed = false;
        changed |= this->sensitiveFlowBV->setSensitiveFieldFlow(idx);
        changed |= doDeepUnion(this->sensitiveFlowBV->getChildSfbv(idx), incomingSfbv);
        return changed;
    }

    inline bool doDeepUnion(SensitiveFlowBV* dstSfbv, SensitiveFlowBV* srcSfbv) {
        bool changed = false;
        // Union the pointers

        if (srcSfbv && dstSfbv) {
            // A better way to find the set bits
            int i = srcSfbv->getSensitiveFieldFlows().find_first();
            while (i != -1) {
                if (!dstSfbv->getSensitiveFieldFlows().test(i)) {
                    // Create new Object
                    dstSfbv->nestedSensitiveFieldFlows[i] = new SensitiveFlowBV();
                    changed = true;
                }
                changed |= doDeepUnion(dstSfbv->nestedSensitiveFieldFlows[i],
                        srcSfbv->nestedSensitiveFieldFlows[i]);
                i = srcSfbv->getSensitiveFieldFlows().find_next(i);
            }
            /*
            for (int i = 0; i < MAX_FIELDS; i++) {
                if (srcSfbv->getSensitiveFieldFlows().test(i)) {
            
                }
            }
            */
            changed |= dstSfbv->unionBV(srcSfbv->getSensitiveFieldFlows());
        }
        //llvm::errs() << "Returning changed: " << changed << "\n";
        return changed;
    }

    inline bool fieldUnion(SensitiveFlowBV* srcSfbv) {
        return doDeepUnion(this->sensitiveFlowBV, srcSfbv); // srcSfbv can't be null
    }

    inline bool isSensitiveFieldFlow(int field) {
        return sensitiveFlowBV->isSensitiveFieldFlow(field);
    }

    inline bool updateChildSensitiveFieldFlow(ConstraintNode* parent, int childOffset) {
        bool changed = false;
        SensitiveFlowBV* childSfbv = parent->getSensitiveFlowBV()->getChildSfbv(childOffset);
        changed |= doDeepUnion(this->sensitiveFlowBV, childSfbv); // srcSfbv can't be null
        return changed;
    }

    inline void setAllSensitiveFieldFlows() {
        // Set all fields, to two levels
        this->sensitiveFlowBV->setAllSensitiveFieldFlows();
        for (int i = 0; i < MAX_FIELDS; i++) {
            this->sensitiveFlowBV->nestedSensitiveFieldFlows[i] = new SensitiveFlowBV();
            this->sensitiveFlowBV->nestedSensitiveFieldFlows[i]->setAllSensitiveFieldFlows();
        }
    }

    inline int getNumTimesVisited() {
        return numTimesVisited;
    }

    inline void incNumTimesVisited() {
        numTimesVisited++;
    }

    /// Whether a node involves in PWC, if so, all its points-to elements should become field-insensitive.
    //@{
    inline bool isPWCNode() const {
        return _isPWCNode;
    }
    inline void setPWCNode() {
        _isPWCNode = true;
    }
    //@}

    /// Direct and Indirect PAG edges
    inline bool isdirectEdge(ConstraintEdge::ConstraintEdgeK kind) {
        return (kind == ConstraintEdge::Copy || kind == ConstraintEdge::NormalGep || kind == ConstraintEdge::VariantGep );
    }
    inline bool isIndirectEdge(ConstraintEdge::ConstraintEdgeK kind) {
        return (kind == ConstraintEdge::Load || kind == ConstraintEdge::Store);
    }

    ///  Iterators
    //@{
    inline iterator directOutEdgeBegin() {
        return directOutEdges.begin();
    }
    inline iterator directOutEdgeEnd() {
        return directOutEdges.end();
    }
    inline iterator directInEdgeBegin() {
        return directInEdges.begin();
    }
    inline iterator directInEdgeEnd() {
        return directInEdges.end();
    }

    inline const_iterator directOutEdgeBegin() const {
        return directOutEdges.begin();
    }
    inline const_iterator directOutEdgeEnd() const {
        return directOutEdges.end();
    }
    inline const_iterator directInEdgeBegin() const {
        return directInEdges.begin();
    }
    inline const_iterator directInEdgeEnd() const {
        return directInEdges.end();
    }

    ConstraintEdge::ConstraintEdgeSetTy& incomingAddrEdges() {
        return addressInEdges;
    }
    ConstraintEdge::ConstraintEdgeSetTy& outgoingAddrEdges() {
        return addressOutEdges;
    }

    inline const_iterator outgoingAddrsBegin() const {
        return addressOutEdges.begin();
    }
    inline const_iterator outgoingAddrsEnd() const {
        return addressOutEdges.end();
    }
    inline const_iterator incomingAddrsBegin() const {
        return addressInEdges.begin();
    }
    inline const_iterator incomingAddrsEnd() const {
        return addressInEdges.end();
    }

    inline const_iterator outgoingLoadsBegin() const {
        return loadOutEdges.begin();
    }
    inline const_iterator outgoingLoadsEnd() const {
        return loadOutEdges.end();
    }
    inline const_iterator incomingLoadsBegin() const {
        return loadInEdges.begin();
    }
    inline const_iterator incomingLoadsEnd() const {
        return loadInEdges.end();
    }

    inline const_iterator outgoingLoadValsBegin() const {
        return loadValOutEdges.begin();
    }
    inline const_iterator outgoingLoadValsEnd() const {
        return loadValOutEdges.end();
    }
    inline const_iterator incomingLoadValsBegin() const {
        return loadValInEdges.begin();
    }
    inline const_iterator incomingLoadValsEnd() const {
        return loadValInEdges.end();
    }


    inline const_iterator outgoingStoresBegin() const {
        return storeOutEdges.begin();
    }
    inline const_iterator outgoingStoresEnd() const {
        return storeOutEdges.end();
    }
    inline const_iterator incomingStoresBegin() const {
        return storeInEdges.begin();
    }
    inline const_iterator incomingStoresEnd() const {
        return storeInEdges.end();
    }

    // Call Val
    inline const_iterator outgoingCallValsBegin() const {
        return callValOutEdges.begin();
    }

    inline const_iterator outgoingCallValsEnd() const {
        return callValOutEdges.end();
    }

    inline const_iterator incomingCallValsBegin() const {
        return callValInEdges.begin();
    }

    inline const_iterator incomingCallValsEnd() const {
        return callValInEdges.end();
    }

    // Ret Val
    inline const_iterator outgoingRetValsBegin() const {
        return retValOutEdges.begin();
    }

    inline const_iterator outgoingRetValsEnd() const {
        return retValOutEdges.end();
    }

    inline const_iterator incomingRetValsBegin() const {
        return retValInEdges.begin();
    }

    inline const_iterator incomingRetValsEnd() const {
        return retValInEdges.end();
    }


    inline const_iterator outgoingStoreValsBegin() const {
        return storeValOutEdges.begin();
    }
    inline const_iterator outgoingStoreValsEnd() const {
        return storeValOutEdges.end();
    }
    inline const_iterator incomingStoreValsBegin() const {
        return storeValInEdges.begin();
    }
    inline const_iterator incomingStoreValsEnd() const {
        return storeValInEdges.end();
    }
   //@}

    ///  Add constraint graph edges
    //@{
    inline void addIncomingCopyEdge(CopyCGEdge* inEdge) {
        addIncomingDirectEdge(inEdge);
    }
    inline void addIncomingGepEdge(GepCGEdge* inEdge) {
        addIncomingDirectEdge(inEdge);
    }
    inline void addOutgoingCopyEdge(CopyCGEdge* outEdge) {
        addOutgoingDirectEdge(outEdge);
    }
    inline void addOutgoingGepEdge(GepCGEdge* outEdge) {
        addOutgoingDirectEdge(outEdge);
    }
    inline void addIncomingAddrEdge(AddrCGEdge* inEdge) {
        addressInEdges.insert(inEdge);
        addIncomingEdge(inEdge);
    }

    inline void addIncomingCallValEdge(CallValCGEdge* outEdge) {
        bool added1 = callValInEdges.insert(outEdge).second;
        bool added2 = addIncomingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }
    inline void addIncomingRetValEdge(RetValCGEdge* outEdge) {
        bool added1 = retValInEdges.insert(outEdge).second;
        bool added2 = addIncomingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }

    inline bool hasNoOutEdges() {
        // Check
        if (OutEdges.size() == 0) {
            return true;
        } else {
            return false;
        }
    }

    inline void addIncomingLoadEdge(LoadCGEdge* inEdge) {
        loadInEdges.insert(inEdge);
        addIncomingEdge(inEdge);
    }
    inline void addIncomingLoadValEdge(LoadValCGEdge* inEdge) {
        loadValInEdges.insert(inEdge);
        addIncomingEdge(inEdge);
    }
    inline void addIncomingStoreEdge(StoreCGEdge* inEdge) {
        storeInEdges.insert(inEdge);
        addIncomingEdge(inEdge);
    }
    inline void addIncomingStoreValEdge(StoreValCGEdge* inEdge) {
        storeValInEdges.insert(inEdge);
        addIncomingEdge(inEdge);
    }
    inline void addIncomingDirectEdge(ConstraintEdge* inEdge) {
        assert(inEdge->getDstID() == this->getId());
        bool added1 = directInEdges.insert(inEdge).second;
        bool added2 = addIncomingEdge(inEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }
    inline void addOutgoingAddrEdge(AddrCGEdge* outEdge) {
        addressOutEdges.insert(outEdge);
        addOutgoingEdge(outEdge);
    }
    inline void addOutgoingLoadEdge(LoadCGEdge* outEdge) {
        bool added1 = loadOutEdges.insert(outEdge).second;
        bool added2 = addOutgoingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }

    inline void addOutgoingCallValEdge(CallValCGEdge* outEdge) {
        bool added1 = callValOutEdges.insert(outEdge).second;
        bool added2 = addOutgoingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }
    inline void addOutgoingRetValEdge(RetValCGEdge* outEdge) {
        bool added1 = retValOutEdges.insert(outEdge).second;
        bool added2 = addOutgoingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }

    inline void addOutgoingLoadValEdge(LoadValCGEdge* outEdge) {
        bool added1 = loadValOutEdges.insert(outEdge).second;
        bool added2 = addOutgoingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }

    inline void addOutgoingStoreEdge(StoreCGEdge* outEdge) {
        bool added1 = storeOutEdges.insert(outEdge).second;
        bool added2 = addOutgoingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }
    inline void addOutgoingStoreValEdge(StoreValCGEdge* outEdge) {
        bool added1 = storeValOutEdges.insert(outEdge).second;
        bool added2 = addOutgoingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }
    inline void addOutgoingDirectEdge(ConstraintEdge* outEdge) {
        assert(outEdge->getSrcID() == this->getId());
        bool added1 = directOutEdges.insert(outEdge).second;
        bool added2 = addOutgoingEdge(outEdge);
        assert(added1 && added2 && "edge not added, duplicated adding!!");
    }
    //@}

    /// Remove constraint graph edges
    //{@
    inline void removeOutgoingAddrEdge(AddrCGEdge* outEdge) {
        Size_t num1 = addressOutEdges.erase(outEdge);
        Size_t num2 = removeOutgoingEdge(outEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeIncomingAddrEdge(AddrCGEdge* inEdge) {
        Size_t num1 = addressInEdges.erase(inEdge);
        Size_t num2 = removeIncomingEdge(inEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeOutgoingDirectEdge(ConstraintEdge* outEdge) {
        Size_t num1 = directOutEdges.erase(outEdge);
        Size_t num2 = removeOutgoingEdge(outEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeIncomingDirectEdge(ConstraintEdge* inEdge) {
        Size_t num1 = directInEdges.erase(inEdge);
        Size_t num2 = removeIncomingEdge(inEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeOutgoingLoadEdge(LoadCGEdge* outEdge) {
        Size_t num1 = loadOutEdges.erase(outEdge);
        Size_t num2 = removeOutgoingEdge(outEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeIncomingLoadEdge(LoadCGEdge* inEdge) {
        Size_t num1 = loadInEdges.erase(inEdge);
        Size_t num2 = removeIncomingEdge(inEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeOutgoingStoreEdge(StoreCGEdge* outEdge) {
        Size_t num1 = storeOutEdges.erase(outEdge);
        Size_t num2 = removeOutgoingEdge(outEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeIncomingStoreEdge(StoreCGEdge* inEdge) {
        Size_t num1 = storeInEdges.erase(inEdge);
        Size_t num2 = removeIncomingEdge(inEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    // Load value edges
    inline void removeOutgoingLoadValEdge(LoadValCGEdge* outEdge) {
        Size_t num1 = loadValOutEdges.erase(outEdge);
        Size_t num2 = removeOutgoingEdge(outEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeIncomingLoadValEdge(LoadValCGEdge* inEdge) {
        Size_t num1 = loadValInEdges.erase(inEdge);
        Size_t num2 = removeIncomingEdge(inEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    // Store value edges
    inline void removeOutgoingStoreValEdge(StoreValCGEdge* outEdge) {
        Size_t num1 = storeValOutEdges.erase(outEdge);
        Size_t num2 = removeOutgoingEdge(outEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeIncomingStoreValEdge(StoreValCGEdge* inEdge) {
        Size_t num1 = storeValInEdges.erase(inEdge);
        Size_t num2 = removeIncomingEdge(inEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    // Call value edges
    inline void removeOutgoingCallValEdge(CallValCGEdge* outEdge) {
        Size_t num1 = callValOutEdges.erase(outEdge);
        Size_t num2 = removeOutgoingEdge(outEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeIncomingCallValEdge(CallValCGEdge* inEdge) {
        Size_t num1 = callValInEdges.erase(inEdge);
        Size_t num2 = removeIncomingEdge(inEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    // Return value edges
    inline void removeOutgoingRetValEdge(RetValCGEdge* outEdge) {
        Size_t num1 = retValOutEdges.erase(outEdge);
        Size_t num2 = removeOutgoingEdge(outEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }

    inline void removeIncomingRetValEdge(RetValCGEdge* inEdge) {
        Size_t num1 = retValInEdges.erase(inEdge);
        Size_t num2 = removeIncomingEdge(inEdge);
        //assert((num1 && num2) && "edge not in the set, can not remove!!!");
    }
    //@}


};

#endif /* CONSGNODE_H_ */
