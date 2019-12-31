//===- Andersen.cpp -- Field-sensitive Andersen's analysis-------------------//
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
 * Andersen.cpp
 *
 *  Created on: Nov 12, 2013
 *      Author: Yulei Sui
 */

#include "MemoryModel/PAG.h"
#include "WPA/Andersen.h"
#include "Util/AnalysisUtil.h"
#include <vector>
#include <llvm/Support/CommandLine.h> // for tool output file
#include <chrono>
#include <ctime>

using namespace llvm;
using namespace analysisUtil;


Size_t Andersen::numOfProcessedAddr = 0;
Size_t Andersen::numOfProcessedCopy = 0;
Size_t Andersen::numOfProcessedGep = 0;
Size_t Andersen::numOfProcessedLoad = 0;
Size_t Andersen::numOfProcessedStore = 0;

Size_t Andersen::numOfSCCDetection = 0;
double Andersen::timeOfSCCDetection = 0;
double Andersen::timeOfSCCMerges = 0;
double Andersen::timeOfCollapse = 0;

Size_t Andersen::AveragePointsToSetSize = 0;
Size_t Andersen::MaxPointsToSetSize = 0;
double Andersen::timeOfProcessCopyGep = 0;
double Andersen::timeOfProcessLoadStore = 0;
double Andersen::timeOfUpdateCallGraph = 0;
bool callTrack = false;

static cl::opt<string> WriteAnder("write-ander",  cl::init(""),
                                  cl::desc("Write Andersen's analysis results to a file"));
static cl::opt<string> ReadAnder("read-ander",  cl::init(""),
                                 cl::desc("Read Andersen's analysis results from a file"));

static cl::opt<bool> Profile("profile", cl::init(false), cl::desc("Profile the application"));
static cl::opt<int> ProfileInterval("profile-interval", cl::init(100), cl::desc("Profiling interval for the application"));
static cl::opt<bool> RemoveProfiledNodes("remove-profiled-nodes", cl::init(false), cl::desc("Removed profiled nodes"));

int mergeCount = 0;
int maxNumOutgoingEdges = 0;
int maxNumIncomingEdges = 0;

NodeID maxOutgoingEdgesNodeID = 0;
NodeID maxIncomingEdgesNodeID = 0;
auto start = std::chrono::system_clock::now();

typedef llvm::DenseMap<NodeID,std::vector<NodeID>> RepToNodeMap;
RepToNodeMap repToNodeMap;

void Andersen::analyzeSubgraph(SVFModule svfModule) {
    double andersAnalysisTime;

	double timeStart, timeEnd;
	timeStart = CLOCK_IN_MS();

    DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Start Solving Constraints\n"));
    //dumpStat();
    initializeSubgraph(svfModule);
    processAllAddr();

    do {
        numOfIteration++;

        reanalyze = false;

        // Start solving constraints

        solve();

        double cgUpdateStart = stat->getClk();
        if (updateCallGraph(getIndirectCallsites())){
            reanalyze = true;
        }
        double cgUpdateEnd = stat->getClk();
        timeOfUpdateCallGraph += (cgUpdateEnd - cgUpdateStart) / TIMEINTERVAL;

        errs() << "Reanalyze: " << reanalyze << "\n";
    } while (reanalyze);

    DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Finish Solving Constraints\n"));

    /// finalize the analysis
    finalize();
	timeEnd = CLOCK_IN_MS();
	andersAnalysisTime = (timeEnd - timeStart) / TIMEINTERVAL;

    outs() << "Andersen's Analysis took: " << (long)andersAnalysisTime << " seconds.\n";
}

/*!
 * Andersen analysis
 */
void Andersen::analyze(SVFModule svfModule) {
    /// Initialization for the Solver
    initialize(svfModule);

    bool readResultsFromFile = false;
    if(!ReadAnder.empty())
        readResultsFromFile = this->readFromFile(ReadAnder);

    if(!readResultsFromFile) {
        DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Start Solving Constraints\n"));
        //dumpStat();
        processAllAddr();

        do {
            numOfIteration++;

            reanalyze = false;

            // Start solving constraints

            solve();

            double cgUpdateStart = stat->getClk();
            if (updateCallGraph(getIndirectCallsites())){
                reanalyze = true;
            }
            double cgUpdateEnd = stat->getClk();
            timeOfUpdateCallGraph += (cgUpdateEnd - cgUpdateStart) / TIMEINTERVAL;

        } while (reanalyze);

        DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Finish Solving Constraints\n"));

        /// finalize the analysis
        finalize();
    }

    if(!WriteAnder.empty())
        this->writeToFile(WriteAnder);
}


void Andersen::profileConstraintGraph() {
    // Go over every node in the Constraint Graph and see what's the
    // deal with it
    ConstraintGraph::IDToNodeMapTy::iterator pit = consCG->begin();
    while (pit != consCG->end()) { 
	NodeID nodeID = pit->first;
	if (nodeID == 16) {
		ConstraintNode* node = consCG->getConstraintNode(nodeID);
		ConstraintNode* newDst = consCG->getConstraintNode(34); 
		/*for (ConstraintNode::const_iterator it = node->InEdgeBegin(),
                			eit = node->InEdgeEnd(); it != eit; ++it) {
			ConstraintEdge* edge = *it;
			ConstraintNode* src = edge->getSrcNode();	
			edge->setNewDstNode(newDst);
			newDst->addIncomingEdge(edge);	
				
            	}*/
		bool gepInsideScc = consCG->steensgardMoveEdgesToRepNode(node, newDst); 
	return;
        }
	pit++;
    }


  
    int dummyValCount = 0;
    int dummyObjCount = 0;
    int retPNCount = 0;
    int varArgCount = 0;
    int fiObjCount = 0;
    int gepObjCount = 0;
    int gepValCount = 0;
    int objCount = 0;
    int valCount = 0;
    int totalCount = 0;

    ConstraintGraph::IDToNodeMapTy::iterator it = consCG->begin();
    while (it != consCG->end()) {
        NodeID nodeID = it->first;
        ConstraintNode* constraintNode = consCG->getConstraintNode(nodeID);
	const PAGNode* pagNode = pag->getPAGNode(nodeID);
	/*if (isa<DummyValPN>(pagNode)){
		dummyValCount++;
		outs () <<" Dummy: "<<nodeID<<"\n";
	}
	else if (isa<DummyObjPN>(pagNode)){
		dummyObjCount++;
		outs () <<" Dummy: "<<nodeID<<"\n";
        }*/
	if (isa<RetPN>(pagNode)){
                retPNCount++;
		outs () <<" Ret: "<<nodeID<<"\n";
		ConstraintNode* constraintNode = consCG->getConstraintNode(nodeID);
        	int outEdgeCount = constraintNode->getOutEdges().size();
        	int inEdgeCount = constraintNode->getInEdges().size();
		//outs() << " Ret outEdgeCount: "<<outEdgeCount<<" and inEdgeCount: "<<inEdgeCount<<"\n";

        }
	else if (isa<VarArgPN>(pagNode)){
                varArgCount++;
		outs () <<" VarArg: "<<nodeID<<"\n";
        }
	/*else if (isa<FIObjPN>(pagNode)){
                fiObjCount++;
		outs () <<" FIObj: "<<nodeID<<"\n";
        }*/
	/*else if (isa<GepObjPN>(pagNode)){
                gepObjCount++;
		outs () <<" GepObj: "<<nodeID<<"\n";
        }
	else if (isa<GepValPN>(pagNode)){
                gepValCount++;
		outs () <<" GepVal: "<<nodeID<<"\n";
        }*/
	else if (isa<ObjPN>(pagNode)){
                objCount++;
		//outs () <<" Obj: "<<nodeID<<"\n";
        }
	else if (isa<ValPN>(pagNode)){
                valCount++;
		//outs () <<" Val: "<<nodeID<<"\n";
        }
	totalCount++;
	
        it++;
    }
	
    outs() <<" Total DummyValPN: "<<dummyValCount<<"\n";
    outs() <<" Total DummyObjPN: "<<dummyObjCount<<"\n";
    outs() <<" Total RetPN: "<<retPNCount<<"\n";
    outs() <<" Total VarArgPN: "<<varArgCount<<"\n";
    errs() <<" Total FIObjPN: "<<fiObjCount<<"\n";
    errs() <<" Total GepObjPN: "<<gepObjCount<<"\n";
    outs() <<" Total GepValPN: "<<gepValCount<<"\n";
    outs() <<" Total ObjPN: "<<objCount<<"\n";
    outs() <<" Total ValPN: "<<valCount<<"\n";
    outs() <<" Total : "<<totalCount<<"\n";
    /*ConstraintGraph::IDToNodeMapTy::iterator it = consCG->begin();
    std::vector<int> outEdgeCounts;
    std::vector<int> inEdgeCounts;
    
    std::map<int, NodeID> outEdgeCountToNodeIDMap;
    std::map<int, NodeID> inEdgeCountToNodeIDMap;

    while (it != consCG->end()) {
        NodeID nodeID = it->first;
        ConstraintNode* constraintNode = consCG->getConstraintNode(nodeID);
        int outEdgeCount = constraintNode->getOutEdges().size();
        int inEdgeCount = constraintNode->getInEdges().size();
        outEdgeCounts.push_back(outEdgeCount);
        inEdgeCounts.push_back(inEdgeCount);
        outEdgeCountToNodeIDMap[outEdgeCount] = nodeID;
        inEdgeCountToNodeIDMap[inEdgeCount] = nodeID;
        it++;
    }

    // Sort it 
    std::sort(outEdgeCounts.begin(), outEdgeCounts.end(), greater<int>());
    std::sort(inEdgeCounts.begin(), inEdgeCounts.end(), greater<int>());

    outs() << "Top 100 out-edge counts\n";
    for (int i = 0; i < 100; i++) {
        int edgeCount = outEdgeCounts[i];
        NodeID nodeID = outEdgeCountToNodeIDMap[edgeCount];
        //outs() << edgeCount << " : Node ID : " << nodeID << "\n";
        ConstraintNode* node = consCG->getConstraintNode(nodeID);
        if (node == NULL)
            continue;
        if (RemoveProfiledNodes) {
            bool gepInsideScc = consCG->steensgardMoveEdgesToRepNode(node, node);
            consCG->removeConstraintNode(node);
            outs() <<edgeCount << " :NodeId removed "<<nodeID << "\n";
        }
        // Get the value from the pag
        PAGNode* pagNode = pag->getPAGNode(nodeID);
        outs() << pagNode->getValueName() << "\n";
        if (pagNode->hasValue()) {
            Value* val = const_cast<Value*>(pagNode->getValue());
            outs() << *(val) << "\n";
            if (Argument* arg = dyn_cast<Argument>(val)) {
                outs() << "Argument for " << arg->getParent()->getName() << "\n";
            }
        }
    }

    outs() << "Top 100 in-edge counts\n";

    for (int i = 0; i < 100; i++) {
        int edgeCount = inEdgeCounts[i];
        NodeID nodeID = inEdgeCountToNodeIDMap[edgeCount];
        outs() << edgeCount << " : Node ID : " << nodeID << "\n";
        if (RemoveProfiledNodes) { 
            ConstraintNode* node = consCG->getConstraintNode(nodeID);
            if (node == NULL)
                continue;
            bool gepInsideScc = consCG->steensgardMoveEdgesToRepNode(node, node);
            consCG->removeConstraintNode(node);
            outs() <<edgeCount << " :NodeId removed "<<nodeID << "\n";
        }

        // Get the value from the pag
        PAGNode* pagNode = pag->getPAGNode(nodeID);
        outs() << pagNode->getValueName() << "\n";
        if (pagNode->hasValue()) {
            Value* val = const_cast<Value*>(pagNode->getValue());
            outs() << *(val) << "\n";
            if (Argument* arg = dyn_cast<Argument>(val)) {
                outs() << "Argument for " << arg->getParent()->getName() << "\n";
            }
        }
    }*/
}

/*!
 * Steensgard analysis
 */
void Steensgard::analyze(SVFModule svfModule) {
    /// Initialization for the Solver
    initialize(svfModule);

    bool readResultsFromFile = false;
    if(!ReadAnder.empty())
        readResultsFromFile = this->readFromFile(ReadAnder);

    
    if(!readResultsFromFile) {
        DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Start Solving Constraints\n"));
        //dumpStat();
        if (Profile) {
            profileConstraintGraph();

        }
        
        steensgardProcessAllAddr();
        
        do {
            numOfIteration++;

            reanalyze = false;

            /// Start solving constraints
            if(callTrack)
                steensgardCallSolve();
            else        
                steensgardSolve();
              
            double cgUpdateStart = stat->getClk();
            if (updateCallGraph(getIndirectCallsites())){
                reanalyze = true;
                callTrack = true;
                }
            double cgUpdateEnd = stat->getClk();
            timeOfUpdateCallGraph += (cgUpdateEnd - cgUpdateStart) / TIMEINTERVAL;

        } while (reanalyze);
	cout << " Done Analysis ";
        DBOUT(DGENERAL, llvm::outs() << analysisUtil::pasMsg("Finish Solving Constraints\n"));
	
        /// finalize the analysis
        finalize();
	//dump();
    }

    if(!WriteAnder.empty())
        this->writeToFile(WriteAnder);
}


void Steensgard::steensgardProcessNodeInitial(NodeID nodeId) {

	if (consCG->getRep(nodeId) != nodeId) return;
		
    	numOfIteration++;

   	ConstraintNode* node = consCG->getConstraintNode(nodeId);
	if (node == NULL) {
		return;
	}
	/*if (nodeId == 3){
		bool gepInsideScc = consCG->steensgardMoveEdgesToRepNode(node, node);
		consCG->removeConstraintNode(node);
		return;
	}*/

	const PAGNode* pagNode = pag->getPAGNode(nodeId);
	if (isa<ValPN>(pagNode) || isa<RetPN>(pagNode) || isa<VarArgPN>(pagNode)){
		int st = 0;
		NodeID dst = 0;
		for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(), eit =
			node->directOutEdgeEnd(); ; ) {
			if (it == eit) break;
			if(CopyCGEdge* edge = llvm::dyn_cast<CopyCGEdge>(*it)){
				numOfProcessedCopy++;
				dst = edge->getDstID();
				it++;
				if (dst == nodeId) continue;
				const PAGNode* pagNodeDst = pag->getPAGNode(dst);
				if ((isa<ValPN>(pagNodeDst)) || isa<RetPN>(pagNodeDst) || isa<VarArgPN>(pagNodeDst)){
					//cout << " Merging "<< dst<<" and "<<nodeId<< " \n"; 
					steensgardMerge(dst, nodeId);
					st = 1;
				}
			}
			else it++;
		}
		if (st == 1 ){
			steensgardProcessNodeInitial(nodeId);
		}
	}
}


void Steensgard::steensgardProcessNode(NodeID nodeId) {

    if (consCG->getRep(nodeId) != nodeId) return;

    numOfIteration++;
    
    cout << "\nnodeId Process"<<nodeId;

    ConstraintNode* node = consCG->getConstraintNode(nodeId);
    if (node == NULL) {
	return;
	}
    
    // Handle Load and Store
    for (PointsTo::iterator piter = getPts(nodeId).begin(), epiter =
                getPts(nodeId).end(); piter != epiter; ++piter) {
        
	NodeID ptd = *piter;
        //cout << " ptd "<<ptd;

	//Handle load
        for (ConstraintNode::const_iterator it = node->outgoingLoadsBegin(),
                eit = node->outgoingLoadsEnd(); it != eit; ++it) {
                //cout << " load ";
            if (processLoad(ptd, *it)){
                //cout <<" addworklist:"<<ptd<<" ";
                steensgardPushIntoWorklist(ptd);
            }
        }

        // handle store
        for (ConstraintNode::const_iterator it = node->incomingStoresBegin(),
                eit = node->incomingStoresEnd(); it != eit; ++it) {
                //cout << " store ";
            if (processStore(ptd, *it)){
                steensgardPushIntoWorklist(ptd);
                //cout <<" addworklist:"<<ptd<<" ";
            }
        }
    }

 }



void Steensgard::steensgardWorklistProcess(NodeID nodeId) {

	//processing only memory address nodes
	//cout << "\nNodeId_Worklist: "<<nodeId;
	//flag = false;
	//if (nodeId == 16) return;
	if (consCG->getRep(nodeId) != nodeId) return;

	//cout << "\nNodeId_Worklist: "<<nodeId; 
	NodeID src = 0, dst = 0;
	NodeID mergeNode1 = 0, mergeNode2 = 0;
	bool merged = false;

        ConstraintNode* node = consCG->getConstraintNode(nodeId);
        if (node == NULL)
                return;
	
	const PAGNode* pagNode = pag->getPAGNode(nodeId);

	// Checking if node is a address node and merge all incoming and outgoing copy nodes
	if (isa<ObjPN>(pagNode)){
		//cout << "\nNodeId: "<<nodeId<< " Count: "<< consCG->getCount(nodeId);
                int count = 0;
		numOfIteration++;

                // Finding source nodes of a address node and merge if more than one src copy edge
                for (ConstraintNode::const_iterator it = node->directInEdgeBegin(),
                        eit = node->directInEdgeEnd(); ; ) {
			if (it == eit) break;

                        if(CopyCGEdge* edge = llvm::dyn_cast<CopyCGEdge>(*it)){
				numOfProcessedCopy++;
                                src = edge->getSrcID();
				it++;
				const PAGNode* pagNodeDst = pag->getPAGNode(src);
                                /*if ((isa<ObjPN>(pagNodeDst)) ){
					continue;
				}*/
				if (mergeNode1 == 0){
					mergeNode1 = src;
				}
				else
					mergeNode2 = src;
				if ((mergeNode1 != 0) && (mergeNode2 != 0) && (mergeNode1 != mergeNode2)){
						//cout << " Merging "<<mergeNode2<< " and "<< mergeNode1<<" ";
						steensgardMerge(mergeNode2 , mergeNode1);
						count++;
						merged = true;
				}
                        }
			else it++;
                }

		// Union points of address node with source node
		if (mergeNode1 != 0){
			unionPts(nodeId,mergeNode1);
		}

		//cout<< "Copy_dst: ";
		// merge src with dst and dst with dst
                for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(), eit =
                        node->directOutEdgeEnd(); ; ) {
			if (it == eit) break;

                        if(CopyCGEdge* edge = llvm::dyn_cast<CopyCGEdge>(*it)){
				numOfProcessedCopy++;
                                dst = edge->getDstID();
				it++;
				const PAGNode* pagNodeDst = pag->getPAGNode(dst);
                                /*if (isa<ObjPN>(pagNodeDst) ){
                                        continue;
                                }*/
				if (mergeNode1 == 0){
					mergeNode1 = dst;
				}
				else
					mergeNode2 = dst;
				if ((mergeNode1 != 0) && (mergeNode2 != 0) && (mergeNode1 != mergeNode2)){
					//cout << " Merging "<<mergeNode2<< " and "<< mergeNode1<<" ";
					steensgardMerge(mergeNode2, mergeNode1);
					count++;
					merged = true;
				}
                        }
			else it++;
                }
		// union points of dst with address node and push merged dest in worklist
		if (mergeNode1 != 0){ 
			bool changed = unionPts(mergeNode1, nodeId);
			if (changed || merged){
				pushIntoWorklist(mergeNode1);
			}
		}
		//cout << " Merge Count: "<<count; 
	}
	else{  
		int st = 0;
		steensgardProcessNode(nodeId);
		
		for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(), eit =
        		node->directOutEdgeEnd(); ; ) {
			
			if (it == eit) break;
       			if(CopyCGEdge* edge = llvm::dyn_cast<CopyCGEdge>(*it)){
				numOfProcessedCopy++;
                		dst = edge->getDstID();
				it++;
				if (dst == nodeId) continue;
                		const PAGNode* pagNodeDst = pag->getPAGNode(dst);
                		if (isa<ValPN>(pagNodeDst) || isa<RetPN>(pagNodeDst) || isa<VarArgPN>(pagNodeDst)){
                                	//cout << " Merging "<< dst<<" and "<<nodeId<< " \n";
                                	steensgardMerge(dst, nodeId);
					st = 1;
                		}

           		}
			else it++;
        	}
		if (st == 1) {
			pushIntoWorklist(nodeId);
		}
	}
}

void Steensgard::steensgardMerge(NodeID nodeId,NodeID newRepId) { 
	if(nodeId==newRepId)
		return;
	unionPts(newRepId,nodeId);
	//merging nodes and update edges
	ConstraintNode* node = consCG->getConstraintNode(nodeId);

        /*if (Profile) {
         int numInEdges = node->getInEdges().size();
         int numOutEdges = node->getOutEdges().size();

         if (numInEdges > maxNumIncomingEdges) {
            maxNumIncomingEdges = numInEdges;
            maxOutgoingEdgesNodeID = node->getId();
         }

         if (numOutEdges > maxNumOutgoingEdges) {
            maxNumOutgoingEdges = numOutEdges;
            maxIncomingEdgesNodeID = node->getId();
         }
       }*/
	//bool gepInsideScc = consCG->moveEdgesToRepNode(node, consCG->getConstraintNode(newRepId));
	bool gepInsideScc = consCG->steensgardMoveEdgesToRepNode(node, consCG->getConstraintNode(newRepId));

	consCG->removeConstraintNode(node);

	
	//fetching nodes for whom removed node is rep node,updating those nodes rep node to current rep node,
	// add those nodes to the current rep node's list. 
	/*std::vector<NodeID> temp = consCG->getNode(node->getId());
	//cout << " NodeOfRep is "<<node->getId()<<" :";
	for (std::vector<NodeID>::iterator it = temp.begin() ; it != temp.end(); ++it){
		//cout << *it<< " ";
		consCG->setRep(*it,newRepId);
		consCG->setNodeToRep(*it,newRepId); 
	}*/
	for (std::vector<NodeID>::iterator it = repToNodeMap[nodeId].begin() ; it != repToNodeMap[nodeId].end(); ++it){
                //cout << *it<< " ";
                consCG->setRep(*it,newRepId);
		repToNodeMap[newRepId].push_back(*it);
        }

	// set current rep node to removed node as rep node; add removed node to current rep node's list
    consCG->setRep(node->getId(),newRepId);
    //consCG->setNodeToRep(node->getId(),newRepId);
    repToNodeMap[newRepId].push_back(node->getId());
    if (Profile) {
        mergeCount++;
        if (mergeCount % ProfileInterval == 0){
            /*outs() << "Maximum number of incoming edges in this iteration is: " << maxNumIncomingEdges << " for NodeID: " << maxOutgoingEdgesNodeID << "\n";
            outs() << "Maximum number of outgoing edges in this iteration is: " << maxNumOutgoingEdges << " for NodeID: " << maxIncomingEdgesNodeID << "\n";
            PAGNode* nodeOut = pag->getPAGNode(maxOutgoingEdgesNodeID);
            PAGNode* nodeIn = pag->getPAGNode(maxIncomingEdgesNodeID);
            outs() << "Out node name: " << nodeOut->getValueName() << "\n";
            outs() << "In node name: " << nodeIn->getValueName() << "\n";*/
            auto end = std::chrono::system_clock::now();
            std::chrono::duration<double> elapsed_seconds = end-start;
            outs() << " elapsed time: " << elapsed_seconds.count() << "s and total merge: "<<mergeCount<<"\n";
            start = std::chrono::system_clock::now();
            //maxNumIncomingEdges = 0;
            //maxNumOutgoingEdges = 0;
        }
    }
}


/*!
 * Process address edges
 */
void Steensgard::steensgardProcessAllAddr()
{
    for (ConstraintGraph::const_iterator nodeIt = consCG->begin(), nodeEit = consCG->end(); nodeIt != nodeEit; nodeIt++) {
        ConstraintNode * cgNode = nodeIt->second;
        for (ConstraintNode::const_iterator it = cgNode->incomingAddrsBegin(), eit = cgNode->incomingAddrsEnd();
                it != eit; ++it)
            steensgardProcessAddr(cast<AddrCGEdge>(*it));
	 
    }
}

/*!
 * Process address edges
 */
				
void Steensgard::steensgardProcessAddr(const AddrCGEdge* addr) {
    numOfProcessedAddr++;
    NodeID dst = addr->getDstID();
    NodeID src = addr->getSrcID();
    //cout <<" Dst : "<<dst<< " and Src: "<<src<<"\n";
    addPts(dst,src);
}


/*!
 * Start constraint solving for Andersen
 */
void Andersen::processNode(NodeID nodeId) {

    numOfIteration++;
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
            if (processLoad(ptd, *it)){
                pushIntoWorklist(ptd);
                }
        }

        // handle store
        for (ConstraintNode::const_iterator it = node->incomingStoresBegin(),
                eit = node->incomingStoresEnd(); it != eit; ++it) {
            if (processStore(ptd, *it)){
                pushIntoWorklist((*it)->getSrcID());
                }
        }
    }
    // handle copy, call, return, gep
    for (ConstraintNode::const_iterator it = node->directOutEdgeBegin(), eit =
                node->directOutEdgeEnd(); it != eit; ++it) {
        if (GepCGEdge* gepEdge = llvm::dyn_cast<GepCGEdge>(*it)){
            processGep(nodeId, gepEdge);
        }
        else{
            processCopy(nodeId, *it);
        }
    }
}

/*!
 * Process address edges
 */
void Andersen::processAllAddr()
{
    for (ConstraintGraph::const_iterator nodeIt = consCG->begin(), nodeEit = consCG->end(); nodeIt != nodeEit; nodeIt++) {
        ConstraintNode * cgNode = nodeIt->second;
        for (ConstraintNode::const_iterator it = cgNode->incomingAddrsBegin(), eit = cgNode->incomingAddrsEnd();
                it != eit; ++it)
            processAddr(cast<AddrCGEdge>(*it));
    }
}

/*!
 * Process address edges
 */
void Andersen::processAddr(const AddrCGEdge* addr) {
    numOfProcessedAddr++;

    NodeID dst = addr->getDstID();
    NodeID src = addr->getSrcID();
    if(addPts(dst,src)) {
	//cout <<" Address_addworklist:"<<dst<<" ";
        pushIntoWorklist(dst);
	}
}

/*!
 * Process load edges
 *	src --load--> dst,
 *	node \in pts(src) ==>  node--copy-->dst
 */
bool Andersen::processLoad(NodeID node, const ConstraintEdge* load) {
    /// TODO: New copy edges are also added for black hole obj node to
    ///       make gcc in spec 2000 pass the flow-sensitive analysis.
    ///       Try to handle black hole obj in an appropiate way.
//	if (pag->isBlkObjOrConstantObj(node) || isNonPointerObj(node))
    if (pag->isConstantObj(node) || isNonPointerObj(node))
        return false;

    numOfProcessedLoad++;
    bool l = false;
    NodeID dst = load->getDstID();
    //cout <<" Dst "<<dst<< " ";
    l = addCopyEdge(node, dst);
    return l;
}

/*!
 * Process store edges
 *	src --store--> dst,
 *	node \in pts(dst) ==>  src--copy-->node
 */
bool Andersen::processStore(NodeID node, const ConstraintEdge* store) {
    /// TODO: New copy edges are also added for black hole obj node to
    ///       make gcc in spec 2000 pass the flow-sensitive analysis.
    ///       Try to handle black hole obj in an appropiate way
//	if (pag->isBlkObjOrConstantObj(node) || isNonPointerObj(node))
    if (pag->isConstantObj(node) || isNonPointerObj(node))
        return false;

    numOfProcessedStore++;
    bool s = false;
    NodeID src = store->getSrcID();
    //cout << " Src "<<src<< " ";
    s =  addCopyEdge(src, node);
    return s;
}

/*!
 * Process copy edges
 *	src --copy--> dst,
 *	union pts(dst) with pts(src)
 */
bool Andersen::processCopy(NodeID node, const ConstraintEdge* edge) {
    numOfProcessedCopy++;

    assert((isa<CopyCGEdge>(edge)) && "not copy/call/ret ??");
    NodeID dst = edge->getDstID();
    PointsTo& srcPts = getPts(node);
    bool changed = unionPts(dst,srcPts);
    if (changed){
        pushIntoWorklist(dst);
	}

    return changed;
}

/*!
 * Process gep edges
 *	src --gep--> dst,
 *	for each srcPtdNode \in pts(src) ==> add fieldSrcPtdNode into tmpDstPts
 *		union pts(dst) with tmpDstPts
 */
void Andersen::processGep(NodeID node, const GepCGEdge* edge) {

    PointsTo& srcPts = getPts(edge->getSrcID());
    processGepPts(srcPts, edge);
}

/*!
 * Compute points-to for gep edges
 */
void Andersen::processGepPts(PointsTo& pts, const GepCGEdge* edge)
{
    numOfProcessedGep++;

    PointsTo tmpDstPts;
    for (PointsTo::iterator piter = pts.begin(), epiter = pts.end(); piter != epiter; ++piter) {
        /// get the object
        NodeID ptd = *piter;
        /// handle blackhole and constant
        if (consCG->isBlkObjOrConstantObj(ptd)) {
            tmpDstPts.set(*piter);
        } else {
            /// handle variant gep edge
            /// If a pointer connected by a variant gep edge,
            /// then set this memory object to be field insensitive
            if (isa<VariantGepCGEdge>(edge)) {
                if (consCG->isFieldInsensitiveObj(ptd) == false) {
                    consCG->setObjFieldInsensitive(ptd);
                    consCG->addNodeToBeCollapsed(consCG->getBaseObjNode(ptd));
                }
                // add the field-insensitive node into pts.
                NodeID baseId = consCG->getFIObjNode(ptd);
                tmpDstPts.set(baseId);
            }
            /// Otherwise process invariant (normal) gep
            // TODO: after the node is set to field insensitive, handling invaraint gep edge may lose precision
            // because offset here are ignored, and it always return the base obj
            else if (const NormalGepCGEdge* normalGepEdge = dyn_cast<NormalGepCGEdge>(edge)) {
                if (!matchType(edge->getSrcID(), ptd, normalGepEdge))
                    continue;
                NodeID fieldSrcPtdNode = consCG->getGepObjNode(ptd,	normalGepEdge->getLocationSet());
                tmpDstPts.set(fieldSrcPtdNode);
                addTypeForGepObjNode(fieldSrcPtdNode, normalGepEdge);
                // Any points-to passed to an FIObj also pass to its first field
                if (normalGepEdge->getLocationSet().getOffset() == 0)
                    addCopyEdge(getBaseObjNode(fieldSrcPtdNode), fieldSrcPtdNode);
            }
            else {
                assert(false && "new gep edge?");
            }
        }
    }

    NodeID dstId = edge->getDstID();
    if (unionPts(dstId, tmpDstPts))
        pushIntoWorklist(dstId);
}

/*
 * Merge constraint graph nodes based on SCC cycle detected.
 */
void Andersen::mergeSccCycle()
{
    NodeBS changedRepNodes;

    NodeStack revTopoOrder;
    NodeStack & topoOrder = getSCCDetector()->topoNodeStack();
    while (!topoOrder.empty()) {
        NodeID repNodeId = topoOrder.top();
	//repNodeId = consCG->getRep(repNodeId);
        topoOrder.pop();
        revTopoOrder.push(repNodeId);
        // merge sub nodes to rep node
	//Next line commented out for steensgard
        mergeSccNodes(repNodeId, changedRepNodes);
    }

    // update rep/sub relation in the constraint graph.
    // each node will have a rep node
    for(NodeBS::iterator it = changedRepNodes.begin(), eit = changedRepNodes.end(); it!=eit; ++it) {
        updateNodeRepAndSubs(*it);
    }

    // restore the topological order for later solving.
    while (!revTopoOrder.empty()) {
        NodeID nodeId = revTopoOrder.top();
	//nodeId = consCG->getRep(nodeId);
        revTopoOrder.pop();
        topoOrder.push(nodeId);
    }
}


/**
 * Union points-to of subscc nodes into its rep nodes
 * Move incoming/outgoing direct edges of sub node to rep node
 */
void Andersen::mergeSccNodes(NodeID repNodeId, NodeBS & chanegdRepNodes)
{
    const NodeBS& subNodes = getSCCDetector()->subNodes(repNodeId);
    for (NodeBS::iterator nodeIt = subNodes.begin(); nodeIt != subNodes.end(); nodeIt++) {
        NodeID subNodeId = *nodeIt;
	//subNodeId = consCG->getRep(subNodeId);
        if (subNodeId != repNodeId) {
	     // Commented out next two lines for steensgard as SCC will be detected due to merging
            mergeNodeToRep(subNodeId, repNodeId);
            chanegdRepNodes.set(subNodeId);
	    //cout << "hi ";
        }
    }
}

/**
 * Collapse node's points-to set. Change all points-to elements into field-insensitive.
 */
bool Andersen::collapseNodePts(NodeID nodeId)
{
    bool changed = false;
    PointsTo& nodePts = getPts(nodeId);
    /// Points to set may be changed during collapse, so use a clone instead.
    PointsTo ptsClone = nodePts;
    for (PointsTo::iterator ptsIt = ptsClone.begin(), ptsEit = ptsClone.end(); ptsIt != ptsEit; ptsIt++) {
        if (consCG->isFieldInsensitiveObj(*ptsIt))
            continue;

        if (collapseField(*ptsIt))
            changed = true;
    }
    return changed;
}

/**
 * Collapse field. make struct with the same base as nodeId become field-insensitive.
 */
bool Andersen::collapseField(NodeID nodeId)
{
    /// Black hole doesn't have structures, no collapse is needed.
    /// In later versions, instead of using base node to represent the struct,
    /// we'll create new field-insensitive node. To avoid creating a new "black hole"
    /// node, do not collapse field for black hole node.
    if (consCG->isBlkObjOrConstantObj(nodeId) || consCG->isSingleFieldObj(nodeId))
        return false;

    bool changed = false;

    double start = stat->getClk();

    // set base node field-insensitive.
    consCG->setObjFieldInsensitive(nodeId);

    // replace all occurrences of each field with the field-insensitive node
    NodeID baseId = consCG->getFIObjNode(nodeId);
    NodeID baseRepNodeId = consCG->sccRepNode(baseId);
    NodeBS & allFields = consCG->getAllFieldsObjNode(baseId);
    for (NodeBS::iterator fieldIt = allFields.begin(), fieldEit = allFields.end(); fieldIt != fieldEit; fieldIt++) {
        NodeID fieldId = *fieldIt;
        if (fieldId != baseId) {
            // use the reverse pts of this field node to find all pointers point to it
            PointsTo & revPts = getRevPts(fieldId);
            for (PointsTo::iterator ptdIt = revPts.begin(), ptdEit = revPts.end();
                    ptdIt != ptdEit; ptdIt++) {
                // change the points-to target from field to base node
                PointsTo & pts = getPts(*ptdIt);
                pts.reset(fieldId);
                pts.set(baseId);

                changed = true;
            }
            // merge field node into base node, including edges and pts.
            NodeID fieldRepNodeId = consCG->sccRepNode(fieldId);
            if (fieldRepNodeId != baseRepNodeId)
                mergeNodeToRep(fieldRepNodeId, baseRepNodeId);

            // field's rep node FR has got new rep node BR during mergeNodeToRep(),
            // update all FR's sub nodes' rep node to BR.
            updateNodeRepAndSubs(fieldRepNodeId);
        }
    }

    if (consCG->isPWCNode(baseRepNodeId))
        if (collapseNodePts(baseRepNodeId))
            changed = true;

    double end = stat->getClk();
    timeOfCollapse += (end - start) / TIMEINTERVAL;

    return changed;
}

/*!
 * SCC detection on constraint graph
 */
NodeStack& Andersen::SCCDetect() {
    numOfSCCDetection++;
    double sccStart = stat->getClk();
    WPAConstraintSolver::SCCDetect();
    double sccEnd = stat->getClk();

    timeOfSCCDetection +=  (sccEnd - sccStart)/TIMEINTERVAL;

    double mergeStart = stat->getClk();

    mergeSccCycle();

    double mergeEnd = stat->getClk();

    timeOfSCCMerges +=  (mergeEnd - mergeStart)/TIMEINTERVAL;

    return getSCCDetector()->topoNodeStack();
}

/// Update call graph for the input indirect callsites
bool Andersen::updateCallGraph(const CallSiteToFunPtrMap& callsites) {
    CallEdgeMap newEdges;
    onTheFlyCallGraphSolve(callsites,newEdges);
    NodePairSet cpySrcNodes;	/// nodes as a src of a generated new copy edge
    for(CallEdgeMap::iterator it = newEdges.begin(), eit = newEdges.end(); it!=eit; ++it ) {
        llvm::CallSite cs = it->first;
        for(FunctionSet::iterator cit = it->second.begin(), ecit = it->second.end(); cit!=ecit; ++cit) {
            consCG->connectCaller2CalleeParams(cs,*cit,cpySrcNodes);
        }
    }
    //cout << "callGraph worklist: ";
    for(NodePairSet::iterator it = cpySrcNodes.begin(), eit = cpySrcNodes.end(); it!=eit; ++it) {
      //  cout << it->first<< " ";
        pushIntoWorklist(it->first);
    }

    if(!newEdges.empty())
        return true;
    return false;
}


/*
 * Merge a node to its rep node
 */
void Andersen::mergeNodeToRep(NodeID nodeId,NodeID newRepId) {
    if(nodeId==newRepId)
        return;

    /// union pts of node to rep
    unionPts(newRepId,nodeId);
    /// move the edges from node to rep, and remove the node
    ConstraintNode* node = consCG->getConstraintNode(nodeId);
    bool gepInsideScc = consCG->moveEdgesToRepNode(node, consCG->getConstraintNode(newRepId));
    /// 1. if find gep edges inside SCC cycle, the rep node will become a PWC node and
    /// its pts should be collapsed later.
    /// 2. if the node to be merged is already a PWC node, the rep node will also become
    /// a PWC node as it will have a self-cycle gep edge.

    if (gepInsideScc || node->isPWCNode())
        consCG->setPWCNode(newRepId);

    consCG->removeConstraintNode(node);

    /// set rep and sub relations

    consCG->setRep(node->getId(),newRepId);
    NodeBS& newSubs = consCG->sccSubNodes(newRepId);
    newSubs.set(node->getId());

}

/*
 * Updates subnodes of its rep, and rep node of its subs
 */
void Andersen::updateNodeRepAndSubs(NodeID nodeId) {
    NodeID repId = consCG->sccRepNode(nodeId);
    NodeBS repSubs;
    /// update nodeToRepMap, for each subs of current node updates its rep to newRepId
    //  update nodeToSubsMap, union its subs with its rep Subs
    NodeBS& nodeSubs = consCG->sccSubNodes(nodeId);
    for(NodeBS::iterator sit = nodeSubs.begin(), esit = nodeSubs.end(); sit!=esit; ++sit) {
        NodeID subId = *sit;
        consCG->setRep(subId,repId);
    }
    repSubs |= nodeSubs;
    consCG->setSubs(repId,repSubs);
}
