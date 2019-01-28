/*
 * Created by Tapti Palit 10/11/2018
 */

#include "llvm/Analysis/SVF/Util/SensitiveDataHelper.h"
#include <stdio.h>

using namespace std;
using namespace llvm;

SensitiveDataHelper* SensitiveDataHelper::helper = nullptr;

bool SensitiveDataHelper::isFunctionPtrType(PointerType* ptrType) {
    if (!ptrType)
        return false;
    Type* baseType = ptrType->getPointerElementType();
    while (PointerType* basePtrType = dyn_cast<PointerType>(baseType)) {
        baseType = basePtrType->getPointerElementType();
    }
    if (isa<FunctionType>(baseType)) {
        return true;
    } else if (std::find(functionPtrTypes.begin(), 
                functionPtrTypes.end(), baseType) != functionPtrTypes.end()){
        return true;
    } else {
        return false;
    }
}

bool SensitiveDataHelper::processSequentialTypes(SequentialType* seqType) {
    bool containsFptr = false;
    if (seqType->getNumElements() > 0) {
        Type* baseType = seqType->getElementType();
        if (StructType* subStType = dyn_cast<StructType>(baseType)) {
            containsFptr |= processStructTypes(subStType);
        } else if (SequentialType* subSeqType = dyn_cast<SequentialType>(baseType)) {
            containsFptr |= processSequentialTypes(subSeqType);
        } else if (PointerType* subPtrType = dyn_cast<PointerType>(baseType)){
            containsFptr |= isFunctionPtrType(subPtrType);

        }
    }
    return containsFptr;
}

bool SensitiveDataHelper::processStructTypes(StructType* stType) {
    bool containsFptr = false;
    for (int i = 0; i < stType->getNumElements(); i++) {
        if (StructType* subStType = dyn_cast<StructType>(stType->getElementType(i))) {
            containsFptr |= processStructTypes(subStType);
        } else if (SequentialType* subSeqType = dyn_cast<SequentialType>(stType->getElementType(i))) {
            containsFptr |= processSequentialTypes(subSeqType);
        } else if (PointerType* subPtrType = dyn_cast<PointerType>(stType->getElementType(i))){
            containsFptr |= isFunctionPtrType(subPtrType);
        }
    }
    return containsFptr;
}

void SensitiveDataHelper::collectFuncPtrTypes(Module& M) {
    for (StructType* stType: M.getIdentifiedStructTypes()) {
        bool isFPtrType = processStructTypes(stType);
        if (isFPtrType) {
            functionPtrTypes.push_back(stType);
        }
    }
}
