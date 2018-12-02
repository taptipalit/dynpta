/*
 * SensitiveDataHelper.h
 *
 *  Created on: Oct 11, 2018
 *      Author: Tapti Palit
 */

#ifndef SEN_DATA_HLP_H_
#define SEN_DATA_HLP_H_

#include "llvm/Analysis/SVF/Util/AnalysisUtil.h"
#include "llvm/Analysis/SVF/Util/BasicTypes.h"
#include "llvm/IR/DerivedTypes.h"
#include <iostream>
#include <map>
#include <string>

using namespace std;

/*!
 * Sensitive Data Helper
 */
class SensitiveDataHelper {

private:
    std::vector<llvm::Type*> functionPtrTypes;
    bool processSequentialTypes(llvm::SequentialType*);
    bool processStructTypes(llvm::StructType*);
    SensitiveDataHelper() {
    };


   

public:
    void collectFuncPtrTypes(llvm::Module&);
    bool isFunctionPtrType(llvm::PointerType*);
    
    static SensitiveDataHelper* helper;
    static SensitiveDataHelper* getSensitiveDataHelper() {
        if (helper == nullptr) {
            helper = new SensitiveDataHelper();
        }
        return helper;
    };
};

#endif /* SEN_DATA_HLP_H_ */
