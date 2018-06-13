//===-- FunctionPointerAnalysis.h - Function Pointer Analysis Transformations -----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This header file defines prototypes for accessor functions that expose passes
// in the Scalar transformations library.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_FUNCTION_POINTER_ANALYSIS_H
#define LLVM_TRANSFORMS_FUNCTION_POINTER_ANALYSIS_H

#include "llvm/ADT/StringRef.h"
#include <functional>

namespace llvm {
	class ModulePass;

	ModulePass * createFunctionPointerAnalysisPass();	
}	// End llvm namespace

#endif
