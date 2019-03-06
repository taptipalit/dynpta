//===-- Encryption.h - Encryption Transformations -----------------------*- C++ -*-===//
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

#ifndef LLVM_TRANSFORMS_ENCRYPTION_H
#define LLVM_TRANSFORMS_ENCRYPTION_H

#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/SVF/MemoryModel/PAGEdge.h"
#include <functional>

namespace llvm {
	class ModulePass;

	ModulePass * createEncryptionPass();	
}	// End llvm namespace

#endif
