//===- Try.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Try World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

#define DEBUG_TYPE "try"

STATISTIC(TryCounter, "Counts number of functions greeted");

namespace {
  // Try - The first implementation, without getAnalysisUsage.
  struct Try : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    Try() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
      ++TryCounter;
      errs() << "Try: ";
      errs().write_escaped(F.getName()) << '\n';
      return false;
    }
  };
}

char Try::ID = 0;
static RegisterPass<Try> X("try", "Try World Pass");

namespace {
  // Try2 - The second implementation with getAnalysisUsage implemented.
  struct Try2 : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    Try2() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
      ++TryCounter;
      errs() << "Try: ";
      errs().write_escaped(F.getName()) << '\n';
      return false;
    }

    // We don't modify the program, so we preserve all analyses.
    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.setPreservesAll();
    }
  };
}

char Try2::ID = 0;
static RegisterPass<Try2>
Y("try2", "Try World Pass (with getAnalysisUsage implemented)");
