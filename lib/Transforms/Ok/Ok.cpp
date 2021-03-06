//===- Ok.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Ok World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

#define DEBUG_TYPE "ok"

STATISTIC(OkCounter, "Counts number of functions greeted");

namespace {
  // Ok - The first implementation, without getAnalysisUsage.
  struct Ok : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    Ok() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
      ++OkCounter;
      errs() << "Ok: ";
      errs().write_escaped(F.getName()) << '\n';
      return false;
    }
  };
}

char Ok::ID = 0;
static RegisterPass<Ok> X("ok", "Ok World Pass");

namespace {
  // Ok2 - The second implementation with getAnalysisUsage implemented.
  struct Ok2 : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    Ok2() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
      ++OkCounter;
      errs() << "Ok: ";
      errs().write_escaped(F.getName()) << '\n';
      return false;
    }

    // We don't modify the program, so we preserve all analyses.
    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.setPreservesAll();
    }
  };
}

char Ok2::ID = 0;
static RegisterPass<Ok2>
Y("ok2", "Ok World Pass (with getAnalysisUsage implemented)");
