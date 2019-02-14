#ifndef ENCRYPTION_INTERNAL_H
#define ENCRYPTION_INTERNAL_H

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InlineAsm.h"

#include "llvm/Analysis/AndersenAnalysis/AndersenAA.h"
#include "llvm/Analysis/SVF/WPA/WPAPass.h"
#include "llvm/Transforms/LibcTransform.h"
#include "llvm/Transforms/Encryption.h"
#include "llvm/ADT/SmallVector.h"
#include <vector>
#include <set>
#include <algorithm>
#include <map>
#include <cstring>
#include <cmath>
#endif
