#ifndef TCFS_ANDERSEN_AA_H
#define TCFS_ANDERSEN_AA_H

#include "Andersen.h"

#include "llvm/Pass.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"

class AndersenAAResult: public llvm::AAResultBase<AndersenAAResult>
{
private:
	friend llvm::AAResultBase<AndersenAAResult>;

	Andersen1 anders;
	llvm::AliasResult andersenAlias(const llvm::Value*, const llvm::Value*);
public:
	AndersenAAResult(llvm::Module&, llvm::TargetLibraryInfo&);

	llvm::AliasResult alias(const llvm::MemoryLocation&, const llvm::MemoryLocation&);

	bool pointsToConstantMemory(const llvm::MemoryLocation&, bool);

	std::map<llvm::Value*, std::set<llvm::Value*>>& getSanitizedPtsToGraph(void) { return anders.getSanitizedPtsToGraph(); }
	std::map<llvm::Value*, std::set<llvm::Value*>>& getSanitizedPtsFromGraph(void) { return anders.getSanitizedPtsFromGraph(); }

};

class AndersenAAWrapperPass: public llvm::ModulePass
{
private:
	std::unique_ptr<AndersenAAResult> result;
public:
	static char ID;

	AndersenAAWrapperPass();

	AndersenAAResult& getResult() { return *result; }
	const AndersenAAResult& getResult() const { return *result; }

	bool runOnModule(llvm::Module&) override;
	//bool doFinalization(llvm::Module&) override;
	void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

};
namespace llvm {
  class ModulePass;
  class Module;

  ModulePass *createAndersenAAWrapperPass();
}

#endif
