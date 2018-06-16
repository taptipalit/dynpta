add_llvm_library(LLVMFunctionPointerAnalysis
    FunctionPointerAnalysis.cpp
	ADDITIONAL_HEADER_DIRS
	${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms
    DEPENDS
    intrinsics_gen
	)
