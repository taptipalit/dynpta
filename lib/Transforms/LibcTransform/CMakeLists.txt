add_llvm_library(LLVMLibcTransform
    LibcTransform.cpp
	ADDITIONAL_HEADER_DIRS
	${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms
	)

add_dependencies(LLVMLibcTransform intrinsics_gen)

