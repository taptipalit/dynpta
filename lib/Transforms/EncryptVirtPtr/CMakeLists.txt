add_llvm_loadable_module(LLVMEncryptVirtPtr
    EncryptVirtPtr.cpp
	ADDITIONAL_HEADER_DIRS
	${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms
	)

add_dependencies(LLVMEncryptVirtPtr intrinsics_gen)

