#include "EncryptionInternal.h"
#include "ExtLibraryHandler.h"

using namespace llvm;
namespace external {
	void ExtLibraryHandler::addAESCacheExtFuncHandler(Module& M) {
		std::string FunctionName1 = "decryptStringBeforeLibCall";
		std::string FunctionName2 = "instrumentArrayForLibCall";

		PointerType* intPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
		IntegerType* intType = IntegerType::get(M.getContext(), 64);

		std::vector<Type*> typeVec1;
		typeVec1.push_back(intPtrType);
		ArrayRef<Type*> paramArgArray1(typeVec1);

		FunctionType* FType1 = FunctionType::get(Type::getVoidTy(M.getContext()), paramArgArray1, false);
		Function* instrumentStringFunction = Function::Create(FType1, Function::ExternalLinkage, FunctionName1, &M);

		std::vector<Type*> typeVec2;
		typeVec2.push_back(intPtrType);
		typeVec2.push_back(intType);
		ArrayRef<Type*> paramArgArray2(typeVec2);

		FunctionType* FType2 = FunctionType::get(Type::getVoidTy(M.getContext()), paramArgArray2, false);
		Function* instrumentFwriteCallFunction = Function::Create(FType2, Function::ExternalLinkage, FunctionName2, &M);

        // For pointer to string versions (for asprintf and friends)
		std::string decryptFunctionName = "decryptStringPtrBeforeLibCall";
		std::string encryptFunctionName = "encryptStringPtrAfterLibCall";
		// Build the signature of the function
        PointerType* strPtrType = PointerType::get(intPtrType,0);

		std::vector<Type*> typeVec;
		typeVec.push_back(strPtrType);
		ArrayRef<Type*> paramArgArray(typeVec);

		FunctionType* FType = FunctionType::get(Type::getVoidTy(M.getContext()), paramArgArray, false);
		Function* decryptStringPointerFunction = Function::Create(FType, Function::ExternalLinkage, decryptFunctionName, &M);
		Function* encryptStringPointerFunction = Function::Create(FType, Function::ExternalLinkage, encryptFunctionName, &M);

        // For pointer to array versions (posix_memalign)
        std::vector<Type*> tv2;
        tv2.push_back(strPtrType);
        tv2.push_back(intType);
        ArrayRef<Type*> tvArray(tv2);
        FunctionType* FType3 = FunctionType::get(Type::getVoidTy(M.getContext()), tvArray, false);
        Function::Create(FType3, Function::ExternalLinkage, "encryptArrayPtrAfterLibCall", &M);

        // For va_list types
        StructType* vaListTagType = M.getTypeByName("struct.__va_list_tag");
        if (vaListTagType) {
            std::string decryptVaListName = "decryptVaArgListBeforeLibCall";
            std::string encryptVaListName = "encryptVaArgListAfterLibCall";

            PointerType* vaListTagPtrType = PointerType::get(vaListTagType, 0);

            std::vector<Type*> vaListTypeVec;
            vaListTypeVec.push_back(intPtrType);
            vaListTypeVec.push_back(vaListTagPtrType);
            ArrayRef<Type*> vaListParamArgArray(vaListTypeVec);

            FunctionType* vaListFType = FunctionType::get(Type::getVoidTy(M.getContext()), vaListParamArgArray, false);
            Function::Create(vaListFType, Function::ExternalLinkage, decryptVaListName, &M);
            Function::Create(vaListFType, Function::ExternalLinkage, encryptVaListName, &M);
        }
	}

	void ExtLibraryHandler::addNullExtFuncHandler(Module& M) {
		addNullArrayHandler(M);
		addNullStringHandler(M);
	}

	void ExtLibraryHandler::addNullStringHandler(Module& M) {
		std::string decryptFunctionName = "decryptStringBeforeLibCall";
		std::string encryptFunctionName = "encryptStringAfterLibCall";
		// Build the signature of the function
		PointerType* intPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);

		std::vector<Type*> typeVec;
		typeVec.push_back(intPtrType);
		ArrayRef<Type*> paramArgArray(typeVec);

		FunctionType* FType = FunctionType::get(Type::getVoidTy(M.getContext()), paramArgArray, false);
		Function* decryptStringFunction = Function::Create(FType, Function::ExternalLinkage, decryptFunctionName, &M);
		Function* encryptStringFunction = Function::Create(FType, Function::ExternalLinkage, encryptFunctionName, &M);
	}

	void ExtLibraryHandler::addNullArrayHandler(Module& M) {
		std::string decryptFunctionName = "decryptArrayForLibCall";
        std::string encryptFunctionName = "encryptArrayForLibCall";
	
		// Build the signature of the function
		PointerType* intPtrType = PointerType::get(IntegerType::get(M.getContext(), 8), 0);
		IntegerType* intType = IntegerType::get(M.getContext(), 64);

		std::vector<Type*> typeVec;
		typeVec.push_back(intPtrType);
		typeVec.push_back(intType);
		ArrayRef<Type*> paramArgArray(typeVec);

		FunctionType* FType = FunctionType::get(Type::getVoidTy(M.getContext()), paramArgArray, false);
		Function* decryptFunction = Function::Create(FType, Function::ExternalLinkage, decryptFunctionName, &M);
        Function* encryptFunction = Function::Create(FType, Function::ExternalLinkage, encryptFunctionName, &M);
	}

}
