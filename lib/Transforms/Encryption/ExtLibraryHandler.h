#ifndef EXTERNAL_LIBRARY_HANDLER_H
#define EXTERNAL_LIBRARY_HANDLER_H

namespace external{

	class ExtLibraryHandler {
		private:
			void addNullArrayHandler(llvm::Module&);
			void addNullStringHandler(llvm::Module&);

		public:
			void addNullExtFuncHandler(llvm::Module&);
			void addAESCacheExtFuncHandler(llvm::Module&);
	};
}


#endif
