#ifndef ASMPARSER_H
#define ASMPARSER_H

#include "EncryptionInternal.h"

using namespace llvm;


namespace external {
	class Offset {
		public:
		uint64_t offset;
		int insDataWidth; // The size of operand for this instruction

		Offset(uint64_t offset, int insDataWidth) {
			this->offset = offset;
			this->insDataWidth = insDataWidth;
		}
	};

	class ASMParser {
		public:
			int findNumBytesAccessed(InlineAsm*, Value*, int);
			
		private:
			SmallVector<StringRef, 10> asmInstructions;	

			// Parses the asm block and returns each instruction
			void parseAsmBlock(InlineAsm*);
			void findPositionalName(InlineAsm*, int, std::string*);
			void findInstructionOpcodeStr(StringRef&, StringRef**);
	};
}
#endif
