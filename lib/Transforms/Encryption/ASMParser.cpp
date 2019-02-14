#include "ASMParser.h"

using namespace llvm;

namespace external {



	void ASMParser::findInstructionOpcodeStr(StringRef& instruction, StringRef** opcodeStrPtr) {
		// split on space
		SmallVector<StringRef, 10> tokens;
		StringRef sep(" ");
		instruction.split(tokens, sep);
		*opcodeStrPtr = new StringRef(tokens[0].str());
	}

	int ASMParser::findNumBytesAccessed(InlineAsm* asmBlock, Value* argVal, int argIndex) {
		StringRef movq("movq");
		StringRef movdqu("movdqu");
		StringRef movdqa("movdqa");
		std::vector<Offset> offsetList;
		std::string positionalName;

		parseAsmBlock(asmBlock);
		findPositionalName(asmBlock, argIndex, &positionalName);
		StringRef posNameWithBracket("("+positionalName);
		StringRef spaceStrRef(" ");

		int index1 = -1;
		int index2 = -1;
		int npos = -1;

		bool addressTaken = false;
		for (StringRef asmInstruction: asmInstructions) {
			uint64_t byteOffset = 0;
			if (asmInstruction.find(posNameWithBracket) != StringRef::npos) {
				addressTaken = true;
				// Find the index of the positional name. = index1
				index1 = asmInstruction.find(posNameWithBracket);
				// Find the index of the previous space, from index1. = index2
				index2 = asmInstruction.find_last_of(spaceStrRef, index1);
				// Find the substring from index2, index1
				npos = index1 - index2;
				StringRef byteOffsetStrRef = asmInstruction.substr(index2, npos).trim();
				errs() << "byte offset = " << byteOffsetStrRef << "\n";
				StringRef* opcodeStrPtr = nullptr;
				findInstructionOpcodeStr(asmInstruction, &opcodeStrPtr);
				int insDataWidth = 0;
				if (opcodeStrPtr->equals_lower(movq)) {
					insDataWidth = 8;
				} else if (opcodeStrPtr->equals_lower(movdqu) || opcodeStrPtr->equals_lower(movdqa)) {
					insDataWidth = 16;
				} else {
					assert(false);
				}
				// Convert it to integer
				if (byteOffsetStrRef.empty()) {
					Offset offset(0, insDataWidth);
					offsetList.push_back(offset);
				} else {
					APInt Result;
					byteOffsetStrRef.getAsInteger(10, Result);
					Offset offset(Result.getLimitedValue(), insDataWidth);
					offsetList.push_back(offset);
				}
			}
		}

		if (addressTaken) {
			Offset* maxOffsetPtr = nullptr;
			for (Offset off: offsetList) {
				if (maxOffsetPtr != nullptr) {
					if (off.offset > maxOffsetPtr->offset) {
						maxOffsetPtr = &off;
					}
				} else {
					maxOffsetPtr = &off;
				}
			}
			assert(maxOffsetPtr != nullptr);
			return (maxOffsetPtr->offset + maxOffsetPtr->insDataWidth);
		} else {
			errs() << "Address not taken .. ";
			argVal->dump();
			return -1;
		}
	}

	void ASMParser::parseAsmBlock(InlineAsm* asmBlock) {
		StringRef asmStringRef(asmBlock->getAsmString());
		StringRef separator = "\n\t";
		asmStringRef.split(asmInstructions, separator);
		for (StringRef asmInstruction: asmInstructions) {
			asmInstruction.trim();
		}
	}

	void ASMParser::findPositionalName(InlineAsm* asmBlock, int argIndex, std::string* positionalName) {
		InlineAsm::ConstraintInfoVector constraintVec = asmBlock->ParseConstraints();
		int numOutputs = 0;
		for (auto constraint: constraintVec) {
			if (constraint.Type == InlineAsm::isOutput ) {
				numOutputs++;
			}
		}
		int asmArgIndex = numOutputs + argIndex - 1;
		std::string asmArgIndexStr = std::to_string(asmArgIndex);
		*positionalName = "$" + asmArgIndexStr;
	}

}
