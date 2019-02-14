#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

uint64_t lastAddr;
int dirty;
char asm_str[100];
char offset_str[2];


void encrypt_cache(void*);
void encrypt_cache(void*);

// for external interfaces
void ext_decrypt_cache_pipelined(void*);

#ifdef DEBUG
long aesenccount, aesdeccount, setenc, getdec;
#endif

void setEncryptedValueByte(void* ptr, uint8_t byte_arg) {
	uint64_t aligned_ptr = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0;
	int offset = (uint64_t)ptr % 16;
	int cacheBlock = ((uint64_t) ptr - aligned_ptr) / 16;

#ifdef DEBUG
	setenc++;
#endif
	// Align to 128 bit
	if (aligned_ptr != (uint64_t) lastAddr) {
		if (lastAddr > 0 && dirty) {
#ifdef DEBUG
			aesenccount++;
#endif
			encrypt_cache_pipelined(lastAddr);
		}
		lastAddr = aligned_ptr;
#ifdef DEBUG
		aesdeccount++;
#endif
		decrypt_cache_pipelined(aligned_ptr);
	}

	int dword_arg = byte_arg;
	dirty = 1;
	switch(cacheBlock) {
		case 0:
			switch(offset) {
				case 0:
					asm("pinsrb $0, %0, %%xmm10  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrb $1, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrb $2, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrb $3, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 4:
					asm("pinsrb $4, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 5:
					asm("pinsrb $5, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 6:
					asm("pinsrb $6, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 7:
					asm("pinsrb $7, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 8:
					asm("pinsrb $8, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 9:
					asm("pinsrb $9, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 10:
					asm("pinsrb $10, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 11:
					asm("pinsrb $11, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 12:
					asm("pinsrb $12, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 13:
					asm("pinsrb $13, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 14:
					asm("pinsrb $14, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 15:
					asm("pinsrb $15, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
		case 1:
			switch(offset) {
				case 0:
					asm("pinsrb $0, %0, %%xmm11  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrb $1, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrb $2, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrb $3, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 4:
					asm("pinsrb $4, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 5:
					asm("pinsrb $5, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 6:
					asm("pinsrb $6, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 7:
					asm("pinsrb $7, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 8:
					asm("pinsrb $8, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 9:
					asm("pinsrb $9, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 10:
					asm("pinsrb $10, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 11:
					asm("pinsrb $11, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 12:
					asm("pinsrb $12, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 13:
					asm("pinsrb $13, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 14:
					asm("pinsrb $14, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 15:
					asm("pinsrb $15, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
		case 2:
			switch(offset) {
				case 0:
					asm("pinsrb $0, %0, %%xmm12  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrb $1, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrb $2, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrb $3, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 4:
					asm("pinsrb $4, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 5:
					asm("pinsrb $5, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 6:
					asm("pinsrb $6, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 7:
					asm("pinsrb $7, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 8:
					asm("pinsrb $8, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 9:
					asm("pinsrb $9, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 10:
					asm("pinsrb $10, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 11:
					asm("pinsrb $11, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 12:
					asm("pinsrb $12, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 13:
					asm("pinsrb $13, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 14:
					asm("pinsrb $14, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 15:
					asm("pinsrb $15, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
		case 3:
			switch(offset) {
				case 0:
					asm("pinsrb $0, %0, %%xmm13  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrb $1, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrb $2, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrb $3, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 4:
					asm("pinsrb $4, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 5:
					asm("pinsrb $5, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 6:
					asm("pinsrb $6, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 7:
					asm("pinsrb $7, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 8:
					asm("pinsrb $8, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 9:
					asm("pinsrb $9, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 10:
					asm("pinsrb $10, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 11:
					asm("pinsrb $11, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 12:
					asm("pinsrb $12, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 13:
					asm("pinsrb $13, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 14:
					asm("pinsrb $14, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 15:
					asm("pinsrb $15, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
	}
}

void setEncryptedValueWord(void* ptr, uint16_t word_arg) {
	uint64_t aligned_ptr = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0;
	int offset = (uint64_t)ptr % 16;
	int cacheBlock = ((uint64_t) ptr - aligned_ptr) / 16;

#ifdef DEBUG
	setenc++;
#endif
	// Align to 128 bit
	if (aligned_ptr != (uint64_t) lastAddr) {
		if (lastAddr > 0 && dirty) {
#ifdef DEBUG
			aesenccount++;
#endif
			encrypt_cache_pipelined(lastAddr);
		}
		lastAddr = aligned_ptr;
#ifdef DEBUG
		aesdeccount++;
#endif
		decrypt_cache_pipelined(aligned_ptr);
	}

	int dword_arg = word_arg;
	dirty = 1;
	offset = offset / 2;
	switch(cacheBlock) {
		case 0:
			switch(offset) {
				case 0:
					asm("pinsrw $0, %0, %%xmm10  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrw $1, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrw $2, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrw $3, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 4:
					asm("pinsrw $4, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 5:
					asm("pinsrw $5, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 6:
					asm("pinsrw $6, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 7:
					asm("pinsrw $7, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
		case 1:
			switch(offset) {
				case 0:
					asm("pinsrw $0, %0, %%xmm11  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrw $1, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrw $2, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrw $3, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 4:
					asm("pinsrw $4, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 5:
					asm("pinsrw $5, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 6:
					asm("pinsrw $6, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 7:
					asm("pinsrw $7, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
		case 2:
			switch(offset) {
				case 0:
					asm("pinsrw $0, %0, %%xmm12  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrw $1, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrw $2, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrw $3, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 4:
					asm("pinsrw $4, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 5:
					asm("pinsrw $5, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 6:
					asm("pinsrw $6, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 7:
					asm("pinsrw $7, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
		case 3:
			switch(offset) {
				case 0:
					asm("pinsrw $0, %0, %%xmm13  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrw $1, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrw $2, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrw $3, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 4:
					asm("pinsrw $4, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 5:
					asm("pinsrw $5, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 6:
					asm("pinsrw $6, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 7:
					asm("pinsrw $7, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
	}
}

void setEncryptedValueDWord(void* ptr, uint32_t dword_arg) {
	uint64_t aligned_ptr = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0;
	int offset = (uint64_t)ptr % 16;
	int cacheBlock = ((uint64_t) ptr - aligned_ptr) / 16;

#ifdef DEBUG
	setenc++;
#endif
	// Align to 128 bit
	if (aligned_ptr != (uint64_t) lastAddr) {
		if (lastAddr > 0 && dirty) {
#ifdef DEBUG
			aesenccount++;
#endif
			encrypt_cache_pipelined(lastAddr);
		}
		lastAddr = aligned_ptr;
#ifdef DEBUG
		aesdeccount++;
#endif
		decrypt_cache_pipelined(aligned_ptr);
	}

	dirty = 1;
	offset = offset / 4;
	switch(cacheBlock) {
		case 0:
			switch(offset) {
				case 0:
					asm("pinsrd $0, %0, %%xmm10  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrd $1, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrd $2, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrd $3, %0, %%xmm10 \n\t":: "r"(dword_arg) : );
					break;
			
			}
			break;
		case 1:
			switch(offset) {
				case 0:
					asm("pinsrd $0, %0, %%xmm11  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrd $1, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrd $2, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrd $3, %0, %%xmm11 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
		case 2:
			switch(offset) {
				case 0:
					asm("pinsrd $0, %0, %%xmm12  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrd $1, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrd $2, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrd $3, %0, %%xmm12 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
		case 3:
			switch(offset) {
				case 0:
					asm("pinsrd $0, %0, %%xmm13  \n\t":: "r"(dword_arg) : );
					break;
				case 1:
					asm("pinsrd $1, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 2:
					asm("pinsrd $2, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
				case 3:
					asm("pinsrd $3, %0, %%xmm13 \n\t":: "r"(dword_arg) : );
					break;
			}
			break;
	}
}




uint8_t getDecryptedValueByte(void* ptr) {
	int offset = (uint64_t)ptr % 16;
	register uint32_t result = 0;
	uint64_t aligned_ptr = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0;
	int cacheBlock = ((uint64_t) ptr - aligned_ptr) / 16;
	// Align to 128 bit
	if (aligned_ptr != (uint64_t) lastAddr) {
		if (lastAddr > 0 && dirty) {
#ifdef DEBUG
			aesenccount++;
#endif
			encrypt_cache_pipelined(lastAddr);
			dirty = 0;
		}
		lastAddr = aligned_ptr;

#ifdef DEBUG
		aesdeccount++;
#endif
		decrypt_cache_pipelined(aligned_ptr);
	}
	switch(cacheBlock) {
		case 0:
			switch(offset) {
				case 0:
					asm("pextrb $0, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrb $1, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrb $2, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrb $3, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 4:
					asm("pextrb $4, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 5:
					asm("pextrb $5, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 6:
					asm("pextrb $6, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 7:
					asm("pextrb $7, %%xmm10, %0 \n\t": "=r"(result) : );
					break;

				case 8:
					asm("pextrb $8, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 9:
					asm("pextrb $9, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 10:
					asm("pextrb $10, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 11:
					asm("pextrb $11, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 12:
					asm("pextrb $12, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 13:
					asm("pextrb $13, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 14:
					asm("pextrb $14, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 15:
					asm("pextrb $15, %%xmm10, %0 \n\t": "=r"(result) : );
					break;

			}
			break;
		case 1:
			switch(offset) {
				case 0:
					asm("pextrb $0, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrb $1, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrb $2, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrb $3, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 4:
					asm("pextrb $4, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 5:
					asm("pextrb $5, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 6:
					asm("pextrb $6, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 7:
					asm("pextrb $7, %%xmm11, %0 \n\t": "=r"(result) : );
					break;

				case 8:
					asm("pextrb $8, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 9:
					asm("pextrb $9, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 10:
					asm("pextrb $10, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 11:
					asm("pextrb $11, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 12:
					asm("pextrb $12, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 13:
					asm("pextrb $13, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 14:
					asm("pextrb $14, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 15:
					asm("pextrb $15, %%xmm11, %0 \n\t": "=r"(result) : );
					break;

			}
			break;
		case 2:
			switch(offset) {
				case 0:
					asm("pextrb $0, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrb $1, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrb $2, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrb $3, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 4:
					asm("pextrb $4, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 5:
					asm("pextrb $5, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 6:
					asm("pextrb $6, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 7:
					asm("pextrb $7, %%xmm12, %0 \n\t": "=r"(result) : );
					break;

				case 8:
					asm("pextrb $8, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 9:
					asm("pextrb $9, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 10:
					asm("pextrb $10, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 11:
					asm("pextrb $11, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 12:
					asm("pextrb $12, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 13:
					asm("pextrb $13, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 14:
					asm("pextrb $14, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 15:
					asm("pextrb $15, %%xmm12, %0 \n\t": "=r"(result) : );
					break;

			}
			break;
		case 3:
			switch(offset) {
				case 0:
					asm("pextrb $0, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrb $1, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrb $2, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrb $3, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 4:
					asm("pextrb $4, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 5:
					asm("pextrb $5, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 6:
					asm("pextrb $6, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 7:
					asm("pextrb $7, %%xmm13, %0 \n\t": "=r"(result) : );
					break;

				case 8:
					asm("pextrb $8, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 9:
					asm("pextrb $9, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 10:
					asm("pextrb $10, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 11:
					asm("pextrb $11, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 12:
					asm("pextrb $12, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 13:
					asm("pextrb $13, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 14:
					asm("pextrb $14, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 15:
					asm("pextrb $15, %%xmm13, %0 \n\t": "=r"(result) : );
					break;

			}
			break;


	}
	return (uint8_t)result;

}

uint16_t getDecryptedValueWord(void* ptr) {
	int offset = (uint64_t)ptr % 16;
	register uint32_t result = 0;
	uint64_t aligned_ptr = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0;
	int cacheBlock = ((uint64_t) ptr - aligned_ptr) / 16;
	// Align to 128 bit
	if (aligned_ptr != (uint64_t) lastAddr) {
		if (lastAddr > 0 && dirty) {
#ifdef DEBUG
			aesenccount++;
#endif
			encrypt_cache_pipelined(lastAddr);
			dirty = 0;
		}
		lastAddr = aligned_ptr;

#ifdef DEBUG
		aesdeccount++;
#endif
		decrypt_cache_pipelined(aligned_ptr);
	}
	switch(cacheBlock) {
		case 0:
			switch(offset) {
				case 0:
					asm("pextrw $0, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrw $1, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrw $2, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrw $3, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 4:
					asm("pextrw $4, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 5:
					asm("pextrw $5, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 6:
					asm("pextrw $6, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 7:
					asm("pextrw $7, %%xmm10, %0 \n\t": "=r"(result) : );
					break;

			}
			break;
		case 1:
			switch(offset) {
				case 0:
					asm("pextrw $0, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrw $1, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrw $2, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrw $3, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 4:
					asm("pextrw $4, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 5:
					asm("pextrw $5, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 6:
					asm("pextrw $6, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 7:
					asm("pextrw $7, %%xmm11, %0 \n\t": "=r"(result) : );
					break;

			}
			break;
		case 2:
			switch(offset) {
				case 0:
					asm("pextrw $0, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrw $1, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrw $2, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrw $3, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 4:
					asm("pextrw $4, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 5:
					asm("pextrw $5, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 6:
					asm("pextrw $6, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 7:
					asm("pextrw $7, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
			}
			break;
		case 3:
			switch(offset) {
				case 0:
					asm("pextrw $0, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrw $1, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrw $2, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrw $3, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 4:
					asm("pextrw $4, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 5:
					asm("pextrw $5, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 6:
					asm("pextrw $6, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 7:
					asm("pextrw $7, %%xmm13, %0 \n\t": "=r"(result) : );
					break;

			}
			break;


	}
	return (uint16_t)result;

}

uint32_t getDecryptedValueDWord(void* ptr) {
	int offset = (uint64_t)ptr % 16;
	register uint32_t result = 0;
	uint64_t aligned_ptr = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0;
	int cacheBlock = ((uint64_t) ptr - aligned_ptr) / 16;
	// Align to 128 bit
	if (aligned_ptr != (uint64_t) lastAddr) {
		if (lastAddr > 0 && dirty) {
#ifdef DEBUG
			aesenccount++;
#endif
			encrypt_cache_pipelined(lastAddr);
			dirty = 0;
		}
		lastAddr = aligned_ptr;

#ifdef DEBUG
		aesdeccount++;
#endif
		decrypt_cache_pipelined(aligned_ptr);
	}
	offset = offset / 4;
	switch(cacheBlock) {
		case 0:
			switch(offset) {
				case 0:
					asm("pextrd $0, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrd $1, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrd $2, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrd $3, %%xmm10, %0 \n\t": "=r"(result) : );
					break;
			}
			break;
		case 1:
			switch(offset) {
				case 0:
					asm("pextrd $0, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrd $1, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrd $2, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrd $3, %%xmm11, %0 \n\t": "=r"(result) : );
					break;
			}
			break;
		case 2:
			switch(offset) {
				case 0:
					asm("pextrd $0, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrd $1, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrd $2, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrd $3, %%xmm12, %0 \n\t": "=r"(result) : );
					break;
			}
			break;
		case 3:
			switch(offset) {
				case 0:
					asm("pextrd $0, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 1:
					asm("pextrd $1, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 2:
					asm("pextrd $2, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
				case 3:
					asm("pextrd $3, %%xmm13, %0 \n\t": "=r"(result) : );
					break;
			}
			break;


	}
	return (uint32_t)result;

}

uint64_t getDecryptedValueQWord(void* ptr) {
	uint64_t aligned_ptr = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0 ;
	int offset = (uint64_t)ptr % 16;
	int cacheBlock = ((uint64_t) ptr - aligned_ptr) / 16;
	register uint64_t qword_result;

#ifdef DEBUG
	getdec++;
#endif
	// Align to 128 bit
	if (aligned_ptr != (uint64_t) lastAddr) {
		if (lastAddr > 0 && dirty) {
#ifdef DEBUG
			aesenccount++;
#endif
			encrypt_cache_pipelined(lastAddr);
			dirty = 0;
		}
		lastAddr = aligned_ptr;

#ifdef DEBUG
		aesdeccount++;
#endif
		decrypt_cache_pipelined(aligned_ptr);
	}
	offset = offset/8;

	switch(cacheBlock) {
		case 0:
			switch(offset) {
				case 0:
					asm("pextrq $0, %%xmm10, %0\n\t": "=r"(qword_result) : );
					break;
				case 1:
					asm("pextrq $1, %%xmm10, %0\n\t": "=r"(qword_result) : );
					break;
			}
			break;
		case 1:
			switch(offset) {
				case 0:
					asm("pextrq $0, %%xmm11, %0\n\t": "=r"(qword_result) : );
					break;
				case 1:
					asm("pextrq $1, %%xmm11, %0\n\t": "=r"(qword_result) : );
					break;
			}
			break;
		case 2:
			switch(offset) {
				case 0:
					asm("pextrq $0, %%xmm12, %0\n\t": "=r"(qword_result) : );
					break;
				case 1:
					asm("pextrq $1, %%xmm12, %0\n\t": "=r"(qword_result) : );
					break;
			}
			break;
		case 3:
			switch(offset) {
				case 0:
					asm("pextrq $0, %%xmm13, %0\n\t": "=r"(qword_result) : );
					break;
				case 1:
					asm("pextrq $1, %%xmm13, %0\n\t": "=r"(qword_result) : );
					break;
			}
			break;

	}
	return qword_result;
}

void setEncryptedValueQWord(void* ptr, uint64_t qword_arg) {

	// Align to 512 bits (64 bytes)
	uint64_t aligned_ptr = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0 ;
	int offset = (uint64_t)ptr % 16;
	int cacheBlock = ((uint64_t) ptr - aligned_ptr) / 16;
#ifdef DEBUG
	setenc++;
#endif

	if (aligned_ptr != (uint64_t) lastAddr) {
		if (lastAddr > 0 && dirty) {
#ifdef DEBUG
			aesenccount++;
#endif
			encrypt_cache_pipelined(lastAddr);
		}
		lastAddr = aligned_ptr;
#ifdef DEBUG
		aesdeccount++;
#endif
		decrypt_cache_pipelined(aligned_ptr);
	}

	offset = offset/8;
	dirty = 1;
	// Which block?
	switch(cacheBlock) {
		case 0:
			switch(offset) {
				case 0:
					asm("pinsrq $0, %0, %%xmm10 \n\t":: "r"(qword_arg) : );
					break;
				case 1:
					asm("pinsrq $1, %0, %%xmm10 \n\t":: "r"(qword_arg) : );
					break;
			}
			break;
		case 1:
			switch(offset) {
				case 0:
					asm("pinsrq $0, %0, %%xmm11 \n\t":: "r"(qword_arg) : );
					break;
				case 1:
					asm("pinsrq $1, %0, %%xmm11 \n\t":: "r"(qword_arg) : );
					break;
			}
			break;
		case 2:
			switch(offset) {
				case 0:
					asm("pinsrq $0, %0, %%xmm12 \n\t":: "r"(qword_arg) : );
					break;
				case 1:
					asm("pinsrq $1, %0, %%xmm12 \n\t":: "r"(qword_arg) : );
					break;
			}
			break;
		case 3:
			switch(offset) {
				case 0:
					asm("pinsrq $0, %0, %%xmm13 \n\t":: "r"(qword_arg) : );
					break;
				case 1:
					asm("pinsrq $1, %0, %%xmm13 \n\t":: "r"(qword_arg) : );
					break;
			}
			break;
	}
}

void instrumentStringForLibCall(char *ptr) {
	uint64_t aligned_ptr_int = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0;
	char *aligned_ptr = (char*) aligned_ptr_int;
	int terminate = 0;
	int i = 0;
	encrypt_cache_pipelined();
	while(1) {
		ext_decrypt_cache_pipelined(aligned_ptr);
		for (i=0; i < 48; i++) {
			terminate |= (*(aligned_ptr+i) == '\0');
		}
		if (terminate) break;
		aligned_ptr += 48;
	}
}

void instrumentArrayForLibCall(void* ptr, int numBytes) {
	uint64_t aligned_ptr_int = ((uint64_t) ptr) & 0xFFFFFFFFFFFFFFC0;
	char *aligned_ptr = (char*) aligned_ptr_int;
	encrypt_cache_pipelined();
	int i = 0;
	while ( i < numBytes) {
		ext_decrypt_cache_pipelined(ptr+i);
		i += 48;
	}
}
