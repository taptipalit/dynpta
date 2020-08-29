#include <stdio.h>

long long B1 = 20L*1000L*1000L;
long long B64 = 64L*20L*1000L*1000L;

#define ITER 50

//char buffer[B64];

void encrypt_memory(void*);

int main(int argc, char* argv[]) {
	int doAES = 0;
	printf("%d\n", sizeof(long long int));
	if (argc > 1) {
		char* opt = argv[1];
		if (strcmp(opt, "e") == 0) {
			doAES = 1;
		} else if (strcmp(opt, "m") == 0) {
			doAES = 0;
		} else {
			printf("Usage:\n./aes e (to test encryptions)\n./aes m (to test memory ops)\n");
			exit(-1);
		}
	} else {
		printf("Usage:\n./aes e (to test encryptions)\n./aes m (to test memory ops)\n");
		exit(-1);
		
	}

	volatile char* buffer = malloc(B64);
	volatile char* buffer2 = malloc(B64);
	if (doAES) {
		long long ind = 0;
		for (int i = 0; i < ITER; i++) {
			for (int j = 0; j < B1; j++) {
				ind = j*64;
				encrypt_memory(&buffer[ind]);

			}
		}
	} else {
		long long ind = 0;
		int k = 100;
		for (int i = 0; i < ITER; i++) {
			for (int j = 0; j < B1; j++) {
				ind = j*64;
				k += buffer[ind];
				k += buffer2[ind];
			}
		}
	}
	return 0;
}
