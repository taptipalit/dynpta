#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
	SENSITIVE int* p;
	int a; 
	p = malloc(sizeof(int));
	*p = 100;
	p = &a;
	a = 10;
	printf("Value of *p and a is %d, %d",*p,a);
    return 0;
}
