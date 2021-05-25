#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
	SENSITIVE int a;
	int b;
	int *p;
	p = &b;
	p = &a;
	a = 10;//directly adds encryption
	b = 20;//no change
    	*p = 100;//add check
    	printf ("Value of a, b, *p is: %d, %d, %d", a, b, *p);
    	return 0;
}

