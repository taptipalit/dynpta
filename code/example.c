#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
	SENSITIVE int a;
	int b;
	int *p;
	p = &b;
	p = &a;
	a = 10;
	b = 20;
    	*p = 100;
    	printf ("Value of a, b, *p is: %d, %d, %d", a, b, *p);
    	return 0;
}

