#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
	SENSITIVE int a;
	int *p, *q, *w;
	int b,c,d;
	a = 1;
	b = 2;
	c = 3;
	d = 4;
	p = &a;
	p = &b;
	q = &b;
	q = &c;
	w = &c;
	w = &d;
	*p = 10;
	*q = *q + 1;
	*w = 100;
	

    return 0;
}
