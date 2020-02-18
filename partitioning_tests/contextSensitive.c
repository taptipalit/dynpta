#include<stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

void* malloc_wrap(){
    return malloc(sizeof(int));
}

int main () {
	SENSITIVE int* p;
    int* q;
    int* r;
    p = malloc_wrap();
    q = malloc_wrap();
    r = malloc_wrap();
    *p = 100;
    *q = 10;
    *r = 50;
	printf("Value of *p, *q is %d, %d, %d", *p, *q, *r);	
	return 0;
}	
