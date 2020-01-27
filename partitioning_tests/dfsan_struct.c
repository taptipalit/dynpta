#include<stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

struct Mystruct {
	int a;
	int b;
};

int main () {
 
	SENSITIVE struct Mystruct s;
    //struct Mystruct *sp;
	s.a = 10;
	s.b = 20;
	int *p;
	int a;
	a = 20;
	p = &a;
	p = &s.b;
    //sp = &s;
    //sp->a = 15;
	//p = &a;
	printf("Value of s.a and *p is %d, %d",s.b,*p);	
	return 0;
}	
