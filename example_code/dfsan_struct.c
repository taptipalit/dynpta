#include<stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

struct Mystruct {
	int a;
	int b;
};

int main () {
 
	SENSITIVE struct Mystruct s;
	s.a = 10;
	s.b = 20;
	int *p;
	int a;
	a = 20;
	p = &a;
	p = &s.a;
	//p = &a;
	printf("Value of s.a and *p is %d, %d",s.a,*p);	
	return 0;
}	
