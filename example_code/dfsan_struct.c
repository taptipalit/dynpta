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
	return 0;
}	
