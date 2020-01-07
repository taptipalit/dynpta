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
	struct Mystruct* ptr;
	ptr = &s;
	ptr = malloc(sizeof(struct Mystruct));
	ptr->a = 30;
	ptr->b = 40;
	printf("Value is %d, %d, %d, %d\n",s.a,s.b,ptr->a,ptr->b);
	return 0;
}	
