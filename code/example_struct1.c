#include<stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

struct Mystruct {
	int a;
	int b;
};

int main () {
 
	struct Mystruct s;
	s.a = 10;
	s.b = 20;
	SENSITIVE struct Mystruct* ptr;
	ptr = &s;
	ptr = malloc(sizeof(struct Mystruct));
	ptr->a = 30;
	ptr->b = 40;
	struct Mystruct* ptr1;
	ptr1 = &s;
	ptr1 = malloc(sizeof(struct Mystruct));
	ptr1->a = 50;
	ptr1->b = 60;
	//ptr1 = &s;
	printf("Value is %d, %d, %d, %d, %d, %d\n",s.a,s.b,ptr->a,ptr->b,ptr1->a, ptr1->b);
	return 0;
}	
