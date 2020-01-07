#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))
int val (){
	return 0;
	}
int main(void) {
	SENSITIVE int a;
	if (val() == 0) {
		a = 10;
	}
	else a = 5;
	printf (" Value id %d\n",a);
	return 0;
}	
