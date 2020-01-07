#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    SENSITIVE int a;
    int *q;
int arr[1024]; 
    SENSITIVE int b;
    b = 20;
    a = 10;
    q = &a;
    q = &b;
    q = malloc(sizeof(int));
    *q = 30;
    //q = &b;

    printf("Value is %d, %d,%d\n",a,b,*q);
	for (int i = 0; i < 1024; i++) {
		arr[i] = i;
	}	
    printf("Value is %d, %d,%d\n",a,b,*q);

    

    return 0;
}
