#include <stdio.h>
#include <stdlib.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    int a,b;
    SENSITIVE int *p;
    a = 10;
    p = (int*)malloc(sizeof(int));
    *p = 100;
    free(p);
    p = &a;
    b = *p;
    p = (int*)malloc(sizeof(int));
    *p = 25;


    printf ("Value of a,b,*p ,*q: %d, %d, %d",a,b,*p);
 
    return 0;
}
