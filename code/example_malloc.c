#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    SENSITIVE int a;
    int b;
    int *p, *q;
    a = 10;
    b = 15;
    p = malloc(sizeof(int));
    *p = 100;
    p = &a;
    p = &b;
    q = &a;
    q = malloc(sizeof(int));
    *q = 25;


    printf ("Value of a,b,*p ,*q: %d, %d, %d, %d",a,b,*p,*q);
 
    return 0;
}
