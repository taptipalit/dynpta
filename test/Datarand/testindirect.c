#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

void gunc(int sumnumber) {
    int another;
    another = sumnumber;
    printf("%d\n", another);
}

void func(int *realptr) {
    int k = 10;
    k = realptr;
    printf("%d\n", k);
}

int main(void) {
    SENSITIVE int a = 20;
    int b = 10;
    int* aptr = &a;
    int* bptr = &b;
    int (*fptr)(int*);
    int (*gptr)(int);
    fptr = func;
    (*fptr)(bptr);
    gptr = gunc;
    (*gptr)(a);
    return 0;
}
