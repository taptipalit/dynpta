#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

int dosomething(int* ptr) {
    int* rr = ptr;
    int funnyval = *rr;
    printf("Some thing: %d\n", funnyval);
    return 0;
}

int doanotherthing(int* pp) {
    int *q = pp;
    int sadval = *q;
    printf("Another thing: %d\n", sadval);
    dosomething(pp);
    return 0;
}

int main(void) {
    int (*fptr)(int*);
    SENSITIVE int k = 100;
    fptr = doanotherthing;
    (*fptr)(&k);
    //doanotherthing(&k);
    return 0;
}

