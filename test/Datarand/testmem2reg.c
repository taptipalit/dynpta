#include <stdio.h>

struct Dummy {
    int (*fptr1)();
    int (*fptr2)();
};

int fn1() {
    int a, b;
    scanf("%d", &a);
    scanf("%d", &b);
    int c = a + b;
    int d = b - a;
    return c*d;
}

int fn2() {
    return 20;
}

struct Dummy* getDummy() {
    struct Dummy* dummyptr = malloc(sizeof(struct Dummy));
    dummyptr->fptr2 = fn1;
    return dummyptr;
}

int main(void) {
    struct Dummy* dptr = getDummy();
    int k = (*(dptr->fptr2))();
    printf("k = %d\n", k);
    return 0;
}
