#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    SENSITIVE int j = 10;
    SENSITIVE int h = 40;
    int sum = fn(j, h);
    printf("%d\n", sum);
    return 0;
}

int fn2(int* aptr, int* bptr) {
    int sum = 0;
    sum = *aptr + *bptr;
    return sum;
}

int fn(int a, int b) {
    SENSITIVE int sum = 0;
    sum = a + b;
    return sum;
}

