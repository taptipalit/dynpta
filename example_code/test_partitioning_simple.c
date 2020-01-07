#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    SENSITIVE int a = 10;
    int b = 20;
    int *p = &a;
    int *q = &a;
    printf("%d %d\n", *p, *q);
    q = &b;
    printf("%d\n", *q);
    return 0;
}
