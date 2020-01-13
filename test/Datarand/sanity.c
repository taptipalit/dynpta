#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    int a = 200;
    SENSITIVE int *ptr;
    ptr = &a;
    printf("%d\n", *ptr);
    return 0;
}
