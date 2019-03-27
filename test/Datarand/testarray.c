#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    int *ptrarr[10];
    SENSITIVE int a = 10;
    int b = 20;
    int c = 30;
    ptrarr[0] = &a;
    ptrarr[1] = &b;
    ptrarr[2] = &c;

    printf("%d\n", *(ptrarr[0]));
    printf("%d\n", *(ptrarr[1]));
    printf("%d\n", *(ptrarr[2]));

    return 0;
}
