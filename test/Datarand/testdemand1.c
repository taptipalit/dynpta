#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

void print(int* pointer) {
    int *qptr = pointer;
    printf("This is a funny thing %d\n", *qptr);
}

int main(void) {
    SENSITIVE int a = 10;
    int b = 30;
    int *p1 = &a;
    int *p2 = &b;

    printf("%d\n", *p1);
    printf("%d\n", *p2);
    print(p1);
    return 0;
}