#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

static void something() {
    printf("something");
}

int main(void) {
    SENSITIVE int a = 10;
    int b = 20;
    int *p = &a;
    int *q = &a;
    printf("%d %d\n", *p, *q);
    q = &b;
    printf("%d\n", *q);
    int c = 0;
    scanf("%d", &c);
    if ( c > 100) {
        something();
    }
    return 0;
}
