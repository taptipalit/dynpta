#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

struct K {
    int a;
    int *p;
};
int main(void) {
//    SENSITIVE struct K kobj;
    SENSITIVE double p = 0.05;

    printf("%lf\n", p);

    /*
    p = malloc(sizeof(int));


    int *r;

    r = p;

    printf("%d\n", *r);
    */
    return 0;
}

