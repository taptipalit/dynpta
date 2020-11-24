#include <stdio.h>

void annotate(void*);

struct S {
    int b;
    int *p;
    int a;
};

int main(void) {
    struct S sobj;
    sobj.p = malloc(1024);
    annotate(sobj.p);
    sobj.p[0] = 't';
    printf("%c\n", sobj.p[0]);
    return 0;
}
