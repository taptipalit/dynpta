#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

struct CTX1 {
    int a;
    int b;
    int c;
};

struct CTX2 {
    int n;
    int m;
};

struct CTX3 {
    struct CTX1* ctx1;
    struct CTX2* ctx2;
    int d;
};

int main(void) {
    SENSITIVE struct CTX1* c1 = malloc(sizeof(struct CTX1));
    struct CTX2* c2 = malloc(sizeof(struct CTX2));
    struct CTX3* c3 = malloc(sizeof(struct CTX3));
    c1->a = 10;
    c1->b = 20;
    c1->c = 30;

    c2->n = 400;
    c2->m = 500;

    c3->ctx1 = c1;
    c3->ctx2 = c2;
    c3->d = 4000;

    struct CTX3* c3ptr = c3;
    struct CTX1* c1ptr = c3ptr->ctx1;
    printf("%d\n", c1ptr->a);


    return 0;
}
