#include <stdio.h>

void* (*mwrap)(long) = malloc;

void* malloc_wrapper(int size) {
    char* ptr = 0;
    if (size < 1024) {
        ptr = malloc(1024);
    } else {
        ptr = malloc(size);
    }
    return ptr;
}

void* CRYPTO_malloc(int size) {
    void* ptr = (*mwrap)(size);
    return ptr;
}

struct A {
    int a1;
    int a2;
};

struct B {
    int b1;
    int b2;
};

int main(void) {
    struct A* aptr = CRYPTO_malloc(sizeof(struct A));    
    struct B* bptr = CRYPTO_malloc(sizeof(struct B));
    aptr->a1 = 10;
    bptr->b2 = 30;
    return 0;
}
