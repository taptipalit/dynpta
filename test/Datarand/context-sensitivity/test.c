#include <stdio.h>
#include <stdlib.h>

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
    void (*fptr)();
};

struct B {
    void (*gptr)();
};

void f() {
    printf("hello\n");
}

void g() {
    printf("hi\n");
}

void dothis(struct A* aptr) {
    (*(aptr->fptr))();
}

void dothat(struct B* bptr) {
    (*(bptr->gptr))();
}

int main(void) {
    struct A* aptr = CRYPTO_malloc(sizeof(struct A));    
    struct B* bptr = CRYPTO_malloc(sizeof(struct B));
    aptr->fptr = f;
    bptr->gptr = g;

    dothis(aptr);
    dothat(bptr);
    return 0;
}
