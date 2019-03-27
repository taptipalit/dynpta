#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

typedef struct T {
    int id;
    int age;
} T;


T* getT() {
    T* tptr = malloc(sizeof(T));
    return tptr;
}

int main(void) {
    SENSITIVE T* newT;
    newT = getT();

    newT->id = 100;
    newT->age = 300;

    printf("%d\n", newT->id);

    return 0;
}
