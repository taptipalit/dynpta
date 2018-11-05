#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

typedef struct T {
    int id;
    void (*funcptr)(int);
} T;

int val1 = 200;
int val2 = 300;

void f(int a) {
    int k = 10;
    int d = 100;
    int res = a + k + d;
    printf("%d\n", res);
}

void g(int a) {
    int k = 10;
    int d = 200;
    int res = d - k - a;
    printf("%d\n", res);
}

void dosomething(T* tptr) {
    (*(tptr->funcptr))(200);
}

int main(void) {
    T t;
    t.id = 100;
    void (*fptr) (int);
    int *ptr;
    SENSITIVE int k = 0;
    int j = k + 10;
    printf("%d %d", k, j);
    if ( j < 100) {
        //fptr = f;
        ptr = &val1;
        t.funcptr = g;
    } else {
        //fptr = g;
        ptr = &val2;
        t.funcptr = f;
    }
    //(*fptr)(*ptr);
    dosomething(&t);
    (*(t.funcptr))(23);
    return 0;
}
