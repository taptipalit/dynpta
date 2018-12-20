#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

typedef struct St {
    void (*funcptr)(int);
} St;

typedef struct Bt {
    void (*guncptr)(int);
} Bt;

void func(int a) {
    int k = 10;
    int d = 100;
    int res = a + k + d;
    printf("%d\n", res);
}

void gunc(int a) {
    int k = 10;
    int d = 200;
    int res = d - k - a;
    printf("%d\n", res);
}

int main(void) {
    St st;
    Bt bt;
    int *unknownptr;
    int k = 100;
    st.funcptr = gunc;
    (*(st.funcptr))(23);
    bt.guncptr = st.funcptr;
    (*(bt.guncptr))(100);
    unknownptr = &k;
    printf("%d\n", *unknownptr);
    return 0;
}
