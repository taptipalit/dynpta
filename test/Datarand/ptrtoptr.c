#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

struct Stud {
    int *a;
    int *b;
};

void dothis(struct Stud* ss) {
    int* k = &(ss->b);
    printf("%d\n", *k);
}

int main(void) {
    int num1 = 100;
    int num2 = 200;
    SENSITIVE struct Stud st;
    st.a = &num1;
    st.b = &num2;
    struct Stud* sptr = &st;
    dothis(sptr);
    return 0;
}
