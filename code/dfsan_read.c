#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    SENSITIVE int a;
    a = 5;
    return 0;
}
