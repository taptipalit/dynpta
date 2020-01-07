#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    SENSITIVE int a;

    return 0;
}
