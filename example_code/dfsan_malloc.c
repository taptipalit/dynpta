#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    SENSITIVE int* p;
    p = malloc(sizeof(int));
    return 0;
}
