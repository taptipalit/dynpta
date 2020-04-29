#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

SENSITIVE int allow_script;

int main(void) {
    allow_script = 1;

    if (allow_script == 1) {
        printf("Scripts allowed!\n");
    }
    return 0;
}
