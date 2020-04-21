#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

int main(void) {
    SENSITIVE int allow_script;
    allow_script = 1;

    if (allow_script == 1) {
        printf("Scripts allowed!\n");
    }
    return 0;
}
