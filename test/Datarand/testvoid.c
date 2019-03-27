#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

void dostuff(char* p) {
    char c;
    while (*p != '\0') {
        c = *p;
        *p++ = c + 1;
    }
}

int main(void) {
    SENSITIVE char name[10];
    strcpy(name, "tapti");
    dostuff(name);
    char id[5];
    strcpy(id, "3939");
    dostuff(id);
    printf("%s %s\n", name, id);
    return 0;
}
