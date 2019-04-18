#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

struct Student {
    char name[10];
    int id;
};

int main(void) {
    SENSITIVE int a;
    int b;
    struct Student s;
    a = 1000;
    s.id = a;
   
    b = a;
    printf ("%d\n", b);
    printf ("%d\n", s.id);
    return 0;
}
