#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

struct Student {
    char name[10];
    int id;
    int b;
};

int main(void) {
    SENSITIVE int a;
    int b;
    struct Student s;
    a = 1000;
    s.id = a;
    s.b = 30;
   
    b = s.id;
    printf ("%d %d\n", s.id, s.b);
    return 0;
}
