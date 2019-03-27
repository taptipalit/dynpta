#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

struct Student {
    char name[10];
    int id;
};

int main(void) {
    SENSITIVE int a;
    int b;
//    int *dptr = 0;
    struct Student s;
    a = 1000;
    s.id = a;
   // printf("%d\n", s.id);
//    int *ptr;
 //   ptr = &a;
  //  int z = 100;
   // z = *ptr;
 //   dptr = &b;
   // *dptr = a;
    b = a;
    printf ("%d\n", b);
    printf ("%d\n", s.id);

    /*
    int *p1 = &a;
    int *p2 = &b;

    printf("%d\n", *p1);
    printf("%d\n", *p2);
    */
    return 0;
}
