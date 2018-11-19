#include <stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

typedef struct Student {
    int *pointer;
    int id;
    char name[10];
} Student;

int main(void) {
    SENSITIVE int a = 10;
    Student stud;
    int* localpointer;
    stud.pointer = &a;
    stud.id = 20;
    Student* sptr;
    sptr = &stud;
    int b = 30;
    int *p1 = &a;
    int *p2 = &b;

    printf("%d\n", *p1);
    printf("%d\n", *p2);
    printf("%d\n", *(sptr->pointer));
    printf("%d\n", stud.id);
    localpointer = sptr->pointer;
    printf("%d\n", localpointer);
    return 0;
}
