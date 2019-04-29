#include <stdio.h>
#include <string.h>
#define SENSITIVE __attribute__((annotate("sensitive")))


#define CRT_FILE            "../my_crt.crt"

struct ST {
    char* ptr;
    void* alcatraz;
};

void print(char* ptr) {
    printf("%s\n", ptr);
}


struct Alcatraz {
    char p[10];
    char q[10];
    char r[10];
};

char* (*mymalloc)();

struct Alcatraz* get_alc(struct ST);
/*
int main(void) {
    mymalloc = malloc;
    SENSITIVE struct ST* stptr = malloc(sizeof(struct ST));
    stptr->ptr = malloc(100);
    strcpy(stptr->ptr, "aaa");
    stptr->alcatraz = (*mymalloc)(sizeof(struct Alcatraz));

    print(stptr->ptr);
    struct ST* ptptr = malloc(sizeof(struct ST));
    ptptr->ptr = malloc(100);
    strcpy(ptptr->ptr, "aaa");
    ptptr->alcatraz = (*mymalloc)(sizeof(struct Alcatraz));



    struct Alcatraz* ac = (struct Alcatraz*)((*ptptr).alcatraz);
    ac->p = "my";
    ac->q = "hello";
    ac->r = "hi";
    printf("%s %s %s\n", ac->p, ac->q, ac->r);


    return 0;
}
*/

inline struct Alcatraz* get_alc(struct ST st) {
    return (struct Alcatraz*)(st.alcatraz);
}

void printalc(struct Alcatraz* alc) {
    strcpy(alc->p, "Tapti");
    printf("%s\n", alc->p);
}

int main(void) {
    SENSITIVE struct ST* stptr = malloc(sizeof(struct ST));
    stptr->alcatraz = calloc(1, sizeof(struct Alcatraz));
    struct Alcatraz* ac = get_alc(*stptr);
    printalc(ac);
    return 0;
}
