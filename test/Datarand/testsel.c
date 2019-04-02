#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

struct sthelse {
    int num;
    int age;
};

struct privkey {
    int hash;
    char thing[1000];
};

struct ssl {
    struct privkey* pkey;
    struct sthelse* sth;
};

struct funny {
    int a;
    int b;
};

struct ngx {
    struct funny* funn;
    struct ssl* sslctx;
};


void printall(struct ngx* ngxarg) {
    printf("%d\n", ngxarg->sslctx->pkey->hash);
}

void printsub(struct ssl* sslarg) {
    printf("%d\n", sslarg->pkey->hash);
}

int main(void) {
    void (*fptr1)(struct ngx*);
    void (*fptr2)(struct ssl*);
    fptr1 = printall;
    fptr2 = printsub;
    struct sthelse* sthptr = malloc(sizeof(struct sthelse));
    SENSITIVE struct privkey* pkptr = malloc(sizeof(struct privkey));
    struct ssl* sslptr = malloc(sizeof(struct ssl));
    struct funny* funnyptr = malloc(sizeof(struct funny));
    struct ngx* ngxptr = malloc(sizeof(struct ngx));

    struct ngx* cpyparent = ngxptr;

    sthptr->num = 100;
    sthptr->age = 29;

    pkptr->hash = 999;
    strcpy(pkptr->thing, "hllp");

    sslptr->pkey = pkptr;
    sslptr->sth = sthptr;

    funnyptr->a = 40;
    funnyptr->b = 50;

    ngxptr->funn = funnyptr;
    ngxptr->sslctx = sslptr;

    (*fptr1)(cpyparent);
    (*fptr2)(cpyparent->sslctx);
}

/*
int main(void) {
    SENSITIVE int a;
    int *ptr = &a;
    int *qtr = ptr;
    printf("%d\n", *ptr);
    printf("%d\n", *qtr);
    return 0;
}
*/
