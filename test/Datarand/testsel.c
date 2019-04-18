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


void printall(struct ngx** ngxarg) {
    struct ngx* ptr = ngxarg[1];
    printf("%d\n", ptr->sslctx->pkey->hash);
    printf("%d\n", ptr->sslctx->sth->num);
}

void printsub(struct ssl* sslarg) {
    printf("%d\n", sslarg->pkey->hash);
}

void printsome(struct ngx* ngxsome) {
    printf("%d\n", ngxsome->funn->a);
}

int main(void) {
    void (*fptr1)(struct ngx**);
    void (*fptr2)(struct ssl*);
    fptr1 = printall;
    fptr2 = printsub;
    struct sthelse* sthptr = malloc(sizeof(struct sthelse));
    SENSITIVE struct privkey* pkptr = malloc(sizeof(struct privkey));
    struct ssl* sslptr = malloc(sizeof(struct ssl));
    struct funny* funnyptr = malloc(sizeof(struct funny));
    struct ngx* ngxptr = malloc(sizeof(struct ngx));

    /*
    struct ngx* cpyparent1 = ngxptr;
    struct ngx* cpyparent2 = ngxptr;

    struct ngx* ngxarr[2];
    ngxarr[0] = cpyparent1;
    ngxarr[1] = cpyparent2;
    sthptr->num = 100;
    sthptr->age = 29;
    */

    pkptr->hash = 999;
    /*
    strcpy(pkptr->thing, "hllp");

    sslptr->pkey = pkptr;
    sslptr->sth = sthptr;
    */
    sthptr->num = sslptr->pkey->hash;

    /*
    funnyptr->a = 40;
    funnyptr->b = 50;

    ngxptr->funn = funnyptr;
    ngxptr->sslctx = sslptr;

    (*fptr1)(ngxarr);
    (*fptr2)(cpyparent1->sslctx);

    printsome(cpyparent2);


    */
    printf("%d\n", sthptr->num);

    /*
    printf("%d\n", sslptr->sth->age);
    */
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
