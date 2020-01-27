#include<stdio.h>
#define SENSITIVE __attribute__((annotate("sensitive")))
void fun(int* p){
    *p = 1;
    printf("Value of a in function is %d\n",*p);
    int k = *p;
    int l = *p;

    printf("Value of k = %d\n", k);
    printf("Value of l = %d\n", l);
}
int main(){
    SENSITIVE int a;
    a = 10;
    fun(&a);
    printf("Value of a in main is %d\n",a);
    return 0;
}


