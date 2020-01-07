#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
//#include <sanitizer/dfsan_interface.h>
#define SENSITIVE __attribute__((annotate("sensitive")))

int main(){
    SENSITIVE int a ;
    //int *p;

    //p = malloc(sizeof(int));
    //dfsan_label a_label = dfsan_create_label("ak", 0);
    dfsan_set_label(1, &a, 1);

    //out = 5;
    //dfsan_label out_label = dfsan_read_label(&a, 1);
    a = 5;

    //p = &out;
    //*p = a;
    //dfsan_label p_label = dfsan_get_label(*p);
 
    //printf("a_label = %" PRIu16 "\n", a_label);
    //printf("out_label = %" PRIu16 "\n", out_label);
    //printf("p_label = %" PRIu16 "\n", p_label);
    //printf("abd has d: %d\n", dfsan_has_label(p_label, a_label));
}
