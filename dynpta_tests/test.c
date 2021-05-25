#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define mark_sensitive annotate

int main(void) {
    int *arr = malloc(100);
    annotate(arr);
    for (int i = 0; i < 20; i++) {
        arr[i] = i;
    }
    for (int i = 0; i < 20; i++) {
        printf("%d\n", arr[i]);
    }
    return 0;
}
