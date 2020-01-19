#include <stdio.h>

void* (*mwrap)(long) = malloc;

void* malloc_wrapper(int size) {
    char* ptr = 0;
    if (size < 1024) {
        ptr = malloc(1024);
    } else {
        ptr = malloc(size);
    }
    return ptr;
}

void* wrapwrapper(int size) {
    void* ptr = (*mwrap)(size);
    return ptr;
}
