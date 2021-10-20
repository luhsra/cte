#include <stdio.h>

int address_taken_in_other(void);

int (*other_fnptr)(void) = address_taken_in_other;

int other2(int i, int n) {
    return i + n * 9;
}

int other1(void) {
    printf("other: %d\n", other2(3, 5));
    return other_fnptr();
}
