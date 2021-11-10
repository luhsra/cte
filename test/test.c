#include <stdio.h>
#include <stdint.h>
#include <cte.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



int other1(void);


int a = 9;
int b = 10;

int address_taken_in_other(void) {
    return a + 10;
}

int testfnptr(void) {
    printf("a = %d, b = %d\n", a, b);
    return 1;
}

int (*fnptr)(void);

int test3(int i, int n) {
    return i + n * a;
}

int test2(int x) {
    int y = b + test3(x, 6);
    return y;
}

int mini(int x) {
    return x;
}

int test1(void);

int rec(int i) {
    if (i <= 0)
        return mini(0);
    return rec(i - 1);
}

/* void dump_text(const char *filename) { */
/*     extern char __executable_start; */
/*     extern char __etext; */
/*     uintptr_t len = (uintptr_t)&__etext - (uintptr_t)&__executable_start; */
/*     FILE *file = fopen(filename, "wb"); */
/*     fwrite(&__executable_start, len, 1, file); */
/*     fclose(file); */
/* } */

int main(void) {
    int fd = open("test.dict", O_RDWR|O_CREAT, 0644);
    int rc = cte_init();
    if (rc < 0) {
        perror("CTE Error");
        return 2;
    }

    cte_wipe();

    cte_dump_state(fd);

    fnptr = testfnptr;
    test1();
    other1();
    return 0;
}

int test1(void) {
    /* rec(10); */
    int y = test2(42);
    printf(">> %d\n", y);
    printf("return from test1\n");
    return y + 1;
}
