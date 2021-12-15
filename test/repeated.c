#include <stdio.h>
#include <stdint.h>
#include <cte.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>

#define noinline __attribute__((noinline))

int _func1(void) { return 1; }
int (*func1)(void) = &_func1;
int _func2(void) { return 2; }
int (*func2)(void) = &_func2;
int _func3(void) { return 3; }
int (*func3)(void) = &_func3;
int _func4(void) { return 4; }
int (*func4)(void) = &_func4;


int main(void) {
    int fd = open("repeated.dict", O_RDWR|O_CREAT|O_TRUNC, 0644);
    int rc = cte_init(0);
    if (rc < 0) {
        perror("CTE Error");
        return 2;
    }

    cte_enable_threshold();

    for (unsigned i = 0; i < 50; i++) {
        int wiped = cte_wipe_threshold(80, 20);

        int a;
        a += func1();
        if (i % 2 == 0)
            a += func2();
        else
            a += func3();
    }

    return 0;
}

