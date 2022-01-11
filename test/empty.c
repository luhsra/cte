#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <cte.h>
#include <time.h>
#include <mmview.h>
#include <fcntl.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/mman.h>

#include "cte_mprotect.h"

__attribute__((weak))
bool check_empty() {
    return false;
}

__attribute__((weak))
bool check_empty_wipe(long mmview, bool wipe)  {
    long previous = mmview_migrate(mmview);
    // printf("%ld -> %ld\n",  previous, mmview);

    if (wipe) cte_wipe();
    bool ret = check_empty();
    int rc = mmview_migrate(previous); (void) rc;
    // printf("%ld -> %ld\n",  mmview, rc);

    return ret;
}
#define EMPTY_ROUNDS  100000
//#define EMPTY_ROUNDS  1000



__attribute__((weak))
bool check_empty_mprotect(struct cte_range*range, unsigned ranges)  {
    // printf("----\n");
    cte_range_mprotect(range, ranges, PROT_READ);
    bool ret = check_empty();
    cte_range_mprotect(range, ranges, PROT_READ|PROT_EXEC);
    return ret;
}

#define timespec_diff_ns(ts0, ts)   (((ts).tv_sec - (ts0).tv_sec)*1000LL*1000LL*1000LL + ((ts).tv_nsec - (ts0).tv_nsec))

int main(int argc, char *argv[]) {
    unsigned int repeat = 1;
    if (argc > 1) {
        repeat = atoi(argv[1]);
    }

    struct timespec ts0;
    struct timespec ts1;

    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < EMPTY_ROUNDS; i++) {
            check_empty();
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "empty,plain,%f,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, EMPTY_ROUNDS);
    }

    // And now with mmview and libcte
    cte_init(CTE_STRICT_CALLGRAPH);
    //cte_init(0);
    cte_mmview_unshare();
    long global_mmview, empty_mmview;
    long previous;
    int fd;

    global_mmview = mmview_current();
    empty_mmview = mmview_create();

    check_empty_wipe(empty_mmview, true);
    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < EMPTY_ROUNDS; i++) {
            check_empty_wipe(empty_mmview, false);
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "empty,migrate,%f,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, EMPTY_ROUNDS);
    }

    // Statistics over the mmview
    struct cte_range *ranges = malloc(sizeof(struct cte_range) * 10000); 
    fd = open("empty.migrate.dict", O_RDWR|O_CREAT|O_TRUNC, 0644);
    cte_dump_state(fd, 0);
    previous = mmview_migrate(empty_mmview);
    cte_dump_state(fd, CTE_DUMP_FUNCS|CTE_DUMP_TEXTS);
    unsigned range_count = cte_get_wiped_ranges(ranges);
    mmview_migrate(previous);
    if (mmview_delete(empty_mmview) == -1) die("mmview_delete");

    unsigned mprotect_count=0, mprotect_bytes=0;
    cte_range_stat(ranges, range_count, mprotect_count, mprotect_bytes);
    printf("mprotect Ranges: %d, %d\n", mprotect_count, mprotect_bytes);

    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < EMPTY_ROUNDS; i++) {
            check_empty_mprotect(ranges, range_count);
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "empty,mprotect,%f,%d,%d,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, EMPTY_ROUNDS,
                mprotect_count, mprotect_bytes);
    }

    close(fd);
}
