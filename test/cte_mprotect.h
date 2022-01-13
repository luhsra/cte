#pragma once

#include <stdint.h>
#include <syscall.h>
#include <sys/mman.h>

#define ROUND_PAGE_UP(p) ((void*) (((uintptr_t)(p) + 0xfff) & ~0xfffUL))
#define ROUND_PAGE_DOWN(p) ((void*) (((uintptr_t)(p) + 0) & ~0xfffUL))
#define die(msg) do {perror(msg); exit(EXIT_FAILURE);} while(0)



#define cte_range_mprotect(range, ranges, prot) do {                    \
    for (unsigned i = 0; i < (ranges); i++) {                           \
       void *first_page = ROUND_PAGE_UP(range[i].address);                 \
       void *last_page = ROUND_PAGE_DOWN(range[i].address + range[i].length); \
       if (last_page <= first_page) continue;                           \
       if (syscall(SYS_mprotect, first_page, last_page - first_page, prot) == -1) \
           die("mprotect");                                             \
    }                                                                   \
    } while(0)

#define cte_range_stat(range, ranges, mprotect_calls, mprotect_bytes) do {      \
        for (unsigned i = 0; i < (ranges); i++) {                       \
            void *first_page = ROUND_PAGE_UP(range[i].address);         \
            void *last_page = ROUND_PAGE_DOWN(range[i].address + range[i].length); \
            if (last_page <= first_page) continue;                      \
            mprotect_calls ++; mprotect_bytes += (last_page - first_page); \
        }                                                               \
    } while(0)

#define cte_range_dump(type, range, ranges) do {                         \
        for (unsigned i = 0; i < (ranges); i++) {                       \
            void *first_page = ROUND_PAGE_UP(range[i].type);         \
            void *last_page = ROUND_PAGE_DOWN(range[i].type + range[i].length); \
            if (last_page <= first_page) continue;                      \
            printf("mprotect %ld-%ld => %p + %p (%ld pages)\n", range[i].type, range[i].type+range[i].length, \
                   first_page, last_page, (last_page - first_page) >> 12);\
        }                                                               \
    } while(0)
