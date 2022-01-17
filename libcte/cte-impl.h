#pragma once

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "../common/meta.h"

#define CTE_ESSENTIAL       __attribute__((section(".cte_essential"), used))
#define CTE_ESSENTIAL_NAKED __attribute__((section(".cte_essential"), used, naked))
#define CTE_ESSENTIAL_USED  __attribute__((section(".cte_essential"), used))

#define CTE_SEALED          __attribute__((section(".cte_sealed")))

struct cte_text {
    char *filename;
    cte_meta_header *meta;
    void *vaddr;
    size_t offset;
    size_t size;
};
typedef struct cte_text cte_text;

struct cte_function {
    uint32_t text_idx; // From which library
    char *name;
    size_t size;
    void *vaddr;
    void *body;
    cte_meta_function *meta;
    bool essential;
    uint32_t sibling_idx;
};
typedef struct cte_function cte_function;

struct cte_plt {
    uint32_t text_idx; // From which library
    void *vaddr;
    size_t size;
};
typedef struct cte_plt cte_plt;

struct cte_vector {
    void *front;
    size_t length;
    size_t element_size;
    size_t capacity;
};
typedef struct cte_vector cte_vector;

typedef struct __attribute__((packed)) cte_implant {
    uint8_t  mov[2];
    uint64_t mov_imm;
    uint8_t  icall[2];
    uint32_t func_idx;
} cte_implant;

#if CONFIG_STAT
typedef struct cte_stat {
    uint64_t  init_time;
    uint32_t  wipe_count; // How often was cte_wipe called
    
    uint64_t  restore_count; // total number of restores invocations
    uint64_t  restore_time;  // cumulative restore time
    uint64_t *restore_times;
    
    uint64_t  last_wipe_time; // how long did the last wipe take
    uint64_t  last_wipe_count; // how many functions were wiped
    uint64_t  last_wipe_bytes; // how many bytes were wiped
    struct timespec  last_wipe_timestamp;
    cte_function *last_wipe_function; // The function that called the last wipe

    uint64_t  cur_wipe_count; // how many functions are still wiped
    uint64_t  cur_wipe_bytes; // how many bytes are still wiped

    uint32_t  text_bytes; // sum of all text-segment bytes
    uint32_t  function_bytes; // sum of all text-segment bytes
} cte_stat_t;

#define timespec_diff_ns(ts0, ts)   (((ts).tv_sec - (ts0).tv_sec)*1000LL*1000LL*1000LL + ((ts).tv_nsec - (ts0).tv_nsec))

#endif

extern void cte_restore_entry(void);

#define cte_implant_init(ptr, _func_idx) do {                            \
    ptr->mov[0] = 0x48; /* 64bit prefix */                              \
    ptr->mov[1] = 0xb8; /* absmov to %rax  */                          \
    ptr->mov_imm = (uint64_t)cte_restore_entry;                        \
    ptr->icall[0] = 0xff; /* call *%rax */                             \
    ptr->icall[1] = 0xd0;                                              \
    ptr->func_idx = (_func_idx);                                        \
    } while(0)

#define cte_implant_valid(ptr) (ptr &&              \
        ptr->mov[0] == 0x48 &&                      \
        ptr->mov[1] == 0xb8 &&                      \
        ptr->mov_imm == (uint64_t)cte_restore_entry &&\
        ptr->icall[0] == 0xff &&                      \
        ptr->icall[1] == 0xd0)

#define CTE_MAX_FUNC_ALIGN 16
