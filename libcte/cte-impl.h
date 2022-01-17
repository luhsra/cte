#pragma once

#include <stdlib.h>
#include <stdbool.h>

#define CTE_ESSENTIAL       __attribute__((section(".cte_essential"), used))
#define CTE_ESSENTIAL_NAKED __attribute__((section(".cte_essential"), used, naked))
#define CTE_ESSENTIAL_USED  __attribute__((section(".cte_essential"), used))

#define CTE_SEALED          __attribute__((section(".cte_sealed")))


struct __attribute__((packed)) cte_info_fn {
    void *vaddr;
    int flags;
    int calles_count;
    void **callees;
};
typedef struct cte_info_fn cte_info_fn;

struct cte_text {
    char *filename;
    struct cte_info_fn *info_fns;
    size_t info_fns_count;
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
    struct cte_info_fn *info_fn;
    bool essential : 1;
    bool disable_caller_validation : 1;
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
    union __attribute__((packed)) {
        struct __attribute__((packed))  {
            uint8_t  mov[2];
            uint64_t mov_imm;
            uint8_t  icall[2];
        } icall;
        struct __attribute__((packed)) {
            uint8_t  nop[7];
            uint8_t  call[1];
            int32_t  offset;
        } call;
    } ;
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

static const int FLAG_INDIRECTLY_ALLOWED = (1 << 2); // FIXME: Wrong place
static const int FLAG_ADDRESS_TAKEN = (1 << 1);
static const int FLAG_DEFINITION = (1 << 0);

extern void cte_restore_entry(void);

#define CTE_MAX_FUNC_ALIGN 16
