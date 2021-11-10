#pragma once

#include <stdlib.h>
#include <stdbool.h>

#define CTE_ESSENTIAL       __attribute__((section(".cte_essential"), used))
#define CTE_ESSENTIAL_NAKED __attribute__((section(".cte_essential"), used, naked))

struct cte_info_fn {
    void *vaddr;
    int flags;
    int calles_count;
    void **callees;
};
typedef struct cte_info_fn cte_info_fn;

struct cte_text {
    struct cte_info_fn *info_fns;
    size_t info_fns_count;
    void *vaddr;
    size_t size;
};
typedef struct cte_text cte_text;

struct cte_function {
    char *name;
    size_t size;
    void *vaddr;
    void *body;
    struct cte_info_fn *info_fn;
    bool essential;
};
typedef struct cte_function cte_function;

struct cte_plt {
    void *vaddr;
    size_t size;
};
typedef struct cte_plt cte_plt;

struct cte_vector {
    void *front;
    size_t length;
};
typedef struct cte_vector cte_vector;

static const int FLAG_ADDRESS_TAKEN = (1 << 1);
static const int FLAG_DEFINITION = (1 << 0);
