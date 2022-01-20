#pragma once

#include <stddef.h>
#include <stdint.h>

static const uint32_t CTE_VERSION = 2;

static const uint32_t FLAG_DEFINITION = (1 << 0);
static const uint32_t FLAG_ADDRESS_TAKEN = (1 << 1);
static const uint32_t FLAG_INDIRECT_CALLS = (1 << 2);
static const uint32_t FLAG_INDIRECT_JUMPS = (1 << 3);
static const uint32_t FLAG_VISITED = (1 << 31);

typedef struct cte_meta_function {
    void *vaddr;
    size_t size;
    uint32_t *callees;
    uint32_t *jumpees;
    uint32_t *siblings;
    uint32_t callees_count;
    uint32_t jumpees_count;
    uint32_t siblings_count;
    uint32_t flags;
} cte_meta_function;

typedef struct cte_meta_header {
    char magic[4];
    uint32_t version;
    uint32_t functions_count;
    uint32_t size;
} cte_meta_header;

static inline
cte_meta_function *cte_meta_get_functions(cte_meta_header *header) {
    return (cte_meta_function*)(&header[1]);
}
