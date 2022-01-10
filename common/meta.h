#pragma once

#include <cstdint>
#include <stdint.h>

static const uint32_t CTE_VERSION = 1;

static const uint32_t FLAG_DEFINITION = (1 << 0);
static const uint32_t FLAG_ADDRESS_TAKEN = (1 << 1);

typedef struct cte_meta_function {
    void *vaddr;
    void **callees;
    void **siblings;
    uint32_t calles_count;
    uint32_t siblings_count;
    uint32_t flags;
} cte_meta_function;

typedef struct cte_meta_header {
    char magic[4];
    uint32_t version;
    uint32_t functions_count;
    uint32_t padding;
} cte_meta_header;
