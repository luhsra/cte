#pragma once

#define CTE_ESSENTIAL       __attribute__((section(".cte_essential"), used))
#define CTE_ESSENTIAL_NAKED __attribute__((section(".cte_essential"), used, naked))


struct cte_info_fn {
    void *vaddr;
    int flags;
    int calles_count;
    void **callees;
};

struct cte_text {
    cte_info_fn *info_fns;
    size_t info_fns_count;
    void *vaddr;
    size_t size;
};

struct cte_function {
    std::string name;
    size_t size;
    void *vaddr;
    void *body;
    cte_info_fn *info_fn;
    bool essential;

    void reload() {
        memcpy(vaddr, body, size);
    }

    void kill() {
        memset(vaddr, 0xcc, size);
    }
};

struct cte_plt {
    void *vaddr;
    size_t size;
};

static constexpr int FLAG_ADDRESS_TAKEN = (1 << 1);
static constexpr int FLAG_DEFINITION = (1 << 0);

extern "C" {
    int cte_restore(void *addr, void *call_addr);
    void cte_restore_entry(void);
}
