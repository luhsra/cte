#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>

struct cte_info_fn {
    void *fn;
    void *fn_end;
    int flags;
    int calles_count;
    void **callees;
};

static const int FLAG_ADDRESS_TAKEN = (1 << 0);

extern struct cte_info_fn __start___cte_fn_;
extern struct cte_info_fn __stop___cte_fn_;
static struct cte_info_fn *info_fns = &__start___cte_fn_;
size_t info_fns_count;

__attribute__((section("__cte_disposable_text_")))
static int cte_sort_compare(const void *e1, const void *e2) {
    struct cte_info_fn *a = (struct cte_info_fn*)e1;
    struct cte_info_fn *b = (struct cte_info_fn*)e2;

    // Zeroed out cte_info_fns go to the end of the list
    if (a->fn == NULL) return 1;
    if (b->fn == NULL) return -1;

    if (a->fn > b->fn) return  1;
    if (a->fn < b->fn) return -1;
    return 0;
}

__attribute__((section("__cte_disposable_text_")))
static int cte_find_compare(const void *addr, const void *element) {
    const struct cte_info_fn *el = element;
    if (addr == el->fn)
        return 0;
    if (addr < el->fn)
        return -1;
    else
        return 1;
}

__attribute__((section("__cte_disposable_text_")))
static struct cte_info_fn *cte_find(void *addr) {
    return bsearch(addr, info_fns, info_fns_count, sizeof(struct cte_info_fn),
                   cte_find_compare);
}

__attribute__((section("__cte_disposable_text_")))
static struct cte_info_fn *cte_callee_as_info_fn(void *callee_ptr) {
    if (callee_ptr >= (void*)(&__start___cte_fn_) &&
        callee_ptr < (void*)(&__stop___cte_fn_))
        return (struct cte_info_fn*)callee_ptr;
    return NULL;
}

__attribute__((section("__cte_disposable_text_")))
static size_t cte_info_fn_index(struct cte_info_fn* ptr) {
    return ptr - info_fns;
}

__attribute__((section("__cte_disposable_text_")))
void cte_init(void) {
    // Sort the buffer
    size_t old_count = &__stop___cte_fn_ - info_fns;
    qsort(info_fns, old_count, sizeof(struct cte_info_fn), cte_sort_compare);

    // Zero out duplicates but keep the address_taken bit
    size_t new_count = 0;
    struct cte_info_fn *curr = info_fns;
    struct cte_info_fn *first = NULL;
    while (curr < &__stop___cte_fn_) {
        if (!first) {
            first = curr;
            new_count++;
        }
        curr++;

        if (curr >= &__stop___cte_fn_ || curr->fn != first->fn) {
            // zero out the duplicates and set flags
            int flags = first->flags;
            for (struct cte_info_fn *i = first; i < curr; i++) {
                if (i->fn_end == NULL)
                    *i = (const struct cte_info_fn) { 0 };
                else
                    i->flags |= flags;
            }
            first = NULL;
        }
    }

    // Sort the buffer again to eliminate zeroed out duplicates
    qsort(info_fns, old_count, sizeof(struct cte_info_fn), cte_sort_compare);
    info_fns_count = new_count;

    // Replace the callee references with pointers to the cte_info_fn
    // if that's possible
    for (struct cte_info_fn *info = info_fns;
         info < info_fns + info_fns_count; info++) {
        for (int i = 0; i < info->calles_count; i++) {
            void *callee_fn = (void*)info->callees[i];
            struct cte_info_fn *callee_info = cte_find(callee_fn);
            if (callee_info != NULL)
                info->callees[i] = callee_info;
        }
    }
}

__attribute__((section("__cte_disposable_text_")))
static void cte_graph_keep(struct cte_info_fn *info, bool *keep_entries) {
    size_t index = cte_info_fn_index(info);

    // Abort recursion when processing recursive functions
    if (keep_entries[index])
        return;

    // Mark this info_fn as not to eliminate
    keep_entries[index] = true;

    // Process callees
    for (int i = 0; i < info->calles_count; i++) {
        struct cte_info_fn *callee_info = cte_callee_as_info_fn(info->callees[i]);
        if (callee_info)
            cte_graph_keep(callee_info, keep_entries);
    }
}

static void *cte_align_to_page(void *addr) {
    static size_t page_size = 0;
    if (page_size == 0) {
        page_size = sysconf(_SC_PAGESIZE);
    }
    return (void*)((size_t)addr & ~(page_size - 1));
}

__attribute__((section("__cte_disposable_text_")))
static void cte_eliminate_begin(void *start, void *stop) {
    void *aligned_start = cte_align_to_page(start);
    size_t len = (char*)stop - (char*)aligned_start;
    mprotect(aligned_start, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

static void cte_eliminate_end(void *start, void *stop) {
    void *aligned_start = cte_align_to_page(start);
    size_t len = (char*)stop - (char*)aligned_start;
    mprotect(aligned_start, len, PROT_READ | PROT_EXEC);
    __builtin___clear_cache(aligned_start, stop);
}

static void cte_eliminate_range(void *start, void *stop) {
    for (unsigned char *it = start; it < (unsigned char*)stop; it++) {
        *it = 0xcc;
    }
}

void cte_eliminate_self(void) {
    extern char __start___cte_disposable_text_;
    extern char __stop___cte_disposable_text_;
    char *start = &__start___cte_disposable_text_;
    char *stop = &__stop___cte_disposable_text_;
    cte_eliminate_begin(start, stop);
    cte_eliminate_range(start, stop);
    cte_eliminate_end(start, stop);
}

__attribute__((section("__cte_disposable_text_")))
void cte_eliminate_graph(void *keep_fns[], long count) {
    // Array to track the functions that we want to keep
    bool keep_entries[info_fns_count];
    for (bool *e = keep_entries; e < keep_entries + info_fns_count; e++)
        *e = false;

    // Follow call graph of keep_fns
    for (long i = 0; i < count; i++)
        cte_graph_keep(cte_find(keep_fns[i]), keep_entries);

    // Collect all adress-taken functions
    for (size_t i = 0; i < info_fns_count; i++) {
        struct cte_info_fn *info = &info_fns[i];
        keep_entries[i] = keep_entries[i] || (info->flags & FLAG_ADDRESS_TAKEN);

        // Recursively mark all functions that are called from
        // address-taken functions
        if (keep_entries[i])
            cte_graph_keep(info, keep_entries);
    }

    // Eliminate unused functions
    void *start = info_fns[0].fn;
    void *stop = info_fns[info_fns_count-1].fn_end;
    size_t eliminated_count = 0;
    size_t eliminated_bytes = 0;
    size_t total_bytes = 0;
    cte_eliminate_begin(start, stop);
    for (size_t i = 0; i < info_fns_count; i++) {
        struct cte_info_fn *info = &info_fns[i];
        if (info->fn >= info->fn_end)
            continue;
        size_t fn_bytes = (size_t)info->fn_end - (size_t)info->fn;
        total_bytes += fn_bytes;
        if (!keep_entries[i]) {
            cte_eliminate_range(info->fn, info->fn_end);
            eliminated_count++;
            eliminated_bytes += fn_bytes;
        }
    }
    printf("CTE: eliminated count: %lu / %lu\n", eliminated_count, info_fns_count);
    printf("CTE: eliminated bytes: %lu / %lu\n", eliminated_bytes, total_bytes);
    cte_eliminate_end(start, stop);
}
