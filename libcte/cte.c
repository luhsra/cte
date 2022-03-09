#define _GNU_SOURCE
#include <stddef.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ucontext.h>
#include <syscall.h>
#include <link.h>
#include <assert.h>

#include <fcntl.h>
#include <link.h>
#include <elf.h>
#include <time.h>
#include <gelf.h>
#include "cte.h"
#include "cte-impl.h"
#include "cte-printf.h"
#include "mmview.h"
#include "../common/meta.h"

CTE_SEALED static cte_vector texts;     // vector of cte_text
CTE_SEALED static cte_vector plts;      // vector of cte_plt
CTE_SEALED static cte_vector functions; // vector of cte_function

CTE_SEALED static void *bodies;         // stores function bodies
CTE_SEALED static size_t bodies_size;

CTE_SEALED static bool strict_callgraph;
CTE_SEALED static bool strict_ctemeta;


static void *vdso_start = NULL;
static size_t vdso_size = 0;

static void *cte_sealed_sec_vaddr = NULL;
static size_t cte_sealed_sec_size = 0;

#define func_id(func_ptr) ((func_ptr) - (cte_function *) functions.front)
#define FUNC_ID_INVALID (uint32_t)(~0)

#if CONFIG_STAT
cte_stat_t cte_stat;

static __thread cte_stat_t *cte_stat_thread;

CTE_ESSENTIAL
static cte_stat_t *cte_get_stat(void) {
    return (cte_stat_thread) ? cte_stat_thread : &cte_stat;
}

static void cte_stat_init() {
    cte_stat.init_time = 0;
    cte_stat.restore_count = 0;
    cte_stat.restore_times = calloc(functions.length, sizeof(*cte_stat.restore_times));
}

void cte_stat_init_thread(void) {
    cte_stat_thread = calloc(1, sizeof(cte_stat_t));
    cte_stat_thread->init_time = cte_stat.init_time;
    cte_stat_thread->restore_times = calloc(functions.length, sizeof(*cte_stat.restore_times));
    cte_stat_thread->text_bytes = cte_stat.text_bytes;
    cte_stat_thread->function_bytes = cte_stat.function_bytes;
}

#define CLOCK_LIBCTE CLOCK_REALTIME
#else
void cte_stat_init_thread(void) {}
#endif

#if CONFIG_THRESHOLD
struct cte_wipestat {
    uint16_t wipe;
    uint16_t restore;
};
static __thread struct cte_wipestat *__wipestat;
#define cte_get_wipestat() (__wipestat)

void cte_enable_threshold() {
    if (!__wipestat)
        __wipestat = calloc(functions.length, sizeof(*__wipestat));
}
#endif

static void *cte_memset(void *dst, int pat, size_t n);

struct build_id_note {
    ElfW(Nhdr) nhdr;

    char name[4];
    uint8_t build_id[0];
};

static void cte_mmap_inc(void **addr, size_t *size) {
    static size_t page_size = 0;
    if (page_size == 0) {
        page_size = sysconf(_SC_PAGESIZE);
    }
    // We allocate Memory in 128K increments to save mremap calls
    size_t new_size = *size + (page_size * 32);
    if (!*addr) {
        *addr = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else {
        *addr = mremap(*addr, *size, new_size, MREMAP_MAYMOVE);
    }
    if (*addr == MAP_FAILED) {
        cte_die("mmap failed\n");
    }
    *size = new_size;
}

static void cte_vector_init(cte_vector *vector, size_t element_size) {
    vector->length = 0;
    vector->element_size = element_size;
    vector->front = NULL;
    vector->capacity = 0;
}

static void *cte_vector_push(cte_vector *vector) {
    size_t old_size = vector->length * vector->element_size;
    size_t new_size = old_size + vector->element_size;
    while (new_size > vector->capacity) {
        cte_mmap_inc(&vector->front, &vector->capacity);
    }
    vector->length++;
    return vector->front + old_size;
}

CTE_ESSENTIAL
static void *cte_vector_get(cte_vector *vector, uint32_t idx) {
    if (vector->length <= idx) {
        return 0;
    }
    return vector->front + vector->element_size * idx;
}

#define for_each_cte_vector(vector, elem)                    \
    for (elem = (vector)->front;                             \
         (void*)elem < (vector)->front + ((vector)->element_size) * (vector)->length; \
         elem = (void*) elem + ((vector)->element_size))

static int cte_sort_compare_function(const void *e1, const void *e2) {
    cte_function *a = (cte_function*)e1;
    cte_function *b = (cte_function*)e2;

    // Zeroed out cte_functions go to the end of the list
    if (a->vaddr == NULL) return 1;
    if (b->vaddr == NULL) return -1;

    if (a->vaddr > b->vaddr) return  1;
    if (a->vaddr < b->vaddr) return -1;
    return 0;
}

CTE_ESSENTIAL
static void *cte_align_to_page(void *addr) {
    static size_t page_size = 0;
    if (page_size == 0) {
        page_size = sysconf(_SC_PAGESIZE);
    }
    return (void*)((size_t)addr & ~(page_size - 1));
}

static void *cte_get_vaddr(struct dl_phdr_info *info, uintptr_t addr) {
    return (void*)((uintptr_t)info->dlpi_addr + addr);
}

CTE_ESSENTIAL
static int cte_find_compare_function(const void *addr, const void *element) {
    cte_function *el = (cte_function*)element;
    if (addr == el->vaddr)
        return 0;
    if (addr < el->vaddr)
        return -1;
    else
        return 1;
}

CTE_ESSENTIAL
static int cte_find_compare_in_function(const void *post_call_addr,
                                        const void *element) {
    // Note that pos_call_addr is the address after the call in the caller.
    cte_function *el = (cte_function*)element;
    if (post_call_addr > el->vaddr &&
        (uint8_t*)post_call_addr <= ((uint8_t*)el->vaddr + el->size))
        return 0;
    if (post_call_addr <= el->vaddr)
        return -1;
    else
        return 1;
}


CTE_ESSENTIAL
static
void cte_implant_init(cte_implant *ptr, unsigned _func_idx) {
    // If there cte_restore is close enough, we call it directly
    ptrdiff_t diff = (void*) cte_restore_entry - ((void*)ptr + 12);
    if (INT_MIN < diff  && diff < INT_MAX) {
        for (unsigned i = 0; i < 7; i++)
            ptr->call.nop[i] = 0x90; // nop
        ptr->call.call[0] = 0xe8;
        ptr->call.offset  = diff;
    } else {
        ptr->icall.mov[0] = 0x48; /* 64bit prefix */
        ptr->icall.mov[1] = 0xb8; /* absmov to %rax  */
        ptr->icall.mov_imm = (uint64_t)cte_restore_entry;
        ptr->icall.icall[0] = 0xff; /* call *%rax */
        ptr->icall.icall[1] = 0xd0;
    }
    ptr->func_idx = (_func_idx);
}

CTE_ESSENTIAL
static
bool cte_implant_valid(cte_implant *ptr) {
    // Is it a direct call?
    if (ptr && ptr->call.call[0] == 0xe8 &&
        ptr->call.offset == (void*) cte_restore_entry - ((void*)ptr + 12)) {
        return true;
    }
    // Is it an indirect call?
    if (ptr && (ptr->icall.mov[0] == 0x48) && (ptr->icall.mov[1] == 0xb8) && (ptr->icall.mov_imm == (uint64_t)cte_restore_entry)
        && (ptr->icall.icall[0] == 0xff) && (ptr->icall.icall[1] == 0xd0)) {
        return true;
    }

    return false;
}


CTE_ESSENTIAL
static cte_function *cte_find_function(void* addr) {
    return bsearch(addr, functions.front, functions.length,
                   sizeof(cte_function), cte_find_compare_function);
}

CTE_ESSENTIAL
static cte_function *cte_get_function(size_t index) {
    return cte_vector_get(&functions, index);
}

CTE_ESSENTIAL
static cte_function *cte_find_containing_function(void *addr) {
    return bsearch(addr, functions.front, functions.length,
                   sizeof(cte_function), cte_find_compare_in_function);
}

CTE_ESSENTIAL
static inline
char cte_func_state(cte_function *func) {
    cte_implant *implant = func->vaddr;
    if (*(uint8_t *)implant == 0xcc)
        return CTE_KILL;
    if (func->size >= sizeof(cte_implant)) {
        if (cte_implant_valid(implant))
            return CTE_WIPE;
    }
    return CTE_LOAD;
}

static bool cte_is_plt(void *addr) {
    cte_plt *plt;
    for_each_cte_vector(&plts, plt) {
        if (addr >= plt->vaddr && addr < plt->vaddr + plt->size)
            return true;
    }
    return false;
}

/* Visited Flags per function.

   We have to perform several (limited) depth-first searches on the
   functions. For this, we require a visited. As resetting the flag
   for each serch takes too long, we use a flag vector with one 16-bit
   counter per function. Each time, we perform a new search, we
   increment the current visited mark.
 */
static __thread uint16_t *visited_flags;
static __thread uint16_t functions_visited_flag;
#define FUNCTIONS_VISITED_FLAG_MAX ((1 << (sizeof(functions_visited_flag) * 8)) - 1)

static void cte_reset_visited_flags(void) {
    
    if (visited_flags && (functions_visited_flag < FUNCTIONS_VISITED_FLAG_MAX)) {
        // This is the common/hot path
        functions_visited_flag++;
    } else { // Cold path an Initialize
        if (!visited_flags)
            visited_flags = malloc(sizeof(*visited_flags) * functions.length);
        functions_visited_flag  = 1;
        cte_memset(visited_flags, 0, sizeof(*visited_flags) * functions.length);
    }
}
#define cte_is_visited(fn)  (visited_flags[func_id(fn)] == functions_visited_flag)
#define cte_set_visited(fn) do { visited_flags[func_id(fn)] = functions_visited_flag; } while(0)


static void *cte_meta_decode_vaddr(cte_meta_function *fn) {
    void *addr = fn->vaddr;
    if (fn->flags & FLAG_EXTERN_REF)
        addr = *((void**)addr);

    while (cte_is_plt(addr)) { // Multi-level plt indirections exist!
        uint8_t *a = (uint8_t*)addr;
        if (a[0] != 0xff)
            return NULL;
        if (a[1] != 0x25)
            return NULL;
        uint8_t *rip = a + 6;
        uint32_t offset = *((uint32_t*)(a + 2));
        uintptr_t *got_entry = (uintptr_t*)(rip + offset);
        addr = (void*)(*got_entry);
    }
    return addr;
}

static cte_meta_header *cte_meta_init(void *data, size_t size,
                                      void *load_addr, char *filename) {
    if (size < sizeof(cte_meta_header))
        cte_die("Invalid meta info: %s\n", filename);

    cte_meta_header *header = data;
    if (strcmp(header->magic, "CTE"))
        cte_die("Invalid meta info: %s\n", filename);

    if (header->version != CTE_VERSION)
        cte_die("%s: Unexpected meta info version: %u (expected: %u)\n",
                filename, header->version, CTE_VERSION);

    if (size != header->size)
        cte_die("Corrupt meta info: %s\n", filename);

    if (size < (sizeof(cte_meta_header) +
                header->functions_count * sizeof(cte_meta_function)))
        cte_die("Corrupt meta info: %s\n", filename);

    cte_meta_function *fn_start = (void*)((uint8_t*)data +
                                          sizeof(cte_meta_header));
    cte_meta_function *fn_end = fn_start + header->functions_count;

#define ADDR_OFFSET(base, offset) \
    ((void*)((uintptr_t)(base) + (uintptr_t)(offset)))

    for (cte_meta_function *fn = fn_start; fn < fn_end; fn++) {
        fn->vaddr = ADDR_OFFSET(load_addr, fn->vaddr);

        if (fn->callees)
            fn->callees = ADDR_OFFSET(data, fn->callees);
        if (fn->jumpees)
            fn->jumpees = ADDR_OFFSET(data, fn->jumpees);
        if (fn->siblings)
            fn->siblings = ADDR_OFFSET(data, fn->siblings);

        if ((fn->callees && ((void*)&fn->callees[fn->callees_count] > data + size)) ||
            (fn->jumpees && ((void*)&fn->jumpees[fn->jumpees_count] > data + size)) ||
            (fn->siblings && ((void*)&fn->siblings[fn->siblings_count] > data + size)))
            cte_die("Corrupt meta info\n");
    }
#undef ADDR_OFFSET

    return header;
}

static cte_meta_header *cte_meta_load(char *objname, void *load_addr) {
    char filename[256];
    strcpy(filename, objname);
    strcat(filename, ".cte");

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        printf("Warning: Could not open %s\n", filename);
        return NULL;
    }
    struct stat sb;
    fstat(fd, &sb);

    size_t size = sb.st_size;
    char *data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED)
        cte_die("mmap failed: %s\n", filename);
    close(fd);
    stat(objname, &sb);
    printf("disk,%s,%lu,%lu\n", filename, size, sb.st_size);

    return cte_meta_init(data, size, load_addr, filename);
}

typedef struct cte_pset {
    uint32_t *front;
    size_t length;
} cte_pset;

static const cte_pset EMPTY_PSET;

static void cte_pset_insert(cte_pset *pset, uint32_t item) {
    for (size_t n = 0; n < pset->length; n++) {
        if (pset->front[n] == item)
            return;
    }
    size_t offset = pset->length++;
    pset->front = realloc(pset->front, pset->length * sizeof(uint32_t));
    pset->front[offset] = item;
}

static void cte_pset_free(cte_pset *pset) {
    free(pset->front);
}


static void cte_meta_propagate_jumpees(cte_function *fn, cte_pset *pset) {
    if (!fn || !fn->meta || cte_is_visited(fn))
        return;
    cte_set_visited(fn);

    for (uint32_t i = 0; i < fn->meta->jumpees_count; i++) {
        cte_pset_insert(pset, fn->meta->jumpees[i]);
        cte_function *jumpee = cte_get_function(fn->meta->jumpees[i]);
        cte_meta_propagate_jumpees(jumpee, pset);
    }
}

static void cte_meta_propagate_address_taken(cte_function *fn) {
    if (cte_is_visited(fn))
        return;
    cte_set_visited(fn);

    for (uint32_t i = 0; i < fn->meta->jumpees_count; i++) {
        cte_function *jumpee = cte_get_function(fn->meta->jumpees[i]);
        if (jumpee && jumpee->meta) {
            cte_meta_propagate_address_taken(jumpee);
            jumpee->meta->flags |= FLAG_ADDRESS_TAKEN;
        }
    }
}

static void cte_meta_assign_global_indices(cte_meta_function *meta_fns,
                                           uint32_t *indices,
                                           uint32_t *indices_count) {
    uint32_t i = 0;
    while (i < *indices_count) {
        cte_function *fn = cte_find_function(meta_fns[indices[i]].vaddr);
        if (fn) {
            indices[i] = fn - (cte_function*)functions.front;
            i++;
        } else {
            (*indices_count)--;
            indices[i] = indices[*indices_count];
        }
    }
}

static void cte_meta_assign(void) {
    cte_text *text;
    cte_function *fn;

    // Decode all functions
    // FIXME: requires env BIND_NOW set
    for_each_cte_vector(&texts, text) {
        if (!text->meta)
            continue;
        cte_meta_function *start = cte_meta_get_functions(text->meta);
        cte_meta_function *end = start + text->meta->functions_count;
        for (cte_meta_function *meta = start; meta < end; meta++) {
            void *org_addr = meta->vaddr;
            meta->vaddr = cte_meta_decode_vaddr(meta);
            cte_function *fn = cte_find_function(meta->vaddr);
            if (!fn) {
                // Ignore VDSO functions
                if (meta->vaddr >= vdso_start &&
                    meta->vaddr < vdso_start + vdso_size)
                    continue;

                printf("Warning: Function not found: [%s] %p (<text>+%p) -> %p\n",
                       text->filename, org_addr,
                       (void*)(org_addr - text->vaddr), meta->vaddr);
                continue;
            }

            if (fn->meta) {
                if (fn->meta->flags & FLAG_DEFINITION) {
                    fn->meta->flags |= meta->flags & FLAG_ADDRESS_TAKEN;
                } else {
                    meta->flags |= fn->meta->flags & FLAG_ADDRESS_TAKEN;
                    fn->meta = meta;
                }
            } else {
                fn->meta = meta;
            }
            if (meta->flags & FLAG_DEFINITION) {
                // Update size according to meta info
                fn->size = meta->size;
            }
        }
    }


    // Update callee, jumpee and sibling indices to global function indices
    for_each_cte_vector(&texts, text) {
        if (!text->meta)
            continue;
        cte_meta_function *start = cte_meta_get_functions(text->meta);
        cte_meta_function *end = start + text->meta->functions_count;
        for (cte_meta_function *meta = start; meta < end; meta++) {
            cte_meta_assign_global_indices(start, meta->callees,
                                           &meta->callees_count);
            cte_meta_assign_global_indices(start, meta->jumpees,
                                           &meta->jumpees_count);
            cte_meta_assign_global_indices(start, meta->siblings,
                                           &meta->siblings_count);
        }
    }

    // Check if all fns have a .meta member and its definition flag set
    for_each_cte_vector(&functions, fn) {
        cte_text *text = cte_vector_get(&texts, fn->text_idx);
        if (!fn->meta)
            printf("Warning: Meta info not found: [%s] %s\n",
                   text->filename, fn->name);
        else if (!(fn->meta->flags & FLAG_DEFINITION))
            printf("Warning: Meta info function definition not found: [%s] %s\n",
                   text->filename, fn->name);
    }

    // Propagate FLAG_ADDRESS_TAKEN
    cte_reset_visited_flags();
    for_each_cte_vector(&functions, fn) {
        if (fn->meta && (fn->meta->flags & FLAG_ADDRESS_TAKEN))
            cte_meta_propagate_address_taken(fn);
    }

    // Propagate callees and copy meta objects
    uint8_t *data = NULL;
    size_t data_capacity = 0;
    size_t data_size = 0;
    for_each_cte_vector(&functions, fn) {
        if (!fn->meta)
            continue;

        // Propagate and gather all callees from jumpees
        cte_pset set = EMPTY_PSET;
        cte_reset_visited_flags();
        for (uint32_t i = 0; i < fn->meta->callees_count; i++) {
            cte_pset_insert(&set, fn->meta->callees[i]);
            cte_function *cfn = cte_get_function(fn->meta->callees[i]);
            if (!cfn)
                continue;
            cte_meta_propagate_jumpees(cfn, &set);
        }

        // Allocate and initialize a new meta object
        size_t i_meta = data_size;
        size_t i_callees = i_meta + sizeof(cte_meta_function);
        size_t i_jumpees = i_callees + set.length * sizeof(uint32_t);
        size_t i_siblings = i_jumpees + fn->meta->jumpees_count * sizeof(uint32_t);
        data_size = i_siblings + fn->meta->siblings_count * sizeof(uint32_t);
        while (data_size > data_capacity) {
            cte_mmap_inc((void*)(&data), &data_capacity);
        }

        cte_meta_function *meta = (cte_meta_function*)(&data[i_meta]);
        uint32_t *callees = (uint32_t*)(&data[i_callees]);
        uint32_t *jumpees = (uint32_t*)(&data[i_jumpees]);
        uint32_t *siblings = (uint32_t*)(&data[i_siblings]);
        *meta = *fn->meta;
        memcpy(callees, set.front, set.length * sizeof(uint32_t));
        meta->callees_count = set.length;
        memcpy(jumpees, fn->meta->jumpees,
               fn->meta->jumpees_count * sizeof(uint32_t));
        memcpy(siblings, fn->meta->siblings,
               fn->meta->siblings_count * sizeof(uint32_t));
        cte_pset_free(&set);
    }


    // Assign newly created meta objects to the functions
    size_t data_idx = 0;
    for_each_cte_vector(&functions, fn) {
        if (!fn->meta)
            continue;
        size_t i_meta = data_idx;
        cte_meta_function *meta = (cte_meta_function*)(&data[i_meta]);
        size_t i_callees = i_meta + sizeof(cte_meta_function);
        size_t i_jumpees = i_callees + meta->callees_count * sizeof(uint32_t);
        size_t i_siblings = i_jumpees + meta->jumpees_count * sizeof(uint32_t);
        data_idx = i_siblings + meta->siblings_count * sizeof(uint32_t);
        meta->callees = (uint32_t*)(&data[i_callees]);
        meta->jumpees = (uint32_t*)(&data[i_jumpees]);
        meta->siblings = (uint32_t*)(&data[i_siblings]);
        fn->meta = meta;
    }

    // Propagate indirect jumps
    for_each_cte_vector(&functions, fn) {
        if (!fn->meta)
            continue;
        for (uint32_t i = 0; i < fn->meta->callees_count; i++) {
            cte_function *cf = cte_get_function(fn->meta->callees[i]);
            if (cf && cf->meta && cf->meta->flags & FLAG_INDIRECT_JUMPS)
                fn->meta->flags |= FLAG_INDIRECT_CALLS;
        }
        for (uint32_t i = 0; i < fn->meta->siblings_count; i++) {
            cte_function *sf = cte_get_function(fn->meta->siblings[i]);
            if (sf && sf->meta && sf->meta->flags & FLAG_INDIRECT_JUMPS)
                fn->meta->flags |= FLAG_INDIRECT_CALLS;
        }
    }

    // Write protect meta info
    if (mprotect(data, data_capacity, PROT_READ) == -1)
        cte_die("Meta: %s: sealing failed\n", text->filename);

    // Unmap original meta files
    for_each_cte_vector(&texts, text) {
        if (!text->meta)
            continue;
        if (munmap(text->meta, text->meta->size) < 0)
            cte_die("Meta: %s: unmap failed\n", text->filename);
        text->meta = NULL;
    }

#if CONFIG_STAT
    // Output statistics
    uint64_t c_total_fns = functions.length;
    uint64_t c_meta_fns = 0;
    uint64_t c_address_taken_fns = 0;
    uint64_t c_indirect_calls_fns = 0;
    uint64_t c_total_callees = 0;
    uint64_t c_total_siblings = 0;
    uint64_t c_max_callees = 0;
    uint64_t c_max_siblings = 0;
    cte_function *fn_max_callees = NULL;
    cte_function *fn_max_siblings = NULL;
    for_each_cte_vector(&functions, fn) {
        if (!fn->meta)
            continue;
        c_meta_fns++;
        c_address_taken_fns += (fn->meta->flags & FLAG_ADDRESS_TAKEN) ? 1 : 0;
        c_indirect_calls_fns += (fn->meta->flags & FLAG_INDIRECT_CALLS) ? 1 : 0;
        c_total_callees += fn->meta->callees_count;
        c_total_siblings += fn->meta->siblings_count;
        if (fn->meta->callees_count > c_max_callees) {
            c_max_callees = fn->meta->callees_count;
            fn_max_callees = fn;
        }
        if (fn->meta->siblings_count > c_max_siblings) {
            c_max_siblings = fn->meta->siblings_count;
            fn_max_siblings = fn;
        }
    }
    printf("Meta: total_fns: %lu\n", c_total_fns);
    printf("Meta: meta_fns:  %lu\n", c_meta_fns);
    printf("Meta: address_taken_fns:  %lu\n", c_address_taken_fns);
    printf("Meta: indirect_calls_fns: %lu\n", c_indirect_calls_fns);
    printf("Meta: avg_callees:  %f\n", (float)c_total_callees / c_meta_fns);
    printf("Meta: avg_siblings: %f\n", (float)c_total_siblings / c_meta_fns);
    printf("Meta: max_callees:  %lu (%s)\n", c_max_callees, fn_max_callees->name);
    printf("Meta: max_siblings: %lu (%s)\n", c_max_siblings, fn_max_siblings->name);
    printf("ram,data,%lu\n", data_capacity);
#endif
}

static
Elf * cte_elf_begin(int fd) {
    if (elf_version(EV_CURRENT) == EV_NONE)
        return NULL;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        return NULL;

    if (elf_kind(elf) != ELF_K_ELF) {
        elf_end(elf);
        return NULL;
    }
    return elf;
}

static unsigned
cte_elf_scan_symbols(Elf *elf, cte_text * text, ElfW(Addr) dlpi_addr) {
    unsigned ret = 0;
    // Collect Symbols
    Elf_Scn* section = NULL;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(section , &shdr) != &shdr)
            return 0;

        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            Elf_Data *data = elf_getdata(section, NULL);
            int sym_count = shdr.sh_size / shdr.sh_entsize;
            for (int i = 0; i < sym_count; ++i) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                char *name = strdup(elf_strptr(elf, shdr.sh_link, sym.st_name));

                // Only defined functions
                if (sym.st_shndx == SHN_UNDEF)
                    continue;
                if (GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
                    GELF_ST_TYPE(sym.st_info) != STT_GNU_IFUNC)
                    continue;

                void *vaddr = (void*)((uintptr_t)dlpi_addr + sym.st_value);
                if (vaddr < text->vaddr || vaddr >= text->vaddr + text->size)
                    continue;

                // Ignore plt entries
                if (cte_is_plt(vaddr))
                    continue;

                cte_function f = {
                    .text_idx  = text - (cte_text *)texts.front,
                    .name      = name,
                    .size      = sym.st_size,
                    .vaddr     = vaddr,
                    .body      = NULL,
                    .meta      = NULL,
                    .essential = false,
                    .sibling_idx = FUNC_ID_INVALID,
                };

                // Push Function
                cte_function *fs = cte_vector_push(&functions);
                *fs = f;
                ret ++;
            }
        }
    }
    return ret;
}

cte_rules *cte_rules_init(cte_wipe_policy def) {
    cte_rules* ret = malloc(sizeof(cte_rules) + sizeof(cte_wipe_policy) * functions.length);
    ret->length = functions.length;
    for (unsigned i = 0; i < functions.length; i++)
        ret->policy[i] = def;
    return ret;
}

void cte_rules_free(cte_rules *rules) {
    free(rules);
}

unsigned cte_rules_set(cte_rules *rules, cte_wipe_policy policy) {
    unsigned ret = 0;
    for (unsigned i = 0; i < rules->length; i++) {
        if (!(rules->policy[i] & CTE_SYSTEM_FORCE)) {
            rules->policy[i] = policy;
            ret++;
        }
    }
    return ret;
}

static void
cte_rules_set_func_0(cte_rules *rules, cte_wipe_policy policy, cte_function* func) {
    // cte_printf("mark %s with %d\n", func->name, policy);
    if (!(rules->policy[func_id(func)] & CTE_FORCE)) {
        rules->policy[func_id(func)] = policy;
    }
}

static
unsigned cte_rules_set_func_1(cte_rules *rules, cte_wipe_policy policy, cte_function *func) {
    unsigned ret = 0;
    unsigned func_stack_max = 0;
    unsigned idx = 0;
    cte_function **func_stack = NULL;

#define func_stack_push(func) do {       \
        if (idx + 1 >= func_stack_max) { \
            func_stack_max += 10;        \
            func_stack = realloc(func_stack, sizeof(cte_function *) * func_stack_max);\
        }                                \
        func_stack[idx ++] = func;       \
    } while(0)

    func_stack_push(func);

    while(idx > 0) {
        cte_function *cur = func_stack[--idx]; // pop
        cte_rules_set_func_0(rules, policy, cur);
        cte_set_visited(cur);

        ret++;

        for (unsigned i = 0; i < cur->meta->callees_count; i++) {
            cte_function *f = cte_vector_get(&functions, cur->meta->callees[i]);
            if (f && !cte_is_visited(f))
                func_stack_push(f);
        }
        for (unsigned i = 0; i < cur->meta->jumpees_count; i++) {
            cte_function *f = cte_vector_get(&functions, cur->meta->jumpees[i]);
            if (f && !cte_is_visited(f))
                func_stack_push(f);
        }
        for (unsigned i = 0; i < cur->meta->siblings_count; i++) {
            cte_function *f = cte_vector_get(&functions, cur->meta->siblings[i]);
            if (f && !cte_is_visited(f))
                func_stack_push(f);
        }
    }
#undef func_stack_push
//     cte_printf("Max Stack Depth %d\n", func_stack_max);
    free(func_stack);

    return ret;
}

unsigned cte_rules_set_func(cte_rules *rules, cte_wipe_policy policy, void *fptr, char children) {
    unsigned ret = 0;

    // Find the argument function
    cte_function *func = cte_find_function(fptr);
    if (! func) return 0;

    if (children) {
        cte_reset_visited_flags();
        ret += cte_rules_set_func_1(rules, policy, func);
    } else {
        cte_rules_set_func_0(rules, policy, func);
    }
 
    return ret;
}

unsigned cte_rules_set_funcname(cte_rules *rules, cte_wipe_policy policy, char *pat, char children) {
    unsigned ret = 0;
    cte_function *fn;
    // cte_printf("Pat: %s %d\n", pat, children);
    if (children)
        cte_reset_visited_flags();

    for_each_cte_vector(&functions, fn) {
        if (fnmatch(pat, fn->name, 0) == 0) {
            if (children)
                ret += cte_rules_set_func_1(rules, policy, fn);
            else {
                cte_rules_set_func_0(rules, policy, fn);
                ret += 1;
            }
        }
    }


    return ret;
}

unsigned cte_rules_set_indirect(cte_rules *rules, cte_wipe_policy policy) {
    unsigned ret = 0;
    cte_function *fn;

    cte_reset_visited_flags();
    
    for_each_cte_vector(&functions, fn) {
        if (fn->meta && fn->meta->flags & FLAG_ADDRESS_TAKEN)
            ret += cte_rules_set_func_1(rules, policy, fn);
    }

    return ret;
}

static
void cte_handle_build_id(struct dl_phdr_info *info, cte_text *text, int j) {
    struct build_id_note *build_id = NULL;
    struct build_id_note *note = (void *)(info->dlpi_addr +
                                          info->dlpi_phdr[j].p_vaddr);
    ptrdiff_t len = info->dlpi_phdr[j].p_filesz;
    
    while (len >= (int)sizeof(struct build_id_note)) {
        if (note->nhdr.n_type == NT_GNU_BUILD_ID &&
            note->nhdr.n_descsz != 0 &&
            note->nhdr.n_namesz == 4 &&
            memcmp(note->name, "GNU", 4) == 0) {
            build_id = note;
            break;
        }

#define ALIGN(val, align)       (((val) + (align) - 1) & ~((align) - 1))
        size_t offset = sizeof(ElfW(Nhdr)) +
            ALIGN(note->nhdr.n_namesz, 4) +
            ALIGN(note->nhdr.n_descsz, 4);
#undef ALIGN
        note = (struct build_id_note *)((char *)note + offset);
        len -= offset;
    }

    // No build ID found
    if (!build_id) return;

    char filename[note->nhdr.n_descsz + 1 + 100];
    char *p = filename;
    p += cte_sprintf(p, "/usr/lib/debug/.build-id/%02x/", build_id->build_id[0]);

    for (unsigned i = 1; i < note->nhdr.n_descsz; i++) {
        p += cte_sprintf(p, "%02x", build_id->build_id[i]);
    }
    p += cte_sprintf(p, ".debug");

    // Open the debug file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return;

    Elf *elf = cte_elf_begin(fd);
    if (! elf) return;

    unsigned count = cte_elf_scan_symbols(elf, text, info->dlpi_addr);

    cte_printf("Loaded debug info with %d symbols (%s)\n", count, filename);

    elf_end (elf);
}

static int cte_callback(struct dl_phdr_info *info, size_t _size, void *data) {
    (void)_size;

    // Get the real object name
    char *filename = data;
    if (info->dlpi_name[0] != '\0')
        filename = (char*)info->dlpi_name;

    // Find the text segment
    void *text_vaddr = NULL;
    size_t text_size = 0;
    ElfW(Off) text_offset = 0;
    for (int j = 0; j < info->dlpi_phnum; j++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[j];
        if (phdr->p_type != PT_LOAD)
            continue;
        if (phdr->p_flags & PF_X) {
            if (text_vaddr)
                return CTE_ERROR_FORMAT;
            text_vaddr = cte_get_vaddr(info, phdr->p_vaddr);
            text_size = phdr->p_memsz;
            text_offset = phdr->p_offset;
            printf("segment: [%s] %p, %lu\n", filename, text_vaddr, text_size);
        }
    }

    if (!strcmp(filename, "linux-vdso.so.1")) {
        vdso_start = text_vaddr;
        vdso_size = text_size;
        return 0;
    }

    // Open the object file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        cte_die("[cte_init] Could not open file: %s (%s)\n", filename, info->dlpi_name);
        return 0;
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1)
        return CTE_ERROR_ELF;

    void *eaddr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (eaddr == MAP_FAILED)
        return CTE_ERROR_ELF;

    Elf *elf = cte_elf_begin(fd);
    if (!elf)
        return CTE_ERROR_ELF;

    // Get section header string table index
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        return CTE_ERROR_ELF;

    Elf_Scn *section;

    void *essential_sec_vaddr = NULL;
    size_t essential_sec_size = 0;

    section = NULL;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr shdr;
        char *name;
        if (gelf_getshdr(section, &shdr) != &shdr)
            return CTE_ERROR_ELF;
        if ((name = elf_strptr(elf, shstrndx, shdr.sh_name)) == NULL)
            return CTE_ERROR_ELF;

        if (strcmp(name, ".cte_essential") == 0) {
            essential_sec_vaddr = cte_get_vaddr(info, shdr.sh_addr);
            essential_sec_size = shdr.sh_size;
            printf("essential section: [%s] %s (%p, %lu)\n", filename, name,
                   essential_sec_vaddr, essential_sec_size);
        }
        if (strcmp(name, ".cte_essential") == 0) {
            cte_sealed_sec_vaddr = cte_get_vaddr(info, shdr.sh_addr);
            cte_sealed_sec_size = shdr.sh_size;
        }
        if (strcmp(name, ".plt") == 0 || strcmp(name, ".plt.got") == 0) {
            cte_plt *plt = cte_vector_push(&plts);
            *plt = (cte_plt) {
                .vaddr = cte_get_vaddr(info, shdr.sh_addr),
                .size = shdr.sh_size,
            };
        }
    }

    // Init meta data
    cte_meta_header *meta;
    if (strict_callgraph || strict_ctemeta)
        meta = cte_meta_load(filename, (void*)info->dlpi_addr);
    else
        meta = NULL;

    if (strict_ctemeta && meta == NULL ) {
        cte_die("CTE_STRICT_META: No meta file for %s\n", filename);
    }

    cte_text *text = cte_vector_push(&texts);
    uint32_t text_idx = (text - (cte_text *)texts.front);
    *text = (cte_text) {
        .filename = strdup(filename),
        .meta = meta,
        .vaddr = text_vaddr,
        .offset = text_offset,
        .size = text_size,
    };
#if CONFIG_STAT
    cte_stat.text_bytes += text_size;
#endif

    if(!text->filename)
        cte_die("strdup failed");

    // Collect ELF symbol info
    cte_elf_scan_symbols(elf, text, info->dlpi_addr);

    // Collect info from debug file, if build id is present
    // Read Symbols from debug info
    for (int j = 0; j < info->dlpi_phnum; j++) {
        if (info->dlpi_phdr[j].p_type == PT_NOTE) {
            cte_handle_build_id(info, text, j);
        }
    }

    // Step 1: Sort by vaddr
    qsort(functions.front, functions.length,
          sizeof(cte_function),
          cte_sort_compare_function);

    // Step 2: Mark essential functions, identify duplicates, identify plt functions
    size_t count = 0;
    cte_function *function = NULL, *it;
    for_each_cte_vector(&functions, it) {
        if (it->text_idx != text_idx) {
            count++;
            continue; // From previous library
        }

        if ((uint8_t*)it->vaddr + it->size > (uint8_t*)text->vaddr + text->size)
            cte_die("function exceeds text segment: %s\n", it->name);

        // Identify plt entry
        if (cte_is_plt(it->vaddr)) {
            // Zero out
            it->vaddr = NULL;
            continue;
        }

        // Identify Duplicates
        if (!function || function->vaddr != it->vaddr) {
            function = it;
            count++;
        } else {
            // Zero out duplicate
            it->vaddr = NULL;
            //cte_debug("duplicate: %s %s\n", function->name, it->name);
            continue;
        }

        // Function is an essential function?
        if (essential_sec_vaddr) {
            function->essential |= (it->vaddr >= essential_sec_vaddr) &&
                ((uint8_t*)it->vaddr < (uint8_t*)essential_sec_vaddr + essential_sec_size);
        }

        // Does this function have an essential name?
        struct { char begin; char *pattern; } names[] = {
            {0, "_start"}, {0, "__libc_start_main"}, {0, "main"}, {0, "syscall"}, {0, "start_thread"},
            {0, "__tls_get_addr_slow"}, {0, "__strcasecmp_l_avx"},
            // mprotect
            {0, "mprotect"}, {0, "pkey_mprotect"}, {0, "__mprotect"},
            // // memcpy
            // {0, "memcpy@GLIBC_2.2.5"}, {0, "__memcpy_avx_unaligned_erms"},
            // // memset
            // {1, "__memcmp"}, {1, "__memmove"}, {1, "__memset"}, {1, "__wmemset"}, {1, "__wmemchr"},
            // restore
            {0, "bsearch"},
#if CONFIG_THRESHOLD
            // threshold wiping
            {0, "__tls_get_addr"}, {0, "_dl_update_slotinfo"}, {0, "update_get_addr"},
#endif
            ////////////////////////////////////////////////////////////////
            // Disable Caller Validation for these functions

            // We disable callsite detection for the trampoline function
            // of dynamic loading, as its callsite is highly weird.
            // FIXME: Just improve the callsite detection?
            {2, "_dl_runtime_resolve_xsavec"},
            {3, "_dl_relocate_object"},

            // We do not validate the caller of sigreturn and exit
            {2, "__restore_rt"}, {2, "_dl_fini"}, {2, "_fini"}
        };
        for (unsigned i = 0; i < sizeof(names)/sizeof(*names); i++) {
            if (names[i].begin == 0 && strcmp(names[i].pattern, it->name) == 0) {
                function->essential |= true;
                break;
            }
            if (names[i].begin == 1 && strncmp(names[i].pattern, it->name, strlen(names[i].pattern)) == 0) {
                function->essential |= true;
                break;
            }
            if (names[i].begin == 2 && strcmp(names[i].pattern, it->name) == 0) {
                function->disable_caller_validation |= 1;
                break;
            }
            if (names[i].begin == 3 && strcmp(names[i].pattern, it->name) == 0) {
                function->disable_callee_validation |= 1;
                break;
            }
        }

        if (function->essential) {
            //cte_debug("essential: %s %d\n", it->name, function->essential);
        }
    }

    // Step 3: Sort by vaddr again and eliminate zeroed-out duplicates (truncate)
    qsort(functions.front, functions.length,
          sizeof(cte_function),
          cte_sort_compare_function);
    functions.length = count;

    // The function bodies are saved after all elfs have been read

    elf_end (elf);
    return 0;
}

CTE_ESSENTIAL
static void cte_modify_begin(void *start, size_t size) {
    uint8_t *stop = (uint8_t*)start + size;
    uint8_t *aligned_start = cte_align_to_page(start);
    size_t len = stop - aligned_start;
    mprotect(aligned_start, len, PROT_READ | PROT_WRITE | PROT_EXEC);
    // cte_printf("modify_begin: [%p-%p]%p-%p\n", start, stop, aligned_start, aligned_start+len);
}

CTE_ESSENTIAL
static void cte_modify_end(void *start, size_t size) {
    uint8_t *stop = (uint8_t*)start + size;
    uint8_t *aligned_start = cte_align_to_page(start);
    size_t len = stop - aligned_start;
    mprotect(aligned_start, len, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)aligned_start, (char*)stop);
    // cte_printf("modify_end: [%p-%p]%p-%p\n", start, stop, aligned_start, aligned_start+len);
}

#pragma GCC push_options
#pragma GCC optimize ("-fno-tree-loop-distribute-patterns")
__attribute__((noinline))
CTE_ESSENTIAL
static void *cte_memcpy(void *dst, const void *src,size_t n)
{
    size_t i;

    for (i=0;i<n;i++)
        *(char *) dst++ = *(char *) src++;
    return dst;
}
__attribute__((noinline))
CTE_ESSENTIAL
static void *cte_memset(void *dst, int pat, size_t n)
{
    size_t i;

    for (i=0;i<n;i++)
        *(char *) dst++ = (char)pat;
    return dst;
}
#pragma GCC pop_options


#if CONFIG_DEBUG
CTE_ESSENTIAL_USED
static void cte_debug_restore(void *addr, void *post_call_addr,
                              cte_function *function,
                              cte_function *caller) {
    cte_text *function_text = cte_vector_get(&texts, function->text_idx);
    cte_text *caller_text = NULL;
    char *caller_rel_name;
    uintptr_t caller_rel_offset;
    if (caller) {
        caller_text = cte_vector_get(&texts, caller->text_idx);
        caller_rel_name = caller->name;
        caller_rel_offset = post_call_addr - caller->vaddr;
    } else {
        // Find nearest text before post_call_addr
        cte_text *t = NULL;
        for_each_cte_vector(&texts, t) {
            if (t->vaddr > post_call_addr &&
                (!caller_text ||
                 post_call_addr - t->vaddr < post_call_addr - caller_text->vaddr))
                caller_text = t;
        }
        caller_rel_name = "??";
        caller_rel_offset = 0;
    }

    cte_printf("---------\n");
    cte_printf("Function %s (%p, %s [x+%p])\n",
               function->name, addr, function_text->filename,
               addr - function_text->vaddr);
    cte_printf("called before %s+%p (%p, %s [x+%p])\n",
               caller_rel_name, caller_rel_offset, post_call_addr,
               (caller_text) ? caller_text->filename : "??",
               (caller_text) ? (post_call_addr - caller_text->vaddr) : 0);

    if (caller && caller->meta) {
        cte_printf("Allowed callees (%d)\n", caller->meta->callees_count);
        for (uint32_t i = 0; i < caller->meta->callees_count; i++) {
            cte_function *cd = cte_get_function(caller->meta->callees[i]);
            cte_printf("  %p: %s\n", cd->vaddr, cd->name);
        }
    }
    cte_printf("---------\n");
}
#else
#define cte_debug_restore(addr, post_call_addr, function, caller)
#endif

typedef enum cte_callsite_type {
    CALLSITE_TYPE_DIRECT,
    CALLSITE_TYPE_INDIRECT,
    CALLSITE_TYPE_DIRECT_OR_INDIRECT,
    CALLSITE_TYPE_INVALID,
    CALLSITE_TYPE_SIGRETURN, 
} cte_callsite_type;

CTE_ESSENTIAL
static cte_callsite_type cte_decode_callsite(void *post_call_addr) {

    // Decode the instruction callsite.
    // We only have the post-call address (aka return address).
    // Since x86 has variable instruction lengths,
    // we sometimes cannot say exactly what the previous instrucion is.

    unsigned char *b = post_call_addr;
    bool indirect = false;
    bool direct = false;
    bool signal = false;

#define EXT_MOD(ob) ((ob >> 6) & 0x03)
#define EXT_REG(ob) ((ob >> 3) & 0x07)
#define EXT_RM(ob) (ob & 0x07)

    if (b[-2] == 0xff && EXT_REG(b[-1]) == 2 &&
        ((EXT_MOD(b[-1]) == 3) ||
         (EXT_MOD(b[-1]) == 0 && EXT_RM(b[-1]) != 4))) {
        indirect = true;
    }
    if (b[-3] == 0xff && EXT_REG(b[-2]) == 2 &&
        ((EXT_MOD(b[-2]) == 0 && EXT_RM(b[-2]) == 4) ||
         (EXT_MOD(b[-2]) == 1 && EXT_RM(b[-2]) != 4))) {
        indirect = true;
    }
    if (b[-4] == 0xff && EXT_REG(b[-3]) == 2 &&
        (EXT_MOD(b[-3]) == 1 && EXT_RM(b[-3]) == 4)) {
        indirect = true;
    }
    if (b[-6] == 0xff && EXT_REG(b[-5]) == 2 &&
        ((EXT_MOD(b[-5]) == 0 && (EXT_RM(b[-5]) == 4 || EXT_RM(b[-5]) == 5)) ||
         (EXT_MOD(b[-5]) == 2 && EXT_RM(b[-5]) != 4))) {
        indirect = true;
    }
    if (b[-7] == 0xff && EXT_REG(b[-6]) == 2 &&
        (EXT_MOD(b[-6]) == 2 && EXT_RM(b[-6]) == 4)) {
        indirect = true;
    }
    // GCC does not use far indirect calls (EXT_MOD=3)

    // direct call
    if (b[-5] == 0xe8)
        direct = true;
    // GCC does not use the callf instruction (Opcode 0x9a)

    if (!(indirect || direct)) {
        // It could be the signal handler resturn after our return.
        cte_function* f = cte_find_function(post_call_addr);
        // cte_printf("Return to Function Entry: %p\n", post_call_addr);
        if (f && cte_func_state(f) == CTE_WIPE) {
            b = f->body;
        }

        if (/* mov 0xf, rax */
            b[0] == 0x48 && b[1] == 0xc7 && b[2] == 0xc0 && b[3] == 0x0f
            && b[4] == 0    && b[5] == 0    && b[6] == 0
            /* syscall */
            && b[7] == 0xf  && b[8] == 0x05) {
            signal = true;
        }
    }

    if (indirect && direct)
        return CALLSITE_TYPE_DIRECT_OR_INDIRECT;
    if (indirect)
        return CALLSITE_TYPE_INDIRECT;
    if (direct)
        return CALLSITE_TYPE_DIRECT;
    if (signal)
        return CALLSITE_TYPE_SIGRETURN;

    return CALLSITE_TYPE_INVALID;

#undef EXT_REG
#undef EXT_MOD
#undef EXT_RM
}

CTE_ESSENTIAL
static bool cte_check_call(void* called_addr, cte_function *callee,
                           cte_function *caller) {
    if ((strict_callgraph && !caller->meta) ||
        !(caller->meta->flags & FLAG_DEFINITION)) {
        cte_printf("Invalid caller meta info: %s\n", caller->name);
        return false;
    }

    if ((caller->meta->flags & FLAG_INDIRECT_CALLS) &&
        (callee->meta && (callee->meta->flags & FLAG_ADDRESS_TAKEN))) {
        return true;
    }

    // A caller function was found, and it has .meta set
    // Let's see if we are allowed to call function f
    for (uint32_t i = 0; i < caller->meta->callees_count; i++) {
        cte_function *callee = cte_get_function(caller->meta->callees[i]);
        if (callee->vaddr == called_addr)
            return true;
    }

    return false;
}

CTE_ESSENTIAL_USED __attribute__((__visibility__("hidden")))
int cte_restore(void *addr, void *post_call_addr) {
#if CONFIG_STAT
    struct timespec ts0;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts0) == -1) cte_die("clock_gettime");
    cte_get_stat()->restore_count += 1;
#endif

    cte_implant *implant = addr;
    if (!cte_implant_valid(implant))
        cte_die("cte_restore called from invalid implant\n");

    // Find the called function
    cte_function *f = cte_vector_get(&functions, implant->func_idx);
    if(!f)
        cte_die("Could not find function with id %d (max_id=%d)\n",
                implant->func_idx, functions.length);


    /*
    cte_function *f2 = cte_find_function(implant);
    if (f != f2)
        cte_die("Bsearch yielded a different result...\n");
    */



    if (!f->disable_caller_validation) {
        cte_callsite_type type = cte_decode_callsite(post_call_addr);
        if (type == CALLSITE_TYPE_INVALID) {
            cte_printf("WARNING: Invalid Callsite (callee %s): ", f->name);
            unsigned char *s = post_call_addr;
            for (unsigned char *b = s - 16; b < s; b++)
                cte_printf("%x ", *b);
            cte_printf(" <RETADDR %p>", s);
            for (unsigned char *b = s; b < s+16; b++)
                cte_printf(" %x", *b);
            cte_printf("\n");
            cte_debug_restore(addr, post_call_addr, f,
                              cte_find_containing_function(post_call_addr));
            cte_printf("\n");
            cte_die("Invalid Callsite at: %p\n", post_call_addr);
        }

        if (strict_callgraph
            && type != CALLSITE_TYPE_SIGRETURN) {
            // Find the caller
            cte_function *cf = cte_find_containing_function(post_call_addr);
            if (!cf) {
                cte_debug_restore(addr, post_call_addr, f, cf);
                // If unknown caller comes from a known library=> fail
                // FIXME: One would validate if the calle comes from another library
                cte_text *text;
                for_each_cte_vector(&texts, text) {
                    if (text->vaddr <= post_call_addr && post_call_addr < (text->vaddr+text->size))
                        cte_die("Caller not found: %p->%s\n", post_call_addr, f->name);
                }
            } else if (!cte_check_call(addr, f, cf) && !cf->disable_callee_validation) {
                // Failed to find the callee
                cte_debug_restore(addr, post_call_addr, f, cf);
                cte_die("Unrecognized callee (%s->%s)\n", cf->name, f->name);
            }
        }
    }

    // cte_printf("-> load: %s\n", f->name);
    // Load the called function

    cte_modify_begin(addr, f->size);
    cte_memcpy(addr, f->body, f->size);
    cte_modify_end(addr, f->size);
#if CONFIG_STAT
    cte_get_stat()->cur_wipe_count -= 1;
    cte_get_stat()->cur_wipe_bytes -= f->size;
#endif

#if CONFIG_THRESHOLD
    struct cte_wipestat *wipestat = cte_get_wipestat();
#endif

    // Load the sibling
    if (f->meta) {
        for (uint32_t i = 0; i < f->meta->siblings_count; i++) {
            cte_function *func_sibling = cte_get_function(f->meta->siblings[i]);
            if (cte_func_state(func_sibling) != CTE_LOAD) {
                // cte_printf("-> load sibling: %s\n", func_sibling->name);
                cte_modify_begin(func_sibling->vaddr, func_sibling->size);
                cte_memcpy(func_sibling->vaddr, func_sibling->body, func_sibling->size);
                cte_modify_end(func_sibling->vaddr, func_sibling->size);

#if CONFIG_STAT
                cte_get_stat()->cur_wipe_count -= 1;
                cte_get_stat()->cur_wipe_bytes -= func_sibling->size;
#endif
#if CONFIG_THRESHOLD
                if (wipestat) wipestat[func_id(func_sibling)].restore++;
#endif

            }
        }
    } else {
        if (f->sibling_idx != FUNC_ID_INVALID) { // We have a sibling:
            cte_function *func_sibling = cte_vector_get(&functions, f->sibling_idx);
            if (cte_func_state(func_sibling) != CTE_LOAD) {
                // cte_printf("-> load sibling: %s\n", func_sibling->name);
                cte_modify_begin(func_sibling->vaddr, func_sibling->size);
                cte_memcpy(func_sibling->vaddr, func_sibling->body, func_sibling->size);
                cte_modify_end(func_sibling->vaddr, func_sibling->size);

#if CONFIG_STAT
                cte_get_stat()->cur_wipe_count -= 1;
                cte_get_stat()->cur_wipe_bytes -= func_sibling->size;
#endif
#if CONFIG_THRESHOLD
                if (wipestat) wipestat[func_id(func_sibling)].restore++;
#endif

            }
        }
    }
#if CONFIG_THRESHOLD
    if (wipestat) wipestat[func_id(f)].restore ++;
#endif

#if CONFIG_STAT
    struct timespec ts;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts) == -1) cte_die("clock_gettime");

    uint64_t restore_time = timespec_diff_ns(ts0, ts);
    cte_get_stat()->restore_time += restore_time;
    cte_get_stat()->restore_times[func_id(f)] = timespec_diff_ns(cte_get_stat()->last_wipe_timestamp, ts);
#endif

    return 0;
}


CTE_ESSENTIAL
static int cte_wipe_fn(cte_function *fn, cte_wipe_policy policy) {
    cte_implant *implant = fn->vaddr;
    // FIXME: This should actually load the function
    if (policy == CTE_LOAD)
        cte_die("Policy CTE_LOAD is not yet implemented");

    // CTE_WIPE|CTE_KILL: Wipe the whole function body
    if (policy == CTE_KILL) {
        if (fn->size < 1) { // We need at last 1 byte to wipe it
            return 0;
        }
        cte_memset(fn->vaddr,
                   0xcc, // int3 int3 int3...
                   fn->size);
        return 1;
    } else if (policy == CTE_WIPE ) {
        if (fn->size < sizeof(cte_implant)) {
            cte_text *text = cte_vector_get(&texts, fn->text_idx);
            if(!text) cte_die("idiot");
            cte_debug("function %s/%s not large enough for implant (%d < %d)\n",
                      text->filename, fn->name, fn->size, sizeof(cte_implant));
            return 0;
        }
        cte_memset(fn->vaddr,
                   0xcc, // int3 int3 int3...
                   fn->size);
        // FIXME: rax not preserved -> Cannot be fixed without library local tramploline
        cte_implant_init(implant, func_id(fn));
    } else {
        cte_die("Invalid Wipe mode: %s mode=%d\n", fn->name, policy);
    }

    return 1;
}

int cte_init(int flags) {
#if CONFIG_STAT
    struct timespec ts0;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts0) == -1) cte_die("clock_gettime");

    cte_stat.text_bytes     = 0;
    cte_stat.function_bytes = 0;
#endif

    strict_callgraph = flags & CTE_STRICT_CALLGRAPH;
    strict_ctemeta   = flags & CTE_STRICT_CTEMETA;

    cte_vector_init(&functions,  sizeof(cte_function));
    cte_vector_init(&texts,      sizeof(cte_text));
    cte_vector_init(&plts,       sizeof(cte_plt));

    if (strict_callgraph || strict_ctemeta) {
        char *env = getenv("LD_BIND_NOW");
        if (!env || *env == 0) {
            cte_die("ctemeta: Please set LD_BIND_NOW to a non-empty string\n");
        }
    }

    // extern char *__progname;
    extern char * program_invocation_name;
    int rc = dl_iterate_phdr(cte_callback, program_invocation_name);
    if (rc < 0)
        return rc;

    if (strict_callgraph || strict_ctemeta)
        cte_meta_assign();

    // Save the function bodies
    cte_function *it;
    for_each_cte_vector(&functions, it) {
        bodies_size += it->size;
    }
    bodies = mmap(NULL, bodies_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(bodies == MAP_FAILED) {
        cte_die("mmap failed");
    }
    void *ptr = bodies;
    for_each_cte_vector(&functions, it) {
        it->body = ptr;
        memcpy(it->body, it->vaddr, it->size);
        ptr += it->size;
    }

    // Enlarge the functions sizes, if they are followed by NOPs
    const struct {uint8_t len; uint8_t opcode[15]; } nop_codes[] = {
        {1,  {0x00}},
        {1,  {0x90}},
        {2,  {0x66, 0x90}},
        {2,  {0x3e, 0x90}},
        {2,  {0x3e, 0x90}},
        {3,  {0x0f, 0x1f, 0x00}},
        {3,  {0x0f, 0x19, 0x00}},
        {4,  {0x0f, 0x1f, 0x40, 0x00}},
        {5,  {0x0f, 0x1f, 0x44, 0x00, 0x00}},
        {6,  {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00}},
        {7,  {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00}},
        {8,  {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}},
        {9,  {0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}},
        {10, {0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}},
        {11, {0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}},
    };
    cte_function *func;
    for_each_cte_vector(&functions, func) {
        if (!func->body) continue; // Skip Aliases

        ////////////////////////////////////////////////////////////////
        // Nop enlargement
        uint8_t *P = func->vaddr + func->size;
        uint8_t I = 0;
        while((uintptr_t )&P[I] & (CTE_MAX_FUNC_ALIGN -1)) { // As long as we are not aligned
            // Search for NOP opcode
            bool found = false;
            for (unsigned idx = 0; idx < sizeof(nop_codes) / sizeof(*nop_codes); idx++) {
                if (memcmp(nop_codes[idx].opcode, &P[I], nop_codes[idx].len) == 0) {
                    I += nop_codes[idx].len;
                    found = true;
                    break;
                }
            }
            if (! found) break;
            if (!strcmp(func->name, "svctcp_rendezvous_abort")) {
                cte_debug("%s %d - %d\n", func->name, func->size, I);
            }
        }
        // Enlarge this function to include nops
        func->size += I;

#if CONFIG_STAT
        cte_stat.function_bytes += func->size;
#endif

        ////////////////////////////////////////////////////////////////
        // Find Sibling Functions (only for non-meta functions)
        unsigned length = strlen(func->name);
        if (!func->meta && length > 5 && strncmp(func->name + length - 5, ".cold", 5) == 0) {
            // func is a cold function. We have to find its hot counterpart:
            cte_function *func_hot = NULL, *func2;

            func->name[length - 5] = '\0'; // Sorry mum.
            for_each_cte_vector(&functions, func2) {
                if (strcmp(func->name, func2->name) == 0)
                    func_hot = func2;
            }
            func->name[length - 5] = '.';

            if (!func_hot) continue;

            func->sibling_idx = func_id(func_hot);
            func_hot->sibling_idx = func_id(func);
            // cte_printf("Hot/Cold Pair: \t%s\n\t%s\n", func->name, func_hot->name);
        }
    }

#if CONFIG_STAT
    cte_stat_init();
#endif

    // Seal everything
    // TODO: problem: cte_sealed not in own segment
    /* if (mprotect(cte_sealed_sec_vaddr, cte_sealed_sec_size, PROT_READ) == -1) */
    /*     cte_die("sealing failed"); */
    if (mprotect(texts.front, texts.capacity, PROT_READ) == -1)
        cte_die("sealing failed");
    if (mprotect(plts.front, plts.capacity, PROT_READ) == -1)
        cte_die("sealing failed");
    if (mprotect(functions.front, functions.capacity, PROT_READ) == -1)
        cte_die("sealing failed");
    if (mprotect(bodies, bodies_size, PROT_READ) == -1)
        cte_die("sealing failed");

#if CONFIG_STAT
    struct timespec ts1;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts1) == -1) cte_die("clock_gettime");

    cte_stat.init_time = timespec_diff_ns(ts0, ts1);
    printf("init time: %.2f ms\n", cte_stat.init_time / (double)1e6);

    printf("ram,functions,%lu\n", functions.length * functions.element_size);
    printf("ram,texts,%lu\n", texts.length * texts.element_size);
    printf("ram,plts,%lu\n", plts.length * plts.element_size);
    printf("ram,visited,%lu\n", sizeof(*visited_flags) * functions.length);
    printf("ram,bodies,%lu\n", bodies_size);
#endif
    return 0;
}

int cte_mmview_unshare(void) {
    cte_text *text;
    for_each_cte_vector(&texts, text) {
        int rc = mmview_unshare(text->vaddr, text->size);
        if (rc != 0) {
            cte_die("unshare failed");
        }
    }
    return 0;
}


CTE_ESSENTIAL
int cte_wipe(cte_rules *rules) {
#if CONFIG_STAT
    //if (cte_get_stat()->wipe_count) {
    //    cte_printf("restore_time: %d us/wipe\n", (uint32_t)(cte_get_stat()->restore_time/cte_get_stat()->wipe_count/1e3));
    //}
    cte_get_stat()->wipe_count ++;

    struct timespec ts0;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts0) == -1) cte_die("clock_gettime");
#endif

    cte_text *text = texts.front;
    cte_function *fs = functions.front;

    // Find caller function, as we do not wipe it
    void *retaddr = __builtin_extract_return_addr (__builtin_return_address (0));
    cte_function * cf = cte_find_containing_function(retaddr);

    for (cte_text *t = text; t < text + texts.length; t++)
        cte_modify_begin(t->vaddr, t->size);

    int wipe_count = 0;
    int wipe_bytes = 0;

#if CONFIG_THRESHOLD
    // Copy Thread local pointer
    struct cte_wipestat *wipestat = cte_get_wipestat();
#endif

    for (cte_function *f = fs; f < fs + functions.length; f++) {
        if (!f->body) continue; // Aliases

#if CONFIG_THRESHOLD
        // WIPESTAT: If a function reaches a given threshold, it is no
        // longer wiped, as we assume it is loaded every time
        int threshold = rules ? rules->threshold : 0;
        int min_wipe = rules ? rules->min_wipe : 0;
        if (wipestat && threshold > 0 && wipestat[func_id(f)].wipe > min_wipe) {
            int percentage =
                wipestat[func_id(f)].restore * 100
                / wipestat[func_id(f)].wipe;
            if (percentage >= threshold) {
                // cte_printf("nowipe %s, percentage: %d, threshold:%d\n", f->name, percentage, threshold);
                continue;
            }
        }
#endif
        // Fetch the wiping policy
        cte_wipe_policy policy = CTE_WIPE;
        if (rules) {
            policy = rules->policy[func_id(f)] & ~(CTE_FLAG_MASK);
        }

        cte_wipe_policy func_state = cte_func_state(f);

        if (!f->essential && f != cf) {
            if (func_state != policy) {
                if (cte_wipe_fn(f, policy)) { // Wipe Function!
                    func_state = policy;
                }
            }
#if CONFIG_THRESHOLD
            // WIPESTAT: Limit wipe statistics and Increment wipe counters
            if (wipestat) {
                if (wipestat[func_id(f)].wipe > 50000) {
                    wipestat[func_id(f)].wipe    /= 2;
                    wipestat[func_id(f)].restore /= 2;
                }
                wipestat[func_id(f)].wipe++;
            }
#endif
        }

        if (func_state != CTE_LOAD) {
            wipe_count += 1;
            wipe_bytes += f->size;
        }
    }

    for (cte_text *t = text; t < text + texts.length; t++)
        cte_modify_end(t->vaddr, t->size);

#if CONFIG_STAT
    struct timespec ts1;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts1) == -1) cte_die("clock_gettime");

    cte_get_stat()->last_wipe_time  = timespec_diff_ns(ts0, ts1);
    cte_get_stat()->last_wipe_count = wipe_count;
    cte_get_stat()->last_wipe_bytes = wipe_bytes;
    cte_get_stat()->last_wipe_timestamp = ts1;
    cte_get_stat()->last_wipe_function = cf;

    cte_get_stat()->cur_wipe_count = wipe_count;
    cte_get_stat()->cur_wipe_bytes = wipe_bytes;

    // cte_fdprintf(1, "wipe time: %d us\n", (uint32_t) (cte_get_stat()->last_wipe_time/1e3));
#endif
    return wipe_count;
}

#ifdef CONFIG_STAT
CTE_ESSENTIAL
static void cte_mark_loadable(bool *loadables, cte_function *function) {
    uint32_t idx = func_id(function);
    if (loadables[idx])
        return;

    loadables[idx] = true;

    if (!function->meta)
        return;

    for (uint32_t i = 0; i < function->meta->callees_count; i++) {
        cte_function *cf = cte_get_function(function->meta->callees[i]);
        cte_mark_loadable(loadables, cf);
    }

    for (uint32_t i = 0; i < function->meta->jumpees_count; i++) {
        cte_function *cf = cte_get_function(function->meta->jumpees[i]);
        cte_mark_loadable(loadables, cf);
    }

    for (uint32_t i = 0; i < function->meta->siblings_count; i++) {
        cte_function *cf = cte_get_function(function->meta->siblings[i]);
        cte_mark_loadable(loadables, cf);
    }
}
#endif

void cte_dump_state(int fd, unsigned flags) {
    cte_fdprintf(fd, "{\n");


#define HEX32(x) ((x) >> 32), ((x) & 0xffffffff)
#if CONFIG_STAT
    cte_fdprintf(fd, "  \"init_time\": 0x%08x%08x,\n", HEX32(cte_get_stat()->init_time));
    cte_fdprintf(fd, "  \"restore_count\": %d,\n", cte_get_stat()->restore_count);
    cte_fdprintf(fd, "  \"restore_time\": 0x%08x%08x,\n", HEX32(cte_get_stat()->restore_time));
    cte_fdprintf(fd, "  \"last_wipe_time\": 0x%08x%08x,\n", HEX32(cte_get_stat()->last_wipe_time));
    cte_fdprintf(fd, "  \"last_wipe_count\": %d,\n", cte_get_stat()->last_wipe_count);
    cte_fdprintf(fd, "  \"last_wipe_bytes\": %d,\n", cte_get_stat()->last_wipe_bytes);
    cte_fdprintf(fd, "  \"last_wipe_function\": \"%s\",\n", cte_get_stat()->last_wipe_function->name);
    cte_fdprintf(fd, "  \"cur_wipe_count\": %d,\n", cte_get_stat()->cur_wipe_count);
    cte_fdprintf(fd, "  \"cur_wipe_bytes\": %d,\n", cte_get_stat()->cur_wipe_bytes);
    cte_fdprintf(fd, "  \"function_count\": %d,\n", functions.length);
    cte_fdprintf(fd, "  \"function_bytes\": %d,\n", cte_get_stat()->function_bytes);
    cte_fdprintf(fd, "  \"text_count\": %d,\n", texts.length);
    cte_fdprintf(fd, "  \"text_bytes\": %d,\n", cte_get_stat()->text_bytes);
#endif

    if (flags & CTE_DUMP_TEXTS) {
        cte_text *text;
        cte_fdprintf(fd, "  \"texts\": [\n");
        unsigned idx = 0;
        for_each_cte_vector(&texts, text) {
            cte_fdprintf(fd, "    [%d, \"%s\", %d],\n", idx++, text->filename, text->size);
        }
        cte_fdprintf(fd, "  ],\n");
    }

    if (flags & CTE_DUMP_FUNCS) {
        bool *loadables = NULL;
#if CONFIG_STAT
        if (flags & CTE_DUMP_FUNCS_LOADABLE) {
            loadables = mmap(NULL, functions.length, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if(loadables == MAP_FAILED) {
                cte_die("mmap failed");
            }

            for (uint32_t i = 0; i < functions.length; i++) {
                cte_function *f = cte_vector_get(&functions, i);
                loadables[i] = !f->meta;
            }
            cte_mark_loadable(loadables, cte_get_stat()->last_wipe_function);
        }
#endif

        cte_function *func;

        cte_fdprintf(fd, "  \"functions\": [\n");
        for_each_cte_vector(&functions, func) {
            if (!func->body) continue;

            cte_text *text = cte_vector_get(&texts, func->text_idx);

            cte_fdprintf(fd, "    [%d, \"%s\", %d, %d, %d, %s, 0x%08x%08x, %s],\n",
                         func->text_idx, func->name, func->size,
                         func->vaddr - text->vaddr + text->offset,
                         cte_func_state(func),
                         func->essential ? "True": "False",
#if CONFIG_STAT
                         HEX32(cte_get_stat()->restore_times[func_id(func)]),
#else
                         HEX32(-1UL),
#endif
                         (loadables && loadables[func_id(func)]) ? "True" : "False"
                );
        }
        cte_fdprintf(fd, "  ],\n");

        if (loadables) {
            munmap(loadables, functions.length);
        }
    }

    cte_fdprintf(fd, "}\n\1");

#undef HEX32

}

unsigned cte_get_wiped_ranges(struct cte_range *ranges) {
    struct cte_function *func;
    unsigned ret = 0;
    uint32_t libcte_text_idx = cte_find_function(&cte_get_wiped_ranges)->text_idx;
    uint32_t libelf_text_idx = cte_find_function(&elf_end)->text_idx;

    for_each_cte_vector(&functions, func) {
        if (!func->body) continue;
        if (cte_func_state(func) != CTE_LOAD
            && func->text_idx != libcte_text_idx
            && func->text_idx != libelf_text_idx) {
            // CTE_WIPE | CTE_KILL
            if (ret > 0 &&
                func->vaddr == (ranges[ret-1].address + ranges[ret-1].length) ) {
                ranges[ret-1].length += func->size;
                // cte_printf("CTE_LOAD: %s\n", func->name);
            } else { // New interval
                cte_text *text = cte_vector_get(&texts, func->text_idx);

                ranges[ret].address = func->vaddr;
                ranges[ret].length = func->size;
                ranges[ret].file_offset = func->vaddr - text->vaddr + text->offset;
                ret++;
            }
        }
    }
    return ret;
}



