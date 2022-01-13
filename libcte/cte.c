#define _GNU_SOURCE
#include <stddef.h>
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

#include <fcntl.h>
#include <link.h>
#include <elf.h>
#include <time.h>
#include <gelf.h>
#include "cte.h"
#include "cte-impl.h"
#include "cte-printf.h"
#include "mmview.h"

CTE_SEALED static cte_vector texts;     // vector of cte_text
CTE_SEALED static cte_vector plts;      // vector of cte_plt
CTE_SEALED static cte_vector functions; // vector of cte_function

CTE_SEALED static void *bodies;         // stores function bodies
CTE_SEALED static size_t bodies_size;

CTE_SEALED static bool strict_callgraph;

static void *cte_sealed_sec_vaddr = NULL;
static size_t cte_sealed_sec_size = 0;

#define func_id(func_ptr) ((func_ptr) - (cte_function *) functions.front)
#define FUNC_ID_INVALID (uint32_t)(~0)

#if CONFIG_STAT
cte_stat_t cte_stat;

static void cte_stat_init() {
    cte_stat.init_time = 0;
    cte_stat.restore_count = 0;
    cte_stat.restore_times = calloc(functions.length, sizeof(*cte_stat.restore_times));
}

#define CLOCK_LIBCTE CLOCK_REALTIME
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
    size_t new_size = *size + page_size;
    if (!*addr) {
        *addr = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else {
        *addr = mremap(*addr, *size, new_size, MREMAP_MAYMOVE);
    }
    if (*addr == MAP_FAILED) {
        cte_die("mmap failed");
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


static int cte_sort_compare_info_fn(const void *e1, const void *e2) {
    cte_info_fn *a = (cte_info_fn*)e1;
    cte_info_fn *b = (cte_info_fn*)e2;

    // Zeroed out cte_info_fns go to the end of the list
    if (a->vaddr == NULL) return 1;
    if (b->vaddr == NULL) return -1;

    if (a->vaddr > b->vaddr) return  1;
    if (a->vaddr < b->vaddr) return -1;
    return 0;
}

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

static int cte_find_compare_info_fn(const void *addr, const void *element) {
    cte_info_fn *el = (cte_info_fn*)element;
    if (addr == el->vaddr)
        return 0;
    if (addr < el->vaddr)
        return -1;
    else
        return 1;
}

CTE_ESSENTIAL
static void *cte_align_to_page(void *addr) {
    static size_t page_size = 0;
    if (page_size == 0) {
        page_size = sysconf(_SC_PAGESIZE);
    }
    return (void*)((size_t)addr & ~(page_size - 1));
}

static int cte_fns_init(cte_info_fn *info_fns, size_t *info_fns_count) {
    // Sort the buffer
    size_t old_count = *info_fns_count;
    qsort(info_fns, old_count, sizeof(cte_info_fn),
          cte_sort_compare_info_fn);

    // Zero out duplicates but keep the address_taken bit
    size_t new_count = 0;
    cte_info_fn *curr = info_fns;
    cte_info_fn *first = NULL;
    cte_info_fn *stop = info_fns + old_count;
    while (curr < stop) {
        if (!first) {
            first = curr;
            new_count++;
        }
        curr++;

        if (curr >= stop || curr->vaddr != first->vaddr) {
            // zero out the duplicates and set flags
            cte_info_fn *selected = first;
            int flags = first->flags;
            for (cte_info_fn *i = first + 1; i < curr; i++) {
                if (i->calles_count > 0) {
                    if (selected->calles_count > 0)
                        cte_die("Multiple definitions\n");
                    selected->vaddr = NULL;
                    selected = i;
                } else {
                    i->vaddr = NULL;
                }
                flags |= i->flags & FLAG_ADDRESS_TAKEN;
            }
            selected->flags |= flags & FLAG_ADDRESS_TAKEN;
            first = NULL;
        }
    }

    // Sort the buffer again to eliminate zeroed out duplicates
    qsort(info_fns, old_count, sizeof(cte_info_fn),
          cte_sort_compare_info_fn);
    *info_fns_count = new_count;
    return 0;
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
static inline
bool cte_func_loaded(cte_function *func) {
    cte_implant *implant = func->vaddr;
    if (func->size >= sizeof(cte_implant)) {
        if (cte_implant_valid(implant))
            return false;
    }
    return true;
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

                // Only functions
                if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
                if (sym.st_size == 0) continue;

                cte_function f = {
                    .text_idx  = text - (cte_text *)texts.front,
                    .name      = name,
                    .size      = sym.st_size,
                    .vaddr     = (void*)((uintptr_t)dlpi_addr + sym.st_value),
                    .body      = NULL,
                    .info_fn   = NULL,
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

    if (!strcmp(filename, "linux-vdso.so.1"))
        return 0;

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

    // Find the text segment
    void *text_vaddr = NULL;
    size_t text_size = 0;
    ElfW(Off) text_offset = 0;
    for (int j = 0; j < info->dlpi_phnum; j++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[j];
        if (phdr->p_type != PT_LOAD) continue;
        if (phdr->p_flags & PF_X) {
            if (text_vaddr)
                return CTE_ERROR_FORMAT;
            text_vaddr = cte_get_vaddr(info, phdr->p_vaddr);
            text_size = phdr->p_memsz;
            text_offset = phdr->p_offset;
            printf("segment: [%s] %p, %lu\n", filename, text_vaddr, text_size);
        }
    }

    cte_info_fn *info_fns = NULL;
    size_t info_fns_count = 0;
    void *essential_sec_vaddr = NULL;
    size_t essential_sec_size = 0;
    cte_plt *plt = NULL;

    // Collect function metadata from compiler plugin
    section = NULL;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr shdr;
        char *name;
        if (gelf_getshdr(section, &shdr) != &shdr)
            return CTE_ERROR_ELF;
        if ((name = elf_strptr(elf, shstrndx, shdr.sh_name)) == NULL)
            return CTE_ERROR_ELF;

        if (strcmp(name, ".cte_fn") == 0) {
            void *addr = cte_get_vaddr(info, shdr.sh_addr);
            info_fns = addr;
            info_fns_count = shdr.sh_size / sizeof(cte_info_fn);
            printf("fn section: [%s] %s (%p, count: %lu)\n", filename, name,
                   info_fns, info_fns_count);
            int rc = cte_fns_init(info_fns, &info_fns_count);
            if (rc < 0)
                return rc;
            break;
        }
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
        if (strcmp(name, ".plt") == 0) {
            plt = cte_vector_push(&plts);
            *plt = (cte_plt) {
                .text_idx = 0, // Gets set later
                .vaddr = cte_get_vaddr(info, shdr.sh_addr),
                .size = shdr.sh_size,
            };
        }
    }

    cte_text *text = cte_vector_push(&texts);
    uint32_t text_idx = (text - (cte_text *)texts.front);
    *text = (cte_text) {
        .filename = strdup(filename),
        .info_fns = info_fns,
        .info_fns_count = info_fns_count,
        .vaddr = text_vaddr,
        .offset = text_offset,
        .size = text_size,
    };
#ifdef CONFIG_STAT
    cte_stat.text_bytes += text_size;
#endif

    if(!text->filename)
        cte_die("strdup failed");

    if (plt)
        plt->text_idx = text_idx;

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

    // Step 2: Mark essential functions, identify duplicates
    size_t count = 0;
    cte_function *function = NULL, *it;
    for_each_cte_vector(&functions, it) {
        if (it->text_idx != text_idx) {
            count++;
            continue; // From previous library
        }

        if ((uint8_t*)it->vaddr + it->size > (uint8_t*)text->vaddr + text->size)
            cte_die("function exceeds text segment: %s\n", it->name);

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

        // Function is an essential sections?
        if (essential_sec_vaddr) {
            function->essential |= (it->vaddr >= essential_sec_vaddr) &&
                ((uint8_t*)it->vaddr < (uint8_t*)essential_sec_vaddr + essential_sec_size);
        }

        // Does this function have an essential name?
        struct { char begin; char *pattern; } names[] = {
            {0, "_start"}, {0, "__libc_start_main"}, {0, "main"}, {0, "syscall"}, {0, "start_thread"},
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
        }
        if (function->essential) {
            //cte_debug("essential: %s %d\n", it->name, function->essential);
        }

        if (text->info_fns) {
            function->info_fn = bsearch(function->vaddr, text->info_fns,
                                        text->info_fns_count,
                                        sizeof(cte_info_fn),
                                        cte_find_compare_info_fn);
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

CTE_ESSENTIAL
static void *cte_decode_plt(void *entry) {
    uint8_t *a = (uint8_t*)entry;
    if (a[0] != 0xff)
        return NULL;
    if (a[1] != 0x25)  // FIXME: this was determined empirically
        return NULL;
    uint8_t *rip = a + 6;
    uint32_t offset = *((uint32_t*)(a + 2));
    uintptr_t *got_entry = (uintptr_t*)(rip + offset);
    return (void*)(*got_entry);
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

    if (caller && caller->info_fn) {
        cte_printf("Allowed callees (%d)\n", caller->info_fn->calles_count);
        for (int i = 0; i < caller->info_fn->calles_count; i++) {
            void *callee = caller->info_fn->callees[i];
            cte_function *cd = bsearch(callee, functions.front, functions.length,
                                       sizeof(cte_function),
                                       cte_find_compare_function);
            if (cd) {
                cte_printf("  %p: %s\n", callee, cd->name);
            } else {
                cte_plt *p, *plt = NULL;
                for_each_cte_vector(&plts, p) {
                    if (callee >= p->vaddr && callee < (p->vaddr + p->size)) {
                        plt = p;
                        break;
                    }
                }
                if (plt) {
                    cte_text *text = cte_vector_get(&texts, plt->text_idx);
                    cte_printf("  %p: .plt+%p [%s]\n", callee,
                               callee - plt->vaddr, text->filename);
                } else {
                    cte_printf("  %p: ??\n", callee);
                }
            }
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
        ((EXT_MOD(b[-5]) == 0 && EXT_RM(b[-5]) == 4) ||
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

    if (indirect && direct)
        return CALLSITE_TYPE_DIRECT_OR_INDIRECT;
    if (indirect)
        return CALLSITE_TYPE_INDIRECT;
    if (direct)
        return CALLSITE_TYPE_DIRECT;
    return CALLSITE_TYPE_INVALID;

#undef EXT_REG
#undef EXT_MOD
#undef EXT_RM
}

CTE_ESSENTIAL
static void cte_indirectly_allow(cte_function *function) {
    if (!function || !function->info_fn)
        return;
    if (function->info_fn->flags & FLAG_INDIRECTLY_ALLOWED)
        return;

    function->info_fn->flags |= FLAG_INDIRECTLY_ALLOWED;

    for (int i = 0; i < function->info_fn->calles_count; i++) {
        void *callee = function->info_fn->callees[i];
        cte_function *cf = bsearch(callee, functions.front, functions.length,
                                   sizeof(cte_function),
                                   cte_find_compare_function);
        cte_indirectly_allow(cf);
    }
}

CTE_ESSENTIAL
static bool cte_check_call(void* called_addr, cte_function *caller, int depth) {
    if (!caller->info_fn) {
        /* cte_printf("CALLER NO INFO_FN: %s\n", caller->name); */
        return true;
    }

    // A caller function was found, and it has a info_fn
    // Let's see if we are allowed to call function f
    for (int i = 0; i < caller->info_fn->calles_count; i++) {
        void *callee = caller->info_fn->callees[i];
        if (callee == called_addr) {
            return true;
        }
        // Maybe the callee is a pointer to a .plt section
        // FIXME: performance?
        cte_plt *pa = plts.front;
        for (cte_plt *p = pa; p < &pa[plts.length]; p++) {
            if (callee >= p->vaddr &&
                (uint8_t*)callee < ((uint8_t*)p->vaddr + p->size)) {
                void *real_callee = cte_decode_plt(callee);

                // Update the callee pointer in order to avoid checking
                // the plts in the future for this callee.
                // FIXME: This should be safe...
                // FIXME: However, this should not be allowed.
                //        As an attacker might tamper callee addresses.
                // NOTE:  The recursive callee check below relies on it.
                caller->info_fn->callees[i] = real_callee;

                if (real_callee == called_addr) {
                    return true;
                }
            }
        }
    }

    // In some cases functions are called with a jump instruction and reuse
    // their parent's frame.
    // In these situations we won't find the real caller via the return pointer
    // To solve this, we recursively iterate the calles and check their callees.
    // Nesting is bound (by the depth argument) to avoid recursion.
    if (depth > 0) {
        for (int i = 0; i < caller->info_fn->calles_count; i++) {
            void *callee = caller->info_fn->callees[i];
            cte_function *cf = bsearch(callee, functions.front, functions.length,
                                       sizeof(cte_function),
                                       cte_find_compare_function);
            if (cf && cte_check_call(called_addr, cf, depth - 1))
                return true;
        }
    }

    return false;
}

CTE_ESSENTIAL_USED __attribute__((__visibility__("hidden")))
int cte_restore(void *addr, void *post_call_addr) {
#if CONFIG_STAT
    struct timespec ts0;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts0) == -1) cte_die("clock_gettime");
    cte_stat.restore_count += 1;
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
    cte_function *f2 = bsearch(implant, functions.front, functions.length,
                               sizeof(cte_function), cte_find_compare_function);
    if (f != f2)
        cte_die("Bsearch yielded a different result...\n");
    */

    cte_callsite_type type = cte_decode_callsite(post_call_addr);

    if (type == CALLSITE_TYPE_INVALID) {
        cte_printf("Invalid Callsite: ");
        unsigned char *s = post_call_addr;
        for (unsigned char *b = s - 16; b < s; b++)
            cte_printf("%x ", *b);
        cte_printf("\n");
        cte_debug_restore(addr, post_call_addr, f,
                          bsearch(post_call_addr, functions.front, functions.length,
                                  sizeof(cte_function), cte_find_compare_in_function));
        cte_printf("\n");
        /* cte_die("Invalid Callsite at: %p\n", post_call_addr); */
    }

    if (!strict_callgraph)
        goto allowed;

    if (type != CALLSITE_TYPE_DIRECT) {  // TODO: get rid of invalid callsites
        // The function can be inserted if its address is taken
        if (f->info_fn && (f->info_fn->flags & FLAG_ADDRESS_TAKEN)) {

            // This is most likely an indirect call.
            // Mark all callees as indirectly allowed.
            cte_indirectly_allow(f);

            goto allowed;
        }

        // Maybe the callee has been indirectly allowed.
        if (f->info_fn && (f->info_fn->flags & FLAG_INDIRECTLY_ALLOWED)) {
            cte_printf("Allow indirect callee %s\n", f->name);
            goto allowed;
        }
    }

    // Find the caller
    cte_function *cf = bsearch(post_call_addr, functions.front, functions.length,
                               sizeof(cte_function), cte_find_compare_in_function);
    if (!cf) {
        cte_debug_restore(addr, post_call_addr, f, cf);
        cte_die("Caller not found\n");
    }

    if (cte_check_call(addr, cf, 2))
        goto allowed;

    // Failed to find the callee
    cte_debug_restore(addr, post_call_addr, f, cf);
    cte_die("Unrecognized callee\n");

    allowed:
    // cte_printf("-> load: %s\n", f->name);
    // Load the called function

    cte_modify_begin(addr, f->size);
    cte_memcpy(addr, f->body, f->size);
    cte_modify_end(addr, f->size);
#if CONFIG_STAT
    cte_stat.cur_wipe_count -= 1;
    cte_stat.cur_wipe_bytes -= f->size;
#endif

#if CONFIG_THRESHOLD
    struct cte_wipestat *wipestat = cte_get_wipestat();
#endif

    // Load the sibling
    if (f->sibling_idx != FUNC_ID_INVALID) { // We have a sibling:
        cte_function *func_sibling = cte_vector_get(&functions, f->sibling_idx);
        if (!cte_func_loaded(func_sibling)) {
            // cte_printf("-> load sibling: %s\n", func_sibling->name);
            cte_modify_begin(func_sibling->vaddr, func_sibling->size);
            cte_memcpy(func_sibling->vaddr, func_sibling->body, func_sibling->size);
            cte_modify_end(func_sibling->vaddr, func_sibling->size);

#if CONFIG_STAT
            cte_stat.cur_wipe_count -= 1;
            cte_stat.cur_wipe_bytes -= func_sibling->size;
#endif
#if CONFIG_THRESHOLD
            if (wipestat) wipestat[func_id(func_sibling)].restore++;
#endif

        }
    }
#if CONFIG_THRESHOLD
    if (wipestat) wipestat[func_id(f)].restore ++;
#endif

#if CONFIG_STAT
    struct timespec ts;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts) == -1) cte_die("clock_gettime");

    uint64_t restore_time = timespec_diff_ns(ts0, ts);
    cte_stat.restore_time += restore_time;
    cte_stat.restore_times[func_id(f)] = timespec_diff_ns(cte_stat.last_wipe_timestamp, ts);
#endif

    return 0;
}


CTE_ESSENTIAL
static int cte_wipe_fn(cte_function *fn) {
    cte_implant *implant = fn->vaddr;

    if (fn->size < sizeof(cte_implant)) {
        cte_text *text = cte_vector_get(&texts, fn->text_idx);
        if(!text) cte_die("idiot");
        cte_debug("function %s/%s not large enough for implant (%d < %d)\n",
                  text->filename, fn->name, fn->size, sizeof(cte_implant));
        return 0;
    }

    // FIXME: rax not preserved -> Cannot be fixed without library local tramploline
    cte_implant_init(implant, func_id(fn));

    // Wipe the rest of the function body
    cte_memset(fn->vaddr + sizeof(cte_implant),
           0xcc, // int3 int3 int3...
           fn->size  - sizeof(cte_implant));

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

    cte_vector_init(&functions,  sizeof(cte_function));
    cte_vector_init(&texts,      sizeof(cte_text));
    cte_vector_init(&plts,       sizeof(cte_plt));

    // extern char *__progname;
    extern char * program_invocation_name;
    int rc = dl_iterate_phdr(cte_callback, program_invocation_name);
    if (rc < 0)
        return rc;

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

#ifdef CONFIG_STAT
        cte_stat.function_bytes += func->size;
#endif

        ////////////////////////////////////////////////////////////////
        // Find Sibling Functions
        unsigned length = strlen(func->name);
        if (length > 5 && strncmp(func->name + length - 5, ".cold", 5) == 0) {
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
int cte_wipe_threshold(int threshold, int min_wipe) {
    (void) threshold; (void) min_wipe;
#if CONFIG_STAT
    //if (cte_stat.wipe_count) {
    //    cte_printf("restore_time: %d us/wipe\n", (uint32_t)(cte_stat.restore_time/cte_stat.wipe_count/1e3));
    //}
    cte_stat.wipe_count ++;

    struct timespec ts0;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts0) == -1) cte_die("clock_gettime");
#endif

    cte_text *text = texts.front;
    cte_function *fs = functions.front;

    // Find caller function, as we do not wipe it
    void *retaddr = __builtin_extract_return_addr (__builtin_return_address (0));
    cte_function * cf = bsearch(retaddr, functions.front, functions.length,
                                sizeof(cte_function), cte_find_compare_in_function);

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

        if (!f->essential && f != cf) {
            if (cte_func_loaded(f)) {
                if (cte_wipe_fn(f)) { // Wipe Function!
                    wipe_count += 1;
                    wipe_bytes += f->size;
                }
            } else {
                // The function is still wiped, account for that
                wipe_count += 1;
                wipe_bytes += f->size;
            }
            // WIPESTAT: Limit wipe statistics and Increment wipe counters
#if CONFIG_THRESHOLD
            if (wipestat) {
                if (wipestat[func_id(f)].wipe > 50000) {
                    wipestat[func_id(f)].wipe    /= 2;
                    wipestat[func_id(f)].restore /= 2;
                }
                wipestat[func_id(f)].wipe++;
            }
#endif
        }
    }

    for (cte_text *t = text; t < text + texts.length; t++)
        cte_modify_end(t->vaddr, t->size);

#if CONFIG_STAT
    struct timespec ts1;
    if (syscall(SYS_clock_gettime, CLOCK_LIBCTE, &ts1) == -1) cte_die("clock_gettime");

    cte_stat.last_wipe_time  = timespec_diff_ns(ts0, ts1);
    cte_stat.last_wipe_count = wipe_count;
    cte_stat.last_wipe_bytes = wipe_bytes;
    cte_stat.last_wipe_timestamp = ts1;
    cte_stat.last_wipe_function = cf;

    cte_stat.cur_wipe_count = wipe_count;
    cte_stat.cur_wipe_bytes = wipe_bytes;

    // cte_fdprintf(1, "wipe time: %d us\n", (uint32_t) (cte_stat.last_wipe_time/1e3));
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
    loadables[function->sibling_idx] = true;

    if (!function->info_fn)
        function = cte_vector_get(&functions, function->sibling_idx);
    if (!function->info_fn)
        return;

    for (int i = 0; i < function->info_fn->calles_count; i++) {
        void *callee = function->info_fn->callees[i];
        cte_function *cf = bsearch(callee, functions.front, functions.length,
                                   sizeof(cte_function),
                                   cte_find_compare_function);
        cte_mark_loadable(loadables, cf);
    }
}
#endif

void cte_dump_state(int fd, unsigned flags) {
    
    cte_fdprintf(fd, "{\n");

#define HEX32(x) ((x) >> 32), ((x) & 0xffffffff)
    cte_fdprintf(fd, "  \"init_time\": 0x%08x%08x,\n", HEX32(cte_stat.init_time));
    cte_fdprintf(fd, "  \"restore_count\": %d,\n", cte_stat.restore_count);
    cte_fdprintf(fd, "  \"restore_time\": 0x%08x%08x,\n", HEX32(cte_stat.restore_time));
    cte_fdprintf(fd, "  \"last_wipe_time\": 0x%08x%08x,\n", HEX32(cte_stat.last_wipe_time));
    cte_fdprintf(fd, "  \"last_wipe_count\": %d,\n", cte_stat.last_wipe_count);
    cte_fdprintf(fd, "  \"last_wipe_bytes\": %d,\n", cte_stat.last_wipe_bytes);
    cte_fdprintf(fd, "  \"last_wipe_function\": \"%s\",\n", cte_stat.last_wipe_function->name);
    cte_fdprintf(fd, "  \"cur_wipe_count\": %d,\n", cte_stat.cur_wipe_count);
    cte_fdprintf(fd, "  \"cur_wipe_bytes\": %d,\n", cte_stat.cur_wipe_bytes);
    cte_fdprintf(fd, "  \"function_count\": %d,\n", functions.length);
    cte_fdprintf(fd, "  \"function_bytes\": %d,\n", cte_stat.function_bytes);
    cte_fdprintf(fd, "  \"text_count\": %d,\n", texts.length);
    cte_fdprintf(fd, "  \"text_bytes\": %d,\n", cte_stat.text_bytes);

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
#ifdef CONFIG_STAT
        if (flags & CTE_DUMP_FUNCS_LOADABLE) {
            loadables = mmap(NULL, functions.length, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if(loadables == MAP_FAILED) {
                cte_die("mmap failed");
            }

            int xno = 0;
            int xyes = 0;
            int sibl = 0;
            for (uint32_t i = 0; i < functions.length; i++) {
                cte_function *f = cte_vector_get(&functions, i);
                cte_function *sibling = (f->sibling_idx != FUNC_ID_INVALID)
                    ? (cte_vector_get(&functions, f->sibling_idx)) : NULL;
                if (f->text_idx == 6) {
                    /* cte_text *t = cte_vector_get(&texts, f->text_idx); */
                    /* cte_printf("INFO FN: %d  %s :: %s\n", (!!f->info_fn), t->filename, f->name); */
                    if (f->info_fn)
                        xyes++;
                    else
                        xno++;
                    if (f->sibling_idx != FUNC_ID_INVALID)
                        sibl++;
                }
                loadables[i] = !(f->info_fn || (sibling && sibling->info_fn));
                /* if (f->info_fn) { */
                /*     loadables[i] ||= f->info_fn->flags | FLAG_ADDRESS_TAKEN; */
                /* } */
            }
            cte_printf(" INFO FN yes: %d, no: %d, siblings: %d\n", xyes, xno, sibl);
            /* cte_mark_loadable(loadables, cte_stat.last_wipe_function); */
        }
#endif

        cte_function *func;

        cte_fdprintf(fd, "  \"functions\": [\n");
        for_each_cte_vector(&functions, func) {
            if (!func->body) continue;

            bool loaded = cte_func_loaded(func);
            cte_text *text = cte_vector_get(&texts, func->text_idx);

            cte_fdprintf(fd, "    [%d, \"%s\", %d, %d, %s, %s, 0x%08x%08x, %s],\n",
                         func->text_idx, func->name, func->size,
                         func->vaddr - text->vaddr + text->offset,
                         loaded ? "True": "False",
                         func->essential ? "True": "False",
#if CONFIG_STAT
                         HEX32(cte_stat.restore_times[func_id(func)]),
#else
                         HEX32(-1),
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
    for_each_cte_vector(&functions, func) {
        if (!func->body) continue;
        if (!cte_func_loaded(func)) {
            if (ret > 0 &&
                func->vaddr == (ranges[ret-1].address + ranges[ret-1].length) ) {
                ranges[ret-1].length += func->size;
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



// Require LD_PRELOAD
void *dlopen(const char *path, int flags) {
    static void *(*original_dlopen)(const char*, int) = NULL;
    if (!original_dlopen) {
        original_dlopen = dlsym(RTLD_NEXT, "dlopen");
    }
    void *ret = (*original_dlopen)(path, flags);
    // FIXME: Re-wipe

    return ret;
}
