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
#include <fcntl.h>
#include <link.h>
#include <elf.h>
#include <gelf.h>
#include "cte.h"
#include "cte-impl.h"
#include "printf.h"

static cte_vector texts;     // vector of cte_text
static cte_vector plts;      // vector of cte_plt
static cte_vector functions; // vector of cte_function

static void cte_vector_init(cte_vector *vector, size_t element_size) {
    vector->length = 0;
    vector->element_size = element_size;
    vector->front = NULL;
}

static void *cte_vector_push(cte_vector *vector) {
    size_t bsize = vector->length * vector->element_size;
    vector->length++;
    vector->front = realloc(vector->front, bsize + vector->element_size);
    return vector->front + bsize;
}

CTE_ESSENTIAL
static void *cte_vector_get(cte_vector *vector, uint32_t idx) {
    if (vector->length <= idx) {
        return 0;
    }
    return vector->front + vector->element_size * idx;
}


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
            int flags = first->flags;
            for (cte_info_fn *i = first; i < curr; i++) {
                if (i->flags & FLAG_DEFINITION)
                    i->flags |= flags & FLAG_ADDRESS_TAKEN;
                else
                    *i = (const cte_info_fn) {};
            }
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

static int cte_sort_compare_function(const void *e1, const void *e2) {
    cte_function *a = (cte_function*)e1;
    cte_function *b = (cte_function*)e2;

    if (a->vaddr > b->vaddr) return  1;
    if (a->vaddr < b->vaddr) return -1;
    return 0;
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
static int cte_find_compare_in_function(const void *addr, const void *element) {
    cte_function *el = (cte_function*)element;
    if (addr >= el->vaddr && (uint8_t*)addr < ((uint8_t*)el->vaddr + el->size))
        return 0;
    if (addr < el->vaddr)
        return -1;
    else
        return 1;
}

static int cte_callback(struct dl_phdr_info *info, size_t _size, void *data) {
    (void)_size;

    // Get the real object name
    char *filename = data;
    if (info->dlpi_name[0] != '\0')
        filename = (char*)info->dlpi_name;

    // Open the object file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        // FIXME
        // fprintf(stderr, "Could not open: %s\n", fn, strerror(errno));
        return 0;
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1)
        return CTE_ERROR_ELF;

    void *eaddr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (eaddr == MAP_FAILED)
        return CTE_ERROR_ELF;

    if (elf_version(EV_CURRENT) == EV_NONE)
        return CTE_ERROR_ELF;

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        return CTE_ERROR_ELF;

    if (elf_kind(elf) != ELF_K_ELF)
        return CTE_ERROR_ELF;

    // Get section header string table index
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        return CTE_ERROR_ELF;

    Elf_Scn *section;

    // Find the text segment
    void *text_vaddr = NULL;
    size_t text_size = 0;
    for (int j = 0; j < info->dlpi_phnum; j++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[j];
        if (phdr->p_type != PT_LOAD) continue;
        if (phdr->p_flags & PF_X) {
            if (text_vaddr)
                return CTE_ERROR_FORMAT;
            text_vaddr = cte_get_vaddr(info, phdr->p_vaddr);
            text_size = phdr->p_memsz;
            printf("segment: [%s] %p, %lu\n", filename, text_vaddr, text_size);
        }
    }

    // Collect function metadata from compiler plugin
    cte_info_fn *info_fns = NULL;
    size_t info_fns_count = 0;
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
        if (strcmp(name, ".plt") == 0) {
            cte_plt *plt = cte_vector_push(&plts);
            *plt = (cte_plt) {
                .vaddr = cte_get_vaddr(info, shdr.sh_addr),
                .size = shdr.sh_size,
            };
        }
    }

    cte_text *text = cte_vector_push(&texts);
    *text = (cte_text) {
        .info_fns = info_fns,
        .info_fns_count = info_fns_count,
        .vaddr = text_vaddr,
        .size = text_size,
    };

    // Collect ELF symbol info
    section = NULL;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(section , &shdr) != &shdr)
            return CTE_ERROR_ELF;

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
                    .name = name,
                    .size = sym.st_size,
                    .vaddr = (void*)((uintptr_t)info->dlpi_addr + sym.st_value),
                    .body = NULL,
                    .info_fn = NULL,
                    .essential = false,
                };

                f.body = malloc(sym.st_size);
                memcpy(f.body, f.vaddr, f.size);

                if (text->info_fns)
                    f.info_fn = bsearch(f.vaddr, text->info_fns,
                                        text->info_fns_count,
                                        sizeof(cte_info_fn),
                                        cte_find_compare_info_fn);

                if (essential_sec_vaddr)
                    f.essential = (f.vaddr >= essential_sec_vaddr) &&
                        ((uint8_t*)f.vaddr < (uint8_t*)essential_sec_vaddr + essential_sec_size);
                // FIXME
                if (strcmp(f.name, "_start") == 0 ||
                    strcmp(f.name, "__libc_start_main") == 0 ||
                    strcmp(f.name, "main") == 0 ||
                    strcmp(f.name, "syscall") == 0 ||


                    // mprotect
                    strcmp(f.name, "mprotect") == 0 ||
                    strcmp(f.name, "pkey_mprotect") == 0 ||
                    strcmp(f.name, "__mprotect") == 0 ||

                    // memcpy
                    strcmp(f.name, "memcpy@GLIBC_2.2.5") == 0 ||
                    strcmp(f.name, "__memcpy_avx_unaligned_erms") == 0 ||

                    // memset
                    strcmp(f.name, "__memcmp_sse4_1") == 0 ||
                    strcmp(f.name, "__memset_avx2_erms") == 0 ||
                    strcmp(f.name, "__memset_avx2_unaligned_erms") == 0 ||
                    strcmp(f.name, "__wmemset_chk_avx2_unaligned") == 0 ||
                    strcmp(f.name, "__wmemset_avx2_unaligned") == 0 ||
                    strcmp(f.name, "__memset_chk_avx2_unaligned") == 0 ||
                    strcmp(f.name, "__memset_avx2_unaligned") == 0 ||
                    strcmp(f.name, "__memset_chk_avx2_unaligned_erms") == 0 ||
                    strcmp(f.name, "__wmemcmp_avx2_movbe") == 0 ||
                    strcmp(f.name, "__wmemchr_avx2") == 0 ||

                    // restore
                    strcmp(f.name, "bsearch") == 0) {
                    f.essential = true;
                }

                if ((uint8_t*)f.vaddr + f.size > (uint8_t*)text->vaddr + text->size)
                    printf("WARNING: exceeds text\n");

                // Add new function if not already registered (aliases)
                cte_function *old = bsearch(f.vaddr, functions.front,
                                            functions.length,
                                            sizeof(cte_function),
                                            cte_find_compare_function);
                if (old) {
                    old->essential |= f.essential;
                } else {
                    cte_function *fs = cte_vector_push(&functions);
                    *fs = f;

                    // Sort functions
                    // FIXME: performance: only sort once; handle duplicates later
                    qsort(functions.front, functions.length,
                          sizeof(cte_function),
                          cte_sort_compare_function);
                }
            }
        }
    }
    return 0;
}

CTE_ESSENTIAL
static void cte_modify_begin(void *start, size_t size) {
    uint8_t *stop = (uint8_t*)start + size;
    uint8_t *aligned_start = cte_align_to_page(start);
    size_t len = stop - aligned_start;
    mprotect(aligned_start, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

CTE_ESSENTIAL
static void cte_modify_end(void *start, size_t size) {
    uint8_t *stop = (uint8_t*)start + size;
    uint8_t *aligned_start = cte_align_to_page(start);
    size_t len = stop - aligned_start;
    mprotect(aligned_start, len, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)aligned_start, (char*)stop);
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

CTE_ESSENTIAL_USED
static int cte_restore(void *addr, void *call_addr) {
    cte_implant *implant = addr;
    if (!cte_implant_valid(implant))
        cte_die("cte_restore called from invalid implant\n");

    // Find the called function
    cte_function *f = cte_vector_get(&functions, implant->func_idx);
    if(!f)
        cte_die("Could not find function with id %d\n", implant->func_idx);

    /*
    cte_function *f2 = bsearch(implant, functions.front, functions.length,
                               sizeof(cte_function), cte_find_compare_function);
    if (f != f2)
        cte_die("Bsearch yielded a different result...\n");
    */

    // The function can be inserted if its address is taken
    if (f->info_fn && (f->info_fn->flags | FLAG_ADDRESS_TAKEN))
        goto allowed;

    // Find the caller
    cte_function * cf = bsearch(call_addr, functions.front, functions.length,
                 sizeof(cte_function), cte_find_compare_in_function);
    if (cf && cf->info_fn) {
        // A caller function was found, and it has a info_fn
        // Let's see if we are allowed to call function f
        for (int i = 0; i < cf->info_fn->calles_count; i++) {
            void *callee = cf->info_fn->callees[i];
            if (callee == addr) {
                goto allowed;
            }
            // Maybe the callee is a pointer to a .plt section
            // FIXME: performance?
            cte_plt *pa = plts.front;
            for (cte_plt *p = pa; p < &pa[plts.length]; p++) {
                if (callee >= p->vaddr &&
                    (uint8_t*)callee < ((uint8_t*)p->vaddr + p->size)) {
                    void *real_callee = cte_decode_plt(callee);
                    if (real_callee == addr) {
                        // Update the callee pointer in order to avoid checking
                        // the plts in the future for this callee.
                        // FIXME: this should be safe...
                        cf->info_fn->callees[i] = real_callee;
                        goto allowed;
                    }
                }
            }
        }
        asm("int3\n");
    }

    allowed:
    cte_modify_begin(addr, f->size);
    memcpy(addr, f->body, f->size);
    cte_modify_end(addr, f->size);
    return 0;
}

CTE_ESSENTIAL_NAKED
static void cte_restore_entry(void) {
    asm("pushq %rdi\n"
        "pushq %rsi\n"

        // rdi (first argument) is the current return pointer of this function
        "movq 16(%rsp), %rdi\n"
        // rsi (second argument) is the call address in the caller
        "movq 24(%rsp), %rsi\n"

        // Modify the return value to return to the original function start addr
        "leaq -12(%rdi), %rdi\n"
        "movq %rdi, 16(%rsp)\n"

        // Save the caller-saved registers
        // rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11
        "pushq %rax\n"
        "pushq %rdx\n"
        "pushq %rcx\n"
        "pushq %r8\n"
        "pushq %r9\n"
        "pushq %r10\n"
        "pushq %r11\n"

        // The stack must be 16-byte aligned before the call
        "leaq -8(%rsp), %rsp\n"

        "call cte_restore\n"

        "leaq 8(%rsp), %rsp\n"

        // Restore the caller-saved registers
        "popq %r11\n"
        "popq %r10\n"
        "popq %r9\n"
        "popq %r8\n"
        "popq %rcx\n"
        "popq %rdx\n"
        "popq %rax\n"
        "popq %rsi\n"
        "popq %rdi\n"
        "ret\n");
}


CTE_ESSENTIAL
static void cte_wipe_fn(cte_function *fn) {
    cte_implant *implant = fn->vaddr;

    if (fn->size < sizeof(cte_implant)) {
        cte_debug("function %s not large enough for implant (%d < %d)\n",
                  fn->name, fn->size, sizeof(cte_implant));
        return;
    }

    // FIXME: rax not preserved -> Cannot be fixed without library local tramploline
    cte_implant_init(implant, (fn - (cte_function *)functions.front));

    // Wipe the rest of the function body
    memset(fn->vaddr + sizeof(cte_implant),
           0xcc, // int3 int3 int3...
           fn->size  - sizeof(cte_implant));
}

int cte_init(void) {
    cte_vector_init(&functions,  sizeof(cte_function));
    cte_vector_init(&texts,      sizeof(cte_text));
    cte_vector_init(&plts,       sizeof(cte_plt));

    extern char *__progname;
    int rc = dl_iterate_phdr(cte_callback, __progname);
    if (rc < 0)
        return rc;
    return 0;
}

CTE_ESSENTIAL
int cte_wipe(void) {
    cte_text *text = texts.front;
    cte_function *fs = functions.front;

    for (cte_text *t = text; t <= text + texts.length; t++)
        cte_modify_begin(t->vaddr, t->size);

    for (cte_function *f = fs; f < fs + functions.length; f++) {
        if (!f->essential)
            cte_wipe_fn(f);
    }

    for (cte_text *t = text; t <= text + texts.length; t++)
        cte_modify_end(t->vaddr, t->size);
    return 0;
}
