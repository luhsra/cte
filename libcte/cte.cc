#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string>
#include <sys/ucontext.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <link.h>
#include <fcntl.h>
#include <map>
#include <libelfin/elf/elf++.hh>
#include <vector>
#include "cte.h"

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

static const int FLAG_ADDRESS_TAKEN = (1 << 1);
static const int FLAG_DEFINITION = (1 << 0);

static std::vector<cte_text> texts;
static std::map<void*, cte_function> functions;
static std::vector<cte_plt> plts;

static int cte_sort_compare(const void *e1, const void *e2) {
    struct cte_info_fn *a = (struct cte_info_fn*)e1;
    struct cte_info_fn *b = (struct cte_info_fn*)e2;

    // Zeroed out cte_info_fns go to the end of the list
    if (a->vaddr == NULL) return 1;
    if (b->vaddr == NULL) return -1;

    if (a->vaddr > b->vaddr) return  1;
    if (a->vaddr < b->vaddr) return -1;
    return 0;
}

static int cte_find_compare(const void *addr, const void *element) {
    struct cte_info_fn *el = (struct cte_info_fn*)element;
    if (addr == el->vaddr)
        return 0;
    if (addr < el->vaddr)
        return -1;
    else
        return 1;
}

static struct cte_info_fn *cte_find(struct cte_text *text, void *addr) {
    return (struct cte_info_fn*) bsearch(addr, text->info_fns,
                                         text->info_fns_count,
                                         sizeof(struct cte_info_fn),
                                         cte_find_compare);
}

// static size_t cte_info_fn_index(struct cte_text *text,
//                                 struct cte_info_fn* ptr) {
//     return ptr - text->info_fns;
// }

__attribute__((section(".cte_essential")))
static void *cte_align_to_page(void *addr) {
    static size_t page_size = 0;
    if (page_size == 0) {
        page_size = sysconf(_SC_PAGESIZE);
    }
    return (void*)((size_t)addr & ~(page_size - 1));
}

static int cte_fns_init(struct cte_info_fn *info_fns, size_t *info_fns_count) {
    // Sort the buffer
    size_t old_count = *info_fns_count;
    qsort(info_fns, old_count, sizeof(struct cte_info_fn),
          cte_sort_compare);

    // Zero out duplicates but keep the address_taken bit
    size_t new_count = 0;
    struct cte_info_fn *curr = info_fns;
    struct cte_info_fn *first = NULL;
    struct cte_info_fn *stop = info_fns + old_count;
    while (curr < stop) {
        if (!first) {
            first = curr;
            new_count++;
        }
        curr++;

        if (curr >= stop || curr->vaddr != first->vaddr) {
            // zero out the duplicates and set flags
            int flags = first->flags;
            for (struct cte_info_fn *i = first; i < curr; i++) {
                if (i->flags & FLAG_DEFINITION)
                    i->flags |= flags & FLAG_ADDRESS_TAKEN;
                else
                    *i = (const struct cte_info_fn) {};
            }
            first = NULL;
        }
    }

    // Sort the buffer again to eliminate zeroed out duplicates
    qsort(info_fns, old_count, sizeof(struct cte_info_fn),
          cte_sort_compare);
    *info_fns_count = new_count;
    return 0;
}

static void *cte_get_vaddr(struct dl_phdr_info *info, uintptr_t addr) {
    return (void*)((uintptr_t)info->dlpi_addr + addr);
}

static int callback(struct dl_phdr_info *info, size_t, void *data) {
    // Get the real object name
    char *filename = (char*)data;
    if (info->dlpi_name[0] != '\0')
        filename = (char*)info->dlpi_name;

    // Open the object file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        // fprintf(stderr, "Could not open: %s\n", fn, strerror(errno));
        return 0;
    }

    // Find the text segment
    void *text_vaddr = NULL;
    size_t text_size = 0;
    for (int j = 0; j < info->dlpi_phnum; j++) {
        auto &phdr = info->dlpi_phdr[j];
        if (phdr.p_type != PT_LOAD) continue;
        if (phdr.p_flags & PF_X) {
            if (text_vaddr)
                return CTE_ERROR_FORMAT;
            text_vaddr = cte_get_vaddr(info, phdr.p_vaddr);
            text_size = phdr.p_memsz;
            printf("segment: [%s] %p, %lu\n", filename, text_vaddr, text_size);
        }
    }

    elf::elf obj(elf::create_mmap_loader(fd));

    // Collect function metadata from compiler plugin
    struct cte_info_fn *info_fns = NULL;
    size_t info_fns_count = 0;
    void *essential_sec_vaddr = NULL;
    size_t essential_sec_size = 0;
    for (auto &sec : obj.sections()) {
        if (sec.get_name() == ".cte_fn") {
            void *addr = cte_get_vaddr(info, sec.get_hdr().addr);
            info_fns = (struct cte_info_fn*)addr;
            info_fns_count = sec.size() / sizeof(struct cte_info_fn);
            printf("fn section: [%s] %s (%p, count: %lu)\n", filename,
                   sec.get_name().c_str(), info_fns, info_fns_count);
            int rc = cte_fns_init(info_fns, &info_fns_count);
            if (rc < 0)
                return rc;
            break;
        }
        if (sec.get_name() == ".cte_essential") {
            essential_sec_vaddr = cte_get_vaddr(info, sec.get_hdr().addr);
            essential_sec_size = sec.size();
            printf("essential section: [%s] %s (%p, %lu)\n",
                   filename, sec.get_name().c_str(),
                   essential_sec_vaddr, essential_sec_size);
        }
        if (sec.get_name() == ".plt") {
            plts.push_back({
                    .vaddr = cte_get_vaddr(info, sec.get_hdr().addr),
                    .size = sec.size(),
                });
        }
    }

    texts.push_back({
            .info_fns = info_fns,
            .info_fns_count = info_fns_count,
            .vaddr = text_vaddr,
            .size = text_size,
        });
    struct cte_text *text = &texts.back();

    // Collect ELF symbol info
    for (auto &sec : obj.sections()) {
        auto sec_type = sec.get_hdr().type;
        if (sec_type == elf::sht::symtab || sec_type == elf::sht::dynsym) {
            for (auto sym : sec.as_symtab()) {
                auto &d = sym.get_data();
                // Only functions
                if (d.type() != elf::stt::func) continue;
                if (d.size == 0) continue;

                struct cte_function f = {
                    .name = sym.get_name(),
                    .size = d.size,
                    .vaddr = (void*)((uintptr_t)info->dlpi_addr + d.value),
                    .body = NULL,
                    .info_fn = NULL,
                    .essential = false,
                };

                f.body = malloc(d.size);
                memcpy(f.body, f.vaddr, f.size);

                if (text->info_fns)
                    f.info_fn = cte_find(text, f.vaddr);

                if (essential_sec_vaddr)
                    f.essential = (f.vaddr >= essential_sec_vaddr) &&
                        (f.vaddr < (char*)essential_sec_vaddr + essential_sec_size);
                // FIXME
                if (f.name == "_start" ||
                    f.name == "__libc_start_main" ||
                    f.name == "main" ||

                    // mprotect
                    f.name == "pkey_mprotect" ||
                    f.name == "__mprotect" ||

                    // memcpy
                    f.name == "memcpy@GLIBC_2.2.5" ||
                    f.name == "__memcpy_avx_unaligned_erms" ||

                    // memset
                    f.name == "__memcmp_sse4_1" ||
                    f.name == "__memset_avx2_erms" ||
                    f.name == "__memset_avx2_unaligned_erms" ||

                    // restore
                    f.name == "_ZNKSt3mapIPv12cte_functionSt4lessIS0_ESaISt4pairIKS0_S1_EEE5countERS5_" ||
                    f.name == "_ZNKSt8_Rb_treeIPvSt4pairIKS0_12cte_functionESt10_Select1stIS4_ESt4lessIS0_ESaIS4_EE4findERS2_" ||
                    f.name == "_ZNKSt8_Rb_treeIPvSt4pairIKS0_12cte_functionESt10_Select1stIS4_ESt4lessIS0_ESaIS4_EE14_M_lower_boundEPKSt13_Rb_tree_nodeIS4_EPKSt18_Rb_tree_node_baseRS2_" ||
                    f.name == "_S_right" ||
                    f.name == "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base" ||

                    // signal handler (what the hell)
                    f.name == "strcmp" ||
                    f.name == "check_match" ||
                    f.name == "do_lookup_x" ||
                    f.name == "_dl_lookup_symbol_x" ||
                    f.name == "_dl_fixup" ||
                    f.name == "_dl_runtime_resolve_xsavec") {
                    f.essential = true;
                }

                functions[f.vaddr] = f;

                // if (text->info_fns) {
                //     printf("fn: [%s] %s (%p, %lx) %d\n",
                //            filename,
                //            f.name.c_str(),
                //            f.vaddr, f.size,
                //            f.essential);
                // }
                if ((char*)f.vaddr + f.size > (char*)text->vaddr + text->size)
                    printf("WARNING: exceeds text\n");
            }
        }
    }
    return 0;
}

__attribute__((section(".cte_essential")))
static void cte_modify_begin(void *start, size_t size) {
    char *stop = (char*)start + size;
    char *aligned_start = (char*)cte_align_to_page(start);
    size_t len = stop - aligned_start;
    mprotect(aligned_start, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

__attribute__((section(".cte_essential")))
static void cte_modify_end(void *start, size_t size) {
    char *stop = (char*)start + size;
    char *aligned_start = (char*)cte_align_to_page(start);
    size_t len = stop - aligned_start;
    mprotect(aligned_start, len, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)aligned_start, (char*)stop);
}

__attribute__((section(".cte_essential")))
static void *decode_plt(void *entry) {
    unsigned char *a = (unsigned char*)entry;
    if (a[0] != 0xff)
        return NULL;
    if (a[1] != 0x25)  // FIXME: this was determined empirically
        return NULL;
    unsigned char *rip = a + 6;
    uint32_t offset = *((uint32_t*)(a + 2));
    uintptr_t *got_entry = (uintptr_t*)(rip + offset);
    return (void*)(*got_entry);
}

extern "C" {
    __attribute__((section(".cte_essential"), used))
    static int cte_restore(void *addr, void *call_addr) {
        // Find the function
        if (functions.count(addr) != 1)
            asm("int3\n");
        struct cte_function *f = &functions[addr];
        struct cte_function *cf = NULL;

        // The function can be inserted if its address is taken
        if (f->info_fn && (f->info_fn->flags | FLAG_ADDRESS_TAKEN))
            goto allowed;

        // Find the caller
        // FIXME performance
        for (auto &item : functions) {
            auto c = &item.second;
            if (call_addr >= c->vaddr && call_addr < ((char*)c->vaddr + c->size)) {
                cf = c;
                break;
            }
        }
        if (cf && cf->info_fn) {
            // A caller function was found, and it has a info_fn
            // Let's see if we are allowed to call function f
            for (int i = 0; i < cf->info_fn->calles_count; i++) {
                void *callee = cf->info_fn->callees[i];
                if (callee == addr) {
                    goto allowed;
                }
                // Maybe the callee is a pointer to a .plt section
                // FIXME performance?
                size_t len = plts.size();
                struct cte_plt *pa = plts.data();
                for (struct cte_plt *p = pa; p < &pa[len]; p++) {
                    if (callee >= p->vaddr &&
                        callee < ((char*)p->vaddr + p->size)) {
                        void *real_callee = decode_plt(callee);
                        if (real_callee == addr) {
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
}

__attribute__((section(".cte_essential"), naked))
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

__attribute__((section(".cte_essential")))
static void cte_wipe_fn(void *start, size_t size) {
    if (size < 12)
        return;

    // FIXME: rax not preserved
    unsigned char *fn = (unsigned char*)start;
    fn[0] = 0x48; // 64bit prefix
    fn[1] = 0xb8; // absmov to %rax
    *((uint64_t*)&fn[2]) = (uint64_t)cte_restore_entry;
    fn[10] = 0xff; // call *%rax
    fn[11] = 0xd0; // ...

    memset(fn + 12, 0xcc, size - 12);
}

extern "C" {
    int cte_init(void) {
        extern char *__progname;
        int rc = dl_iterate_phdr(callback, __progname);
        if (rc < 0)
            return rc;
        return 0;
    }

    __attribute__((section(".cte_essential")))
    int cte_wipe(void) {
        // FIXME
        struct cte_text *text = &texts.front();
        struct cte_text *text_stop = &texts.back();

        static std::vector<cte_function> funcs;
        if (funcs.empty()) {
            for(auto item : functions)
                funcs.push_back(item.second);
        }
        struct cte_function *func = &funcs.front();
        struct cte_function *func_stop = &funcs.back();
        // FIXME: front, back -> empty

        ////////////////////////////////////////////////////
        // (no libstdc++ code below)

        for (auto it = text; it <= text_stop; it++)
            cte_modify_begin(it->vaddr, it->size);

        for (auto it = func; it <= func_stop; it++) {
            if (!it->essential)
                cte_wipe_fn(it->vaddr, it->size);
        }

        for (auto it = text; it <= text_stop; it++)
            cte_modify_end(it->vaddr, it->size);
        return 0;
    }
}

// static void cte_graph_keep(struct cte_info_fn *info, bool *keep_entries) {
//     size_t index = cte_info_fn_index(info);

//     // Abort recursion when processing recursive functions
//     if (keep_entries[index])
//         return;

//     // Mark this info_fn as not to eliminate
//     keep_entries[index] = true;

//     // Process callees
//     for (int i = 0; i < info->calles_count; i++) {
//         struct cte_info_fn *callee_info = cte_callee_as_info_fn(info->callees[i]);
//         if (callee_info)
//             cte_graph_keep(callee_info, keep_entries);
//     }
// }

// void cte_eliminate_graph(void *keep_fns[], long count) {
//     // Array to track the functions that we want to keep
//     bool keep_entries[info_fns_count];
//     for (bool *e = keep_entries; e < keep_entries + info_fns_count; e++)
//         *e = false;

//     // Follow call graph of keep_fns
//     for (long i = 0; i < count; i++)
//         cte_graph_keep(cte_find(keep_fns[i]), keep_entries);

//     // Collect all adress-taken functions
//     for (size_t i = 0; i < info_fns_count; i++) {
//         struct cte_info_fn *info = &info_fns[i];
//         keep_entries[i] = keep_entries[i] || (info->flags & FLAG_ADDRESS_TAKEN);

//         // Recursively mark all functions that are called from
//         // address-taken functions
//         if (keep_entries[i])
//             cte_graph_keep(info, keep_entries);
//     }

//     // Eliminate unused functions
//     void *start = info_fns[0].fn;
//     void *stop = info_fns[info_fns_count-1].fn_end;
//     size_t eliminated_count = 0;
//     size_t eliminated_bytes = 0;
//     size_t total_bytes = 0;
//     cte_eliminate_begin(start, stop);
//     for (size_t i = 0; i < info_fns_count; i++) {
//         struct cte_info_fn *info = &info_fns[i];
//         if (info->fn >= info->fn_end)
//             continue;
//         size_t fn_bytes = (size_t)info->fn_end - (size_t)info->fn;
//         total_bytes += fn_bytes;
//         if (!keep_entries[i]) {
//             cte_eliminate_range(info->fn, info->fn_end);
//             eliminated_count++;
//             eliminated_bytes += fn_bytes;
//         }
//     }
//     printf("CTE: eliminated count: %lu / %lu\n", eliminated_count, info_fns_count);
//     printf("CTE: eliminated bytes: %lu / %lu\n", eliminated_bytes, total_bytes);
//     cte_eliminate_end(start, stop);
// }
