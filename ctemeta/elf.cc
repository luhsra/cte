#include <cstdint>
#include <link.h>
#include <iomanip>
#include <string>
#include <map>
#include <vector>
#include <elf.h>
#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include "ctemeta.hh"
#include "util.hh"

bool keep_sizes = false;

static void error_libelf(void) {
    error(Error::ELF, "libelf: %s\n", elf_errmsg( -1));
}

static std::map<addr_t, Function>
scan_functions(Elf *elf, addr_t text_start, addr_t text_end) {
    bool symtab_found = false;
    std::map<addr_t, Function> map;
    Elf_Scn* scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr)
            error(Error::ELF, "ELF: Invalid section\n");

        if (shdr.sh_type == SHT_SYMTAB)
            symtab_found = true;

        // I think, DYNSYM is a subset of SYMTAB in most cases..
        // However, we'll look at both for now and discard duplicates.
        // (SYMTAB can be stripped, but CTE requires it)
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            // uint64_t symtab = elf_scnshndx(scn);
            Elf_Data *data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;
            for (int i = 0; i < count; ++i) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                std::string name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                bool no_code = false;

                // Only defined functions
                if (sym.st_shndx == SHN_UNDEF)
                    continue;
                if (sym.st_value < text_start || sym.st_value >= text_end)
                    continue;
                if (GELF_ST_TYPE(sym.st_info) == STT_SECTION)
                    continue;
                if (GELF_ST_TYPE(sym.st_info) == STT_NOTYPE) {
                    warn("ELF: Ignore non-typed symbol in text: %s\n",
                         name.c_str());
                    continue;
                }
                if (GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
                    GELF_ST_TYPE(sym.st_info) != STT_GNU_IFUNC) {
                    warn("ELF: Found non-function symbol (type: %u) in text: %s\n",
                         GELF_ST_TYPE(sym.st_info), name.c_str());
                    no_code = true;
                }

                addr_t vaddr = sym.st_value;
                addr_t size = sym.st_size;
                Function f { name, vaddr, size, true, false };
                f.no_code = no_code;
                if (map.count(vaddr) == 0) {
                    map[vaddr] = f;
                } else {
                    if (!map[vaddr].merge_same(f))
                        error(Error::ELF,
                              "Differing function symbols to the same address: %s, %s\n",
                              f.str().c_str(), map[vaddr].str().c_str());
                }
            }
        }
    }

    if (!symtab_found)
        error(Error::ELF, "Symbol table not found\n");

    return map;
}

static void enlarge_body(Section &sec, Function &fn, Function *next_fn) {
    if (fn.definition && !fn.no_code) {
        // Enlarge to the start of the nex function
        addr_t new_size = (next_fn) ? (next_fn->vaddr - fn.vaddr) : fn.size;

        // New size must not exceed the section boundary,
        // or if there is no next_fn, enlarge to the section boundary
        if ((fn.vaddr + new_size > sec.vaddr + sec.size) || !next_fn)
            new_size = sec.vaddr + sec.size - fn.vaddr;

        if (new_size < fn.size)
            error(Error::ELF, "ELF: Enlarge function body: %s: "
                  "Corrupt sizes. This should not happen.", fn.str().c_str());

        if (fn.size != 0 && new_size >= fn.size + 64)
            warn("ELF: Enlarge function body: %s: "
                 "Sanity warning: old size: 0x%lx, new size: 0x%lx\n",
                 fn.str().c_str(), fn.size, new_size);

        if (new_size > fn.size)
            debug("ELF: Enlarge function body: %s: "
                  "old size: 0x%lx, new size: 0x%lx\n",
                  fn.str().c_str(), fn.size, new_size);

        // Finally, assign new size
        fn.size = new_size;
    }
}

static std::map<addr_t, Section>
scan_sections(Elf *elf, std::map<addr_t, Function> &functions) {
    std::map<addr_t, Section> map;
    Elf_Scn* scn = NULL;

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        error_libelf();

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr)
            error(Error::ELF, "ELF: Invalid section\n");

        if (shdr.sh_flags & SHF_EXECINSTR) {
            Elf_Data *data = elf_getdata(scn, NULL);
            std::string name = elf_strptr(elf, shstrndx, shdr.sh_name);

            if (!data || data->d_size != shdr.sh_size)
                error(Error::ELF, "ELF: Unsupported executable section %s\n",
                      name.c_str());

            addr_t vaddr = shdr.sh_addr;
            addr_t size = shdr.sh_size;
            uint8_t *buf = (uint8_t*)data->d_buf;
            bool is_plt = (name.rfind(".plt", 0) == 0);
            bool is_fini = name == ".fini";

            if (map.count(vaddr) == 0) {
                map[vaddr] = Section(name, vaddr, size, is_plt);
            } else {
                error(Error::ELF, "ELF: Overlapping sections %s, %s\n",
                      name.c_str(), map[vaddr].name.c_str());
            }

            addr_t vaddr_end = vaddr + size;
            info("ELF: executable section: 0x%lx-0x%lx: %s\n",
                  vaddr, vaddr_end, name.c_str());

            auto it = functions.lower_bound(vaddr);
            auto end = functions.upper_bound(vaddr_end - 1);
            while (it != end) {
                Function &fn = it->second;
                Function *fn_next;
                addr_t border;
                bool merged;
                do {
                    merged = false;
                    it++;
                    fn_next = (it != functions.end()) ? &it->second : nullptr;

                    border = (fn_next) ? fn_next->vaddr : vaddr_end;
                    if (fn_next && fn.vaddr + fn.size > border) {
                        if (!fn.no_code && !fn_next->no_code &&
                            fn_next->size == 0) {
                            // Merge zero sized symbols with an overlapping
                            // previous symbol (special case for some libraries).
                            // A call or jump to the merged symbol will cause a
                            // sibling relationship.
                            debug("ELF: Merge functions: %s and %s\n",
                                  fn.str().c_str(), fn_next->str().c_str());
                            fn.merge_containing(*fn_next);
                            functions.erase(it--);
                            merged = true;
                        } else {
                            error(Error::ELF,
                                  "Function/object %s exceeds next function %s\n",
                                  fn.str().c_str(), fn_next->str().c_str());
                        }
                    } else if (fn.vaddr + fn.size > border) {
                        error(Error::ELF, "Function/object %s exceeds section end\n",
                              fn.str().c_str());
                    }
                } while (merged);

                fn.section = vaddr;
                fn.definition = !is_plt;
                if (!keep_sizes)
                    enlarge_body(map.at(vaddr), fn, fn_next);
                fn.code.assign(&buf[fn.vaddr - vaddr], &buf[border - vaddr]);

                if (is_fini)
                    fn.address_taken = true;
            }
        }
    }

    // Remove no-code functions
    for (auto it = functions.begin(); it != functions.end(); it++) {
        Function &fn = it->second;
        if (fn.no_code)
            functions.erase(it--);
    }

    for (auto &item : functions) {
        Function &fn = item.second;
        if (fn.definition && fn.size == 0)
            warn("ELF: Zero-sized function: %s\n", fn.str().c_str());
    }

    return map;
}

static std::vector<Relocation>
scan_relocations(Elf *elf, addr_t text_start, addr_t text_end) {
    std::vector<Relocation> vec;
    Elf_Scn* scn = NULL;

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        error_libelf();

    // Find cte specific sections.  We ignore relocations in these
    // sections, as they are not relevant for address taken information.
    std::vector<std::pair<addr_t, addr_t>> ignored_ranges;
    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr)
            error(Error::ELF, "ELF: Invalid section\n");

        std::string name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (name == ".cte_fn" || name == ".cte_data") {
            info("Ignore relocations in section: %s\n", name.c_str());

            addr_t start = shdr.sh_addr;
            addr_t end = shdr.sh_addr + shdr.sh_size;
            ignored_ranges.push_back({ start, end });
        }
    }

    // Scan relocation sections
    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr)
            error(Error::ELF, "ELF: Invalid section\n");

        char *name = elf_strptr(elf, shstrndx, shdr.sh_name);

        if (shdr.sh_type == SHT_REL) {
            error(Error::ELF, "ELF: Relocations without addend (SHT_REL) are "
                  "currently not supported: section %s\n", name);
        }

        if (shdr.sh_type == SHT_RELA) {
            info("ELF: relocation section: %s\n", name);

            GElf_Word symtab_idx = shdr.sh_link;
            Elf_Scn *symtab_scn = elf_getscn(elf, symtab_idx);
            Elf_Data *symtab_data = elf_getdata(symtab_scn, NULL);

            Elf_Data *data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;
            for (int i = 0; i < count; ++i) {
                GElf_Rela rel;
                gelf_getrela(data, i, &rel);

                GElf_Xword rel_type = GELF_R_TYPE(rel.r_info);
                addr_t offset = rel.r_offset;
                addr_t value;
                bool extern_ref = false;
                const char *sym_name = "";
                uint64_t symbol_idx = GELF_R_SYM(rel.r_info);

                // Ignore relocations in cte sections
                bool ignored = false;
                for (auto it = ignored_ranges.begin();
                     it < ignored_ranges.end();
                     it++) {
                    if (offset >= it->first && offset < it->second)
                        ignored = true;
                }
                if (ignored)
                    continue;

                // Process relocations and calculate values
                if (rel_type == R_X86_64_64 ||
                    rel_type == R_X86_64_GLOB_DAT) {
                    if (symbol_idx == 0)
                        error(Error::ELF, "Unexpected relocation data: "
                              "idx: %d, type: %lu, sym_idx: 0, addend: 0x%lx\n",
                              i, rel_type, rel.r_addend);
                    GElf_Sym sym;
                    gelf_getsym(symtab_data, symbol_idx, &sym);

                    if (GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
                        GELF_ST_TYPE(sym.st_info) != STT_GNU_IFUNC)
                        continue;

                    if (sym.st_shndx >= SHN_LORESERVE) {
                        warn("Ignore relocation to unsupported symbol: "
                             "idx: %d, type: %lu\n", i, rel_type);
                        continue;
                    }

                    extern_ref = (sym.st_shndx == SHN_UNDEF);

                    // Name of the symbol
                    GElf_Shdr symtab_shdr;
                    gelf_getshdr(symtab_scn, &symtab_shdr);
                    sym_name = elf_strptr(elf, symtab_shdr.sh_link, sym.st_name);

                    value = sym.st_value + rel.r_addend;

                } else if (rel_type == R_X86_64_RELATIVE ||
                           rel_type == R_X86_64_IRELATIVE) {
                    if (symbol_idx != 0)
                        error(Error::ELF, "Unexpected relocation data: "
                              "idx: %d, type: %lu, sym_idx: %lu, addend: 0x%lx\n",
                              i, rel_type, symbol_idx, rel.r_addend);
                    value = rel.r_addend;

                } else if (rel_type == R_X86_64_COPY) {
                    if (symbol_idx == 0)
                        error(Error::ELF, "Unexpected relocation data: "
                              "idx: %d, type: %lu, sym_idx: 0, addend: 0x%lx\n",
                              i, rel_type, rel.r_addend);
                    GElf_Sym sym;
                    gelf_getsym(symtab_data, symbol_idx, &sym);
                    if (GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
                        GELF_ST_TYPE(sym.st_info) != STT_GNU_IFUNC)
                        continue;
                    warn("Unsupported relocation: "
                         "idx: %d, type: %lu, sym_idx: 0, addend: 0x%lx\n",
                         i, rel_type, rel.r_addend);
                    continue;

                } else if (rel_type == R_X86_64_TPOFF64 ||
                           rel_type == R_X86_64_JUMP_SLOT) {
                    debug("Ignore relocation: idx: %d, type: %lu\n", i, rel_type);
                    continue;

                } else {
                    warn("Ignore unsupported relocation: idx: %d, type: %lu\n",
                         i, rel_type);
                    continue;
                }

                if (!(extern_ref || (value >= text_start && value < text_end))) {
                    // Relocation target is not external and does not target the code.
                    continue;
                }

                debug("Relevant relocation [%d] at 0x%lx, vlaue: 0x%lx (%s), type: %lu\n",
                      i, offset, value, sym_name, rel_type);

                vec.push_back({ offset, value, extern_ref, sym_name });
            }
        }
    }

    return vec;
}

static std::vector<std::string> get_debug_files(Elf *elf) {
    std::vector<std::string> ret;
    Elf_Scn* scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr)
            error(Error::ELF, "ELF: Invalid section\n");

        if (shdr.sh_type != SHT_NOTE)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        uint8_t *rdata = (uint8_t*)data->d_buf;
        ElfW(Nhdr) nhdr;
        size_t offset = 0;
        do {
            size_t name_offset;
            size_t desc_offset;
            offset = gelf_getnote(data, offset, &nhdr, &name_offset, &desc_offset);
            if (nhdr.n_type == NT_GNU_BUILD_ID &&
                nhdr.n_descsz != 0 &&
                nhdr.n_namesz == 4 &&
                memcmp(&rdata[name_offset], "GNU", 4) == 0) {

                std::stringstream filename;
                filename << "/usr/lib/debug/.build-id/";
                filename << std::hex << std::setfill('0') << std::setw(2)
                         << (int)rdata[desc_offset] << "/";
                for (unsigned i = 1; i < nhdr.n_descsz; i++) {
                    filename << std::hex << std::setfill('0') << std::setw(2)
                             << (int)rdata[desc_offset + i];
                }
                filename << ".debug";

                std::string name = filename.str();
                debug("Found debug info: %s\n", name.c_str());

                // Add the filnanme to the list if the file exists
                struct stat buffer;
                if (stat(name.c_str(), &buffer) == 0) {
                    ret.push_back(name);
                }
            }
        } while (offset == 0);
    }
    return ret;
}

Cte Cte::from_elf(const char *filename) {
    if (elf_version(EV_CURRENT) == EV_NONE)
        error_libelf();

    int file = open(filename, O_RDONLY);
    if (file < 0)
        error(Error::IO, "IO error: %s: %s\n", filename, strerror(errno));

    Elf *elf = elf_begin(file, ELF_C_READ, NULL);
    if (!elf)
        error_libelf();

    if (elf_kind(elf) != ELF_K_ELF) {
        elf_end(elf);
        error(Error::ELF, "Invalid ELF\n");
    }

    // ELF header info
    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf , &ehdr))
        error_libelf();
    if (ehdr.e_type != ET_DYN && ehdr.e_type != ET_REL)
        error(Error::ELF, "ELF should be position independent\n");
    if (ehdr.e_machine != EM_X86_64)
        error(Error::ELF, "ELF: unsupported architecture\n");

    size_t phdrnum;
    if (elf_getphdrnum(elf, &phdrnum) != 0)
        error_libelf();
    GElf_Phdr phdr;

    // Find the text segment
    addr_t text_vaddr = 0;
    addr_t text_size = 0;
    bool text_found = false;
    for (size_t i = 0; i < phdrnum; i++) {
        if (gelf_getphdr(elf, i, &phdr) != &phdr)
            error_libelf();
        if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
            if (text_found)
                error(Error::ELF, "ELF: Unsupported: Multiple executable segments\n");
            if (phdr.p_memsz != phdr.p_filesz)
                error(Error::ELF, "ELF: text segment filesize (%lu) != memsize (%lu)\n",
                      phdr.p_filesz, phdr.p_memsz);
            text_vaddr = phdr.p_vaddr;
            text_size = phdr.p_memsz;
            text_found = true;
            info("ELF: executable segment: 0x%lx-0x%lx\n",
                  text_vaddr, text_vaddr + text_size);
        }
    }

    std::map<addr_t, Function> functions;

    // Collect info from debug file, if build id is present
    // read symbols from debug info
    std::vector<std::string> dbgs = get_debug_files(elf);

    // Prefer debug elf file for the symbols (functions)
    if (!dbgs.empty()) {
        // FIXME: Currently, the first found dbgsym elf is taken
        const char *filename = dbgs[0].c_str();
        info("ELF: Use debug info: %s\n", filename);
        int dbgfile = open(filename, O_RDONLY);
        if (dbgfile < 0)
            error(Error::IO, "IO error: %s: %s\n", filename, strerror(errno));

        Elf *dbgelf = elf_begin(dbgfile, ELF_C_READ, NULL);
        if (!dbgelf)
            error_libelf();

        if (elf_kind(dbgelf) != ELF_K_ELF) {
            elf_end(dbgelf);
            error(Error::ELF, "Invalid ELF\n");
        }
        functions = scan_functions(dbgelf, text_vaddr, text_vaddr + text_size);
        elf_end(dbgelf);
        close(dbgfile);
    } else {
        functions = scan_functions(elf, text_vaddr, text_vaddr + text_size);
    }

    // Get section and relocation data
    auto sections = scan_sections(elf, functions);
    auto relocations = scan_relocations(elf, text_vaddr, text_vaddr + text_size);

    elf_end(elf);
    close(file);

    return { text_vaddr, text_size, functions, sections, relocations };
}
