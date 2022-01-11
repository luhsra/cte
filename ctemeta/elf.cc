#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <elf.h>
#include <gelf.h>
#include "ctemeta.hh"
#include "util.hh"

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

                // Only functions
                if (sym.st_value < text_start || sym.st_value >= text_end)
                    continue;
                if (GELF_ST_TYPE(sym.st_info) != STT_FUNC &&
                    GELF_ST_TYPE(sym.st_info) != STT_GNU_IFUNC)
                    warn("ELF: Found non function symbol in text: %s\n",
                         name.c_str());

                addr_t vaddr = sym.st_value;
                addr_t size = sym.st_size;
                Function f { name, vaddr, size, true };
                if (map.count(vaddr) == 0) {
                    map[vaddr] = f;
                } else {
                    if (!map[vaddr].merge(f))
                        error(Error::ELF,
                              "Differing redundant function symbols: %s, %s\n",
                              f.str().c_str(), map[vaddr].str().c_str());
                }
            }
        }
    }

    if (!symtab_found)
        error(Error::ELF, "Symbol table not found");

    return map;
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
                it++;
                addr_t border = (it != end) ? it->second.vaddr : vaddr_end;
                if (fn.vaddr + fn.size > border)
                    error(Error::ELF,
                          "Function %s exceeds next function or section end\n",
                          fn.str().c_str());
                fn.code.assign(&buf[fn.vaddr - vaddr], &buf[border - vaddr]);
                fn.section = vaddr;
                fn.definition = !is_plt;
            }
        }
    }

    // Finally, scan all functions and warn about zero-sized functions
    // TODO: We could extend the functions to the next function start.
    //       Maybe, with some sanity-checks (size, ...)
    for (auto &item : functions) {
        auto &fn = item.second;
        if (fn.size == 0 && fn.definition) {
            warn("ELF: Zero-sized symbol: %s (0x%lx)\n",
                 fn.name.c_str(), fn.vaddr);
        }
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
                bool plt = (rel_type == R_X86_64_JUMP_SLOT);
                bool got = (rel_type == R_X86_64_GLOB_DAT);
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
                    rel_type == R_X86_64_GLOB_DAT ||
                    rel_type == R_X86_64_JUMP_SLOT) {
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

                    // Name of the symbol
                    GElf_Shdr symtab_shdr;
                    gelf_getshdr(symtab_scn, &symtab_shdr);
                    char *name = elf_strptr(elf, symtab_shdr.sh_link, sym.st_name);

                    if (sym.st_shndx == SHN_UNDEF) {
                        // This symbol is located in another object

                        // This is a direct reference (no plt incirection) to a
                        // function in another ELF object.
                        // FIXME: Handling this would require rearranging some
                        //        data structures
                        if (rel_type == R_X86_64_64)
                            error(Error::ELF,
                                  "Direct reference to an undefined function: %s\n",
                                  name);

                        continue;
                    }

                    value = sym.st_value + rel.r_addend;
                } else if (rel_type == R_X86_64_RELATIVE ||
                           rel_type == R_X86_64_IRELATIVE) {
                    if (symbol_idx != 0)
                        error(Error::ELF, "Unexpected relocation data: "
                              "idx: %d, type: %lu, sym_idx: %lu, addend: 0x%lx\n",
                              i, rel_type, symbol_idx, rel.r_addend);
                    value = rel.r_addend;
                } else if (rel_type == R_X86_64_TPOFF64) {
                    debug("Ignore relocation: idx: %d, type: %lu\n", i, rel_type);
                    continue;
                } else {
                    warn("Ignore unsupported relocation: idx: %d, type: %lu\n",
                         i, rel_type);
                    continue;
                }

                if (!(value >= text_start && value < text_end)) {
                    // Relocation does not target the executable segment.
                    continue;
                }

                // printf("%lx -> %d: [%lu] 0x%lx\n", offset, i, rel_type, value);

                vec.push_back({ offset, value, plt, got });
            }
        }
    }

    return vec;
}

Cte Cte::from_elf(int file) {
    if (elf_version(EV_CURRENT) == EV_NONE)
        error_libelf();

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
                error(Error::ELF, "ELF: text segment filesize != memsize\n");
            text_vaddr = phdr.p_vaddr;
            text_size = phdr.p_memsz;
            text_found = true;
            info("ELF: executable segment: 0x%lx-0x%lx\n",
                  text_vaddr, text_vaddr + text_size);
        }
    }

    // Collect info from debug file, if build id is present
    // Read Symbols from debug info
    for (size_t i = 0; i < phdrnum; i++) {
        if (gelf_getphdr(elf, i, &phdr) != &phdr)
            error_libelf();
        if (phdr.p_type == PT_NOTE) {
            // TODO cte_handle_build_id
        }
    }

    // Get function and section data
    auto functions = scan_functions(elf, text_vaddr, text_vaddr + text_size);
    auto sections = scan_sections(elf, functions);
    auto relocations = scan_relocations(elf, text_vaddr, text_vaddr + text_size);

    elf_end(elf);

    return { text_vaddr, text_size, functions, sections, relocations };
}
