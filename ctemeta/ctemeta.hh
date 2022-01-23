#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <ostream>

typedef uint64_t addr_t;

struct Function {
    std::string name;
    addr_t vaddr;
    addr_t size;
    addr_t section;
    bool definition; // Currently, this is ->section.is_plt (if section != 0)
    bool address_taken;
    bool has_indirect_calls;
    bool has_indirect_jumps;
    bool extern_ref; // Function not defined here and no plt entry
    bool visited;    // Auxiliary flag for propagate functions

    std::set<addr_t> siblings;
    std::set<addr_t> callees;
    std::set<addr_t> jumpees;
    std::vector<uint8_t> code; // Extends to next function start (>= size)

    Function()
        : name(""), vaddr(0), size(0), section(0), definition(false),
          address_taken(false), has_indirect_calls(false),
          has_indirect_jumps(false), extern_ref(false), visited(false) {}

    Function(std::string name, addr_t vaddr, addr_t size, bool definition,
             bool extern_ref)
        : name(name), vaddr(vaddr), size(size), section(0),
          definition(definition), address_taken(false),
          has_indirect_calls(false), has_indirect_jumps(false),
          extern_ref(extern_ref), visited(false) {}

    bool merge_same(Function &other);
    bool merge_containing(Function &other);

    std::string str();
};

struct Section {
    std::string name;
    addr_t vaddr;
    addr_t size;
    bool is_plt;

    Section()
        : name(""), vaddr(0), size(0), is_plt(false) {}

    Section(std::string name, addr_t vaddr, addr_t size, bool is_plt)
        : name(name), vaddr(vaddr), size(size), is_plt(is_plt) {}
};

struct Relocation {
    addr_t offset;        // where is the relocation (vaddr)
    addr_t value;         // what does the relocation refer to (vaddr)
    bool extern_ref;      // relocations points to an external reference
    std::string sym_name; // Name of the target symbol if existing

    Relocation()
        : offset(0), value(0), extern_ref(false) {}

    Relocation(addr_t offset, addr_t vaddr, bool extern_ref,
               std::string sym_name)
        : offset(offset), value(vaddr), extern_ref(extern_ref),
          sym_name(sym_name) {}
};

struct Cte {
    addr_t text_vaddr;
    addr_t text_size;
    std::map<addr_t, Function> functions;
    std::map<addr_t, Section> sections;
    std::vector<Relocation> relocations;

    Cte(addr_t text_vaddr, addr_t text_size,
        std::map<addr_t, Function> functions,
        std::map<addr_t, Section> sections,
        std::vector<Relocation> relocations)
        : text_vaddr(text_vaddr), text_size(text_size),
          functions(functions), sections(sections), relocations(relocations) {}

    static Cte from_elf(const char *filename);

    void analyze();
    void analyze_function(Function &fn);

    void register_call(Function &sender, addr_t source, addr_t target);
    void register_jump(Function &sender, addr_t source, addr_t target);
    void register_address_taken(Function &sender, addr_t source, addr_t target);
    void register_indirect_call(Function &fn, addr_t source);
    void register_indirect_jump(Function &fn, addr_t source);

    Function *containing_function(addr_t addr);
    Section *containing_section(addr_t addr);
    bool in_text_segment(addr_t addr);

    void propagate();
    void propagate_jumpees(Function &fn, std::set<addr_t> &gather);
    void propagate_siblings(Function &fn);
    void propagate_indirect_jumps(Function &fn);
    void propagate_address_taken(Function &fn);
    void clear_visited();

    std::vector<uint8_t> dump();

    void print(std::ostream &stream);
    void print(std::ostream &stream, Function &fn);
};
