#include <iterator>
#include <string.h>
#include <sstream>
#include "ctemeta.hh"
#include "util.hh"

bool Function::merge_same(Function &other) {
    if (vaddr == other.vaddr && (size == other.size ||
                                 size == 0 || other.size == 0)) {
        if (name == "")
            name = other.name;
        if (size == 0)
            size = other.size;
        address_taken = address_taken || other.address_taken;
        has_indirect_calls = has_indirect_calls || other.has_indirect_calls;
        siblings.insert(other.siblings.begin(), other.siblings.end());
        callees.insert(other.callees.begin(), other.callees.end());
        jumpees.insert(other.jumpees.begin(), other.jumpees.end());
        return true;
    }
    return false;
}

bool Function::merge_containing(Function &other) {
    if (vaddr + size > other.vaddr) {
        address_taken = address_taken || other.address_taken;
        has_indirect_calls = has_indirect_calls || other.has_indirect_calls;
        siblings.insert(other.siblings.begin(), other.siblings.end());
        callees.insert(other.callees.begin(), other.callees.end());
        jumpees.insert(other.jumpees.begin(), other.jumpees.end());
        return true;
    }
    return false;
}

std::string Function::str() {
    std::stringstream s;
    s << name << " [";
    s << "0x" << std::hex << vaddr;
    s << "/+0x" << std::hex << size;
    s << "]";
    return s.str();
}

Function *Cte::containing_function(addr_t addr) {
    auto nextf = functions.upper_bound(addr);
    if (nextf == functions.begin())
        return NULL;
    Function *fn = &(std::prev(nextf))->second;
    if (addr >= fn->vaddr + fn->size)
        return NULL;
    return fn;
}

Section *Cte::containing_section(addr_t addr) {
    auto nextf = sections.upper_bound(addr);
    if (nextf == sections.begin())
        return NULL;
    Section *s = &(std::prev(nextf))->second;
    if (addr >= s->vaddr + s->size)
        return NULL;
    return s;
}

bool Cte::in_text_segment(addr_t addr) {
    return (addr >= text_vaddr) && (addr < text_vaddr + text_size);
}

static Function *make_plt_function(Cte *cte, Section *scn, addr_t vaddr) {
    // There may be already a plt-Function,
    // because containing_function does not find zero-sized symbols.
    if (!cte->functions.count(vaddr)) {
        Function newfn { "<plt entry>", vaddr, 0, false, false };
        newfn.section = scn->vaddr;
        cte->functions[vaddr] = newfn;
    }
    return &cte->functions[vaddr];
}

static Function *make_extern_function(Cte *cte, Relocation &r) {
    // The value of an external function is the place of the relocation
    // and not its value (which is 0 in most cases)
    addr_t vaddr = r.offset;
    if (!cte->functions.count(vaddr)) {
        Function newfn { "<extern ref: " + r.sym_name + ">", vaddr, 0, false, true };
        cte->functions[vaddr] = newfn;
    }
    return &cte->functions[vaddr];
}

void Cte::register_call(Function &sender, addr_t source, addr_t target) {
    Function *fn = containing_function(target);
    if (!fn) {
        Section *scn = containing_section(target);
        if (scn && scn->is_plt) {
            fn = make_plt_function(this, scn, target);

            debug("Register call to plt (%s) at %s+0x%lx\n",
                  scn->name.c_str(), sender.name.c_str(), source - sender.vaddr);
        } else {
            warn("Ignore call to unknown location %lx at %s+0x%lx\n",
                 target, sender.name.c_str(), source - sender.vaddr);
            return;
        }
    }

    if (target != fn->vaddr) {
        sender.siblings.insert(fn->vaddr);

        warn("Found call to non function start %s+0x%lx at %s+0x%lx; "
             "registered as sibling\n",
             fn->name.c_str(), target - fn->vaddr,
             sender.name.c_str(), source - sender.vaddr);
    } else {
        sender.callees.insert(fn->vaddr);

        debug("Register call to function %s at %s+0x%lx\n",
              fn->name.c_str(), sender.name.c_str(), source - sender.vaddr);
    }
}

void Cte::register_jump(Function &sender, addr_t source, addr_t target) {
    Function *fn = containing_function(target);
    if (!fn) {
        Section *scn = containing_section(target);
        if (scn && scn->is_plt) {
            fn = make_plt_function(this, scn, target);

            debug("Register jump to plt (%s) at %s+0x%lx\n",
                  scn->name.c_str(), sender.name.c_str(), source - sender.vaddr);
        } else {
            warn("Ignore jump to unknown location %lx at %s+0x%lx\n",
                 target, sender.name.c_str(), source - sender.vaddr);
            return;
        }
    }

    if (fn->vaddr == sender.vaddr)
        return;

    if (target != fn->vaddr) {
        sender.siblings.insert(fn->vaddr);

        debug("Register sibling due to jump to %s+0x%lx at %s+0x%lx",
              fn->name.c_str(), target - fn->vaddr,
              sender.name.c_str(), source - sender.vaddr);
    } else {
        sender.jumpees.insert(fn->vaddr);

        debug("Register jump to function %s at %s+0x%lx\n",
              fn->name.c_str(), sender.name.c_str(), source - sender.vaddr);
    }
}

void Cte::register_address_taken(Function &sender, addr_t source, addr_t target) {
    if (!in_text_segment(target))
        return;

    Function *fn = containing_function(target);
    if (!fn) {
        Section *scn = containing_section(target);
        if (scn && scn->is_plt) {
            fn = make_plt_function(this, scn, target);
        } else {
            debug("Ignore address taken of unknown location 0x%lx at %s+0x%lx\n",
                  target, sender.name.c_str(), source - sender.vaddr);
            return;
        }
    }

    if (target != fn->vaddr) {
        if (sender.vaddr != fn->vaddr) {
            warn("Address taken of non function start "
                 "%s+0x%lx at %s+0x%lx; registered as sibling\n",
                 fn->name.c_str(), target - fn->vaddr,
                 sender.name.c_str(), source - sender.vaddr);
            sender.siblings.insert(fn->vaddr);
        } else {
            warn("Address taken of non function start "
                 "%s+0x%lx at %s+0x%lx\n",
                 fn->name.c_str(), target - fn->vaddr,
                 sender.name.c_str(), source - sender.vaddr);
        }
        return;
    }

    fn->address_taken = true;

    debug("Register address taken of function %s at %s+0x%lx\n",
          fn->name.c_str(), sender.name.c_str(), source - sender.vaddr);
}

void Cte::register_indirect_call(Function &fn, addr_t source) {
    fn.has_indirect_calls = true;

    debug("Register indirect call to function at %s+0x%lx\n",
          fn.name.c_str(), source - fn.vaddr);
}

void Cte::register_indirect_jump(Function &fn, addr_t source) {
    fn.has_indirect_jumps = true;

    debug("Register indirect jump to function at %s+0x%lx\n",
          fn.name.c_str(), source - fn.vaddr);
}

void Cte::analyze() {
    // Relocations
    for (auto &reloc : relocations) {
        Function *fn;
        if (reloc.extern_ref) {
            fn = make_extern_function(this, reloc);
            debug("Extern reference to %s: relocation at 0x%lx\n",
                  reloc.sym_name.c_str(), reloc.offset);
        } else {
            if (!functions.count(reloc.value)) {
                warn("Missing function symbol at 0x%lx: relocation at 0x%lx\n",
                     reloc.value, reloc.offset);
                continue;
            }
            fn = &functions[reloc.value];
        }
        fn->address_taken = true;
    }

    // Functions
    for (auto &item : functions) {
        auto &fn = item.second;
        analyze_function(fn);
    }
}

void Cte::clear_visited() {
    for (auto &item : functions) {
        auto &fn = item.second;
        fn.visited = false;
    }
}

void Cte::propagate() {
    for (auto &item : functions) {
        auto &fn = item.second;
        std::set<addr_t> gather;
        clear_visited();
        for (addr_t addr : fn.callees) {
            auto &callee = functions.at(addr);
            propagate_jumpees(callee, gather);
        }
        fn.callees.insert(gather.begin(), gather.end());
    }

    for (auto &item : functions) {
        auto &fn = item.second;
        clear_visited();
        propagate_siblings(fn);
    }

    for (auto &item : functions) {
        auto &fn = item.second;
        propagate_indirect_jumps(fn);
    }

    clear_visited();
    for (auto &item : functions) {
        auto &fn = item.second;
        if (fn.address_taken)
            propagate_address_taken(fn);
    }
}

void Cte::propagate_jumpees(Function &fn, std::set<addr_t> &gather) {
    if (fn.visited)
        return;
    fn.visited = true;

    for (addr_t addr : fn.jumpees) {
        gather.insert(addr);
        auto &jumpee = functions.at(addr);
        propagate_jumpees(jumpee, gather);
    }
}

void Cte::propagate_siblings(Function &fn) {
    if (fn.visited)
        return;
    fn.visited = true;

    for (addr_t addr : fn.siblings) {
        auto &sibling = functions.at(addr);
        propagate_siblings(sibling);

        for (addr_t addr : sibling.siblings) {
            fn.siblings.insert(addr);
        }
        for (addr_t addr : sibling.callees) {
            fn.callees.insert(addr);
        }
        for (addr_t addr : sibling.jumpees) {
            fn.jumpees.insert(addr);
        }
    }
}

void Cte::propagate_indirect_jumps(Function &fn) {
    for (addr_t addr : fn.callees) {
        auto &callee = functions.at(addr);
        if (callee.has_indirect_jumps)
            fn.has_indirect_calls = true;
    }

    for (addr_t addr : fn.siblings) {
        auto &sibling = functions.at(addr);
        if (sibling.has_indirect_jumps)
            fn.has_indirect_calls = true;
    }
}

void Cte::propagate_address_taken(Function &fn) {
    if (fn.visited)
        return;
    fn.visited = true;

    for (addr_t addr : fn.jumpees) {
        auto &jumpee = functions.at(addr);
        propagate_address_taken(jumpee);
        jumpee.address_taken = true;
    }
}
