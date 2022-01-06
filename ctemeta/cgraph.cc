#include <iterator>
#include <string.h>
#include <sstream>
#include "ctemeta.hh"
#include "util.hh"

bool Function::merge(Function &other) {
    if (vaddr == other.vaddr && size == other.size &&
        siblings.empty() && other.siblings.empty() &&
        callees.empty() && other.callees.empty() &&
        jumpees.empty() && other.jumpees.empty()) {
        address_taken = address_taken || other.address_taken;
        has_indirect_calls = has_indirect_calls || other.has_indirect_calls;
        return true;
    }
    return false;
}

std::string Function::str() {
    std::stringstream s;
    s << name << "[";
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
    Function newfn { "<plt entry>", 0, vaddr, 0, false };
    newfn.section = scn->vaddr;
    cte->functions[vaddr] = newfn;
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

    if (fn->vaddr == sender.vaddr)
        return;

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

            debug("Register address taken of %lx plt (%s) at %s+0x%lx\n",
                  target, scn->name.c_str(), sender.name.c_str(),
                  source - sender.vaddr);
        } else {
            warn("Ignore address taken of unknown location %lx at %s+0x%lx\n",
                 target, sender.name.c_str(), source - sender.vaddr);
            return;
        }
    }

    if (target != fn->vaddr) {
        warn("Ignore address taken of non function start %s+0x%lx at %s+0x%lx\n",
             fn->name.c_str(), target - fn->vaddr,
             sender.name.c_str(), source - sender.vaddr);
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

void Cte::analyze() {
    // Relocations
    for (auto it = relocations.begin(); it != relocations.end(); it++) {
        Function *fn;
        if (it->symbol_undef) {
            // The target function is not defined in this ELF.
            if (functions.count(it->value)) {
                fn = &functions[it->value];
            } else {
                Function newfn { "<extern function>", it->symbol_idx,
                                 it->value, 0, false };
                functions[it->value] = newfn;
                fn = &functions[it->value];
            }
        } else {
            if (!functions.count(it->value)) {
                warn("Missing function symbol at 0x%lx: Relocation at 0x%lx\n",
                     it->value, it->offset);
                continue;
            }
            fn = &functions[it->value];
        }

        if (!it->plt && !it->got)
            fn->address_taken = true;
    }

    // Functions
    for (auto it = functions.begin(); it != functions.end(); it++) {
        analyze_function(it->second);
    }
}
