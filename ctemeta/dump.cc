#include "ctemeta.hh"
#include "util.hh"
#include <cstdint>
#include <ostream>
#include <vector>
#include "../common/meta.h"

std::vector<uint8_t> Cte::dump() {
    std::vector<uint8_t> buf;

    // Add header
    buf.resize(sizeof(cte_meta_header), 0);
    auto *header = reinterpret_cast<cte_meta_header*>(buf.data());
    *header = (cte_meta_header) {
        .magic = "CTE",
        .version = CTE_VERSION,
        .functions_count = (uint32_t)functions.size(),
        .size = 0,
    };

    addr_t p_fn = sizeof(cte_meta_header);
    addr_t p_data = p_fn + functions.size() * sizeof(cte_meta_function);
    buf.resize(p_data, 0);

    for (auto &item : functions) {
        auto &fn = item.second;

        addr_t p_callees = 0;
        addr_t p_jumpees = 0;
        addr_t p_siblings = 0;

        // Append calles
        if (!fn.callees.empty()) {
            p_callees = p_data;
            addr_t size = fn.callees.size() * sizeof(void*);
            buf.resize(p_data + size, 0);
            void **m_callee = reinterpret_cast<void**>(buf.data() + p_data);
            uint32_t i = 0;
            for (addr_t callee : fn.callees) {
                m_callee[i] = (void*)callee;
                i++;
            }
            p_data += size;
        }

        // Append jumpees
        if (!fn.jumpees.empty()) {
            p_jumpees = p_data;
            addr_t size = fn.jumpees.size() * sizeof(void*);
            buf.resize(p_data + size, 0);
            void **m_jumpee = reinterpret_cast<void**>(buf.data() + p_data);
            uint32_t i = 0;
            for (addr_t jumpee : fn.jumpees) {
                m_jumpee[i] = (void*)jumpee;
                i++;
            }
            p_data += size;
        }

        // Append siblings
        if (!fn.siblings.empty()) {
            p_siblings = p_data;
            addr_t size = fn.siblings.size() * sizeof(void*);
            buf.resize(p_data + size, 0);
            void **m_sibling = reinterpret_cast<void**>(buf.data() + p_data);
            uint32_t i = 0;
            for (addr_t sibling : fn.siblings) {
                m_sibling[i] = (void*)sibling;
                i++;
            }
            p_data += size;
        }

        // Append function
        auto *mfn = reinterpret_cast<cte_meta_function*>(buf.data() + p_fn);
        *mfn = (cte_meta_function) {
            .vaddr = (void*)fn.vaddr,
            .size = fn.size,
            .callees = (void**)p_callees,
            .jumpees = (void**)p_jumpees,
            .siblings = (void**)p_siblings,
            .callees_count = (uint32_t)fn.callees.size(),
            .jumpees_count = (uint32_t)fn.jumpees.size(),
            .siblings_count = (uint32_t)fn.siblings.size(),
            .flags = (uint32_t)((fn.definition << 0) |
                                (fn.address_taken << 1) |
                                (fn.has_indirect_calls << 2) |
                                (fn.has_indirect_jumps << 3)),
        };
        p_fn += sizeof(cte_meta_function);
    }

    header = reinterpret_cast<cte_meta_header*>(buf.data());
    header->size = buf.size();
    return buf;
}

void Cte::print(std::ostream &stream) {
    for (auto &item : functions) {
        Function &fn = item.second;
        print(stream, fn);
    }
}

void Cte::print(std::ostream &stream, Function &fn) {
    stream << fn.str()
           << ((fn.definition) ? "" : " (extern)")
           << ((fn.address_taken) ? " (address-taken)" : "")
           << ((fn.has_indirect_calls) ? " (icalls)" : "")
           << "\n";

    for (addr_t addr : fn.siblings) {
        Function &sfn = functions.at(addr);
        stream << "   (S)  " << sfn.str() << "\n";
    }
    for (addr_t addr : fn.callees) {
        Function &cfn = functions.at(addr);
        stream << "        " << cfn.str() << "\n";
    }
    for (addr_t addr : fn.jumpees) {
        Function &jfn = functions.at(addr);
        stream << "   (J)  " << jfn.str() << "\n";
    }
}
