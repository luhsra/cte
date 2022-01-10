#include "ctemeta.hh"
#include "util.hh"
#include <cstdint>
#include <ostream>
#include <vector>
#include "../common/meta.h"

std::vector<uint8_t> Cte::dump() {
    std::vector<uint8_t> buf_fns;
    std::vector<uint8_t> buf_data;

    addr_t p_fn = 0;
    addr_t p_data = 0;

    // Add header
    buf_fns.resize(p_fn + sizeof(cte_meta_header), 0);
    auto *mfn = reinterpret_cast<cte_meta_header*>(buf_fns.data() + p_fn);
    *mfn = (cte_meta_header) {
        .magic = "CTE",
        .version = CTE_VERSION,
        .functions_count = (uint32_t)functions.size(),
        .padding = 0,
    };
    p_fn += sizeof(cte_meta_header);

    for (auto &item : functions) {
        auto &fn = item.second;

        addr_t p_callees = 0;
        addr_t p_siblings = 0;

        // Append calles
        if (!fn.callees.empty()) {
            p_callees = p_data;
            addr_t size = fn.callees.size() * sizeof(void*);
            buf_data.resize(p_data + size, 0);
            void **m_callee = reinterpret_cast<void**>(buf_data.data() + p_data);
            uint32_t i = 0;
            for (auto &callee : fn.callees) {
                m_callee[i] = (void*)callee;
                i++;
            }
            p_data += size;
        }

        // Append siblings
        if (!fn.siblings.empty()) {
            p_siblings = p_data;
            addr_t size = fn.siblings.size() * sizeof(void*);
            buf_data.resize(p_data + size, 0);
            void **m_sibling = reinterpret_cast<void**>(buf_data.data() + p_data);
            uint32_t i = 0;
            for (auto &sibling : fn.siblings) {
                m_sibling[i] = (void*)sibling;
                i++;
            }
            p_data += size;
        }

        // Append function
        buf_fns.resize(p_fn + sizeof(cte_meta_function), 0);
        auto *mfn = reinterpret_cast<cte_meta_function*>(buf_fns.data() + p_fn);
        *mfn = (cte_meta_function) {
            .vaddr = (void*)fn.vaddr,
            .callees = (void**)p_callees,
            .siblings = (void**)p_siblings,
            .calles_count = (uint32_t)fn.callees.size(),
            .siblings_count = (uint32_t)fn.siblings.size(),
            .flags = (uint32_t)((fn.definition << 0) |
                                (fn.address_taken << 1) |
                                (fn.has_indirect_calls << 2)),
        };
        p_fn += sizeof(cte_meta_function);
    }

    buf_fns.insert(buf_fns.end(), buf_data.begin(), buf_data.end());
    return buf_fns;
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
