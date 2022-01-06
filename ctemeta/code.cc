#include <Zydis/Zydis.h>
#include "ctemeta.hh"
#include "util.hh"

void Cte::analyze_function(Function &fn) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter formatter;
    if (dump_instructions) {
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_ATT);
        formatter.hex_uppercase = false;
        printf("\n%016lx <%s>:\n", fn.vaddr, fn.name.c_str());
    }

    ZyanU64 pc = fn.vaddr;
    ZyanU8 *buffer = fn.code.data();
    ZyanUSize offset = 0;
    ZyanUSize size = fn.size;
    ZydisDecodedInstruction inst;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer + offset, size - offset,
                                               &inst, ops, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
                                               ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY))) {
        auto category = inst.meta.category;
        if (category == ZYDIS_CATEGORY_CALL ||
            category == ZYDIS_CATEGORY_UNCOND_BR ||
            category == ZYDIS_CATEGORY_COND_BR) {

            // We collect all the direct callees.
            // Because of tail call optimization, we also have to look at
            // all branch instructions, not just calls (-> jumpees).

            // Here, we also look at branches with inter-function targets
            // that do not go to the start of a function body but to
            // somewhere inside the body (e.g. compiler generated .cold
            // functions or custom assembler code).  These functions must
            // be kept together with the original function (-> siblings).

            ZydisBranchType bt = inst.meta.branch_type;
            if (bt == ZYDIS_BRANCH_TYPE_SHORT || bt == ZYDIS_BRANCH_TYPE_NEAR) {

                if (inst.operand_count_visible != 1) {
                    // This should not happpen
                    warn("%s+0x%lx: call/branch operand count != 1",
                         fn.name.c_str(), pc - fn.vaddr);
                } else {
                    ZydisDecodedOperand &op = ops[0];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        addr_t target = (op.imm.is_relative)
                            ? pc + inst.length + op.imm.value.s
                            : op.imm.value.u;
                        if (category == ZYDIS_CATEGORY_CALL)
                            register_call(fn, pc, target);
                        else
                            register_jump(fn, pc, target);
                    } else {
                        register_indirect_call(fn, pc);
                    }
                }
            } else {
                warn("%s+0x%lx: unrecognized branch instruction",
                     fn.name.c_str(), pc - fn.vaddr);
            }

        } else {

            // Loop through all %rip-offset arguments.
            // If one of them is a function address we set the
            // address_taken flag in the respective function.

            for (int i = 0; i < inst.operand_count_visible; i++) {
                ZydisDecodedOperand &op = ops[i];

                // rip-relative addressing (-> lea instruction)
                if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    op.mem.type == ZYDIS_MEMOP_TYPE_AGEN &&
                    op.mem.segment != ZYDIS_REGISTER_FS &&
                    op.mem.segment != ZYDIS_REGISTER_GS &&
                    op.mem.base == ZYDIS_REGISTER_RIP &&
                    op.mem.index == ZYDIS_REGISTER_NONE) {
                    addr_t target;
                    ZydisCalcAbsoluteAddress(&inst, &op, pc, &target);
                    register_address_taken(fn, pc, target);
                }
                // TODO:  Absolute addressing (mov)
                // FIXME: This can lead to false positives
            }
        }

        if (dump_instructions) {
            char buffer[256];
            printf("  %lx: \t", pc);
            ZydisFormatterFormatInstruction(&formatter, &inst, ops,
                                            inst.operand_count_visible, buffer,
                                            sizeof(buffer), pc);
            puts(buffer);
        }

        offset += inst.length;
        pc += inst.length;
    }
}
