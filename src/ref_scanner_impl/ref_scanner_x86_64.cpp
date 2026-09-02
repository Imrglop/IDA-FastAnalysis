#include "ref_scanner_x86_64.h"


#include <type_traits>
#include <idp.hpp>
#include <Zydis/Zydis.h>

std::unordered_set<uintptr_t> RefScanner_x86_64::find_write_drefs(uintptr_t virtual_base_addr, const std::byte *begin,
                                                                  const std::byte *end) {
    std::unordered_set<uintptr_t> write_refs_to;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    for (const std::byte *ptr = begin; ptr < end;) {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        ZyanUSize remaining = static_cast<ZyanUSize>(end - ptr);
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, ptr, remaining, &insn, operands))) {
            //msg("FastAnalysis: zydis decode failed at %llX\n", virtual_base_addr + (ptr - begin));
            break;
        }

        // Check if the first (destination) operand is a RIP-relative memory write
        if (insn.operand_count_visible >= 1) {
            const ZydisDecodedOperand &dst = operands[0];
            if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                (dst.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                dst.mem.base == ZYDIS_REGISTER_RIP &&
                dst.mem.index == ZYDIS_REGISTER_NONE &&
                dst.mem.disp.has_displacement) {
                ptrdiff_t diff = ptr - begin;
                auto referenced_addr = virtual_base_addr + diff + insn.length + dst.mem.disp.value;
                write_refs_to.insert(referenced_addr);
            }
        }

        ptr += insn.length;
    }

    return write_refs_to;
}
