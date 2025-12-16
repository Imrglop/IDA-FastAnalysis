#include "ref_scanner_x86_64.h"
#include "hde64.h"

std::unordered_set<uintptr_t> RefScanner_x86_64::find_write_drefs(uintptr_t virtual_base_addr, const std::byte* begin, const std::byte* end) {
    std::unordered_set<uintptr_t> write_refs_to;

    for (const std::byte* ptr = begin; ptr < end;) {
        hde64s insn;
        auto insn_len = hde64_disasm(ptr, &insn);

        if (insn_len == 0)
            break;

        if (insn.flags & F_MODRM) {
            uint8_t mod = (insn.modrm & 0xC0) >> 6;
            uint8_t rm = insn.modrm & 0x07;

            bool is_mov_to_mem =
                insn.opcode == 0x88 ||
                insn.opcode == 0x89 ||
                insn.opcode == 0xC6 ||
                insn.opcode == 0xC7 ||
                insn.opcode == 0xA2 ||
                insn.opcode == 0xA3;

            if (is_mov_to_mem && mod == 0 && rm == 5) {
                ptrdiff_t diff = ptr - begin;

                auto referencedAddr = virtual_base_addr + diff + insn.len + insn.disp.disp32;
                write_refs_to.insert(referencedAddr);
            }
        }

        ptr += insn.len;
    }

    return write_refs_to;
}
