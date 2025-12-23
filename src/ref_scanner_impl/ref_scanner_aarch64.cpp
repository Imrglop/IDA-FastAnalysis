#include "ref_scanner_aarch64.h"

#include <optional>

// helper functions for ARM64 instruction decoding

static bool is_adrp(uint32_t insn) {
    return (insn & 0x9F000000) == 0x90000000;
}

static uint32_t get_rd(uint32_t insn) {
    return insn & 0x1F;
}

static uint32_t get_rn(uint32_t insn) {
    return insn >> 5 & 0x1F;
}

static uint64_t get_adrp_addr(uint32_t insn, ptrdiff_t insn_offset) {
    int32_t imm_lo = insn >> 29 & 0x3;
    int32_t imm_hi = insn >> 5 & 0x7FFFF;
    int64_t imm = imm_hi << 2 | imm_lo;

    // sign-extend
    if (imm & 1 << 20) {
        imm |= ~((1LL << 21) - 1);
    }

    int64_t offset = imm << 12;
    auto page_base = insn_offset & ~0xFFF;
    return page_base + offset;
}

static bool is_str(uint32_t insn) {
    return (insn & 0x3F400000) == 0x39000000;
}

static bool is_add(uint32_t insn) {
    return (insn & 0x7F000000) == 0x11000000;
}

static bool is_ldr(uint32_t insn) {
    return (insn & 0xFFC00000) == 0xF9400000;
}

static uint32_t get_imm12(uint32_t insn) {
    return insn >> 10 & 0xFFF;
}

static int32_t get_imm9_sign_extended(uint32_t insn) {
    int32_t raw = static_cast<int32_t>(insn) >> 12 & 0x1FF;
    return (raw << 23) >> 23;
}

static std::tuple<uint32_t, uint32_t, int64_t> decode_str(uint32_t insn) {
    uint32_t rt = get_rd(insn);
    uint32_t rn = get_rn(insn);

    uint64_t offset = 0;
    bool is_unsigned_scaled = insn >> 24 & 1;
    if (is_unsigned_scaled) {
        offset = get_imm12(insn) * 8;
    } else {
        offset = get_imm9_sign_extended(insn);
    }

    return std::make_tuple(rt, rn, offset);
}

std::unordered_set<uintptr_t> RefScanner_aarch64::find_write_drefs(uintptr_t virtual_base_addr, const std::byte* begin, const std::byte* end) {
    // step 1: find next ADRP instruction
    // step 2: find the next instruction that adds page offset and does a store operation

    std::unordered_set<uintptr_t> refs;

    auto begin_u32 = reinterpret_cast<const uint32_t*>(begin);
    auto end_u32 = reinterpret_cast<const uint32_t*>(end);

    for (const auto* ptr = reinterpret_cast<const uint32_t*>(begin); ptr < end_u32; ptr++) {
        auto insn_data = *ptr;

        if (is_adrp(insn_data)) {
            uint32_t adrp_rd = get_rd(insn_data); // the register adrp writes to, usually x8, so adrp_rd would be 8

            for (const uint32_t* j = ptr + 1; j < ptr + 16 /*just an arbitrary safety limit for now*/ && j < end_u32; ++j) {
                auto cur_insn = *j;

                // STR (store) B/W/H/X
                if (is_str(cur_insn)) {
                    auto [str_rt, str_rn, str_offset] = decode_str(cur_insn);

                    if (str_rn == adrp_rd) {
                        uintptr_t referenced_addr = get_adrp_addr(insn_data, (j - begin_u32) * sizeof(uint32_t) + virtual_base_addr) + str_offset;
                        refs.insert(referenced_addr);
                        break;
                    }
                }

                // check for common non-store instructions that follow ADRP just to get out of the loop early

                // check for ADD, LDR, or another ADRP just in case
                if (get_rd(cur_insn) == adrp_rd && (is_add(cur_insn) || is_ldr(cur_insn) || is_adrp(cur_insn))) {
                    break;
                }
            }
        }
    }

    return refs;
}
