#pragma once
#include <unordered_set>
#include <span>
#include <cstdint>

struct RefScanner_aarch64 {
    static std::unordered_set<uintptr_t> find_write_drefs(uintptr_t virtual_base_addr, const std::byte* begin, const std::byte* end);
};