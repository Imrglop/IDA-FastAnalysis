#pragma once
#include <unordered_set>
#include <span>

struct RefScanner_x86_64 {
    static std::unordered_set<uintptr_t> find_write_drefs(uintptr_t virtual_start_addr, const std::byte* begin, const std::byte* end);
};