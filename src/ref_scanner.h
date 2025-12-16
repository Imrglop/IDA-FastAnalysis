#pragma once
#include <unordered_set>
#include <span>

#include <ida.hpp>

struct RefScanner {
    enum Arch {
        X86_64
    };

    static std::unordered_set<ea_t> find_write_drefs(Arch arch, uintptr_t virtual_base_addr, std::byte* begin, std::byte* end);
};
