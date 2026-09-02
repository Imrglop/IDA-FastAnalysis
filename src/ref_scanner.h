#pragma once
#include <type_traits>
#include <unordered_set>

#include <ida.hpp>

struct RefScanner {
    enum Arch {
        X86_64,
        AARCH64
    };

    static std::unordered_set<uintptr_t> find_write_drefs(Arch arch, uintptr_t virtual_base_addr,
        const std::byte* begin, const std::byte* end);
};
