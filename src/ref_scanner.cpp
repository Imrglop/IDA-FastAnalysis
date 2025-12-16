#include "ref_scanner.h"

#include <stdexcept>

#include "ref_scanner_impl/ref_scanner_x86_64.h"

std::unordered_set<ea_t> RefScanner::find_write_drefs(Arch arch, uintptr_t virtual_base_addr, std::byte* begin, std::byte* end) {
    if (arch == X86_64) {
        return RefScanner_x86_64::find_write_drefs(virtual_base_addr, begin, end);
    }

    throw std::runtime_error("scanner not implemented");
}
