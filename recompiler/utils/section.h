#pragma once

#include <typedefs.h>
#include <span>

namespace recompiler {

struct Section {
    std::span<const u8_t> bytes;
    u32_t start_addr, end_addr;

    Section(std::span<const u8_t> bytes_in, u32_t start_addr_in) noexcept
        : bytes(bytes_in)
        , start_addr(start_addr_in)
        , end_addr(start_addr_in + bytes_in.size())
    { }

    u32_t length() const noexcept
    {
        return end_addr - start_addr;
    }

    bool is_in(u32_t addr, u32_t length = 0) const noexcept
    {
        return start_addr <= addr && (addr + length) < end_addr;
    }
};

}
