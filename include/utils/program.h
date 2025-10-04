#pragma once

#include <typedefs.h>
#include <algorithm>
#include "section.h"
#include "formatters_base.h"

namespace recompiler {

#define ARM_CPU_PAGE_SIZE 0x1000
// a has to be a power of two
#define ALIGN_TO_NUM(n, a) (((n) + ((a) - 1u)) & -(a))
#define ALIGN_PAGE_NUM(n) ALIGN_TO_NUM(n, ARM_CPU_PAGE_SIZE)

struct Program {
    Section code_sec, rodata_sec, data_sec;
    u32_t start_addr;
    u32_t bss_size;

    Program(std::span<const u8_t> code_in, std::span<const u8_t> rodata_in, std::span<const u8_t> data_in, u32_t start_addr_in, u32_t bss_size_in) noexcept
        : code_sec(code_in, start_addr_in)
        , rodata_sec(rodata_in, ALIGN_PAGE_NUM(code_sec.end_addr))
        , data_sec(data_in, ALIGN_PAGE_NUM(rodata_sec.end_addr))
        , start_addr(start_addr_in)
        , bss_size(bss_size_in)
    { }

    bool is_in(u32_t addr, u32_t length = 0) const noexcept
    {
        return code_sec.is_in(addr, length)
            || rodata_sec.is_in(addr, length)
            || data_sec.is_in(addr, length)
            || (data_sec.end_addr <= addr && (addr + length) < (data_sec.end_addr + bss_size));
    }

    bool copy_from(u32_t addr, std::span<u8_t> into) const
    {
        const auto handle_sec = [](const Section& sec, u32_t addr, std::span<u8_t> into) {
            const u32_t off = addr - sec.start_addr;
            std::span<const u8_t> part = sec.bytes.subspan(off);
            std::copy_n(part.begin(), into.size(), into.begin());
            return true;
        };

        if(code_sec.is_in(addr, into.size()))
        {
            return handle_sec(code_sec, addr, into);
        }
        else if(rodata_sec.is_in(addr, into.size()))
        {
            return handle_sec(rodata_sec, addr, into);
        }
        else if(data_sec.is_in(addr, into.size()))
        {
            return handle_sec(data_sec, addr, into);
        }
        return false;
    }
};

}

template <> struct fmt::formatter<recompiler::Program> : skip_flags_parse {
    format_context::iterator format(const recompiler::Program& program, format_context& ctx) const
    {
        return fmt::format_to(ctx.out(), "Program(code @ 0x{:08x}, rodata @ 0x{:08x}, data @ 0x{:08x}, bss @ 0x{:08x}-0x{:08x})",
            program.code_sec.start_addr,
            program.rodata_sec.start_addr,
            program.data_sec.start_addr,
            program.data_sec.end_addr,
            program.data_sec.end_addr + program.bss_size
        );
    }
};
