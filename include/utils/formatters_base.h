#pragma once

#include <concepts>
#include <type_traits>

#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/std.h>

#include "../magic_enum_inc.h"

template<class T>
concept is_enum = std::is_enum_v<T>;

struct skip_flags_parse {
    constexpr fmt::format_parse_context::iterator parse(fmt::format_parse_context& ctx)
    {
        auto it = ctx.begin();
        while(it != ctx.end() && *it != '}')
            ++it;
        return it;
    }
};

template <typename enum_type> requires is_enum<enum_type>
struct base_enum_format {
    fmt::format_context::iterator format(const enum_type& value, fmt::format_context& ctx) const {
        return fmt::format_to(ctx.out(), "{}", magic_enum::enum_name<enum_type>(value));
    }
};

template <typename enum_type> requires is_enum<enum_type>
struct fmt::formatter<enum_type> : base_enum_format<enum_type>, skip_flags_parse { };
