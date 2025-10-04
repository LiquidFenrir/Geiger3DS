#pragma once

#include <typedefs.h>
#include <compare>
#include "formatters_base.h"
#include "program.h"

namespace recompiler {

enum class Kind : int {
    Absolute,
    RelativeByte,
    RelativeThumb,
    RelativeArm,
};

struct OffsetTranslator;

template<Kind K>
class Offset {
    friend struct OffsetTranslator;
    const OffsetTranslator* parent;
    u32_t value;

public:
    static constexpr inline Kind kind = K;

    const OffsetTranslator* get_parent() const noexcept
    {
        return parent;
    }

    // read the value contained
    u32_t operator*() const noexcept
    {
        return get();
    }
    // read the value contained
    u32_t get() const noexcept
    {
        return value;
    }
    // read the value contained after converting to other Kind
    template<Kind Kout>
    u32_t get() const noexcept
    {
        return *to<Kout>();
    }

    template<Kind Kout = K>
    Offset<Kout> make(u32_t replace_val) const noexcept
    {
        Offset<Kout> out(parent);
        out.value = replace_val;
        return out;
    }

    template<Kind Kout>
    Offset<Kout> to() const noexcept;

    /*
    copy constructor
    Correct implicit conversion between offset kinds, helps with passing around
    */
    template<Kind Kin>
    Offset(const Offset<Kin>& in) noexcept
        : Offset(in.get_parent(), in.template get<K>())
    { }

    /*
    copy assignment operator
    Correct implicit conversion between offset kinds, helps with passing around
    */
    template<Kind Kin>
    Offset& operator=(const Offset<Kin>& in) noexcept
    {
        parent = in.get_parent();
        value = in.template get<K>();
        return *this;
    }

    Offset& operator--() noexcept
    {
        --value;
        return *this;
    }
    Offset& operator++() noexcept
    {
        ++value;
        return *this;
    }
    
    Offset operator--(int) noexcept
    {
        auto out = *this;
        --value;
        return out;
    }
    Offset operator++(int) noexcept
    {
        auto out = *this;
        ++value;
        return out;
    }

    bool valid(u32_t length = 0) const noexcept;
    bool in_code(u32_t length = 0) const noexcept;

    Offset() = delete;

    template<Kind Kin>
    bool sibling(const Offset<Kin>& in) const noexcept
    {
        return parent == in.get_parent();
    }
    
    // const OffsetTranslator* parent;
private:
    Offset(const OffsetTranslator* p_in, u32_t v_in) noexcept
        : parent(p_in)
        , value(v_in)
    { }

    Offset(const OffsetTranslator* p_in) noexcept
        : Offset(p_in, 0)
    { }
};

struct OffsetTranslator {
    template<typename T>
    static constexpr inline bool is_offset_v = std::is_same_v<Offset<Kind::Absolute>, T>
                    || std::is_same_v<Offset<Kind::RelativeByte>, T>
                    || std::is_same_v<Offset<Kind::RelativeThumb>, T>
                    || std::is_same_v<Offset<Kind::RelativeArm>, T>;

    template<Kind K>
    Offset<K> make(u32_t v_in = 0) const noexcept
    {
        return Offset<K>(this, v_in);
    }

    const Program& program;
    explicit OffsetTranslator(const Program& program_in) noexcept
        : program(program_in)
    { }
};

template<Kind K>
template<Kind Kout>
Offset<Kout> Offset<K>::to() const noexcept
{
    // shortcut
    if constexpr (Kout == K) return *this;

    auto out_value = value;

    if constexpr (K == Kind::Absolute) out_value -= parent->program.code_sec.start_addr;
    else if constexpr (K == Kind::RelativeArm) out_value *= 4;
    else if constexpr (K == Kind::RelativeThumb) out_value *= 2;

    // out_value is a relative byte offset

    if constexpr (Kout == Kind::Absolute) out_value += parent->program.code_sec.start_addr; // absolute byte offset
    else if constexpr (Kout == Kind::RelativeArm) out_value /= 4; // relative arm offset
    else if constexpr (Kout  == Kind::RelativeThumb) out_value /= 2; // relative thumb offset

    return parent->make<Kout>(out_value);
}

template<Kind K>
bool Offset<K>::valid(u32_t length) const noexcept
{
    const auto absolute = to<Kind::Absolute>();
    return parent->program.is_in(*absolute, length);
}
template<Kind K>
bool Offset<K>::in_code(u32_t length) const noexcept
{
    const auto absolute = to<Kind::Absolute>();
    return parent->program.code_sec.is_in(*absolute, length);
}

template<Kind KL, Kind KR>
inline std::partial_ordering operator<=>(const Offset<KL>& lhs, const Offset<KR>& rhs)
{
    if(not lhs.sibling(rhs))
        return std::partial_ordering::unordered;

    const auto l_abs = lhs.template get<Kind::Absolute>();
    const auto r_abs = rhs.template get<Kind::Absolute>();

    if(l_abs < r_abs)
        return std::partial_ordering::less;
    else if(l_abs == r_abs)
        return std::partial_ordering::equivalent;
    else
        return std::partial_ordering::greater;
}

}

ENUM_FORMATTER_BASE(recompiler::Kind)
