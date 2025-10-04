#pragma once

#include <cstdlib>
#include <utility>
#include <typedefs.h>
#include "formatters_base.h"

namespace recompiler {

enum class Fuzzy : s8_t {
    Unknown, // 0 hint
    MaybeNo = -1,
    No = -2,
    MaybeYes = 1,
    Yes = 2,
};

inline bool is_sure(Fuzzy val)
{
    return val == Fuzzy::No || val == Fuzzy::Yes;
}
inline bool is_clueless(Fuzzy val)
{
    return val == Fuzzy::Unknown;
}
inline bool is_negative(Fuzzy val)
{
    return val < Fuzzy::Unknown;
}
inline bool is_positive(Fuzzy val)
{
    return val > Fuzzy::Unknown;
}

inline Fuzzy make_negative(Fuzzy mag)
{
    return Fuzzy( - std::abs(s8_t(mag)));
}
inline Fuzzy make_positive(Fuzzy mag)
{
    return Fuzzy(std::abs(s8_t(mag)));
}

inline s8_t get_sureness(Fuzzy mag)
{
    return std::abs(s8_t(mag));
}

inline Fuzzy copy_sureness(Fuzzy direction, Fuzzy sureness)
{
    if(direction == Fuzzy::Unknown || sureness == Fuzzy::Unknown)
        return Fuzzy::Unknown;

    const bool vsig = is_negative(direction);
    return vsig ? make_negative(sureness) : make_positive(sureness);
}

inline Fuzzy copy_direction(Fuzzy sureness, Fuzzy direction)
{
    return copy_sureness(direction, sureness);
}

}

ENUM_FORMATTER_BASE(recompiler::Fuzzy)
