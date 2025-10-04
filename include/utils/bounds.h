#pragma once

#include <typedefs.h>
#include "formatters_base.h"

namespace recompiler {

enum class Bound {
    Open,
    Closed,
};

template<Bound BL, Bound BH, typename T, typename L, typename H>
inline constexpr bool is_between(const T& v, const L& low, const H& high)
{
    const bool low_ok = (BL == Bound::Open) ? low < v : low <= v;
    if(!low_ok) return false;
    
    const bool high_ok = (BH == Bound::Open) ? v < high : v <= high;
    if(!high_ok) return false;

    return true;
}

}
