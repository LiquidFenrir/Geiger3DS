#pragma once

#include <utility>

namespace recompiler {

template<typename F>
struct OnExitScope {
    F&& f;
    ~OnExitScope()
    {
        f();
    }
};
inline auto call_on_scope_exit(auto&& f)
{
    return OnExitScope(std::forward<decltype(f)>(f));
}

}
