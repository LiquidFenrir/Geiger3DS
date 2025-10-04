#pragma once

#include "signature_info.h"
#include <type_traits>
#include <utility>
#include <magic_enum/magic_enum.hpp>

// will most probably not work when virtual is in the picture
#define OVERLOAD_ENUM_RESOLVER(overload_name, over_var, signature) \
    magic_enum::enum_switch([](auto id) { \
        using flag_t = decltype(id); \
        using sig_info = signature_info<signature>; \
        using sig_info_base = sig_info::without_class; \
        if constexpr (sig_info::is_member) { \
            using sig_obj_t = sig_info::class_type; \
            using mfunc_t = sig_info::with_back_args<flag_t>; \
            using ret_func_t = sig_info_base::with_front_args<sig_obj_t*>; \
            if constexpr (requires (sig_obj_t* self) { \
                static_cast<mfunc_t::pointer>(&self->overload_name); \
            }) \
            { \
                static constexpr auto overload = static_cast<mfunc_t::pointer>(&(static_cast<sig_obj_t*>(nullptr)->overload_name)); \
                return static_cast<ret_func_t::pointer>([](sig_obj_t* self, auto... args) -> typename ret_func_t::return_type { \
                    return (self->*overload)(std::forward<decltype(args)>(args)..., flag_t{}); \
                }); \
            } \
            else return static_cast<ret_func_t::pointer>(nullptr); \
        } else { \
            using func_t = sig_info::with_back_args<flag_t>; \
            if constexpr (requires () { \
                static_cast<func_t::pointer>(overload_name); \
            }) \
            { \
                static constexpr auto overload = static_cast<func_t::pointer>(overload_name); \
                return static_cast<sig_info::pointer>([](auto... args) -> typename func_t::return_type { \
                    return overload(std::forward<decltype(args)>(args)..., flag_t{}); \
                }); \
            } \
            else return static_cast<sig_info::pointer>(nullptr); \
        } \
    }, over_var)

namespace recompiler {

template<auto AV, auto BV>
struct tmp_pair_v {
    using A_t = decltype(AV);
    using B_t = decltype(BV);
    static constexpr inline A_t A = AV;
    static constexpr inline B_t B = BV;
};

template<typename T, typename U>
struct tmp_pair_t {
    using A_t = T;
    using B_t = U;

    template<auto... Ps>
    requires((std::is_same_v<typename decltype(Ps)::A_t, A_t> && std::is_same_v<typename decltype(Ps)::B_t, B_t>) && ...)
    struct list { constexpr list() = default; };
    template<typename... Ps>
    requires((std::is_same_v<typename Ps::A_t, A_t> && std::is_same_v<typename Ps::B_t, B_t>) && ...)
    struct listtypes { constexpr listtypes() = default; };
};

template<typename E, typename T, typename... Ys>
requires (std::is_enum_v<E>)
struct OverloadList {
    using TP = tmp_pair_t<E, T>;

    template<typename... Xs>
    requires (sizeof...(Xs) != 0 && requires { typename TP::listtypes<Ys..., Xs...>; })
    static constexpr auto make()
    {
        return OverloadListImpl<Ys..., Xs...>{};
    }

    template<E EV, T TV>
    using with = OverloadList<E, T, Ys..., tmp_pair_v<EV, TV>>;

    static constexpr auto make() requires (requires { typename TP::listtypes<Ys...>; })
    {
        return OverloadListImpl<Ys...>{};
    }

    template<typename... Vs>
    struct OverloadListImpl {
        template<E EV> requires (std::is_same_v<magic_enum::enum_constant<EV>, magic_enum::enum_constant<Vs::A>> || ...)
        constexpr T get(magic_enum::enum_constant<EV>) const
        {
            const T* out = nullptr;
            ([&](const Vs* const)
            {
                if constexpr (std::is_same_v<magic_enum::enum_constant<EV>, magic_enum::enum_constant<Vs::A>>)
                {
                    out = &Vs::B;
                    return true;
                }
                else return false;
            }(static_cast<const Vs*>(nullptr)) || ...);

            [[assume(out != nullptr)]];
            return *out;
        }

    private:
        friend OverloadList;
        constexpr OverloadListImpl() = default;
    };

private:
    constexpr OverloadList() = default;
};

}
