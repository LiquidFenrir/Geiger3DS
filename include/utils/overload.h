#pragma once

#include "signature_info.h"
#include <type_traits>
#include <utility>
#include "magic_enum_inc.h"

// will most probably not work when virtual is in the picture
#define OVERLOAD_ENUM_RESOLVER(overload_name, over_var, signature) \
    magic_enum::enum_switch([&](auto id) { \
        using flag_t = decltype(id); \
        using sig_info = signature_info<signature>; \
        using sig_info_base = sig_info::without_class; \
        if constexpr (sig_info::is_member) { \
            using sig_obj_t = sig_info::class_type; \
            using mfunc_t = sig_info::with_back_args<flag_t>; \
            using ret_func_t = sig_info_base::with_front_args<sig_obj_t*>; \
            if constexpr (requires () { \
                static_cast<mfunc_t::pointer>(&sig_obj_t::overload_name); \
            }) \
            { \
                /* static constexpr auto overload = static_cast<mfunc_t::pointer>(&sig_obj_t::overload_name); */ \
                return static_cast<ret_func_t::pointer>([](sig_obj_t* self, auto... args) -> typename ret_func_t::return_type { \
                    /* return (self->*overload)(std::forward<decltype(args)>(args)..., flag_t{}); */ \
                    return self->overload_name(std::forward<decltype(args)>(args)..., flag_t{}); \
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

template<typename E, typename T, typename... Vs>
struct OverloadListBuilt : public Vs... {
    template<typename ECV>
    static constexpr bool is_key_type = (std::is_same_v<ECV, typename Vs::Key> || ...);
    template<E EV>
    static constexpr bool is_key_value = is_key_type<magic_enum::enum_constant<EV>>;

    using Vs::get...;
};

template<typename E, typename T, typename... Vs>
requires (std::is_enum_v<E>)
struct OverloadList {
    template<E EV, T TV>
    struct Node {
        using Key = magic_enum::enum_constant<EV>;

        static constexpr T get(Key)
        {
            return TV;
        }
        
        template<E IEV>
        requires (EV == IEV)
        static constexpr T get()
        {
            return TV;
        }
        
        template<typename IE>
        requires (std::is_same_v<Key, IE>)
        static constexpr T get()
        {
            return TV;
        }
    };

    template<E EV, T TV>
    using with = OverloadList<E, T, Vs..., Node<EV, TV>>;

    using type = OverloadListBuilt<E, T, Vs...>;
};

}
