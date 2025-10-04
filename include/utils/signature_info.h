#pragma once

#include <type_traits>
#include <concepts>
#include <tuple>

namespace recompiler {

namespace detail {

template<typename... Xs>
struct signature_info;

template<typename R, class... Args>
requires ((not std::is_same_v<Args, void>) && ...)
struct signature_info<R, void, Args...> {
    static constexpr inline bool is_member = false;

    using function_type = R(Args...);
    using pointer = function_type *;

    using return_type = R;

    static constexpr inline std::size_t argument_count = sizeof...(Args);
    using argument_tuple = std::tuple<Args...>;

    template<std::size_t I>
    requires (0 <= I && I < argument_count)
    using argument_type = std::tuple_element_t<I, argument_tuple>;

    template<typename T_new>
    using with_class = signature_info<T_new, R, void, Args...>;
    using without_class = signature_info<R, void, Args...>;

    template<typename R_new>
    using with_return = signature_info<R_new, void, Args...>;
    template<typename... Args_new>
    using with_args = signature_info<R, void, Args_new...>;
    template<typename... Args_extra>
    using with_front_args = signature_info<R, void, Args_extra..., Args...>;
    template<typename... Args_extra>
    using with_back_args = signature_info<R, void, Args..., Args_extra...>;
};

template<class T, typename R, class... Args>
requires ((not std::is_same_v<Args, void>) && ...)
struct signature_info<T, R, void, Args...> {
    static constexpr inline bool is_member = true;

    using function_type = R(Args...);
    using class_type = std::remove_cvref_t<T>;
    using pointer = function_type class_type::*;

    using return_type = R;

    static constexpr inline std::size_t argument_count = sizeof...(Args);
    using argument_tuple = std::tuple<Args...>;

    template<std::size_t I>
    requires (0 <= I && I < argument_count)
    using argument_type = std::tuple_element_t<I, argument_tuple>;

    template<typename T_new>
    using with_class = signature_info<T_new, R, void, Args...>;
    using without_class = signature_info<R, void, Args...>;

    template<typename R_new>
    using with_return = signature_info<class_type, R_new, void, Args...>;
    template<typename... Args_new>
    using with_args = signature_info<class_type, R, void, Args_new...>;
    template<typename... Args_extra>
    using with_front_args = signature_info<class_type, R, void, Args_extra..., Args...>;
    template<typename... Args_extra>
    using with_back_args = signature_info<class_type, R, void, Args..., Args_extra...>;
};

// template<typename F>
// requires (std::is_pointer_v<std::decay_t<F>> && std::is_function_v<std::remove_pointer_t<std::decay_t<F>>>)
// constexpr auto get_signature_info(F fptr = nullptr) {
//     return signature_info{fptr};
// }

// template<typename F>
// requires (std::is_pointer_v<std::decay_t<F>> && std::is_function_v<std::remove_pointer_t<std::decay_t<F>>>)
// constexpr auto get_signature_info() {
//     return get_signature_info(static_cast<F>(nullptr));
// }

// template<typename F>
// requires (std::is_function_v<F>)
// constexpr auto get_signature_info() {
//     return get_signature_info<F*>();
// }

template<class T, typename R, typename... Args>
constexpr auto get_signature_info(R (T::**)(Args...)) {
    return signature_info<T, R, void, Args...>{};
}
template<typename R, typename... Args>
constexpr auto get_signature_info(R (**)(Args...)) {
    return signature_info<R, void, Args...>{};
}

template<typename F>
requires (std::is_member_function_pointer_v<std::decay_t<F>> || (std::is_pointer_v<std::decay_t<F>> && std::is_function_v<std::remove_pointer_t<std::decay_t<F>>>))
constexpr auto get_signature_info() {
    return get_signature_info(static_cast<std::decay_t<F>*>(nullptr));
}

}

template<typename F>
requires (std::is_member_function_pointer_v<std::decay_t<F>> || (std::is_pointer_v<std::decay_t<F>> && std::is_function_v<std::remove_pointer_t<std::decay_t<F>>>))
using signature_info = decltype(detail::get_signature_info<F>());

}
