#pragma once

#include <oxenc/hex.h>

#include <concepts>
#include <cstring>
#include <span>
#include <string_view>
#include <tuple>
#include <type_traits>

#include "epee/span.h"  // epee

namespace tools {

template <typename T>
concept safe_to_memcpy = std::is_trivially_copyable_v<T> || epee::is_byte_spannable<T>;

template <typename T>
concept byte_spannable = std::convertible_to<T, std::span<const typename T::value_type>> &&
                         oxenc::basic_char<typename T::value_type>;

/// Returns a string_view that views the data of the given object; this is not something you want to
/// do unless the struct is specifically design to be used this way.  The value must be a standard
/// layout type; it should really require is_trivial, too, but we have classes (like crypto keys)
/// that aren't C++-trivial but are still designed to be accessed this way.
template <oxenc::basic_char Char = char, safe_to_memcpy T>
std::basic_string_view<Char> view_guts(const T& val) {
    return {reinterpret_cast<const Char*>(&val), sizeof(val)};
}

/// Convenience wrapper around the above that also copies the result into a new string
template <oxenc::basic_char Char = char, safe_to_memcpy T>
std::basic_string<Char> copy_guts(const T& val) {
    return std::basic_string<Char>{view_guts<Char>(val)};
}

/// Wrapper around the above that converts to hex
template <safe_to_memcpy T>
std::string hex_guts(const T& val) {
    return oxenc::to_hex(view_guts(val));
}

/// Returns a span<S> over the data of the given object.  Like view_guts, this required a trivial
/// type.  This additionally requires that S have alignment no more strict than T, and that S evenly
/// divides T.
template <safe_to_memcpy S, safe_to_memcpy T>
    requires(sizeof(T) % sizeof(S) == 0 && alignof(S) < alignof(T))
std::span<S> span_guts(T& val) {
    return {reinterpret_cast<S*>(&val), sizeof(val)};
}
/// const version of the above, return a span<const S>
template <safe_to_memcpy S, safe_to_memcpy T>
    requires(sizeof(T) % sizeof(S) == 0 && alignof(S) < alignof(T))
std::span<const S> span_guts(const T& val) {
    return {reinterpret_cast<const S*>(&val), sizeof(val)};
}

/// Function to reverse the above functions (not including hex_guts); takes anything byte spannable
/// (spans, strings, views, vectors of char, unsigned char, or std::byte).
template <safe_to_memcpy T, byte_spannable Spannable>
T make_from_guts(const Spannable& s) {
    std::span<const typename Spannable::value_type> span{s};
    if (s.size() != sizeof(T))
        throw std::runtime_error{"Cannot reconstitute type: wrong data size for type"};
    T x;
    std::memcpy(static_cast<void*>(&x), s.data(), sizeof(T));
    return x;
}

/// Loads from a span of hex digits into an existing instance.  If `check_hex` is true (the default)
/// the span will be validated to make sure it is hex, but can be given as false if such validation
/// has already been done.
template <safe_to_memcpy T, byte_spannable Spannable>
void load_from_hex_guts(const Spannable& s, T& x, bool check_hex = true) {
    std::span<const typename Spannable::value_type> span{s};
    if (s.size() != sizeof(T) * 2 || (check_hex && !oxenc::is_hex(span.begin(), span.end())))
        throw std::runtime_error{"Cannot reconstitute type from hex: wrong size or invalid hex"};
    oxenc::from_hex(span.begin(), span.end(), reinterpret_cast<char*>(&x));
}

/// Same as above, but loads the hex into an object of type T that is returned.  If `check_hex` is
/// true (the default) the span will be validated to make sure it is hex, but can be given as false
/// if such validation has already been done.
template <safe_to_memcpy T, byte_spannable Spannable>
T make_from_hex_guts(const Spannable& s, bool check_hex = true) {
    T x;
    load_from_hex_guts(s, x, check_hex);
    return x;
}

// A non-throwing, mutating version of the above.  This should be considered deprecated, but is
// still embedded in a bunch of CHECK_MESS_AND_THROW_BLAH_BLAH macros that should be cleaned up some
// day.
template <safe_to_memcpy T, byte_spannable Spannable>
[[nodiscard]] bool try_load_from_hex_guts(const Spannable& s, T& x) {
    std::span<const typename Spannable::value_type> span{s};
    if (s.size() != 2 * sizeof(T) || !oxenc::is_hex(span.begin(), span.end()))
        return false;
    oxenc::from_hex(span.begin(), span.end(), reinterpret_cast<char*>(&x));
    return true;
}

template <size_t N>
struct skip {
    static constexpr size_t size = N;
};
template <typename T>
using skip_t = skip<sizeof(T)>;

namespace detail {
    template <typename T>
    constexpr bool is_skip = false;
    template <size_t N>
    constexpr bool is_skip<skip<N>> = true;

    template <typename T>
    constexpr bool is_basic_sv = false;
    template <oxenc::basic_char Char>
    constexpr bool is_basic_sv<std::basic_string_view<Char>> = true;

    template <size_t I, typename Next, typename... More, typename Tuple>
    void load_split_tuple(Tuple& t, std::string_view from) {
        if constexpr (is_skip<Next>) {
            from.remove_prefix(Next::size);
        } else {
            auto& e = std::get<I>(t);
            if constexpr (is_basic_sv<Next>) {
                static_assert(I == std::tuple_size_v<Tuple> - 1);
                e = {reinterpret_cast<Next::const_pointer>(from.data()), from.size()};
                from = {};
            } else {
                std::memcpy(&e, from.data(), sizeof(e));
                from.remove_prefix(sizeof(e));
            }
        }

        if constexpr (sizeof...(More))
            load_split_tuple<I + !is_skip<Next>, More...>(t, from);
    }

    template <size_t I, typename Next, typename... More, typename Tuple>
    void load_split_tuple_hex(Tuple& t, std::string_view from) {
        if constexpr (is_skip<Next>) {
            from.remove_prefix(2 * Next::size);
        } else {
            auto& e = std::get<I>(t);
            if constexpr (is_basic_sv<Next>) {
                static_assert(I == std::tuple_size_v<Tuple> - 1);
                e = {reinterpret_cast<Next::const_pointer>(from.data()), from.size()};
                from = {};
            } else {
                oxenc::from_hex(
                        from.begin(), from.begin() + 2 * sizeof(e), reinterpret_cast<char*>(&e));
                from.remove_prefix(2 * sizeof(e));
            }
        }

        if constexpr (sizeof...(More))
            load_split_tuple_hex<I + !is_skip<Next>, More...>(t, from);
    }

    template <typename... T>
    using tuple_without_skips = decltype(std::tuple_cat(
            std::conditional_t<is_skip<T>, std::tuple<>, std::tuple<T>>{}...));

    template <typename T>
    constexpr size_t split_guts_piece_size() {
        if constexpr (is_skip<T>)
            return T::size;
        else if constexpr (is_basic_sv<T>)
            return 0;
        else
            return sizeof(T);
    }

    template <typename... More>
    constexpr bool final_is_string_view = false;
    template <oxenc::basic_char Char>
    constexpr bool final_is_string_view<std::basic_string_view<Char>> = true;
    template <typename T1, typename T2, typename... More>
    constexpr bool final_is_string_view<T1, T2, More...> = final_is_string_view<T2, More...>;

    // Used below to check that either no string view is supplied at all, or exactly one is supplied
    // as the very last argument.
    template <typename... T>
    constexpr bool valid_sv_arg = (is_basic_sv<T> + ...) == 0 ||
                                  ((is_basic_sv<T> + ...) == 1 && final_is_string_view<T...>);

}  // namespace detail

template <typename T>
concept splittable_into = safe_to_memcpy<T> || detail::is_skip<T> || detail::is_basic_sv<T>;

// Splits bytes into a tuple of primitive types, copying the size of each primitive object from
// consecutive locations in the string.  The given string must exactly match the sum of the sizes of
// the primitive inputs.  You may also include `skip<N>` (or `skip_t<T>`) as a type, in which case
// `N` bytes (for skip_t: N=sizeof(T)) will be skipped (the `skip<N>` type is not included in the
// returned tuple).  The *final* type may be a basic_string_view<Char>, in which case the final
// element of the tuple will be such a string view containing any unconsumed characters.
//
// For example:
//
// struct A { int16_t x; };
// struct B { char y[5]; };
// using C = std::array<char, 6>;
// using D = std::array<uint16_t, 4>;
//
// auto val = "\x2a\x00hello world!\x01\x00\x02\x00\x03\x00\x04\x00omg"s;
// auto [a, b, c, d, e] = split_guts_into<A, B, skip<1>, C, D, std::string_view>(val);
//
// yields:
//     a.x == 42
//     b == {'h', 'e', 'l', 'l', 'o'}
//     c == {'w', 'o', 'r', 'l', 'd', '!'}
//     d == {1, 2, 3, 4}  (or {256, 512, 768, 1024} on a big-endian architecture)
//     e == "omg"sv
//
template <splittable_into... T, byte_spannable Spannable>
    requires(sizeof...(T) > 0 && detail::valid_sv_arg<T...>)
constexpr detail::tuple_without_skips<T...> split_guts_into(const Spannable& s) {
    using Char = typename Spannable::value_type;
    std::span<const Char> span{s};
    constexpr auto min_size = (detail::split_guts_piece_size<T>() + ...);
    if (detail::final_is_string_view<T...> ? span.size() < min_size : span.size() != min_size)
        throw std::runtime_error{"Invalid split_guts_into string size"};

    detail::tuple_without_skips<T...> result;
    detail::load_split_tuple<0, T...>(
            result, {reinterpret_cast<const char*>(span.data()), span.size()});
    return result;
}

// Same as the above, but takes input as hex string instead of bytes span, with or without a 0x
// prefix.  If using a `skip<N>` type the `N` refers to bytes skipped, not hex characters (i.e.
// skip<2> skips 4 hex characters of input).
//
// If a trailing std::basic_string_view type is specified then that string view will contain all
// unconsumed *hex* digits, not *byte* values.
template <splittable_into... T>
    requires(sizeof...(T) > 0 && detail::valid_sv_arg<T...>)
constexpr detail::tuple_without_skips<T...> split_hex_into(std::string_view hex_in) {
    if (hex_in.starts_with("0x") || hex_in.starts_with("0X"))
        hex_in.remove_prefix(2);

    constexpr auto min_size = 2 * (detail::split_guts_piece_size<T>() + ...);
    if ((detail::final_is_string_view<T...> ? hex_in.size() < min_size
                                            : hex_in.size() != min_size) ||
        !oxenc::is_hex(hex_in))
        throw std::runtime_error{
                "Invalid split_hex_into string input: incorrect hex string size or invalid hex"};

    detail::tuple_without_skips<T...> result;
    detail::load_split_tuple_hex<0, T...>(result, hex_in);
    return result;
}

}  // namespace tools