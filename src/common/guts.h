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

}  // namespace tools
