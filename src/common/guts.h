#pragma once

#include <oxenc/hex.h>

#include <concepts>
#include <cstring>
#include <span>
#include <string_view>

#include "epee/span.h"  // epee
#include "oxenc/common.h"

namespace tools {

template <typename T>
concept safe_to_memcpy =
        (std::is_standard_layout_v<T> && std::has_unique_object_representations_v<T>) ||
        epee::is_byte_spannable<T>;

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
T make_from_guts(Spannable s) {
    std::span<const typename Spannable::value_type> span{s};
    if (s.size() != sizeof(T))
        throw std::runtime_error("Cannot reconstitute type: wrong type content size");
    T x;
    std::memcpy(static_cast<void*>(&x), s.data(), sizeof(T));
    return x;
}

}  // namespace tools
