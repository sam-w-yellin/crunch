#pragma once

#include <cmath>
#include <concepts>
#include <crunch_types.hpp>
#include <optional>

namespace Crunch {

/**
 * @brief Concept defining a value validator.
 *
 * Validators implement a static `Check` method that validates a value and
 * returns std::nullopt on success or an Error on failure.
 */
template <typename V, typename T>
concept Validator = requires(T value, FieldId field_id) {
    { V::Check(value, field_id) } -> std::same_as<std::optional<Error>>;
};

/**
 * @brief Validates nothing (always succeeds).
 */
struct None {
    template <typename T>
    [[nodiscard]] static constexpr auto Check(T, FieldId) noexcept
        -> std::optional<Error> {
        return std::nullopt;
    }
};

/**
 * @brief Presence validator enforcing that a field MUST be set.
 */
struct Required {
    [[nodiscard]] static constexpr std::optional<Error> check_presence(
        bool set, FieldId id) noexcept {
        if (!set) {
            return Error::validation(id, "field is required but not set");
        }
        return std::nullopt;
    }
};

/**
 * @brief Presence validator allowing an optional field (can be unset).
 */
struct Optional {
    [[nodiscard]] static constexpr std::optional<Error> check_presence(
        bool, FieldId) noexcept {
        return std::nullopt;
    }
};

/**
 * @brief Validates that a boolean value is true.
 */
struct True {
    template <typename T>
        requires std::same_as<T, bool>
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be true");
    }
};

/**
 * @brief Validates that a boolean value is false.
 */
struct False {
    template <typename T>
        requires std::same_as<T, bool>
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (!value) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be false");
    }
};

/**
 * @brief Validates that a floating-point value is finite (not NaN or Inf).
 */
struct IsFinite {
    template <typename T>
        requires std::floating_point<T>
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (std::isfinite(value)) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be finite");
    }
};

/**
 * @brief Validates that a floating-point value is within a tolerance of a
 * target.
 *
 * Checks |value - Target| <= Tolerance.
 */
template <auto Target, auto Tolerance>
struct Around {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (std::abs(value - Target) <= Tolerance) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be around target");
    }
};

/**
 * @brief Concept for validators that check field presence semantics.
 */
template <typename T>
concept IsPresenceValidator =
    std::same_as<T, Required> || std::same_as<T, Optional>;

/** @brief Validates that a value is non-negative (>= 0). */
struct Positive {
    template <typename T>
        requires(std::signed_integral<T> || std::floating_point<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value >= 0) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be >= 0");
    }
};

/** @brief Validates that a value is strictly negative (< 0). */
struct Negative {
    template <typename T>
        requires(std::signed_integral<T> || std::floating_point<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value < 0) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be < 0");
    }
};

/** @brief Validates that a value is not zero. */
struct NotZero {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value != 0) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be != 0");
    }
};

/** @brief Validates that an integral value is even. */
struct Even {
    template <typename T>
        requires std::integral<T> && (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value % 2 == 0) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be even");
    }
};

/** @brief Validates that an integral value is odd. */
struct Odd {
    template <typename T>
        requires std::integral<T> && (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value % 2 != 0) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be odd");
    }
};

/** @brief Validates that a value is less than a compile-time threshold. */
template <auto Threshold>
struct LessThan {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value < Threshold) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be < threshold");
    }
};

/** @brief Validates that a value is greater than a compile-time threshold. */
template <auto Threshold>
struct GreaterThan {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value > Threshold) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be > threshold");
    }
};

/** @brief Validates that a value is less than or equal to a compile-time
 * threshold. */
template <auto Threshold>
struct LessThanOrEqualTo {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value <= Threshold) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be <= threshold");
    }
};

/** @brief Validates that a value is greater than or equal to a compile-time
 * threshold. */
template <auto Threshold>
struct GreaterThanOrEqualTo {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value >= Threshold) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be >= threshold");
    }
};

/** @brief Validates that a value equals a compile-time threshold. */
template <auto Threshold>
struct EqualTo {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T> ||
                 std::is_enum_v<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value == Threshold) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must equal threshold");
    }
};

/** @brief Validates that a value does not equal a compile-time threshold. */
template <auto Threshold>
struct NotEqualTo {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T> ||
                 std::is_enum_v<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (value != Threshold) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must not equal threshold");
    }
};

/** @brief Validates that a value is one of a set of compile-time values. */
template <auto... Values>
struct OneOf {
    template <typename T>
        requires(std::floating_point<T> || std::integral<T> ||
                 std::is_enum_v<T>) &&
                (!std::is_same_v<T, bool>)
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (((value == Values) || ...)) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must be one of allowed values");
    }
};

/** @brief Validates that a string-like or container value has a specific
 * length. */
template <std::size_t N>
struct Length {
    template <typename T>
        requires requires(const T& t) { std::size(t); }
    [[nodiscard]] static constexpr auto Check(const T& value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (std::size(value) == N) {
            return std::nullopt;
        }
        return Error::validation(field_id, "length mismatch");
    }
};

/** @brief Validates that a container has at least N elements. */
template <std::size_t N>
struct LengthAtLeast {
    template <typename T>
        requires requires(const T& t) { std::size(t); }
    [[nodiscard]] static constexpr auto Check(const T& value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (std::size(value) >= N) {
            return std::nullopt;
        }
        return Error::validation(field_id, "length must be at least N");
    }
};

/** @brief Validates that a container has at most N elements. */
template <std::size_t N>
struct LengthAtMost {
    template <typename T>
        requires requires(const T& t) { std::size(t); }
    [[nodiscard]] static constexpr auto Check(const T& value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (std::size(value) <= N) {
            return std::nullopt;
        }
        return Error::validation(field_id, "length must be at most N");
    }
};

/** @brief Validates that a container has unique elements. */
struct Unique {
    template <typename T>
        requires requires(const T& t) {
            { t.begin() } -> std::forward_iterator;
            { t.end() } -> std::forward_iterator;
        }
    [[nodiscard]] static constexpr auto Check(const T& value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        // Simple O(N^2) check to avoid sorting/allocating
        auto end = value.end();
        for (auto it = value.begin(); it != end; ++it) {
            for (auto it2 = std::next(it); it2 != end; ++it2) {
                if (*it == *it2) {
                    return Error::validation(field_id,
                                             "elements must be unique");
                }
            }
        }
        return std::nullopt;
    }
};

/** @brief Validates that a string does not contain embedded nulls. */
struct NullTerminated {
    template <typename T>
        requires std::convertible_to<T, std::string_view>
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        std::string_view sv{value};
        if (!sv.empty() && sv.back() == '\0') {
            return std::nullopt;
        }
        return Error::validation(field_id, "must count null terminator");
    }
};

/*
 * @brief Helper for string literal NTTP.
 * @note I though that strings could be used as NTTPs but
 *       it seems we need this wrapper to make it work.
 */
template <std::size_t N>
struct FixedString {
    char buf[N]{};
    constexpr FixedString(const char (&str)[N]) {
        for (std::size_t i = 0; i < N; ++i) {
            buf[i] = str[i];
        }
    }
    constexpr std::string_view view() const { return {buf, N - 1}; }
};

/** @brief Validates that a string equals a compile-time string. */
template <FixedString S>
struct StringEquals {
    template <typename T>
        requires std::convertible_to<T, std::string_view>
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (std::string_view{value} == S.view()) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must equal expected string");
    }
};

/** @brief Validates that a string does not equal a compile-time string. */
template <FixedString S>
struct StringNotEquals {
    template <typename T>
        requires std::convertible_to<T, std::string_view>
    [[nodiscard]] static constexpr auto Check(T value,
                                              FieldId field_id) noexcept
        -> std::optional<Error> {
        if (std::string_view{value} != S.view()) {
            return std::nullopt;
        }
        return Error::validation(field_id, "must not equal forbidden string");
    }
};

}  // namespace Crunch
