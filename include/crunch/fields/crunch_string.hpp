#pragma once

#include <algorithm>
#include <array>
#include <crunch/core/crunch_types.hpp>
#include <crunch/validators/crunch_validators.hpp>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <string_view>

namespace Crunch::fields {

/**
 * @brief Fixed-size string field backed by std::array.
 *
 * @tparam MaxSize Maximum capacity of the string (compile-time).
 * @tparam Validators Zero or more validators (e.g., Length, OneOf).
 */
template <std::size_t MaxSize, typename... Validators>
    requires((Validator<Validators, std::string_view> && ...) &&
             (sizeof...(Validators) > 0))
class String {
   public:
    using ValueType = std::string_view;
    // cppcheck-suppress unusedStructMember
    static constexpr std::size_t max_size = MaxSize;

    constexpr String() = default;
    constexpr explicit String(std::string_view sv) {
        static_cast<void>(set(sv));
    }

    [[nodiscard]] constexpr std::string_view get() const noexcept {
        return std::string_view{buffer_.data(), current_len_};
    }

    constexpr std::optional<Error> set(std::string_view sv) noexcept {
        if (sv.size() > MaxSize) {
            // Field wrapper will attach the correct ID if available, otherwise
            // 0.
            return Error::capacity_exceeded(0, "string exceeds capacity");
        }
        if (auto err = Validate(sv); err) {
            return err;
        }

        const std::span<char, MaxSize> buf{buffer_};

        // Copy from sv and fill the rest with nulls
        std::ranges::copy(sv, buf.begin());
        std::ranges::fill(buf.subspan(sv.size()), '\0');

        current_len_ = sv.size();
        return std::nullopt;
    }

    constexpr void clear() noexcept {
        current_len_ = 0;
        std::ranges::fill(buffer_, '\0');
    }

    [[nodiscard]] constexpr bool operator==(
        const String& other) const noexcept {
        return get() == other.get();
    }

    [[nodiscard]] constexpr auto Validate(FieldId id = 0) const noexcept
        -> std::optional<Error> {
        return Validate(get(), id);
    }

    [[nodiscard]] static constexpr auto Validate(std::string_view v,
                                                 FieldId id = 0) noexcept
        -> std::optional<Error> {
        for (const auto& result : {Validators::Check(v, id)...}) {
            if (result.has_value()) {
                return result;
            }
        }
        return std::nullopt;
    }

    std::array<char, MaxSize> buffer_{};
    std::size_t current_len_{0};
};

template <typename T>
struct is_string : std::false_type {};

template <std::size_t MaxSize, typename... V>
struct is_string<String<MaxSize, V...>> : std::true_type {};

template <typename T>
inline constexpr bool is_string_v = is_string<T>::value;

}  // namespace Crunch::fields
