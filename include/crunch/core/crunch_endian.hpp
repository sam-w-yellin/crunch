#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstdint>
#include <type_traits>

namespace Crunch {

/**
 * @brief Converts a value to/from Little Endian byte order.
 *
 * @tparam T The type of the value to convert. Must be an integral type or enum.
 * @param value The value to convert.
 * @return The converted value.
 */
template <typename T>
    requires std::integral<T> || std::is_enum_v<T> || std::floating_point<T>
[[nodiscard]] constexpr T LittleEndian(T value) noexcept {
    if constexpr (std::endian::native == std::endian::little) {
        return value;
    } else if constexpr (std::integral<T>) {
        return std::byteswap(value);
    } else if constexpr (std::is_enum_v<T>) {
        using U = std::underlying_type_t<T>;
        return static_cast<T>(std::byteswap(static_cast<U>(value)));
    } else {
        // Floating point
        auto bits = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
        std::ranges::reverse(bits);
        return std::bit_cast<T>(bits);
    }
}

}  // namespace Crunch
