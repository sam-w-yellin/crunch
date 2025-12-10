#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace Crunch {

/**
 * @brief Concept defining the interface for message integrity policies.
 *
 * An IntegrityPolicy calculates a checksum or digest appended to serialized
 * messages. Implementations must provide:
 * - `size()`: Returns the checksum size in bytes. Must be `constexpr`.
 * - `calculate(data)`: Computes the checksum for the given byte span. Must be
 * `constexpr`.
 */
template <typename Policy>
concept IntegrityPolicy = requires(std::span<const std::byte> data) {
    {
        std::bool_constant<(Policy::size(), true)>()
    } -> std::same_as<std::true_type>;
    { Policy::size() } -> std::same_as<std::size_t>;
    {
        std::bool_constant<(Policy::calculate(std::span<const std::byte>{}),
                            true)>()
    } -> std::same_as<std::true_type>;

    {
        Policy::calculate(data)
    } -> std::same_as<std::array<std::byte, Policy::size()>>;
};

/**
 * @brief Integrity policies for verifying message correctness.
 */
namespace integrity {

/**
 * @brief No-op integrity policy.
 *
 * Adds 0 bytes of overhead and performs no integrity checks.
 */
struct None {
    [[nodiscard]] static constexpr std::size_t size() noexcept { return 0; }
    [[nodiscard]] static constexpr auto calculate(
        std::span<const std::byte>) noexcept -> std::array<std::byte, 0> {
        return {};
    }
};

/**
 * @brief CRC-16-CCITT integrity policy.
 *
 * Adds 2 bytes of overhead. Uses polynomial 0x1021 with initial value 0xFFFF.
 *
 * @see https://srecord.sourceforge.net/crc16-ccitt.html
 */
struct CRC16 {
    [[nodiscard]] static constexpr std::size_t size() noexcept { return 2; }

    /**
     * @brief Calculates CRC-16-CCITT checksum.
     * @param data The byte span to calculate checksum over.
     * @return 2-byte array containing the checksum (big-endian).
     */
    [[nodiscard]] static constexpr auto calculate(
        std::span<const std::byte> data) noexcept -> std::array<std::byte, 2> {
        uint16_t crc = 0xFFFF;
        for (std::byte b : data) {
            crc ^= (static_cast<uint8_t>(b) << 8);
            for (int i = 0; i < 8; i++) {
                if (crc & 0x8000) {
                    crc = static_cast<uint16_t>((crc << 1) ^ 0x1021);
                } else {
                    crc = static_cast<uint16_t>(crc << 1);
                }
            }
        }
        return {static_cast<std::byte>((crc >> 8) & 0xFF),
                static_cast<std::byte>(crc & 0xFF)};
    }
};

/**
 * @brief Simple XOR parity integrity policy.
 *
 * Adds 1 byte of overhead. XORs all bytes together for a simple parity check.
 */
struct Parity {
    [[nodiscard]] static constexpr std::size_t size() noexcept { return 1; }

    /**
     * @brief Calculates XOR parity.
     * @param data The byte span to calculate parity over.
     * @return 1-byte array containing the parity byte.
     */
    [[nodiscard]] static constexpr auto calculate(
        std::span<const std::byte> data) noexcept -> std::array<std::byte, 1> {
        std::byte parity{0};
        for (std::byte b : data) {
            parity ^= b;
        }
        return {parity};
    }
};

}  // namespace integrity

}  // namespace Crunch
