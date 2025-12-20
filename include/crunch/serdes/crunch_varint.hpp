#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace Crunch::serdes {

/**
 * @brief Utility for Varint encoding/decoding.
 *
 * Implemented as a header-only library to support constexpr evaluation.
 */
struct Varint {
    /**
     * @brief Encodes a value as a Varint.
     *
     * @param value The value to encode.
     * @param output The output buffer.
     * @param offset The current offset in the buffer.
     * @return std::size_t The number of bytes written.
     */
    static constexpr std::size_t encode(uint64_t value,
                                        std::span<std::byte> output,
                                        std::size_t offset) noexcept {
        std::size_t start_offset = offset;
        while (value >= 0x80) {
            output[offset++] = static_cast<std::byte>((value & 0x7F) | 0x80);
            value >>= 7;
        }
        output[offset++] = static_cast<std::byte>(value);
        return offset - start_offset;
    }

    /**
     * @brief Decodes a Varint from a buffer.
     *
     * @param input The input buffer.
     * @param offset The offset to start reading from.
     * @return std::optional<std::pair<uint64_t, std::size_t>> The decoded value
     * and bytes read, or nullopt on error.
     */
    static constexpr std::optional<std::pair<uint64_t, std::size_t>> decode(
        std::span<const std::byte> input, std::size_t offset) noexcept {
        uint64_t value = 0;
        std::size_t shift = 0;
        std::size_t bytes_read = 0;

        while (offset + bytes_read < input.size()) {
            uint8_t byte = static_cast<uint8_t>(input[offset + bytes_read]);
            bytes_read++;

            if (shift >= 64) {
                // Overflow (more than 10 bytes or too many bits for 64-bit int)
                return std::nullopt;
            }

            value |= static_cast<uint64_t>(byte & 0x7F) << shift;
            shift += 7;

            if ((byte & 0x80) == 0) {
                return std::make_pair(value, bytes_read);
            }
        }
        // Buffer ended before Varint terminated
        return std::nullopt;
    }

    /**
     * @brief Calculates the size requirement for a value encoded as Varint.
     *
     * @param value The value.
     * @return std::size_t The number of bytes required.
     */
    static constexpr std::size_t size(uint64_t value) noexcept {
        if (value == 0) {
            return 1;
        }
        std::size_t bytes = 0;
        while (value > 0) {
            bytes++;
            value >>= 7;
        }
        return bytes;
    }

    /**
     * @brief The maximum size required for a 64-bit integer encoded as Varint.
     * ceil(64 / 7) = 10.
     */
    // cppcheck-suppress unusedStructMember
    static constexpr std::size_t max_size = 10;

    /**
     * @brief Calculates the maximum varint size for a given number of bits.
     * @param value_bits The number of bits.
     * @return The maximum number of bytes required.
     */
    static consteval std::size_t max_varint_size(std::size_t value_bits) {
        return (value_bits + 6) / 7;
    }
};

}  // namespace Crunch::serdes
