#pragma once

#include <crunch/core/crunch_endian.hpp>
#include <crunch/core/crunch_types.hpp>
#include <cstring>
#include <expected>
#include <span>

namespace Crunch {

/**
 * @brief Represents the standard Crunch message header.
 *
 * All protocols share this common header format:
 * - Version (1 byte): Protocol version
 * - Format (1 byte): Serialization format identifier
 * - MessageId (4 bytes): Unique message type identifier
 */
struct CrunchHeader {
    CrunchVersionId version;
    Format format;
    MessageId message_id;
};

/**
 * @brief Parses and returns a copy of the header from the input buffer.
 *
 * @param input The input buffer.
 * @return The parsed header on success, or an Error if the buffer is too small.
 */
[[nodiscard]] constexpr std::expected<CrunchHeader, Error> GetHeader(
    std::span<const std::byte> input) noexcept {
    if (input.size() < StandardHeaderSize) {
        return std::unexpected(
            Error::deserialization("buffer too small for header"));
    }

    CrunchHeader header{};

    std::memcpy(&header.version, input.data(), sizeof(CrunchVersionId));
    std::memcpy(&header.format, input.data() + sizeof(CrunchVersionId),
                sizeof(Format));

    MessageId msg_id;
    std::memcpy(&msg_id,
                input.data() + sizeof(CrunchVersionId) + sizeof(Format),
                sizeof(MessageId));
    header.message_id = LittleEndian(msg_id);

    return header;
}

/**
 * @brief Writes the standard header to the output buffer.
 *
 * @tparam Message The message type (provides message_id).
 * @tparam Serdes The serialization policy (provides format).
 * @param output The output buffer.
 * @return The number of bytes written (always StandardHeaderSize).
 */
template <typename Message, typename Serdes>
[[nodiscard]] constexpr std::size_t WriteHeader(
    std::span<std::byte> output) noexcept {
    std::size_t offset = 0;

    const CrunchVersionId version = CrunchVersion;
    std::memcpy(output.data() + offset, &version, sizeof(version));
    offset += sizeof(version);

    const Format format = Serdes::GetFormat();
    std::memcpy(output.data() + offset, &format, sizeof(format));
    offset += sizeof(format);

    const MessageId msg_id = Message::message_id;
    const MessageId le_msg_id = LittleEndian(msg_id);
    std::memcpy(output.data() + offset, &le_msg_id, sizeof(le_msg_id));
    offset += sizeof(le_msg_id);

    return offset;
}

/**
 * @brief Validates the header and returns offset after header on success.
 *
 * Checks:
 * - Buffer is large enough
 * - Version matches CrunchVersion
 * - Format matches Serdes::GetFormat()
 * - MessageId matches Message::message_id
 *
 * @tparam Message The expected message type.
 * @tparam Serdes The expected serialization policy.
 * @param input The input buffer.
 * @return Offset after header on success, or an Error.
 */
template <typename Message, typename Serdes>
[[nodiscard]] constexpr std::expected<std::size_t, Error> ValidateHeader(
    std::span<const std::byte> input) noexcept {
    auto header_result = GetHeader(input);
    if (!header_result) {
        return std::unexpected(header_result.error());
    }

    const CrunchHeader& header = *header_result;

    if (header.version != CrunchVersion) {
        return std::unexpected(
            Error::deserialization("unsupported crunch version"));
    }

    if (header.format != Serdes::GetFormat()) {
        return std::unexpected(Error::invalid_format());
    }

    if (header.message_id != Message::message_id) {
        return std::unexpected(Error::invalid_message_id());
    }

    return StandardHeaderSize;
}

}  // namespace Crunch
