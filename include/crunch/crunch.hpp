#pragma once

#include <array>
#include <concepts>
#include <crunch/crunch_detail.hpp>
#include <crunch/fields/crunch_enum.hpp>
#include <crunch/fields/crunch_string.hpp>
#include <crunch/integrity/crunch_integrity.hpp>
#include <crunch/messages/crunch_messages.hpp>
#include <crunch/serdes/crunch_serdes.hpp>
#include <crunch/serdes/crunch_static_layout.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

/**
 * @brief The public API for Crunch.
 *
 * This section contains all the interfaces for serializing and deserializing
 * messages, and transitively provides the necessary types for defining
 * messages and fields.
 *
 * @section top_level_apis Top-level APIs
 *
 * - @b GetBuffer: Creates a strongly-typed buffer of the maximum serialized
 *   message size for a given Message, Integrity, and Serdes combination.
 * - @b Validate: Validates field presence and message-level constraints.
 * - @b Serialize: Validates and writes a message into a buffer, appending
 *   integrity checks.
 * - @b Deserialize: Verifies integrity and reads a message from a buffer.
 */

namespace Crunch {

// Expose Buffer, IsBuffer, and Decoder from detail namespace
using detail::Buffer;
using detail::Decoder;
using detail::IsBuffer;

/**
 * @brief Creates a correctly sized Buffer for the given configuration.
 *
 * This function calculates the exact size required for the message
 * serialization plus any integrity overhead at compile time.
 *
 * @tparam Message The CrunchMessage type.
 * @tparam Integrity The IntegrityPolicy (e.g., integrity::None,
 * integrity::CRC16).
 * @tparam Serdes The SerdesPolicy (e.g., serdes::PackedLayout).
 * @return A Buffer object ready for use with Serialize/Deserialize.
 */
template <messages::CrunchMessage Message, typename Integrity, typename Serdes>
    requires IntegrityPolicy<Integrity> && SerdesPolicy<Serdes, Message>
// cppcheck-suppress unusedFunction
[[nodiscard]] constexpr auto GetBuffer() noexcept {
    constexpr std::size_t N =
        detail::GetBufferSize<Message, Integrity, Serdes>();
    return Buffer<Message, Integrity, Serdes, N>{};
}

/**
 * @brief Validates a message (field presence + message-level validation).
 *
 * First validates that all required fields are set, then calls the message's
 * custom Validate() method for any cross-field or business logic validation.
 *
 * @note This API does not execute field validators. Field validators are
 * executed by the fields on-set.

 * @note In the future, this will also validate submessages and run aggregate
 * field validation.
 *
 * @tparam Message The CrunchMessage type to validate.
 * @param message The message to validate.
 * @return std::optional<Error> std::nullopt on success, or an Error if
 * validation fails.
 */
template <messages::CrunchMessage Message>
[[nodiscard]] constexpr auto Validate(const Message& message) noexcept
    -> std::optional<Error> {
    return detail::Validate(message);
}

/**
 * @brief Serializes a message into the provided buffer.
 *
 * Validates the message content, serializes it according to the Serdes policy,
 * and applies the Integrity policy (e.g., checksum).
 *
 * Constraints:
 * - BufferType must be an instantiation of Crunch::Buffer.
 * - Message must satisfy the CrunchMessage concept.
 * - BufferType::MessageType must be the same as Message.
 *
 * @tparam BufferType The Buffer type (deduced from buffer parameter).
 * @tparam Message The CrunchMessage type to serialize.
 * @param buffer The destination Buffer (must match Message type).
 * @param message The message to serialize.
 * @return std::optional<Error> std::nullopt on success, or an Error if
 * validation fails.
 */
template <typename BufferType, typename Message>
    requires IsBuffer<BufferType> && messages::CrunchMessage<Message> &&
             std::same_as<typename BufferType::MessageType, Message>
[[nodiscard]] constexpr auto Serialize(BufferType& buffer,
                                       const Message& message) noexcept
    -> std::optional<Error> {
    using Serdes = typename BufferType::SerdesType;
    using Integrity = typename BufferType::IntegrityType;
    auto res = detail::Serialize<Integrity, Serdes>(buffer.data, message);
    if (!res) {
        return res.error();
    }
    buffer.used_bytes = *res;
    return std::nullopt;
}

/**
 * @brief Serializes a message into the provided buffer without validation.
 *
 * Does strictly serialization logic (header, payload, checksum) without
 * running any validation checks. Useful for forwarding invalid messages,
 * testing, or performance-critical paths where validation is done elsewhere.
 *
 * @tparam BufferType The Buffer type
 * @tparam Message The CrunchMessage type to serialize.
 * @param buffer The destination Buffer (must match Message type).
 * @param message The message to serialize.
 */
template <typename BufferType, typename Message>
    requires IsBuffer<BufferType> && messages::CrunchMessage<Message> &&
             std::same_as<typename BufferType::MessageType, Message>
constexpr void SerializeWithoutValidation(BufferType& buffer,
                                          const Message& message) noexcept {
    using Serdes = typename BufferType::SerdesType;
    using Integrity = typename BufferType::IntegrityType;
    buffer.used_bytes = detail::SerializeWithoutValidation<Integrity, Serdes>(
        buffer.data, message);
}

/**
 * @brief Deserializes a message from a buffer.
 *
 * Verifies the integrity of the buffer, then attempts to deserialize the
 * content into a Message object.
 *
 * Constraints:
 * - BufferType must be an instantiation of Crunch::Buffer.
 * - Message must satisfy the CrunchMessage concept.
 * - BufferType::MessageType must be the same as Message.
 *
 * @tparam BufferType The Buffer type
 * @tparam Message The CrunchMessage type to deserialize into.
 * @param buffer The source Buffer to read from.
 * @param out_message Output parameter for the deserialized message.
 * @return std::optional<Error> std::nullopt on success, or an Error
 * (Integrity/Deserialization).
 */
template <typename BufferType, typename Message>
    requires IsBuffer<BufferType> && messages::CrunchMessage<Message> &&
             std::same_as<typename BufferType::MessageType, Message>
[[nodiscard]] constexpr auto Deserialize(const BufferType& buffer,
                                         Message& out_message)
    -> std::optional<Error> {
    using Serdes = typename BufferType::SerdesType;
    using Integrity = typename BufferType::IntegrityType;
    return detail::Deserialize<Integrity, Serdes>(
        buffer.serialized_message_span(), out_message);
}

}  // namespace Crunch
