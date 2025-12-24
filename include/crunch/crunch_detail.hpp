#pragma once

#include <crunch/core/crunch_endian.hpp>
#include <crunch/core/crunch_header.hpp>
#include <crunch/integrity/crunch_integrity.hpp>
#include <crunch/messages/crunch_messages.hpp>
#include <crunch/serdes/crunch_serdes.hpp>
#include <crunch/serdes/crunch_static_layout.hpp>
#include <cstddef>
#include <cstring>
#include <span>
#include <variant>
/**
 * @brief Internal implementation details for Crunch's public API.
 */
namespace Crunch::detail {

/**
 * @brief A lightweight wrapper around a std::array for
 * serializing/deserializing messages.
 *
 * Encodes the Message, Integrity, and Serdes types, and provides a span
 * interface to the underlying data.
 *
 * @tparam Message The CrunchMessage type this buffer is for.
 * @tparam Integrity The IntegrityPolicy used.
 * @tparam Serdes The SerdesPolicy used.
 * @tparam N The size of the buffer in bytes.
 */
template <typename Message, typename Integrity, typename Serdes, std::size_t N>
struct Buffer {
    using MessageType = Message;
    using IntegrityType = Integrity;
    using SerdesType = Serdes;

    // cppcheck-suppress unusedStructMember
    static constexpr std::size_t Size = N;

    std::array<std::byte, N> data;
    std::size_t used_bytes{0};

    [[nodiscard]] constexpr auto span() noexcept {
        return std::span<std::byte, N>{data};
    }
    [[nodiscard]] constexpr auto span() const noexcept {
        return std::span<const std::byte, N>{data};
    }

    [[nodiscard]] constexpr auto serialized_message_span() const noexcept {
        return std::span<const std::byte>{data.data(), used_bytes};
    }
};

namespace detail {
template <typename T>
struct is_buffer : std::false_type {};

template <typename Message, typename Integrity, typename Serdes, std::size_t N>
struct is_buffer<Buffer<Message, Integrity, Serdes, N>> : std::true_type {};
}  // namespace detail

template <typename T>
concept IsBuffer = detail::is_buffer<T>::value;

/**
 * @brief Compile-time calculation of the size of a buffer for a given message,
 * integrity, and serdes combination.
 *
 * @tparam Message The message type to calculate the buffer size for.
 * @tparam Integrity The integrity policy to use.
 * @tparam Serdes The serialization policy to use.
 * @return The size of the buffer in bytes.
 */
template <messages::CrunchMessage Message, typename Integrity, typename Serdes>
    requires IntegrityPolicy<Integrity> && SerdesPolicy<Serdes, Message>
[[nodiscard]] consteval auto GetBufferSize() noexcept -> std::size_t {
    return Serdes::template Size<Message>() + Integrity::size();
}

/**
 * @brief Forward declaration of Validate to enable recursion in ValidateField.
 *
 * ValidateField calls Validate for submessages, and Validate calls
 * ValidateField for all fields. This forward declaration resolves the circular
 * dependency.
 *
 * @tparam Message The message type to validate.
 * @param message The message to validate.
 * @return std::nullopt on success, or an Error.
 */
template <typename Message>
    requires messages::CrunchMessage<Message>
[[nodiscard]] constexpr auto Validate(const Message& message) noexcept
    -> std::optional<Error>;

/**
 * @brief Helper to validate a single field.
 *
 * @tparam T The type of the field to validate.
 * @param field The field instance to validate.
 * @return std::optional<Error> An error if validation fails, otherwise
 * std::nullopt.
 */
template <typename T>
constexpr std::optional<Error> ValidateField(const T& field) {
    if constexpr (requires { field.validate_presence(); }) {
        if (auto err = field.validate_presence(); err) {
            return err;
        }
    }

    if constexpr (messages::HasCrunchMessageInterface<typename T::FieldType>) {
        if (const auto* ptr = field.get()) {
            // Recurse into the submessage content
            if (auto err = Validate(*ptr); err) {
                return err;
            }
        }
    } else {
        // Scalar, String, Array
        if (auto err = field.Validate(); err) {
            return err;
        }
    }
    return std::nullopt;
}

/**
 * @brief Validates a message (fields presence, values, submessages, and
 * message-level logic).
 *
 * @tparam Message The message type to validate.
 * @param message The message to validate.
 * @return std::optional<Error> std::nullopt on success, or an Error.
 */
template <typename Message>
    requires messages::CrunchMessage<Message>
[[nodiscard]] constexpr auto Validate(const Message& message) noexcept
    -> std::optional<Error> {
    std::optional<Error> err;
    std::apply(
        [&](const auto&... fields) {
            ([&] {
                if (err.has_value()) {
                    return false;
                }
                err = ValidateField(fields);
                return !err.has_value();
            }() &&
             ...);
        },
        message.get_fields());

    if (err.has_value()) {
        return err;
    }

    return message.Validate();
}

/**
 * @brief Serializes the message without any validation checks.
 *
 * @tparam Integrity The integrity policy to use.
 * @tparam Serdes The serialization policy to use.
 * @tparam Message The message type to serialize.
 * @tparam N The size of the buffer.
 * @param buffer The buffer to serialize into.
 * @param message The message to serialize.
 */
template <typename Integrity, typename Serdes, messages::CrunchMessage Message,
          std::size_t N>
    requires IntegrityPolicy<Integrity> && SerdesPolicy<Serdes, Message>

[[nodiscard]] std::size_t SerializeWithoutValidation(
    std::array<std::byte, N>& buffer, const Message& message) noexcept {
    constexpr std::size_t ChecksumSize = Integrity::size();
    constexpr std::size_t PayloadSize = N - ChecksumSize;

    std::span<std::byte, PayloadSize> payload_span(buffer.data(), PayloadSize);

    // Write Header
    WriteHeader<Message, Serdes>(payload_span);

    // Serialize Payload (Serdes policy executes logic on full span)
    const std::size_t bytes_written = Serdes::Serialize(message, payload_span);

    // Calculate and Append Checksum
    if constexpr (ChecksumSize > 0) {
        // Calculate checksum over the header and payload (bytes_written
        // includes both).
        std::span<std::byte> used_payload_span =
            payload_span.subspan(0, bytes_written);
        auto checksum = Integrity::calculate(used_payload_span);

        std::span<std::byte, ChecksumSize> checksum_span(
            buffer.data() + bytes_written, ChecksumSize);
        std::copy(checksum.begin(), checksum.end(), checksum_span.begin());
    }
    return bytes_written + ChecksumSize;
}

/**
 * @brief implementation of Serialize.
 *
 * First field presence and message-level validation.
 * Then, the header is serialized. Then the payload is
 * delegated to the Serdes policy for serialization.
 * Finally, the integrity policy is executed and appended.
 *
 * @tparam Integrity The integrity policy to use.
 * @tparam Serdes The serialization policy to use.
 * @tparam Message The message type to serialize.
 * @tparam N The size of the buffer.
 * @param buffer The buffer to serialize into.
 * @param message The message to serialize.
 * @return std::nullopt on success, or an Error if validation fails.
 */
template <typename Integrity, typename Serdes, messages::CrunchMessage Message,
          std::size_t N>
    requires IntegrityPolicy<Integrity> && SerdesPolicy<Serdes, Message>
[[nodiscard]] auto Serialize(std::array<std::byte, N>& buffer,
                             const Message& message) noexcept
    -> std::expected<std::size_t, Error> {
    // Validate Message
    if (auto err = Validate(message); err.has_value()) {
        return std::unexpected(*err);
    }
    return SerializeWithoutValidation<Integrity, Serdes>(buffer, message);
}

/**
 * @brief implementation of Deserialize.
 *
 * First, the integrity policy is executed to validate the buffer.
 * Then, the header is deserialized. Finally, the payload is
 * delegated to the Serdes policy for deserialization.
 *
 * @tparam Integrity The integrity policy to use.
 * @tparam Serdes The serialization policy to use.
 * @tparam Message The message type to deserialize into.
 * @param buffer The buffer to deserialize from.
 * @param message The message object to populate.
 * @return std::nullopt on success, or an Error if integrity or deserialization
 * fails.
 */
template <typename Integrity, typename Serdes, typename Message>
    requires IntegrityPolicy<Integrity> && SerdesPolicy<Serdes, Message> &&
             messages::CrunchMessage<Message>
[[nodiscard]] auto Deserialize(std::span<const std::byte> buffer,
                               Message& message) noexcept
    -> std::optional<Error> {
    constexpr std::size_t ChecksumSize = Integrity::size();

    if (buffer.size() < ChecksumSize) {
        return Error::deserialization("buffer too small for checksum");
    }
    const std::size_t PayloadSize = buffer.size() - ChecksumSize;

    std::span<const std::byte> payload_span = buffer.subspan(0, PayloadSize);

    // Execute Integrity Check per policy
    if constexpr (ChecksumSize > 0) {
        const auto expected_checksum = Integrity::calculate(payload_span);
        std::span<const std::byte, ChecksumSize> actual_checksum_span(
            buffer.data() + PayloadSize, ChecksumSize);

        // Simple comparison
        const bool match =
            std::equal(expected_checksum.begin(), expected_checksum.end(),
                       actual_checksum_span.begin());
        if (!match) {
            return Error::integrity();
        }
    }

    // Validate Header (Version, Format, MessageId)
    auto header_result = ValidateHeader<Message, Serdes>(payload_span);
    if (!header_result) {
        return header_result.error();
    }

    // Deserialize (Serdes policy executes its logic on the full span)
    if (const auto err = Serdes::Deserialize(payload_span, message);
        err.has_value()) {
        return err;
    }

    // Validate deserialized message
    if (auto err = Validate(message); err.has_value()) {
        return err;
    }

    return std::nullopt;
}

/**
 * @brief Counts how many messages have the given message ID.
 */
template <MessageId Id, typename... Messages>
consteval std::size_t CountMessageId() {
    return ((Messages::message_id == Id ? 1 : 0) + ...);
}

/**
 * @brief Returns true if any message ID appears more than once.
 */
template <typename... Messages>
consteval bool HasDuplicateMessageIds() {
    return ((CountMessageId<Messages::message_id, Messages...>() > 1) || ...);
}

template <typename... Messages>
concept UniqueMessageIds = !HasDuplicateMessageIds<Messages...>();

/**
 * @brief Decoder class for deserializing one of N possible message types from a
 * buffer.
 *
 * @tparam Serdes The serdes policy to use.
 * @tparam Integrity The integrity policy to use.
 * @tparam Messages The message types which may be deserialized (must have
 * unique message IDs).
 */
template <typename Serdes, typename Integrity,
          messages::CrunchMessage... Messages>
    requires UniqueMessageIds<Messages...>
class Decoder {
   public:
    using VariantType = std::variant<Messages...>;

    [[nodiscard]] constexpr std::optional<Error> Decode(
        std::span<const std::byte> buffer, VariantType& out_message) {
        // Validate Header
        const auto header = GetHeader(buffer);
        if (!header) {
            return header.error();
        }

        // Find message which matches header's message_id and deserialize
        std::optional<Error> result = Error::invalid_message_id();
        ([&]() -> bool {
            if (Messages::message_id == header->message_id) {
                Messages msg{};
                auto err = Deserialize<Integrity, Serdes>(buffer, msg);
                if (err) {
                    result = err;
                } else {
                    out_message = std::move(msg);
                    result = std::nullopt;
                }
                return true;
            }
            return false;
        }() || ...);

        return result;
    }

   private:
    std::variant<
        // Variant holding all possible buffer configurations for the given
        // message types, integrity, and serdes
        Buffer<Messages, Integrity, Serdes,
               GetBufferSize<Messages, Integrity, Serdes>()>...>
        buffer;
};

}  // namespace Crunch::detail
