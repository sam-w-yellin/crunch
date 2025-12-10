#pragma once

#include <crunch_endian.hpp>
#include <crunch_integrity.hpp>
#include <crunch_messages.hpp>
#include <crunch_serdes.hpp>
#include <crunch_static_layout.hpp>
#include <cstddef>
#include <cstring>

/**
 * @brief Internal implementation details for Crunch's public API.
 */
namespace Crunch::detail {

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
    if (auto err = field.validate_presence(); err) {
        return err;
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

    // 1a. Write Header
    const CrunchVersionId version = CrunchVersion;
    std::memcpy(payload_span.data(), &version, sizeof(version));

    const Crunch::Format format = Serdes::GetFormat();
    std::memcpy(payload_span.data() + sizeof(version), &format, sizeof(format));

    // 1b. Serialize Payload (Serdes policy executes logic on full span)
    // Serdes expected to handle MessageID if needed (yes, implementation plan
    // says Serdes writes it).
    const std::size_t bytes_written = Serdes::Serialize(message, payload_span);

    // 2. Calculate and Append Checksum
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
 * @tparam N The size of the buffer.
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

    // Validate Header
    if (payload_span.size() <
        StandardHeaderSize) {  // StandardHeaderSize is sizeof(version) +
                               // sizeof(format)
        return Error::deserialization("buffer too small for header");
    }

    // Validate Version
    CrunchVersionId version;
    std::memcpy(&version, payload_span.data(), sizeof(version));
    if (version != CrunchVersion) {
        return Error::deserialization("unsupported crunch version");
    }

    // Validate Serialization Format against buffer configuration
    Crunch::Format format;
    std::memcpy(&format, payload_span.data() + sizeof(version),
                sizeof(Crunch::Format));
    if (format != Serdes::GetFormat()) {
        return Error::invalid_format();
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

}  // namespace Crunch::detail
