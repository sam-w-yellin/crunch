#pragma once

#include <cstdint>
#include <string_view>

namespace Crunch {

/**
 * @brief Unique identifier for a field within a Crunch message.
 */
using FieldId = int32_t;

/**
 * @brief Maximum valid FieldId value.
 *
 * TLV encoding uses the formula: Tag = (FieldId << 3) | WireType
 * This reserves the upper 3 bits of the tag for the wire type, so FieldId
 * must not exceed 2^29 - 1 to avoid overflow.
 */
static constexpr FieldId MaxFieldId = (1 << 29) - 1;

/**
 * @brief Unique identifier for a message type.
 */
using MessageId = int32_t;

/**
 * @brief Serialization format identifier stored in the message header.
 */
enum class Format : uint8_t {
    Packed = 0x01,    ///< No alignment padding (Alignment = 1).
    Aligned4 = 0x02,  ///< 4-byte alignment padding.
    Aligned8 = 0x03,  ///< 8-byte alignment padding.
    TLV = 0x04,       ///< Tag-Length-Value encoding.
};

/**
 * @brief Version identifier for the Crunch library.
 */
using CrunchVersionId = uint8_t;

/**
 * @brief Size of the standard message header in bytes.
 * Header: [Version (1B)] [Format (1B)] [MessageId (4B)]
 */
static constexpr std::size_t StandardHeaderSize =
    sizeof(CrunchVersionId) + sizeof(Format) + sizeof(MessageId);

static constexpr CrunchVersionId CrunchVersion = 0x03;

/**
 * @brief Error codes representing various failure conditions in Crunch.
 */
enum class ErrorCode : uint8_t {
    UNKNOWN = 0,           ///< Unknown error.
    IntegrityCheckFailed,  ///< Message integrity check failed (e.g., CRC
                           ///< mismatch).
    DeserializationError,  ///< Error parsing or decoding message data.
    ValidationFailed,      ///< Field or message logical validation failed.
    InvalidMessageId,      ///< Message ID in header does not match expected ID.
    InvalidFormat,         ///< Serialization format in header does not match
                           ///< expected format.
    CapacityExceeded,      ///< Data exceeds the capacity of the backing
                           ///< storage.
};

/**
 * @brief Represents an error occurred during Crunch operations.
 *
 * Contains an error code, an optional field ID related to the error, and a
 * descriptive message.
 */
struct Error {
    ErrorCode code;  ///< The error code.
    // cppcheck-suppress unusedStructMember
    FieldId field_id{0};  ///< ID of the field associated with the error (0 if
                          ///< not applicable).
    // cppcheck-suppress unusedStructMember
    std::string_view message{};  ///< Static error message string.

    /**
     * @brief Creates an error representing an integrity check failure.
     */
    [[nodiscard]] static constexpr Error integrity() noexcept {
        return {ErrorCode::IntegrityCheckFailed, 0, "integrity check failed"};
    }

    /**
     * @brief Creates an error representing a validation failure.
     * @tparam N Size of the message string literal.
     * @param id The FieldId that failed validation.
     * @param msg The failure description.
     */
    template <size_t N>
    [[nodiscard]] static constexpr Error validation(
        FieldId id, const char (&msg)[N]) noexcept {
        return {ErrorCode::ValidationFailed, id, std::string_view{msg, N - 1}};
    }

    /**
     * @brief Creates an error representing a deserialization failure.
     * @param msg Description of the deserialization error.
     */
    [[nodiscard]] static constexpr Error deserialization(
        std::string_view msg = "deserialization error") noexcept {
        return {ErrorCode::DeserializationError, 0, msg};
    }

    /**
     * @brief Creates an error representing an invalid message ID.
     */
    [[nodiscard]] static constexpr Error invalid_message_id() noexcept {
        return {ErrorCode::InvalidMessageId, 0, "invalid message id"};
    }

    /**
     * @brief Creates an error representing an invalid serialization format.
     */
    [[nodiscard]] static constexpr Error invalid_format() noexcept {
        return {ErrorCode::InvalidFormat, 0, "invalid serialization format"};
    }

    /**
     * @brief Creates an error representing capacity exceeded. Used for strings
     * and aggregated fields.
     * @tparam N Size of the message string literal.
     * @param id The FieldId.
     * @param msg Description.
     */
    template <size_t N>
    [[nodiscard]] static constexpr Error capacity_exceeded(
        FieldId id, const char (&msg)[N]) noexcept {
        return {ErrorCode::CapacityExceeded, id, std::string_view{msg, N - 1}};
    }

    [[nodiscard]] constexpr bool operator==(const Error& other) const noexcept =
        default;

    /**
     * @brief Checks if the error matches a specific error code.
     */
    [[nodiscard]] constexpr bool operator==(ErrorCode c) const noexcept {
        return code == c;
    }
};

}  // namespace Crunch
