#pragma once

#include <algorithm>
#include <concepts>
#include <crunch/core/crunch_endian.hpp>
#include <crunch/core/crunch_types.hpp>
#include <crunch/fields/crunch_string.hpp>
#include <crunch/messages/crunch_field.hpp>
#include <crunch/messages/crunch_messages.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <tuple>

namespace Crunch::serdes {

/**
 * @brief A deterministic, fixed-size binary serialization policy.
 */
template <std::size_t Alignment = 1>
struct StaticLayout {
    static_assert(Alignment == 1 || Alignment == 4 || Alignment == 8,
                  "StaticLayout only supports 1, 4, or 8 byte alignment.");

    /**
     * @brief Gets the Crunch format corresponding to the alignment.
     * @return The format enum.
     */
    [[nodiscard]] static constexpr Crunch::Format GetFormat() noexcept {
        if constexpr (Alignment == 1) {
            return Crunch::Format::Packed;
        } else if constexpr (Alignment == 4) {
            return Crunch::Format::Aligned4;
        } else {
            return Crunch::Format::Aligned8;
        }
    }

    /**
     * @brief Calculates the serialized size of a message.
     * @tparam Message The message type.
     * @return The size in bytes.
     */
    template <typename Message>
    [[nodiscard]] static constexpr std::size_t Size() noexcept {
        return PayloadStartOffset + sizeof(MessageId) +
               calculate_payload_size(Message{});
    }

    /**
     * @brief Serializes a message into the output buffer.
     * @tparam Message The message type.
     * @param msg The message to serialize.
     * @param output The output buffer.
     * @return The number of bytes written.
     */
    template <typename Message>
    static constexpr std::size_t Serialize(
        const Message& msg, std::span<std::byte> output) noexcept {
        std::size_t offset = StandardHeaderSize;
        if (PayloadStartOffset > StandardHeaderSize) {
            std::memset(output.data() + offset, 0,
                        PayloadStartOffset - StandardHeaderSize);
        }
        offset = PayloadStartOffset;

        const MessageId msgId = Message::message_id;
        const MessageId le_msgId = Crunch::LittleEndian(msgId);
        std::memcpy(output.data() + offset, &le_msgId, sizeof(msgId));
        offset += sizeof(msgId);

        std::apply(
            [&](const auto&... fields) {
                ((offset = serialize_field(fields, output, offset)), ...);
            },
            msg.get_fields());
        return offset;
    }

    /**
     * @brief Deserializes a message from the input buffer.
     * @tparam Message The message type.
     * @param input The input buffer.
     * @param msg The message object to populate.
     * @return std::nullopt on success, or an Error on failure.
     */
    template <typename Message>
    [[nodiscard]] static constexpr auto Deserialize(
        std::span<const std::byte> input, Message& msg) noexcept
        -> std::optional<Error> {
        std::size_t offset = PayloadStartOffset;

        MessageId msg_id;
        std::memcpy(&msg_id, input.data() + offset, sizeof(MessageId));
        msg_id = Crunch::LittleEndian(msg_id);
        if (msg_id != Message::message_id) {
            return Error::invalid_message_id();
        }
        offset += sizeof(MessageId);

        std::optional<Error> err = std::nullopt;
        std::apply(
            [&](auto&... fields) {
                ((err.has_value()
                      ? void()
                      : [&] {
                            auto result =
                                deserialize_field(fields, input, offset);
                            if (result.has_value()) {
                                offset = result.value();
                            } else {
                                err = result.error();
                            }
                        }()),
                 ...);
            },
            msg.get_fields());
        return err;
    }

   private:
    /**
     * @brief Aligns a value up to the specified alignment.
     * @param value The value to align.
     * @param alignment The alignment boundary.
     * @return The aligned value.
     */
    [[nodiscard]] static constexpr std::size_t align_up(
        std::size_t value, std::size_t alignment) noexcept {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    /**
     * @brief Calculates the padding needed to align the offset.
     *
     * @tparam T The type whose size determines the alignment requirement.
     * @param offset The current byte offset.
     * @return The number of padding bytes required.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t calculate_padding(
        std::size_t offset) noexcept {
        const std::size_t align = std::min(sizeof(T), Alignment);
        return (align - (offset % align)) % align;
    }

    static constexpr std::size_t PayloadStartOffset =
        align_up(StandardHeaderSize, Alignment);

    /**
     * @brief Calculates the size of the message payload.
     * @tparam Message The message type.
     * @param msg The message instance.
     * @return The payload size.
     */
    template <typename Message>
    [[nodiscard]] static constexpr std::size_t calculate_payload_size(
        const Message& msg) noexcept {
        std::size_t offset = 0;
        std::apply(
            [&](const auto&... fields) {
                ((offset = calculate_field_end_offset(fields, offset)), ...);
            },
            msg.get_fields());
        return offset;
    }

    /**
     * @brief Calculates the end offset of a value based on its type.
     * @tparam T The value type.
     * @param offset The current offset.
     * @return The updated offset after adding the value size.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t calculate_value_end_offset(
        std::size_t offset) noexcept {
        if constexpr (fields::is_string_v<T>) {
            return calculate_string_end_offset<T>(offset);
        } else if constexpr (messages::CrunchMessage<T>) {
            return calculate_message_end_offset<T>(offset);
        } else if constexpr (messages::is_array_field_v<T>) {
            return calculate_array_end_offset<T>(offset);
        } else if constexpr (messages::is_map_field_v<T>) {
            return calculate_map_end_offset<T>(offset);
        } else {
            return calculate_scalar_end_offset<T>(offset);
        }
    }

    /**
     * @brief Calculates the end offset of a field.
     * @tparam Field The field type.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename Field>
    [[nodiscard]] static constexpr std::size_t calculate_field_end_offset(
        const Field&, std::size_t offset) noexcept {
        using ValueType = typename Field::FieldType;
        // ArrayField and MapField don't have is_set byte in wire format
        if constexpr (!messages::is_array_field_v<Field> &&
                      !messages::is_map_field_v<Field>) {
            offset += 1;
        }
        return calculate_value_end_offset<ValueType>(offset);
    }

    /**
     * @brief Calculates the end offset of a nested message.
     * @tparam T The message type.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t calculate_message_end_offset(
        std::size_t offset) noexcept {
        const std::size_t padding =
            calculate_padding<std::byte[Alignment]>(offset);
        offset += padding;
        offset += sizeof(MessageId) + calculate_payload_size(T{});
        return offset;
    }

    /**
     * @brief Calculates the end offset of a scalar value.
     * @tparam T The scalar type.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t calculate_scalar_end_offset(
        std::size_t offset) noexcept {
        using ValT = typename T::ValueType;
        offset += calculate_padding<ValT>(offset) + sizeof(ValT);
        return offset;
    }

    /**
     * @brief Calculates the end offset of a string value.
     * @tparam T The string type.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t calculate_string_end_offset(
        std::size_t offset) noexcept {
        offset += calculate_padding<uint32_t>(offset) + sizeof(uint32_t) +
                  T::max_size;
        return offset;
    }

    /**
     * @brief Calculates the end offset of an array value.
     * @tparam T The array type.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t calculate_array_end_offset(
        std::size_t offset) noexcept {
        using ValT = typename T::ValueType;
        // Align for Length (uint32_t)
        offset += calculate_padding<uint32_t>(offset) + sizeof(uint32_t);

        // Calculate size of MaxSize elements
        // Since element locations depend on alignment which depends on offset,
        // we must iterate.
        for (std::size_t i = 0; i < T::max_size; ++i) {
            offset = calculate_value_end_offset<ValT>(offset);
        }
        return offset;
    }

    /**
     * @brief Calculates the end offset of a map value.
     * @tparam T The map type.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t calculate_map_end_offset(
        std::size_t offset) noexcept {
        using KeyField = typename T::PairType::first_type;
        using ValueField = typename T::PairType::second_type;

        // Align for Length (uint32_t)
        offset += calculate_padding<uint32_t>(offset) + sizeof(uint32_t);

        // Calculate size of MaxSize elements (Key + Value pairs)
        for (std::size_t i = 0; i < T::max_size; ++i) {
            offset = calculate_value_end_offset<KeyField>(offset);
            offset = calculate_value_end_offset<ValueField>(offset);
        }
        return offset;
    }

    /**
     * @brief Serializes a value.
     * @tparam T The value type.
     * @param value The value to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_value(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        if constexpr (fields::is_string_v<T>) {
            return serialize_string(value, output, offset);
        } else if constexpr (messages::CrunchMessage<T>) {
            return serialize_message(value, output, offset);
        } else if constexpr (messages::is_array_field_v<T>) {
            return serialize_array(value, output, offset);
        } else if constexpr (messages::is_map_field_v<T>) {
            return serialize_map(value, output, offset);
        } else {
            return serialize_scalar(value, output, offset);
        }
    }

    /**
     * @brief Serializes a field.
     * @tparam Field The field type.
     * @param field The field to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename Field>
    [[nodiscard]] static constexpr std::size_t serialize_field(
        const Field& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        using ValueType = typename Field::FieldType;

        // ArrayField doesn't have set byte - serialize directly
        if constexpr (messages::is_array_field_v<Field>) {
            return serialize_array(field, output, offset);
        } else if constexpr (messages::is_map_field_v<Field>) {
            return serialize_map(field, output, offset);
        } else {
            const bool set = field.set_;
            output[offset++] = static_cast<std::byte>(set ? 1 : 0);

            if (set) {
                return serialize_value(field.value_, output, offset);
            } else {
                // Zero fill unset fields
                const std::size_t end_offset =
                    calculate_value_end_offset<ValueType>(offset);
                const std::size_t size = end_offset - offset;
                std::memset(output.data() + offset, 0, size);
                return end_offset;
            }
        }
    }

    /**
     * @brief Serializes a string.
     * @tparam T The string type.
     * @param value The string to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_string(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        const std::size_t padding = calculate_padding<uint32_t>(offset);
        if (padding > 0) {
            std::memset(output.data() + offset, 0, padding);
            offset += padding;
        }

        const uint32_t len = static_cast<uint32_t>(value.current_len_);
        const uint32_t le_len = Crunch::LittleEndian(len);
        std::memcpy(output.data() + offset, &le_len, sizeof(len));
        offset += sizeof(len);

        std::memcpy(output.data() + offset, value.buffer_.data(), T::max_size);
        offset += T::max_size;
        return offset;
    }

    /**
     * @brief Serializes a nested message.
     * @tparam T The message type.
     * @param value The message to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_message(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        const std::size_t padding =
            calculate_padding<std::byte[Alignment]>(offset);
        if (padding > 0) {
            std::memset(output.data() + offset, 0, padding);
            offset += padding;
        }

        const MessageId msgId = T::message_id;
        const MessageId le_msgId = Crunch::LittleEndian(msgId);
        std::memcpy(output.data() + offset, &le_msgId, sizeof(msgId));
        offset += sizeof(msgId);

        std::apply(
            [&](const auto&... fields) {
                ((offset = serialize_field(fields, output, offset)), ...);
            },
            value.get_fields());
        return offset;
    }

    /**
     * @brief Serializes a scalar value.
     * @tparam T The scalar type.
     * @param value The value to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_scalar(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        using ValT = typename T::ValueType;
        const std::size_t padding = calculate_padding<ValT>(offset);
        if (padding > 0) {
            std::memset(output.data() + offset, 0, padding);
            offset += padding;
        }

        const auto le_value = Crunch::LittleEndian(value.get());
        std::memcpy(output.data() + offset, &le_value, sizeof(le_value));
        offset += sizeof(le_value);
        return offset;
    }

    /**
     * @brief Serializes an array.
     * @tparam T The array type.
     * @param value The array to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_array(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        using ValT = typename T::ValueType;
        const std::size_t padding = calculate_padding<uint32_t>(offset);
        if (padding > 0) {
            std::memset(output.data() + offset, 0, padding);
            offset += padding;
        }

        const uint32_t len = static_cast<uint32_t>(value.current_len_);
        const uint32_t le_len = Crunch::LittleEndian(len);
        std::memcpy(output.data() + offset, &le_len, sizeof(len));
        offset += sizeof(len);

        // Serialize elements
        for (std::size_t i = 0; i < value.current_len_; ++i) {
            offset = serialize_value(value.items_[i], output, offset);
        }

        // Zero fill remaining slots
        for (std::size_t i = value.current_len_; i < T::max_size; ++i) {
            const std::size_t end = calculate_value_end_offset<ValT>(offset);
            std::memset(output.data() + offset, 0, end - offset);
            offset = end;
        }
        return offset;
    }

    /**
     * @brief Serializes a map.
     * @tparam T The map type.
     * @param value The map to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_map(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        using KeyField = typename T::PairType::first_type;
        using ValueField = typename T::PairType::second_type;

        const std::size_t padding = calculate_padding<uint32_t>(offset);
        if (padding > 0) {
            std::memset(output.data() + offset, 0, padding);
            offset += padding;
        }

        const uint32_t len = static_cast<uint32_t>(value.current_len_);
        const uint32_t le_len = Crunch::LittleEndian(len);
        std::memcpy(output.data() + offset, &le_len, sizeof(len));
        offset += sizeof(len);

        // Serialize elements
        for (std::size_t i = 0; i < value.current_len_; ++i) {
            const auto& pair = value.items_[i];
            offset = serialize_value(pair.first, output, offset);
            offset = serialize_value(pair.second, output, offset);
        }

        // Zero fill remaining slots
        for (std::size_t i = value.current_len_; i < T::max_size; ++i) {
            const std::size_t key_end =
                calculate_value_end_offset<KeyField>(offset);
            std::memset(output.data() + offset, 0, key_end - offset);
            offset = key_end;

            const std::size_t val_end =
                calculate_value_end_offset<ValueField>(offset);
            std::memset(output.data() + offset, 0, val_end - offset);
            offset = val_end;
        }
        return offset;
    }

    /**
     * @brief Deserializes a value.
     * @tparam T The value type.
     * @param value The value to populate.
     * @param set Whether the field is set.
     * @param input The input buffer.
     * @param offset The current offset.
     * @return The updated offset or an error.
     */
    template <typename T>
    [[nodiscard]] static constexpr auto deserialize_value(
        T& value, bool set, std::span<const std::byte> input,
        std::size_t offset) noexcept -> std::expected<std::size_t, Error> {
        if constexpr (fields::is_string_v<T>) {
            return deserialize_string(value, set, input, offset);
        } else if constexpr (messages::CrunchMessage<T>) {
            return deserialize_message(value, set, input, offset);
        } else if constexpr (messages::is_array_field_v<T>) {
            return deserialize_array(value, set, input, offset);
        } else if constexpr (messages::is_map_field_v<T>) {
            return deserialize_map(value, set, input, offset);
        } else {
            return deserialize_scalar(value, set, input, offset);
        }
    }

    /**
     * @brief Deserializes a field.
     * @tparam Field The field type.
     * @param field The field to populate.
     * @param input The input buffer.
     * @param offset The current offset.
     * @return The updated offset or an error.
     */
    template <typename Field>
    [[nodiscard]] static constexpr auto deserialize_field(
        Field& field, std::span<const std::byte> input,
        std::size_t offset) noexcept -> std::expected<std::size_t, Error> {
        // ArrayField and MapField don't have set byte
        if constexpr (messages::is_array_field_v<Field>) {
            return deserialize_array(field, true, input, offset);
        } else if constexpr (messages::is_map_field_v<Field>) {
            return deserialize_map(field, true, input, offset);
        } else {
            const bool set = static_cast<bool>(input[offset++]);
            field.set_ = set;
            return deserialize_value(field.value_, set, input, offset);
        }
    }

    /**
     * @brief Deserializes a nested message.
     * @tparam T The message type.
     * @param value The message to populate.
     * @param set Whether the field is set.
     * @param input The input buffer.
     * @param offset The current offset.
     * @return The updated offset or an error.
     */
    template <typename T>
    [[nodiscard]] static constexpr auto deserialize_message(
        T& value, bool set, std::span<const std::byte> input,
        std::size_t offset) noexcept -> std::expected<std::size_t, Error> {
        const std::size_t padding =
            calculate_padding<std::byte[Alignment]>(offset);
        offset += padding;

        MessageId msg_id;
        std::memcpy(&msg_id, input.data() + offset, sizeof(MessageId));
        msg_id = Crunch::LittleEndian(msg_id);

        if (set && msg_id != T::message_id) {
            return std::unexpected(Error::invalid_message_id());
        }
        offset += sizeof(MessageId);

        if (set) {
            std::optional<Error> err = std::nullopt;
            std::apply(
                [&](auto&... sub_fields) {
                    ((err.has_value()
                          ? void()
                          : [&] {
                                auto result =
                                    deserialize_field(sub_fields, input, offset);
                                if (result.has_value()) {
                                    offset = result.value();
                                } else {
                                    err = result.error();
                                }
                            }()),
                     ...);
                },
                value.get_fields());
            if (err) {
                return std::unexpected(err.value());
            }
        } else {
            // Skip over submessage
            offset += calculate_payload_size(T{});
        }
        return offset;
    }

    /**
     * @brief Deserializes a scalar value.
     * @tparam T The scalar type.
     * @param value The scalar to populate.
     * @param set Whether the field is set.
     * @param input The input buffer.
     * @param offset The current offset.
     * @return The updated offset or an error.
     */
    template <typename T>
    [[nodiscard]] static constexpr auto deserialize_scalar(
        T& value, bool set, std::span<const std::byte> input,
        std::size_t offset) noexcept -> std::expected<std::size_t, Error> {
        using ValT = typename T::ValueType;
        offset += calculate_padding<ValT>(offset);

        if (set) {
            ValT le_value;
            std::memcpy(&le_value, input.data() + offset, sizeof(ValT));
            value.set_without_validation(Crunch::LittleEndian(le_value));
        } else {
            // Default initialization handled by caller
        }
        offset += sizeof(ValT);
        return offset;
    }

    /**
     * @brief Deserializes a string.
     * @tparam T The string type.
     * @param value The string to populate.
     * @param set Whether the field is set.
     * @param input The input buffer.
     * @param offset The current offset.
     * @return The updated offset or an error.
     */
    template <typename T>
    [[nodiscard]] static constexpr auto deserialize_string(
        T& value, bool set, std::span<const std::byte> input,
        std::size_t offset) noexcept -> std::expected<std::size_t, Error> {
        offset += calculate_padding<uint32_t>(offset);

        uint32_t le_len;
        std::memcpy(&le_len, input.data() + offset, sizeof(le_len));
        offset += sizeof(le_len);
        uint32_t len = Crunch::LittleEndian(le_len);

        if (set) {
            if (len > T::max_size) {
                return std::unexpected(Error::capacity_exceeded(
                    0,
                    "deserialized string too long"));  // No ID available here
            }
            std::memcpy(value.buffer_.data(), input.data() + offset,
                        T::max_size);
            value.current_len_ = len;
        } else {
            value.clear();
        }
        offset += T::max_size;
        return offset;
    }

    /**
     * @brief Deserializes an array.
     * @tparam T The array type.
     * @param value The array to populate.
     * @param set Whether the field is set.
     * @param input The input buffer.
     * @param offset The current offset.
     * @return The updated offset or an error.
     */
    template <typename T>
    [[nodiscard]] static constexpr auto deserialize_array(
        T& value, bool set, std::span<const std::byte> input,
        std::size_t offset) noexcept -> std::expected<std::size_t, Error> {
        const auto array_end = calculate_array_end_offset<T>(offset);

        if (!set) {
            value.clear();
            return array_end;
        }

        offset += calculate_padding<uint32_t>(offset);

        uint32_t le_len;
        std::memcpy(&le_len, input.data() + offset, sizeof(le_len));
        offset += sizeof(le_len);
        uint32_t len = Crunch::LittleEndian(le_len);

        if (len > T::max_size) {
            return std::unexpected(
                Error::capacity_exceeded(0, "array capacity exceeded"));
        }
        value.current_len_ = len;

        // Deserialize active elements
        for (size_t i = 0; i < len; ++i) {
            auto res = deserialize_value(value.items_[i], true, input, offset);
            if (!res) {
                return std::unexpected(res.error());
            }
            offset = res.value();
        }

        return array_end;
    }

    /**
     * @brief Deserializes a map.
     * @tparam T The map type.
     * @param value The map to populate.
     * @param set Whether the field is set.
     * @param input The input buffer.
     * @param offset The current offset.
     * @return The updated offset or an error.
     */
    template <typename T>
    [[nodiscard]] static constexpr auto deserialize_map(
        T& value, bool set, std::span<const std::byte> input,
        std::size_t offset) noexcept -> std::expected<std::size_t, Error> {
        const auto map_end = calculate_map_end_offset<T>(offset);

        if (!set) {
            value.clear();
            return map_end;
        }

        offset += calculate_padding<uint32_t>(offset);

        // Deserialize length
        uint32_t le_len;
        std::memcpy(&le_len, input.data() + offset, sizeof(le_len));
        offset += sizeof(le_len);
        uint32_t len = Crunch::LittleEndian(le_len);

        if (len > T::max_size) {
            return std::unexpected(
                Error::capacity_exceeded(0, "map capacity exceeded"));
        }
        value.current_len_ = len;

        // Deserialize key-value pairs
        for (size_t i = 0; i < len; ++i) {
            auto& pair = value.items_[i];

            const auto res_key =
                deserialize_value(pair.first, true, input, offset);
            if (!res_key) {
                return std::unexpected(res_key.error());
            }
            offset = res_key.value();

            const auto res_val =
                deserialize_value(pair.second, true, input, offset);
            if (!res_val) {
                return std::unexpected(res_val.error());
            }
            offset = res_val.value();
        }

        return map_end;
    }
};

using PackedLayout = StaticLayout<1>;
using Aligned32Layout = StaticLayout<4>;
using Aligned64Layout = StaticLayout<8>;

}  // namespace Crunch::serdes
