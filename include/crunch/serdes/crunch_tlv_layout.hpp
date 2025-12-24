#pragma once

#include <bit>
#include <crunch/core/crunch_endian.hpp>
#include <crunch/core/crunch_types.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/fields/crunch_string.hpp>
#include <crunch/messages/crunch_field.hpp>
#include <crunch/messages/crunch_messages.hpp>
#include <crunch/serdes/crunch_varint.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <numeric>
#include <optional>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>

namespace Crunch::serdes {

/**
 * @brief TLV Serialization Policy.
 *
 * Implements a Tag-Length-Value serialization format where:
 * - Fields are identified by Field ID and Wire Type.
 * - Integers/Floats/Bool are encoded as Varints.
 * - Strings, Nested Messages, and Packed Arrays are LengthDelimited.
 * - The top-level message body is length-prefixed (4 bytes) to handle buffer
 * padding.
 */
namespace detail {

/**
 * @brief Helper to extract the underlying scalar type from a field wrapper.
 * @tparam T The field type.
 */
template <typename T>
struct ext {
    using type = typename T::FieldType;
};

template <typename T>
    requires Crunch::fields::is_scalar_v<T>
struct ext<T> {
    using type = T;
};

}  // namespace detail

struct TlvLayout {
    /**
     * @brief Wire types for TLV encoding.
     */
    enum class WireType : uint8_t {
        Varint = 0,
        LengthDelimited = 1,
    };

    static constexpr Crunch::Format GetFormat() { return Crunch::Format::TLV; }

    /**
     * @brief Number of bits used for the wire type in a tag.
     */
    static constexpr std::size_t WireTypeBits = 3;

    /**
     * @brief The maximum number of bits required for a Tag (FieldID +
     * WireType). Used for calculating the maximum size of a tag varint.
     */
    static constexpr std::size_t MaxTagBits =
        sizeof(FieldId) * 8 + WireTypeBits;

    /**
     * @brief Calculates the maximum possible serialized size of a message.
     * @tparam Message The message type.
     * @return The size in bytes.
     */
    template <typename Message>
    [[nodiscard]] static consteval std::size_t Size() noexcept {
        return Crunch::StandardHeaderSize + sizeof(uint32_t) +
               calculate_max_message_size<Message>();
    }

    /**
     * @brief Serializes a message into the output buffer.
     * @tparam Message The message type.
     * @param msg The message to serialize.
     * @param output The output buffer.
     * @return The number of bytes written (offset).
     */
    template <typename Message>
    [[nodiscard]] static constexpr std::size_t Serialize(
        const Message& msg, std::span<std::byte> output) noexcept {
        // Header (including MessageId) is written by top-level serializer
        std::size_t offset = Crunch::StandardHeaderSize;

        const std::size_t length_field_offset = offset;
        offset += sizeof(uint32_t);

        const std::size_t payload_start = offset;
        offset = serialize_fields_helper(msg.get_fields(), output, offset);

        const std::size_t payload_size = offset - payload_start;
        const uint32_t le_len =
            Crunch::LittleEndian(static_cast<uint32_t>(payload_size));
        std::memcpy(output.data() + length_field_offset, &le_len,
                    sizeof(uint32_t));

        return offset;
    }

    /**
     * @brief Deserializes a message from the input buffer.
     * @tparam Message The message type.
     * @param input The input buffer.
     * @param msg The message object to populate.
     * @return std::nullopt on success, or Error.
     */
    template <typename Message>
    [[nodiscard]] static constexpr auto Deserialize(
        std::span<const std::byte> input, Message& msg) noexcept
        -> std::optional<Error> {
        // Header (including MessageId) validated by top-level deserializer
        std::size_t offset = Crunch::StandardHeaderSize;

        if (offset + sizeof(uint32_t) > input.size()) {
            return Error::deserialization("buffer too small for tlv length");
        }

        uint32_t le_len;
        std::memcpy(&le_len, input.data() + offset, sizeof(uint32_t));
        uint32_t payload_len = Crunch::LittleEndian(le_len);
        offset += sizeof(uint32_t);

        if (offset + payload_len > input.size()) {
            return Error::deserialization("tlv length exceeds buffer");
        }

        return deserialize_message_payload(
            input.subspan(0, offset + payload_len), msg, offset);
    }

   private:
    /**
     * @brief Writes a field tag (ID + WireType) as a Varint.
     * @param id The field ID.
     * @param wt The wire type.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    [[nodiscard]] static constexpr std::size_t write_tag(
        FieldId id, WireType wt, std::span<std::byte> output,
        std::size_t offset) noexcept {
        const uint32_t tag = (static_cast<uint32_t>(id) << WireTypeBits) |
                             static_cast<uint8_t>(wt);
        return offset + Varint::encode(tag, output, offset);
    }

    /**
     * @brief Helper to sum field sizes using fold expressions.
     */
    template <typename Tuple, std::size_t... Is>
    [[nodiscard]] static consteval std::size_t sum_fields_impl(
        std::index_sequence<Is...>) noexcept {
        return (calculate_max_field_size_type<
                    std::remove_cvref_t<std::tuple_element_t<Is, Tuple>>>() +
                ... + 0);
    }

    template <typename Tuple>
    [[nodiscard]] static consteval std::size_t sum_fields_helper() noexcept {
        return sum_fields_impl<Tuple>(
            std::make_index_sequence<
                std::tuple_size_v<std::remove_cvref_t<Tuple>>>{});
    }

    /**
     * @brief Calculates the maximum size of a message type.
     * @tparam Message The message type.
     * @return The maximum size in bytes.
     */
    template <typename Message>
    [[nodiscard]] static consteval std::size_t
    calculate_max_message_size() noexcept {
        using FieldsTuple = decltype(std::declval<Message>().get_fields());
        return sum_fields_helper<FieldsTuple>();
    }

    /**
     * @brief Calculates the maximum size of an array field.
     *
     * All arrays use packed encoding:
     * [Tag][TotalLength][Count][Elem1][Elem2]...
     *
     * @tparam ElemT The element type of the array.
     * @param max_elements The maximum number of elements in the array.
     * @return The maximum size in bytes.
     */
    template <typename ElemT>
    [[nodiscard]] static consteval std::size_t calculate_max_array_field_size(
        std::size_t max_elements) noexcept {
        constexpr std::size_t tag_size = Varint::max_varint_size(MaxTagBits);
        constexpr std::size_t length_size = Varint::max_size;
        constexpr std::size_t count_size = Varint::max_size;
        constexpr std::size_t elem_size = calculate_max_value_size<ElemT>();

        return tag_size + length_size + count_size + (max_elements * elem_size);
    }

    /**
     * @brief Calculates the maximum size of a scalar field.
     * @tparam ScalarT The scalar type.
     * @return The maximum size in bytes.
     */
    template <typename ScalarT>
    [[nodiscard]] static consteval std::size_t
    calculate_max_scalar_field_size() noexcept {
        constexpr std::size_t tag_size = Varint::max_varint_size(MaxTagBits);
        return tag_size + Varint::max_size;
    }

    /**
     * @brief Calculates the maximum size of a string field.
     * @tparam StringT The string type.
     * @return The maximum size in bytes.
     */
    template <typename StringT>
    [[nodiscard]] static consteval std::size_t
    calculate_max_string_field_size() noexcept {
        constexpr std::size_t tag_size = Varint::max_varint_size(MaxTagBits);
        return tag_size + Varint::max_size + StringT::max_size;
    }

    /**
     * @brief Calculates the maximum size of a nested message field.
     * @tparam MsgT The nested message type.
     * @return The maximum size in bytes.
     */
    template <typename MsgT>
    [[nodiscard]] static consteval std::size_t
    calculate_max_nested_message_field_size() noexcept {
        constexpr std::size_t tag_size = Varint::max_varint_size(MaxTagBits);
        return tag_size + Varint::max_size + calculate_max_message_size<MsgT>();
    }

    /**
     * @brief Calculates the maximum serialized size of a value field (no tag).
     * @tparam T The field type (key or value).
     * @return The maximum size in bytes for this value type.
     */
    template <typename T>
    [[nodiscard]] static consteval std::size_t
    calculate_max_value_size() noexcept {
        if constexpr (Crunch::fields::is_scalar_v<T>) {
            // Just the varint value, no tag
            return Varint::max_size;
        } else if constexpr (Crunch::fields::is_string_v<T>) {
            // [Length][Data]
            return Varint::max_size + T::max_size;
        } else if constexpr (Crunch::messages::HasCrunchMessageInterface<T>) {
            // [Length][NestedFields]
            return Varint::max_size + calculate_max_message_size<T>();
        } else if constexpr (Crunch::messages::is_array_field_v<T>) {
            return calculate_max_array_field_size<typename T::ValueType>(
                T::max_size);
        } else if constexpr (Crunch::messages::is_map_field_v<T>) {
            using KeyType = typename T::PairType::first_type;
            using ValueType = typename T::PairType::second_type;
            return calculate_max_map_field_size<KeyType, ValueType>(
                T::max_size);
        }
        std::unreachable();
    }

    /**
     * @brief Calculates the maximum size of a map field.
     *
     * Packed encoding: [Tag][TotalLength][Count][Key1][Val1][Key2][Val2]...
     *
     * @tparam KeyT The key type.
     * @tparam ValueT The value type.
     * @param max_elements The maximum number of elements in the map.
     * @return The maximum size in bytes.
     */
    template <typename KeyT, typename ValueT>
    [[nodiscard]] static consteval std::size_t calculate_max_map_field_size(
        std::size_t max_elements) noexcept {
        constexpr std::size_t tag_size = Varint::max_varint_size(MaxTagBits);
        constexpr std::size_t length_size = Varint::max_size;
        constexpr std::size_t count_size = Varint::max_size;
        constexpr std::size_t key_size = calculate_max_value_size<KeyT>();
        constexpr std::size_t value_size = calculate_max_value_size<ValueT>();

        return tag_size + length_size + count_size +
               max_elements * (key_size + value_size);
    }

    /**
     * @brief Calculates the maximum size of a field based on its type.
     * @tparam FieldT The field type.
     * @return The maximum size in bytes.
     */
    template <typename FieldT>
    [[nodiscard]] static consteval std::size_t
    calculate_max_field_size_type() noexcept {
        if constexpr (Crunch::messages::is_array_field_v<FieldT>) {
            return calculate_max_array_field_size<typename FieldT::ValueType>(
                FieldT::max_size);
        } else if constexpr (Crunch::messages::is_map_field_v<FieldT>) {
            using KeyType = typename FieldT::PairType::first_type;
            using ValueType = typename FieldT::PairType::second_type;
            return calculate_max_map_field_size<KeyType, ValueType>(
                FieldT::max_size);
        } else {
            using ValueType = typename detail::ext<FieldT>::type;
            if constexpr (Crunch::fields::is_scalar_v<ValueType>) {
                return calculate_max_scalar_field_size<ValueType>();
            } else if constexpr (Crunch::fields::is_string_v<ValueType>) {
                return calculate_max_string_field_size<ValueType>();
            } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                     ValueType>) {
                return calculate_max_nested_message_field_size<ValueType>();
            }
        }
        return 0;
    }

    /**
     * @brief Serializes a scalar value.
     * @tparam T The scalar value type.
     * @param value The value to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_scalar_value(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        uint64_t encoded_val = 0;
        if constexpr (std::is_same_v<T, bool>) {
            encoded_val = value ? 1 : 0;
        } else if constexpr (std::is_floating_point_v<T>) {
            if constexpr (sizeof(T) == 4) {
                encoded_val =
                    static_cast<uint64_t>(std::bit_cast<uint32_t>(value));
            } else {
                encoded_val = std::bit_cast<uint64_t>(value);
            }
        } else {
            encoded_val = static_cast<uint64_t>(
                std::bit_cast<std::make_unsigned_t<T>>(value));
        }
        return offset + Varint::encode(encoded_val, output, offset);
    }

    /**
     * @brief Serializes a string value.
     * @tparam T The string field value type (wrapper).
     * @param value The string value.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_string_value(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        auto sv = value.get();
        offset += Varint::encode(sv.size(), output, offset);
        std::memcpy(output.data() + offset, sv.data(), sv.size());
        return offset + sv.size();
    }

    /**
     * @brief Fixes up a length-prefixed field by encoding actual length and
     *        shifting content if needed.
     *
     * When serializing length-delimited content, we reserve Varint::max_size
     * for the length. After writing content, we encode the actual length and
     * shift the content back if the varint was smaller than reserved.
     *
     * @param output The output buffer.
     * @param len_offset Offset where the length varint should be written.
     * @param content_start Offset where content begins (after reserved space).
     * @param offset Current offset (end of content).
     * @return The updated offset after shifting.
     */
    [[nodiscard]] static constexpr std::size_t fixup_length_prefix(
        std::span<std::byte> output, std::size_t len_offset,
        std::size_t content_start, std::size_t offset) noexcept {
        const std::size_t content_size = offset - content_start;
        const std::size_t actual_len_varint_size = Varint::size(content_size);
        if (actual_len_varint_size < Varint::max_size) {
            const std::size_t shift = Varint::max_size - actual_len_varint_size;
            std::memmove(output.data() + len_offset + actual_len_varint_size,
                         output.data() + content_start, content_size);
            offset -= shift;
        }
        Varint::encode(content_size, output, len_offset);
        return offset;
    }

    /**
     * @brief Serializes a nested message value.
     * @tparam T The message type.
     * @param value The message to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename T>
    [[nodiscard]] static constexpr std::size_t serialize_nested_message(
        const T& value, std::span<std::byte> output,
        std::size_t offset) noexcept {
        const std::size_t len_offset = offset;
        offset += Varint::max_size;

        const std::size_t content_start = offset;
        const std::size_t msg_size = serialize_fields_helper(
            value.get_fields(), output.subspan(content_start), 0);
        offset += msg_size;

        return fixup_length_prefix(output, len_offset, content_start, offset);
    }

    /**
     * @brief Serializes array content (count + elements) without tag.
     * @tparam FieldT The array field type.
     * @param field The array field instance.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_array_content(
        const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        using ElemT = typename FieldT::ValueType;

        // Write element count
        offset += Varint::encode(field.size(), output, offset);

        // Serialize elements
        for (const auto& item : field) {
            if constexpr (Crunch::fields::is_scalar_v<ElemT>) {
                offset = serialize_scalar_value(item.get(), output, offset);
            } else if constexpr (Crunch::fields::is_string_v<ElemT>) {
                offset = serialize_string_value(item, output, offset);
            } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                     ElemT>) {
                offset = serialize_nested_message(item, output, offset);
            } else if constexpr (Crunch::messages::is_array_field_v<ElemT>) {
                offset = serialize_array_value(item, output, offset);
            } else if constexpr (Crunch::messages::is_map_field_v<ElemT>) {
                offset = serialize_map_value(item, output, offset);
            }
        }
        return offset;
    }

    /**
     * @brief Serializes an array value with length prefix but no tag.
     * @tparam FieldT The array field type.
     * @param field The array field instance.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_array_value(
        const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        const std::size_t len_offset = offset;
        offset += Varint::max_size;
        const std::size_t content_start = offset;

        offset = serialize_array_content(field, output, offset);

        return fixup_length_prefix(output, len_offset, content_start, offset);
    }

    /**
     * @brief Serializes an array field using packed encoding.
     *
     * All array types use the format:
     * [Tag][TotalLength][Count][Elem1][Elem2]...
     *
     * For length-delimited elements (strings, submessages), each element
     * includes its length prefix but NO tag.
     *
     * @tparam FieldT The array field type.
     * @param field The array field instance.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_array_field(
        const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        const FieldId id = field.field_id;
        offset = write_tag(id, WireType::LengthDelimited, output, offset);
        return serialize_array_value(field, output, offset);
    }

    /**
     * @brief Serializes a value without a tag (for use in packed containers).
     * @tparam FieldT The field type.
     * @param field The field to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_value_without_tag(
        const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        if constexpr (Crunch::fields::is_scalar_v<FieldT>) {
            return serialize_scalar_value(field.get(), output, offset);
        } else if constexpr (Crunch::fields::is_string_v<FieldT>) {
            return serialize_string_value(field, output, offset);
        } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                 FieldT>) {
            return serialize_nested_message(field, output, offset);
        } else if constexpr (Crunch::messages::is_array_field_v<FieldT>) {
            return serialize_array_value(field, output, offset);
        } else if constexpr (Crunch::messages::is_map_field_v<FieldT>) {
            return serialize_map_value(field, output, offset);
        }
        return offset;
    }

    /**
     * @brief Serializes map content (count + key-value pairs) without tag.
     * @tparam FieldT The map field type.
     * @param field The map field instance.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_map_content(
        const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        using KeyFieldT = typename FieldT::PairType::first_type;
        using ValueFieldT = typename FieldT::PairType::second_type;

        // Write entry count
        offset += Varint::encode(field.size(), output, offset);

        // Serialize key-value pairs without tags
        return std::accumulate(
            field.begin(), field.end(), offset,
            [&](std::size_t off, const auto& item) {
                off = serialize_value_without_tag<KeyFieldT>(item.first, output,
                                                             off);
                return serialize_value_without_tag<ValueFieldT>(item.second,
                                                                output, off);
            });
    }

    /**
     * @brief Serializes a map value with length prefix but no tag.
     * @tparam FieldT The map field type.
     * @param field The map field instance.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_map_value(
        const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        const std::size_t len_offset = offset;
        offset += Varint::max_size;
        const std::size_t content_start = offset;

        offset = serialize_map_content(field, output, offset);

        return fixup_length_prefix(output, len_offset, content_start, offset);
    }

    /**
     * @brief Serializes a map field using packed encoding.
     *
     * Map format:
     * [Tag][TotalLength][Count][Key1][Val1][Key2][Val2]...
     *
     * Keys and values are serialized without tags. Length-delimited types
     * (strings, submessages) include their length prefix.
     *
     * @tparam FieldT The map field type.
     * @param field The map field instance.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_map_field(
        const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        const FieldId id = field.field_id;
        offset = write_tag(id, WireType::LengthDelimited, output, offset);
        return serialize_map_value(field, output, offset);
    }

    /**
     * @brief Serializes a field based on its type.
     * @tparam FieldT The field type.
     * @param field The field instance.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_field(
        const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        bool is_set = false;
        if constexpr (Crunch::messages::is_array_field_v<FieldT> ||
                      Crunch::messages::is_map_field_v<FieldT>) {
            is_set = !field.empty();
        } else {
            is_set = field.set_;
        }

        if (!is_set) {
            return offset;
        }

        const FieldId id = field.field_id;

        if constexpr (Crunch::messages::is_array_field_v<FieldT>) {
            return serialize_array_field(field, output, offset);
        } else if constexpr (Crunch::messages::is_map_field_v<FieldT>) {
            return serialize_map_field(field, output, offset);
        } else {
            using ValueType = typename detail::ext<FieldT>::type;
            if constexpr (Crunch::fields::is_scalar_v<ValueType>) {
                offset = write_tag(id, WireType::Varint, output, offset);
                return serialize_scalar_value(field.value_.get(), output,
                                              offset);
            } else if constexpr (Crunch::fields::is_string_v<ValueType>) {
                offset =
                    write_tag(id, WireType::LengthDelimited, output, offset);
                return serialize_string_value(field.value_, output, offset);
            } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                     ValueType>) {
                offset =
                    write_tag(id, WireType::LengthDelimited, output, offset);
                return serialize_nested_message(field.value_, output, offset);
            }
        }
        return offset;
    }

    /**
     * @brief Helper to recursively serialize a tuple of fields.
     * @tparam Tuple The tuple type.
     * @tparam I The current index in the tuple.
     * @param t The tuple of fields.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename Tuple, std::size_t I = 0>
    [[nodiscard]] static constexpr std::size_t serialize_fields_helper(
        const Tuple& t, std::span<std::byte> output,
        std::size_t offset) noexcept {
        if constexpr (I < std::tuple_size_v<std::remove_cvref_t<Tuple>>) {
            offset = serialize_field(std::get<I>(t), output, offset);
            return serialize_fields_helper<Tuple, I + 1>(t, output, offset);
        }
        return offset;
    }

    /**
     * @brief Deserializes a single scalar element for an array.
     * @tparam ElemT The element type wrapper.
     * @param val_out Reference to store the deserialized value.
     * @param input The input buffer.
     * @param offset Reference to the current offset (updated on success).
     * @return std::nullopt on success, or Error.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_scalar_array(typename ElemT::ValueType& val_out,
                             std::span<const std::byte> input,
                             std::size_t& offset) noexcept {
        using T = typename ElemT::ValueType;
        const auto res = Varint::decode(input, offset);
        if (!res) {
            return Error::deserialization("invalid varint in packed");
        }
        offset += res->second;

        if constexpr (std::is_same_v<T, bool>) {
            val_out = (res->first != 0);
        } else if constexpr (std::is_floating_point_v<T>) {
            if constexpr (sizeof(T) == 4) {
                val_out = std::bit_cast<T>(static_cast<uint32_t>(res->first));
            } else {
                val_out = std::bit_cast<T>(res->first);
            }
        } else {
            val_out = std::bit_cast<T>(
                static_cast<std::make_unsigned_t<T>>(res->first));
        }
        return std::nullopt;
    }

    /**
     * @brief Reads and validates a length prefix from the input buffer.
     * @param input The input buffer.
     * @param offset Reference to the current offset (updated on success).
     * @param error_msg Error message if decoding fails.
     * @return Length on success, or Error.
     */
    [[nodiscard]] static constexpr std::expected<std::size_t, Error>
    read_length_prefix(std::span<const std::byte> input, std::size_t& offset,
                       const char* error_msg) noexcept {
        const auto len_res = Varint::decode(input, offset);
        if (!len_res) {
            return std::unexpected(Error::deserialization(error_msg));
        }
        offset += len_res->second;
        std::size_t len = static_cast<std::size_t>(len_res->first);
        if (offset + len > input.size()) {
            return std::unexpected(Error::deserialization("buffer underflow"));
        }
        return len;
    }

    /**
     * @brief Deserializes a scalar value (no tag).
     * @tparam ElemT The scalar element type.
     * @param val Output reference for the value.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_scalar_value(ElemT& val, std::span<const std::byte> input,
                             std::size_t& offset) noexcept {
        typename ElemT::ValueType scalar_val;
        if (const auto err =
                deserialize_scalar_array<ElemT>(scalar_val, input, offset)) {
            return err;
        }
        val.set_without_validation(scalar_val);
        return std::nullopt;
    }

    /**
     * @brief Deserializes a string value (no tag).
     * @tparam ElemT The string element type.
     * @param val Output reference for the value.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_string_value(ElemT& val, std::span<const std::byte> input,
                             std::size_t& offset) noexcept {
        auto len_result =
            read_length_prefix(input, offset, "invalid string length");
        if (!len_result) {
            return len_result.error();
        }
        std::size_t len = *len_result;
        std::string_view sv(
            reinterpret_cast<const char*>(input.data() + offset), len);
        offset += len;
        return val.set(sv);
    }

    /**
     * @brief Deserializes a nested message value (no tag).
     * @tparam ElemT The message element type.
     * @param val Output reference for the value.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_message_value(ElemT& val, std::span<const std::byte> input,
                              std::size_t& offset) noexcept {
        auto len_result =
            read_length_prefix(input, offset, "invalid message length");
        if (!len_result) {
            return len_result.error();
        }
        std::size_t len = *len_result;
        if (const auto err = deserialize_message_payload(
                input.subspan(offset, len), val, 0)) {
            return err;
        }
        offset += len;
        return std::nullopt;
    }

    /**
     * @brief Deserializes a nested array value (no tag).
     * @tparam ElemT The array element type.
     * @param val Output reference for the value.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::optional<Error> deserialize_array_value(
        ElemT& val, std::span<const std::byte> input,
        std::size_t& offset) noexcept {
        auto len_result =
            read_length_prefix(input, offset, "invalid array length");
        if (!len_result) {
            return len_result.error();
        }
        std::size_t len = *len_result;
        auto subspan = input.subspan(offset, len);
        std::size_t sub_offset = 0;
        if (const auto err =
                deserialize_array_elements(val, subspan, sub_offset, len)) {
            return err;
        }
        offset += len;
        return std::nullopt;
    }

    /**
     * @brief Deserializes a nested map value (no tag).
     * @tparam ElemT The map element type.
     * @param val Output reference for the value.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::optional<Error> deserialize_map_value(
        ElemT& val, std::span<const std::byte> input,
        std::size_t& offset) noexcept {
        auto len_result =
            read_length_prefix(input, offset, "invalid map length");
        if (!len_result) {
            return len_result.error();
        }
        std::size_t len = *len_result;
        auto subspan = input.subspan(offset, len);
        std::size_t sub_offset = 0;
        if (const auto err =
                deserialize_map_elements(val, subspan, sub_offset, len)) {
            return err;
        }
        offset += len;
        return std::nullopt;
    }

    /**
     * @brief Deserializes a value without a tag (for use in packed containers).
     * @tparam ElemT The element type.
     * @param val Output reference for the value.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_value_without_tag(ElemT& val, std::span<const std::byte> input,
                                  std::size_t& offset) noexcept {
        if constexpr (Crunch::fields::is_scalar_v<ElemT>) {
            return deserialize_scalar_value<ElemT>(val, input, offset);
        } else if constexpr (Crunch::fields::is_string_v<ElemT>) {
            return deserialize_string_value<ElemT>(val, input, offset);
        } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                 ElemT>) {
            return deserialize_message_value<ElemT>(val, input, offset);
        } else if constexpr (Crunch::messages::is_array_field_v<ElemT>) {
            return deserialize_array_value<ElemT>(val, input, offset);
        } else if constexpr (Crunch::messages::is_map_field_v<ElemT>) {
            return deserialize_map_value<ElemT>(val, input, offset);
        } else {
            std::unreachable();
        }
        return std::nullopt;
    }

    /**
     * @brief Deserializes array elements (after count is read).
     * @tparam FieldT The array field type.
     * @param field The field to populate.
     * @param input The input buffer (scoped to array content).
     * @param offset Reference to the current offset.
     * @param end_offset The end of content.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_array_elements(FieldT& field, std::span<const std::byte> input,
                               std::size_t& offset,
                               std::size_t end_offset) noexcept {
        using ElemT = typename FieldT::ValueType;

        // Read count
        const auto count_res = Varint::decode(input, offset);
        if (!count_res) {
            return Error::deserialization("invalid array count");
        }
        offset += count_res->second;
        const std::size_t count = static_cast<std::size_t>(count_res->first);

        // Deserialize elements
        for (std::size_t i = 0; i < count; ++i) {
            ElemT elem{};
            if (const auto err =
                    deserialize_value_without_tag<ElemT>(elem, input, offset)) {
                return err;
            }
            if constexpr (Crunch::fields::is_scalar_v<ElemT>) {
                if (const auto err = field.add(elem.get())) {
                    return err;
                }
            } else {
                if (const auto err = field.add(elem)) {
                    return err;
                }
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Deserializes a message payload from the input buffer.
     * @tparam Message The message type.
     * @param input The input buffer.
     * @param msg The message to populate.
     * @param offset The starting offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename Message>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_message_payload(std::span<const std::byte> input, Message& msg,
                                std::size_t offset) noexcept {
        while (offset < input.size()) {
            const auto tag_res = Varint::decode(input, offset);
            if (!tag_res) {
                return Error::deserialization("invalid tag varint");
            }
            const auto [tag, tag_bytes] = *tag_res;

            offset += tag_bytes;

            const uint32_t field_id =
                static_cast<uint32_t>(tag >> WireTypeBits);
            const WireType wire_type = static_cast<WireType>(tag & 0x07);

            bool found = false;
            std::optional<Error> err = visit_fields_tlv(
                msg.get_fields(), static_cast<FieldId>(field_id), wire_type,
                input, offset, found);

            if (err) {
                return err;
            }
            if (!found) {
                err.emplace(Error::deserialization("unknown fields present"));
                return err;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Deserializes an array field using packed encoding.
     *
     * Format: [TotalLength][Count][Elem1][Elem2]...
     *
     * @tparam FieldT The field type.
     * @param field The field to populate.
     * @param wire_type The wire type encountered.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error> deserialize_array_field(
        FieldT& field, WireType wire_type, std::span<const std::byte> input,
        std::size_t& offset) noexcept {
        if (wire_type != WireType::LengthDelimited) {
            return Error::deserialization("array must be length delimited");
        }

        // Read total length
        const auto len_res = Varint::decode(input, offset);
        if (!len_res) {
            return Error::deserialization("invalid array length");
        }
        offset += len_res->second;
        const std::size_t len = static_cast<std::size_t>(len_res->first);
        if (offset + len > input.size()) {
            return Error::deserialization("array underflow");
        }

        auto subspan = input.subspan(offset, len);
        std::size_t sub_offset = 0;
        if (const auto err =
                deserialize_array_elements(field, subspan, sub_offset, len)) {
            return err;
        }

        offset += len;
        return std::nullopt;
    }

    /**
     * @brief Deserializes a scalar field.
     * @tparam FieldT The field type.
     * @param field The field to populate.
     * @param wire_type The wire type encountered.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_scalar_field(FieldT& field, WireType wire_type,
                             std::span<const std::byte> input,
                             std::size_t& offset) noexcept {
        using ValueType = typename detail::ext<FieldT>::type;
        using T = typename ValueType::ValueType;

        if (wire_type != WireType::Varint) {
            return Error::deserialization("scalar must be varint");
        }

        const auto res = Varint::decode(input, offset);
        if (!res) {
            return Error::deserialization("invalid varint");
        }
        offset += res->second;

        T val;
        if constexpr (std::is_same_v<T, bool>) {
            val = (res->first != 0);
        } else if constexpr (std::is_floating_point_v<T>) {
            if constexpr (sizeof(T) == 4) {
                val = std::bit_cast<T>(static_cast<uint32_t>(res->first));
            } else {
                val = std::bit_cast<T>(res->first);
            }
        } else {
            val = std::bit_cast<T>(
                static_cast<std::make_unsigned_t<T>>(res->first));
        }
        // Deserialize will validate fields after the entire message is
        // deserialized
        field.set_without_validation(val);
        return std::nullopt;
    }

    /**
     * @brief Deserializes a string field.
     * @tparam FieldT The field type.
     * @param field The field to populate.
     * @param wire_type The wire type encountered.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_string_field(FieldT& field, WireType wire_type,
                             std::span<const std::byte> input,
                             std::size_t& offset) noexcept {
        if (wire_type != WireType::LengthDelimited) {
            return Error::deserialization("string requires length delimited");
        }

        const auto len_res = Varint::decode(input, offset);
        if (!len_res) {
            return Error::deserialization("invalid length");
        }
        offset += len_res->second;
        const std::size_t len = static_cast<std::size_t>(len_res->first);
        if (offset + len > input.size()) {
            return Error::deserialization("underflow");
        }

        const std::string_view sv(
            reinterpret_cast<const char*>(input.data() + offset), len);
        offset += len;
        if (const auto err = field.set(sv)) {
            return err;
        }
        return std::nullopt;
    }

    /**
     * @brief Deserializes a nested message field.
     * @tparam FieldT The field type.
     * @param field The field to populate.
     * @param wire_type The wire type encountered.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_nested_message_field(FieldT& field, WireType wire_type,
                                     std::span<const std::byte> input,
                                     std::size_t& offset) noexcept {
        if (wire_type != WireType::LengthDelimited) {
            return Error::deserialization(
                "nested msg requires length delimited");
        }

        const auto len_res = Varint::decode(input, offset);
        if (!len_res) {
            return Error::deserialization("invalid length");
        }
        offset += len_res->second;
        const std::size_t len = static_cast<std::size_t>(len_res->first);
        if (offset + len > input.size()) {
            return Error::deserialization("underflow");
        }

        if constexpr (Crunch::messages::HasCrunchMessageInterface<FieldT>) {
            if (const auto err = deserialize_message_payload(
                    input.subspan(offset, len), field, 0)) {
                return err;
            }
        } else {
            typename FieldT::FieldType temp;
            if (const auto err = deserialize_message_payload(
                    input.subspan(offset, len), temp, 0)) {
                return err;
            }
            // Messages cannot fail on set.
            field.set(temp);
        }
        offset += len;
        return std::nullopt;
    }

    /**
     * @brief Extracts the insertable value from a map entry field.
     * @tparam T The field type.
     * @param f The field to extract from.
     * @return The value suitable for MapField::insert().
     */
    template <typename T>
    [[nodiscard]] static constexpr auto extract_map_value(const T& f) noexcept
        -> decltype(auto) {
        if constexpr (Crunch::messages::is_array_field_v<T> ||
                      Crunch::messages::is_map_field_v<T> ||
                      Crunch::messages::HasCrunchMessageInterface<T>) {
            return f;
        } else {
            return f.get();
        }
    }

    /**
     * @brief Deserializes map elements (after count is read).
     * @tparam FieldT The map field type.
     * @param field The field to populate.
     * @param input The input buffer (scoped to map content).
     * @param offset Reference to the current offset.
     * @param end_offset The end of content.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_map_elements(FieldT& field, std::span<const std::byte> input,
                             std::size_t& offset,
                             std::size_t end_offset) noexcept {
        using KeyFieldT = typename FieldT::PairType::first_type;
        using ValueFieldT = typename FieldT::PairType::second_type;

        // Read count
        const auto count_res = Varint::decode(input, offset);
        if (!count_res) {
            return Error::deserialization("invalid map count");
        }
        offset += count_res->second;
        const std::size_t count = static_cast<std::size_t>(count_res->first);

        // Deserialize key-value pairs
        for (std::size_t i = 0; i < count; ++i) {
            KeyFieldT key_field{};
            ValueFieldT val_field{};

            if (const auto err = deserialize_value_without_tag<KeyFieldT>(
                    key_field, input, offset)) {
                return err;
            }
            if (const auto err = deserialize_value_without_tag<ValueFieldT>(
                    val_field, input, offset)) {
                return err;
            }

            if (const auto err = field.insert(extract_map_value(key_field),
                                              extract_map_value(val_field))) {
                return err;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Deserializes a map field using packed encoding.
     *
     * Format: [TotalLength][Count][Key1][Val1][Key2][Val2]...
     *
     * @tparam FieldT The map field type.
     * @param field The map field instance.
     * @param wire_type The wire type encountered.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error> deserialize_map_field(
        FieldT& field, WireType wire_type, std::span<const std::byte> input,
        std::size_t& offset) noexcept {
        if (wire_type != WireType::LengthDelimited) {
            return Error::deserialization("map must be length delimited");
        }

        // Read total length
        const auto len_res = Varint::decode(input, offset);
        if (!len_res) {
            return Error::deserialization("could not decode map length");
        }
        offset += len_res->second;
        const std::size_t len = static_cast<std::size_t>(len_res->first);
        if (offset + len > input.size()) {
            return Error::deserialization("map underflow");
        }

        auto subspan = input.subspan(offset, len);
        std::size_t sub_offset = 0;
        if (const auto err =
                deserialize_map_elements(field, subspan, sub_offset, len)) {
            return err;
        }

        offset += len;
        return std::nullopt;
    }

    /**
     * @brief Deserializes a field based on its type.
     * @tparam FieldT The field type.
     * @param field The field to populate.
     * @param wire_type The wire type encountered.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error> deserialize_field_value(
        FieldT& field, WireType wire_type, std::span<const std::byte> input,
        std::size_t& offset) noexcept {
        if constexpr (Crunch::messages::is_array_field_v<FieldT>) {
            return deserialize_array_field(field, wire_type, input, offset);
        } else if constexpr (Crunch::messages::is_map_field_v<FieldT>) {
            return deserialize_map_field(field, wire_type, input, offset);
        } else {
            using ValueType = typename detail::ext<FieldT>::type;
            if constexpr (Crunch::fields::is_scalar_v<ValueType>) {
                return deserialize_scalar_field(field, wire_type, input,
                                                offset);
            } else if constexpr (Crunch::fields::is_string_v<ValueType>) {
                return deserialize_string_field(field, wire_type, input,
                                                offset);
            } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                     ValueType>) {
                return deserialize_nested_message_field(field, wire_type, input,
                                                        offset);
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Recursive helper to visit fields in a tuple and find the matching
     * ID.
     * @tparam Tuple The tuple of fields.
     * @tparam I The current index in the tuple.
     * @param fields_tuple The tuple instance.
     * @param target_id The Field ID to look for.
     * @param wt The wire type encountered.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @param found Reference to a bool flag indicating if field was found.
     * @return std::nullopt on success (or not found yet), or Error.
     */
    template <typename Tuple, std::size_t I = 0>
    [[nodiscard]] static constexpr std::optional<Error> visit_fields_tlv(
        Tuple&& fields_tuple, FieldId target_id, WireType wt,
        std::span<const std::byte> input, std::size_t& offset,
        bool& found) noexcept {
        using TupleT = std::remove_cvref_t<Tuple>;
        if constexpr (I < std::tuple_size_v<TupleT>) {
            auto& f = std::get<I>(fields_tuple);
            if (f.field_id == target_id) {
                found = true;
                return deserialize_field_value(f, wt, input, offset);
            }
            return visit_fields_tlv<Tuple, I + 1>(
                std::forward<Tuple>(fields_tuple), target_id, wt, input, offset,
                found);
        }
        return std::nullopt;
    }
};

}  // namespace Crunch::serdes
