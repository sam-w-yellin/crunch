#pragma once

#include <bit>
#include <crunch_endian.hpp>
#include <crunch_field.hpp>
#include <crunch_messages.hpp>
#include <crunch_scalar.hpp>
#include <crunch_string.hpp>
#include <crunch_types.hpp>
#include <crunch_varint.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
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
     *
     * This implementation uses `std::index_sequence` and a fold expression to
     * iterate over the tuple of fields and calculate the maximum size for each
     * field type. This is necessary to avoid "constexpr loop" or circular
     * dependency issues that can arise when calculating sizes for mutually
     * recursive data structures (e.g., a Message containing a Field of its own
     * type) within the class scope.
     */
    template <typename Tuple, std::size_t... Is>
    [[nodiscard]] static constexpr std::size_t sum_fields_impl(
        std::index_sequence<Is...>) noexcept {
        return (calculate_max_field_size_type<
                    std::remove_cvref_t<std::tuple_element_t<Is, Tuple>>>() +
                ... + 0);
    }

    template <typename Tuple>
    [[nodiscard]] static constexpr std::size_t sum_fields_helper() noexcept {
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
    [[nodiscard]] static constexpr std::size_t
    calculate_max_message_size() noexcept {
        using FieldsTuple = decltype(std::declval<Message>().get_fields());
        return sum_fields_helper<FieldsTuple>();
    }

    /**
     * @brief Calculates the maximum size of an array field.
     * @tparam ElemT The element type of the array.
     * @param max_elements The maximum number of elements in the array.
     * @return The maximum size in bytes.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::size_t calculate_max_array_field_size(
        std::size_t max_elements) noexcept {
        constexpr std::size_t TagSize = Varint::max_varint_size(MaxTagBits);
        if constexpr (Crunch::fields::is_scalar_v<ElemT>) {
            // Packed Encoding for Scalars:
            // [Tag][Length][Value1][Value2]...
            // Only ONE Tag and ONE Length prefix for the entire array.
            // We cannot use calculate_max_scalar_field_size() because that
            // would include a Tag per element.
            return TagSize + Varint::max_size +
                   (max_elements * Varint::max_size);
        } else {
            // Repeated Encoding for Strings and Messages:
            // [Tag][Value1][Tag][Value2]...
            // Each element acts as an independent field with its own Tag.
            if constexpr (Crunch::fields::is_string_v<ElemT>) {
                return max_elements * calculate_max_string_field_size<ElemT>();
            } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                     ElemT>) {
                return max_elements *
                       calculate_max_nested_message_field_size<ElemT>();
            }
            std::unreachable();
        }
    }

    /**
     * @brief Calculates the maximum size of a scalar field.
     * @tparam ScalarT The scalar type.
     * @return The maximum size in bytes.
     */
    template <typename ScalarT>
    [[nodiscard]] static constexpr std::size_t
    calculate_max_scalar_field_size() noexcept {
        constexpr std::size_t TagSize = Varint::max_varint_size(MaxTagBits);
        return TagSize + Varint::max_size;
    }

    /**
     * @brief Calculates the maximum size of a string field.
     * @tparam StringT The string type.
     * @return The maximum size in bytes.
     */
    template <typename StringT>
    [[nodiscard]] static constexpr std::size_t
    calculate_max_string_field_size() noexcept {
        constexpr std::size_t TagSize = Varint::max_varint_size(MaxTagBits);
        return TagSize + Varint::max_size + StringT::max_size;
    }

    /**
     * @brief Calculates the maximum size of a nested message field.
     * @tparam MsgT The nested message type.
     * @return The maximum size in bytes.
     */
    template <typename MsgT>
    [[nodiscard]] static constexpr std::size_t
    calculate_max_nested_message_field_size() noexcept {
        constexpr std::size_t TagSize = Varint::max_varint_size(MaxTagBits);
        return TagSize + Varint::max_size + calculate_max_message_size<MsgT>();
    }

    /**
     * @brief Calculates the maximum size of a field based on its type.
     * @tparam FieldT The field type.
     * @return The maximum size in bytes.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t
    calculate_max_field_size_type() noexcept {
        if constexpr (Crunch::messages::is_array_field_v<FieldT>) {
            return calculate_max_array_field_size<typename FieldT::ValueType>(
                FieldT::max_size);
        } else {
            using ValueType = typename FieldT::FieldType;
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

        const std::size_t msg_start = offset;
        const std::size_t msg_size = serialize_fields_helper(
            value.get_fields(), output.subspan(msg_start), 0);
        offset += msg_size;

        const std::size_t actual_len_varint_size = Varint::size(msg_size);
        if (actual_len_varint_size < Varint::max_size) {
            std::size_t shift = Varint::max_size - actual_len_varint_size;
            std::memmove(output.data() + len_offset + actual_len_varint_size,
                         output.data() + msg_start, msg_size);
            offset -= shift;
        }
        Varint::encode(msg_size, output, len_offset);
        return offset;
    }

    /**
     * @brief Serializes a packed array field.
     * @tparam FieldT The array field type.
     * @param id The field ID.
     * @param field The array field instance.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::size_t serialize_packed_array(
        FieldId id, const FieldT& field, std::span<std::byte> output,
        std::size_t offset) noexcept {
        offset = write_tag(id, WireType::LengthDelimited, output, offset);

        const std::size_t len_offset = offset;
        // Reserve maximum space for the length varint (10 bytes).
        // We do this to avoid a second pass over the data to calculate the
        // size. If the actual length takes fewer bytes, we will memmove the
        // content back. Note: memmove is required because the source and
        // destination regions overlap.
        offset += Varint::max_size;
        const std::size_t content_start = offset;

        for (auto& item : field) {
            offset = serialize_scalar_value(item.get(), output, offset);
        }

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
     * @brief Serializes a single element of a repeated (unpacked) array.
     * @tparam ElemT The element type.
     * @param id The field ID.
     * @param item The element to serialize.
     * @param output The output buffer.
     * @param offset The current offset.
     * @return The updated offset.
     */
    template <typename ElemT>
    [[nodiscard]] static constexpr std::size_t
    serialize_repeated_unpacked_element(FieldId id, const ElemT& item,
                                        std::span<std::byte> output,
                                        std::size_t offset) noexcept {
        if constexpr (Crunch::fields::is_string_v<ElemT>) {
            offset = write_tag(id, WireType::LengthDelimited, output, offset);
            return serialize_string_value(item, output, offset);
        } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                 ElemT>) {
            offset = write_tag(id, WireType::LengthDelimited, output, offset);
            return serialize_nested_message(item, output, offset);
        }
        return offset;
    }

    /**
     * @brief Serializes an array field.
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
        using ElemT = typename FieldT::ValueType;
        const FieldId id = field.field_id;

        if constexpr (Crunch::fields::is_scalar_v<ElemT>) {
            // Packed
            return serialize_packed_array(id, field, output, offset);
        } else {
            // Repeated
            for (auto& item : field) {
                offset = serialize_repeated_unpacked_element(id, item, output,
                                                             offset);
            }
        }
        return offset;
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
        if constexpr (Crunch::messages::is_array_field_v<FieldT>) {
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
        } else {
            using ValueType = typename FieldT::FieldType;
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
     * @brief Deserializes a packed array of scalars.
     * @tparam FieldT The field type.
     * @param field The field to populate.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_packed_array(FieldT& field, std::span<const std::byte> input,
                             std::size_t& offset) noexcept {
        using ElemT = typename FieldT::ValueType;
        const auto len_res = Varint::decode(input, offset);
        if (!len_res) {
            return Error::deserialization("invalid length");
        }
        offset += len_res->second;
        const std::size_t len = static_cast<std::size_t>(len_res->first);
        const std::size_t end = offset + len;
        if (end > input.size()) {
            return Error::deserialization("underflow");
        }

        while (offset < end) {
            typename ElemT::ValueType val;
            if (const auto err =
                    deserialize_scalar_array<ElemT>(val, input, offset)) {
                return err;
            }
            if (const auto err = field.add(val)) {
                return err;
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
     * @brief Deserializes a repeated array (non-packed scalars or complex
     * types).
     * @tparam FieldT The field type.
     * @param field The field to populate.
     * @param wire_type The wire type encountered.
     * @param input The input buffer.
     * @param offset Reference to the current offset.
     * @return std::nullopt on success, or Error.
     */
    template <typename FieldT>
    [[nodiscard]] static constexpr std::optional<Error>
    deserialize_repeated_array(FieldT& field, WireType wire_type,
                               std::span<const std::byte> input,
                               std::size_t& offset) noexcept {
        using ElemT = typename FieldT::ValueType;
        if constexpr (Crunch::fields::is_scalar_v<ElemT>) {
            if (wire_type != WireType::Varint) {
                return Error::deserialization(
                    "scalar array element must be varint if not packed");
            }
            typename ElemT::ValueType val;
            if (const auto err =
                    deserialize_scalar_array<ElemT>(val, input, offset)) {
                return err;
            }
            if (const auto err = field.add(val)) {
                return err;
            }
        } else if constexpr (Crunch::fields::is_string_v<ElemT>) {
            const auto len_res = Varint::decode(input, offset);
            if (!len_res) {
                return Error::deserialization("invalid length");
            }
            offset += len_res->second;
            std::size_t len = static_cast<std::size_t>(len_res->first);
            std::string_view sv(
                reinterpret_cast<const char*>(input.data() + offset), len);
            offset += len;
            if (const auto err = field.add(ElemT{sv})) {
                return err;
            }
        } else if constexpr (Crunch::messages::HasCrunchMessageInterface<
                                 ElemT>) {
            const auto len_res = Varint::decode(input, offset);
            if (!len_res) {
                return Error::deserialization("invalid length");
            }
            offset += len_res->second;
            std::size_t len = static_cast<std::size_t>(len_res->first);
            using MsgT = ElemT;
            MsgT temp;
            if (const auto err = deserialize_message_payload(
                    input.subspan(offset, len), temp, 0)) {
                return err;
            }
            offset += len;
            if (const auto err = field.add(temp)) {
                return err;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Deserializes an array field (dispatch to packed or repeated).
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
        using ElemT = typename FieldT::ValueType;
        if constexpr (Crunch::fields::is_scalar_v<ElemT>) {
            const bool is_packed = (wire_type == WireType::LengthDelimited);
            if (is_packed) {
                return deserialize_packed_array(field, input, offset);
            }
        }
        return deserialize_repeated_array(field, wire_type, input, offset);
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
        using ValueType = typename FieldT::FieldType;
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

        typename FieldT::FieldType temp;
        if (const auto err = deserialize_message_payload(
                input.subspan(offset, len), temp, 0)) {
            return err;
        }
        // Messages cannot fail on set.
        field.set(temp);
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
        } else {
            using ValueType = typename FieldT::FieldType;
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
