#include <catch2/catch_test_macros.hpp>
#include <crunch/crunch.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/messages/crunch_messages.hpp>

using namespace Crunch;
using namespace Crunch::messages;
using namespace Crunch::fields;

// Test message types with unique IDs
struct MessageA {
    static constexpr MessageId message_id = 0x0001;
    Field<1, Required, Int32<None>> value;
    CRUNCH_MESSAGE_FIELDS(value);
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const MessageA&) const = default;
};

struct MessageB {
    static constexpr MessageId message_id = 0x0002;
    Field<1, Required, Int16<None>> value;
    CRUNCH_MESSAGE_FIELDS(value);
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const MessageB&) const = default;
};

struct MessageC {
    static constexpr MessageId message_id = 0x0003;
    Field<1, Optional, Int32<None>> value;
    CRUNCH_MESSAGE_FIELDS(value);
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const MessageC&) const = default;
};

using TestDecoder = Decoder<serdes::PackedLayout, integrity::None, MessageA,
                            MessageB, MessageC>;
// Static assertions for UniqueMessageIds concept
struct DuplicateA {
    static constexpr MessageId message_id = 0x0001;  // Same as MessageA
};

// Positive: Unique message IDs should satisfy the concept
static_assert(detail::UniqueMessageIds<MessageA, MessageB, MessageC>,
              "Unique message IDs should satisfy UniqueMessageIds");

// Negative: Duplicate message IDs should NOT satisfy the concept
static_assert(!detail::UniqueMessageIds<MessageA, DuplicateA>,
              "Duplicate message IDs should not satisfy UniqueMessageIds");
static_assert(!detail::UniqueMessageIds<MessageA, MessageB, DuplicateA>,
              "Duplicate message IDs should not satisfy UniqueMessageIds");

TEST_CASE("Decoder: Decode returns error for buffer too small", "[decoder]") {
    TestDecoder decoder;
    TestDecoder::VariantType msg;
    std::array<std::byte, 2> small_buffer{};  // Less than header size

    auto result = decoder.Decode(std::span{small_buffer}, msg);
    REQUIRE(result.has_value());
    REQUIRE(result->message == "buffer too small for header");
}

TEST_CASE("Decoder: Decode returns error for unknown message ID", "[decoder]") {
    TestDecoder decoder;
    TestDecoder::VariantType msg;

    // Create a buffer with a valid header but unknown message ID
    std::array<std::byte, StandardHeaderSize + 10> buffer{};

    // Write header manually
    buffer[0] = static_cast<std::byte>(CrunchVersion);
    buffer[1] = static_cast<std::byte>(serdes::PackedLayout::GetFormat());

    // Write an unknown message ID (0x9999)
    MessageId unknown_id = LittleEndian(static_cast<MessageId>(0x0999));
    std::memcpy(buffer.data() + 2, &unknown_id, sizeof(MessageId));

    auto result = decoder.Decode(std::span{buffer}, msg);
    REQUIRE(result.has_value());
    REQUIRE(result->code == ErrorCode::InvalidMessageId);
}

TEST_CASE("Decoder: Decode successfully deserializes MessageA", "[decoder]") {
    // First serialize a MessageA
    MessageA src;
    REQUIRE_FALSE(src.value.set(42).has_value());

    auto src_buffer =
        GetBuffer<MessageA, integrity::None, serdes::PackedLayout>();
    static_cast<void>(Serialize(src_buffer, src));

    // Now decode it
    TestDecoder decoder;
    TestDecoder::VariantType msg;
    auto result = decoder.Decode(src_buffer.serialized_message_span(), msg);

    REQUIRE_FALSE(result.has_value());
    REQUIRE(std::holds_alternative<MessageA>(msg));
    REQUIRE(std::get<MessageA>(msg).value.get().value() == 42);
}

TEST_CASE("Decoder: Decode successfully deserializes MessageB", "[decoder]") {
    // First serialize a MessageB
    MessageB src;
    REQUIRE_FALSE(src.value.set(static_cast<int16_t>(123)).has_value());

    auto src_buffer =
        GetBuffer<MessageB, integrity::None, serdes::PackedLayout>();
    static_cast<void>(Serialize(src_buffer, src));

    // Now decode it
    TestDecoder decoder;
    TestDecoder::VariantType msg;
    auto result = decoder.Decode(src_buffer.serialized_message_span(), msg);

    REQUIRE_FALSE(result.has_value());
    REQUIRE(std::holds_alternative<MessageB>(msg));
    REQUIRE(std::get<MessageB>(msg).value.get().value() == 123);
}

TEST_CASE("Decoder: Decode returns correct variant type based on message ID",
          "[decoder]") {
    TestDecoder decoder;

    // Serialize MessageA
    MessageA srcA;
    REQUIRE_FALSE(srcA.value.set(100).has_value());
    auto bufferA = GetBuffer<MessageA, integrity::None, serdes::PackedLayout>();
    static_cast<void>(Serialize(bufferA, srcA));

    // Serialize MessageC
    MessageC srcC;
    REQUIRE_FALSE(srcC.value.set(200).has_value());
    auto bufferC = GetBuffer<MessageC, integrity::None, serdes::PackedLayout>();
    static_cast<void>(Serialize(bufferC, srcC));

    // Decode should return correct types
    TestDecoder::VariantType msgA;
    auto resultA = decoder.Decode(bufferA.serialized_message_span(), msgA);
    REQUIRE_FALSE(resultA.has_value());
    REQUIRE(std::holds_alternative<MessageA>(msgA));
    REQUIRE_FALSE(std::holds_alternative<MessageB>(msgA));
    REQUIRE_FALSE(std::holds_alternative<MessageC>(msgA));

    TestDecoder::VariantType msgC;
    auto resultC = decoder.Decode(bufferC.serialized_message_span(), msgC);
    REQUIRE_FALSE(resultC.has_value());
    REQUIRE(std::holds_alternative<MessageC>(msgC));
    REQUIRE_FALSE(std::holds_alternative<MessageA>(msgC));
    REQUIRE_FALSE(std::holds_alternative<MessageB>(msgC));
}
