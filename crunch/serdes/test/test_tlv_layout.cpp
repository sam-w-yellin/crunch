#include <catch2/catch_test_macros.hpp>
#include <crunch_detail.hpp>
#include <crunch_field.hpp>
#include <crunch_messages.hpp>  // For macro
#include <crunch_string.hpp>
#include <crunch_tlv_layout.hpp>
#include <cstdint>
#include <span>
#include <tuple>
#include <vector>

using namespace Crunch;
using namespace Crunch::serdes;
using namespace Crunch::messages;

using namespace Crunch::fields;

struct TestMessage {
    static constexpr MessageId message_id = 999;

    Field<1, Optional, Int32<None>> opt_int;
    Field<2, Required, Int32<None>> req_int;
    Field<3, Optional, String<16, None>> opt_str;
    ArrayField<4, Int32<None>, 4, None> array_field;

    CRUNCH_MESSAGE_FIELDS(opt_int, req_int, opt_str, array_field);

    constexpr std::optional<Error> Validate() const { return std::nullopt; }

    bool operator==(const TestMessage& other) const {
        return get_fields() == other.get_fields();
    }
};

static constexpr std::size_t BufferSize = 128;

// Helper to create a basic valid serialization of TestMessage
// 4 byte header + 4 byte len + payload
std::vector<std::byte> create_valid_message_buffer(
    const std::vector<std::byte>& payload) {
    std::vector<std::byte> buffer;

    // TlvLayout::Deserialize expects the buffer to start with
    // StandardHeaderSize bytes, followed by a 4-byte length.
    buffer.resize(Crunch::StandardHeaderSize + sizeof(uint32_t) +
                  payload.size());
    std::fill(buffer.begin(), buffer.end(), std::byte{0});

    // Write length
    uint32_t len = static_cast<uint32_t>(payload.size());
    buffer[Crunch::StandardHeaderSize] = static_cast<std::byte>(len & 0xFF);
    buffer[Crunch::StandardHeaderSize + 1] =
        static_cast<std::byte>((len >> 8) & 0xFF);
    buffer[Crunch::StandardHeaderSize + 2] =
        static_cast<std::byte>((len >> 16) & 0xFF);
    buffer[Crunch::StandardHeaderSize + 3] =
        static_cast<std::byte>((len >> 24) & 0xFF);

    // Copy payload
    std::copy(payload.begin(), payload.end(),
              buffer.begin() + Crunch::StandardHeaderSize + sizeof(uint32_t));

    return buffer;
}

TEST_CASE("TLV: deserializing a message with an unknown field ID", "[tlv]") {
    TestMessage msg;

    // Payload: Tag(ID=5, Type=Varint) | Value(1)
    // ID=5 is unknown.
    // Tag = (5 << 3) | 0 = 40 = 0x28
    std::vector<std::byte> payload = {std::byte{0x28}, std::byte{0x01}};

    auto buffer = create_valid_message_buffer(payload);

    auto err = TlvLayout::Deserialize(std::span{buffer}, msg);
    REQUIRE(err.has_value());
    REQUIRE(err->message == "unknown fields present");
}

TEST_CASE("TLV: deserializing a message with a repeated field ID", "[tlv]") {
    TestMessage msg;

    // Payload:
    // Tag(ID=1, Type=Varint) | Value(10)
    // Tag(ID=1, Type=Varint) | Value(20)
    // ID=1 is opt_int.
    // Tag = (1 << 3) | 0 = 8 = 0x08
    std::vector<std::byte> payload = {std::byte{0x08}, std::byte{10},
                                      std::byte{0x08}, std::byte{20}};

    auto buffer = create_valid_message_buffer(payload);

    // Should succeed (last wins)
    auto err = TlvLayout::Deserialize(std::span{buffer}, msg);
    REQUIRE(!err.has_value());

    REQUIRE(msg.opt_int.get().has_value());
    REQUIRE(*msg.opt_int.get() == 20);
}

TEST_CASE("TLV: deserializing with truncated varint", "[tlv]") {
    TestMessage msg;

    // Payload: Tag(ID=1, Varint) ... then truncated value
    // Tag = 0x08
    // Value = 0x80 (Start of varint, needs more bytes)
    // But payload ends there.
    std::vector<std::byte> payload = {std::byte{0x08}, std::byte{0x80}};

    auto buffer = create_valid_message_buffer(payload);

    auto err = TlvLayout::Deserialize(std::span{buffer}, msg);
    REQUIRE(err.has_value());
    REQUIRE(err->message == "invalid varint");
}

TEST_CASE("TLV: Serialize unset field", "[tlv]") {
    TestMessage msg;
    REQUIRE_FALSE(msg.req_int.set(0x2A).has_value());
    // opt_int is unset

    std::array<std::byte, BufferSize> buffer;
    std::size_t offset = TlvLayout::Serialize(msg, buffer);

    // Inspect buffer
    // Skip header and length
    std::size_t payload_start = Crunch::StandardHeaderSize + sizeof(uint32_t);
    std::span<std::byte> payload =
        std::span{buffer}.subspan(payload_start, offset - payload_start);

    // Payload should contain ONLY req_int (ID=2)
    // Tag(2, Varint) = (2<<3)|0 = 16 = 0x10
    // Payload should be [0x10, 0x2A]

    REQUIRE(payload.size() == 2);
    REQUIRE(payload[0] == std::byte{0x10});
    REQUIRE(payload[1] == std::byte{0x2A});

    // Explicitly check that ID=1 (opt_int) tag (0x08) is NOT present
    for (auto b : payload) {
        REQUIRE(b != std::byte{0x08});
    }
}

TEST_CASE("TLV: Partial deserialization (Required vs Optional)", "[tlv]") {
    // Missing Optional Field -> OK, field unset
    {
        TestMessage msg;
        // Payload has only ID=2 (req_int)
        std::vector<std::byte> payload = {std::byte{0x10}, std::byte{42}};
        auto buffer = create_valid_message_buffer(payload);

        auto err = TlvLayout::Deserialize(std::span{buffer}, msg);
        REQUIRE(!err.has_value());

        REQUIRE(!msg.opt_int.get().has_value());  // Unset
        REQUIRE(msg.req_int.get().has_value());   // Set

        // Validation passes because req_int is set
        REQUIRE(!Crunch::detail::Validate(msg).has_value());
    }

    // Missing Required Field -> Deserialize OK, Validate Fails
    {
        TestMessage msg;
        // Payload has ONLY ID=1 (opt_int), missing ID=2 (req_int)
        // Tag(1, Varint) = 0x08, Value=10
        std::vector<std::byte> payload = {std::byte{0x08}, std::byte{10}};
        auto buffer = create_valid_message_buffer(payload);

        auto err = TlvLayout::Deserialize(std::span{buffer}, msg);

        // Deserialization itself succeeds (it just parses what's there)
        REQUIRE(!err.has_value());

        REQUIRE(msg.opt_int.get().has_value());
        REQUIRE(!msg.req_int.get().has_value());  // Missing

        // Validation FAILS because req_int is Required but unset
        REQUIRE(Crunch::detail::Validate(msg).has_value());
    }
}

struct MessageWithZeroId {
    static constexpr MessageId message_id = 1000;
    Field<0, Optional, Int32<None>> zero_int;

    CRUNCH_MESSAGE_FIELDS(zero_int);

    constexpr std::optional<Error> Validate() const { return std::nullopt; }

    bool operator==(const MessageWithZeroId& other) const {
        return get_fields() == other.get_fields();
    }
};

TEST_CASE("TLV: Field ID 0", "[tlv]") {
    MessageWithZeroId msg;

    // Payload: Tag(ID=0, Type=Varint) | Value(123)
    // Tag = (0 << 3) | 0 = 0x00
    std::vector<std::byte> payload = {std::byte{0x00}, std::byte{0x7B}};

    auto buffer = create_valid_message_buffer(payload);

    auto err = TlvLayout::Deserialize(std::span{buffer}, msg);
    REQUIRE(!err.has_value());

    REQUIRE(msg.zero_int.get().has_value());
    REQUIRE(*msg.zero_int.get() == 0x7B);
}

TEST_CASE("TLV: Unknown Wire Type", "[tlv]") {
    TestMessage msg;

    // Payload: Tag(ID=1, Type=7) | Value...
    // ID=1 is opt_int (Scalar, expects Varint=0)
    // Tag = (1 << 3) | 7 = 8 | 7 = 15 = 0x0F
    std::vector<std::byte> payload = {std::byte{0x0F}, std::byte{10}};

    auto buffer = create_valid_message_buffer(payload);

    auto err = TlvLayout::Deserialize(std::span{buffer}, msg);
    REQUIRE(err.has_value());
    // Expect failure because Scalar expects Varint
    REQUIRE(err->message == "scalar must be varint");
}

TEST_CASE("TLV: Payload Length Exceeds Buffer", "[tlv]") {
    TestMessage msg;

    // Payload: Tag(ID=2, Type=Varint) | Value(42)
    // Tag = 0x10, Value=0x2A
    std::vector<std::byte> payload = {std::byte{0x10}, std::byte{0x2A}};

    auto buffer = create_valid_message_buffer(payload);

    // Manually increase the declared length in the header
    std::size_t len_offset = Crunch::StandardHeaderSize;
    uint32_t fake_len = 100;
    buffer[len_offset] = static_cast<std::byte>(fake_len & 0xFF);
    buffer[len_offset + 1] = static_cast<std::byte>((fake_len >> 8) & 0xFF);
    buffer[len_offset + 2] = static_cast<std::byte>((fake_len >> 16) & 0xFF);
    buffer[len_offset + 3] = static_cast<std::byte>((fake_len >> 24) & 0xFF);

    auto err = TlvLayout::Deserialize(std::span{buffer}, msg);
    REQUIRE(err.has_value());
    REQUIRE(err->message == "tlv length exceeds buffer");
}

TEST_CASE("TLV: Interspersed Array Fields", "[tlv]") {
    TestMessage msg;

    // Buffer construction:
    // 1. Tag(4, Varint) -> Value 10 (Field 4 = array_field)
    // 2. Tag(2, Varint) -> Value 99 (Field 2 = req_int)
    // 3. Tag(4, Varint) -> Value 20 (Field 4 = array_field)

    // Tag(4, Varint) = (4 << 3) | 0 = 32 (0x20)
    // Tag(2, Varint) = (2 << 3) | 0 = 16 (0x10)

    std::vector<std::byte> payload;

    // Field 4: 10
    payload.push_back(std::byte{0x20});
    payload.push_back(std::byte{10});

    // Field 2: 99
    payload.push_back(std::byte{0x10});
    payload.push_back(std::byte{99});

    // Field 4: 20
    payload.push_back(std::byte{0x20});
    payload.push_back(std::byte{20});

    auto buffer = create_valid_message_buffer(payload);

    auto err = TlvLayout::Deserialize(std::span{buffer}, msg);
    REQUIRE(!err.has_value());

    // Check Field 2 (req_int)
    REQUIRE(msg.req_int.get() == 99);

    // Check Field 4 (Array) - should have BOTH 10 and 20
    REQUIRE(msg.array_field.size() == 2);
    REQUIRE(msg.array_field[0].get() == 10);
    REQUIRE(msg.array_field[1].get() == 20);
}
