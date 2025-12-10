#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>
#include <crunch.hpp>
#include <crunch_messages.hpp>
#include <crunch_scalar.hpp>
#include <crunch_tlv_layout.hpp>

using namespace Crunch;
using namespace Crunch::messages;
using namespace Crunch::fields;
// using namespace Crunch::validators; // Invalid namespace

struct MyMessage {
    CRUNCH_MESSAGE_FIELDS(f1, f2);
    static constexpr MessageId message_id = 0x12345678;

    // Field defines ID and Presence. Inner Type defines Data and Validators.
    Field<1, Required, Int32<Positive>> f1;
    Field<2, Optional, Int16<None>> f2;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }

    bool operator==(const MyMessage&) const = default;
};

TEMPLATE_TEST_CASE("End-to-End Serialization", "[e2e]", serdes::PackedLayout,
                   serdes::TlvLayout) {
    MyMessage msg;
    REQUIRE_FALSE(msg.f1.set(42).has_value());
    REQUIRE_FALSE(msg.f1.Validate().has_value());
    REQUIRE_FALSE(msg.f2.set(static_cast<int16_t>(-15)).has_value());
    REQUIRE_FALSE(msg.f2.Validate().has_value());

    auto buffer = GetBuffer<MyMessage, integrity::CRC16, TestType>();

    static_cast<void>(Serialize(buffer, msg));

    MyMessage msg2;
    auto result = Deserialize(buffer, msg2);
    REQUIRE(!result.has_value());

    REQUIRE(msg2.f1 == msg.f1);
    REQUIRE(msg2.f2 == msg.f2);
    REQUIRE(msg2.f1.get().value() == 42);  // Field.get() returns optional
    REQUIRE(msg2.f2.get().value() == -15);
    REQUIRE(msg == msg2);
}

TEMPLATE_TEST_CASE("Deserialize Output Param", "[e2e]", serdes::PackedLayout,
                   serdes::TlvLayout) {
    MyMessage msg;
    REQUIRE_FALSE(msg.f1.set(123).has_value());
    auto buffer = GetBuffer<MyMessage, integrity::CRC16, TestType>();
    static_cast<void>(Serialize(buffer, msg));

    MyMessage out_msg;
    auto result = Deserialize(buffer, out_msg);
    REQUIRE(!result.has_value());
    REQUIRE(out_msg == msg);
}

TEST_CASE("Aligned Layout Check", "[e2e]") {
    using AlignedIntegrity = integrity::None;
    using AlignedSerdes = serdes::Aligned32Layout;

    MyMessage msg;
    REQUIRE_FALSE(msg.f1.set(0x11223344).has_value());
    REQUIRE_FALSE(msg.f2.set(static_cast<int16_t>(0x5566)).has_value());

    auto buffer = GetBuffer<MyMessage, AlignedIntegrity, AlignedSerdes>();

    // Layout check:
    // Header(5). Align4 -> Start at 8. Padding [5,6].
    // MsgId(4) at 8 -> 12.
    // f1: is_set at 12. Align4 for int32 value causes padding [13,14,15]. Value
    // at 16. f2: is_set at 20. Align2 for int16 value causes padding [21].
    // Value at 22.

    static_cast<void>(Serialize(buffer, msg));

    REQUIRE(buffer.data.size() == 20);
    REQUIRE(buffer.data[2] == std::byte{0});   // Header padding
    REQUIRE(buffer.data[9] == std::byte{0});   // f1 padding
    REQUIRE(buffer.data[17] == std::byte{0});  // f2 padding
}

struct OtherMessage {
    CRUNCH_MESSAGE_FIELDS(f1);
    static constexpr MessageId message_id = 0x77654321;
    Field<1, Optional, Int32<None>> f1;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const OtherMessage&) const = default;
};

TEST_CASE("Serialization Format Verification (E2E)", "[e2e]") {
    // 1. Format Mismatch
    auto packed_buffer =
        GetBuffer<MyMessage, integrity::None, serdes::PackedLayout>();
    MyMessage msg;
    REQUIRE_FALSE(msg.f1.set(1).has_value());
    static_cast<void>(Serialize(packed_buffer, msg));

    auto aligned_buffer =
        GetBuffer<MyMessage, integrity::None, serdes::Aligned32Layout>();
    std::copy(packed_buffer.data.begin(), packed_buffer.data.end(),
              aligned_buffer.data.begin());
    aligned_buffer.used_bytes = packed_buffer.used_bytes;

    MyMessage out_msg;
    auto res1 = Deserialize(aligned_buffer, out_msg);
    REQUIRE(res1.has_value());
    REQUIRE(res1.value() == Error::invalid_format());

    // 2. Message ID Mismatch
    auto other_buffer =
        GetBuffer<OtherMessage, integrity::None, serdes::PackedLayout>();
    const std::size_t bytes_to_copy =
        std::min(packed_buffer.data.size(), other_buffer.data.size());
    std::copy(packed_buffer.data.begin(),
              packed_buffer.data.begin() + bytes_to_copy,
              other_buffer.data.begin());
    other_buffer.used_bytes = packed_buffer.used_bytes;

    OtherMessage other_msg;
    auto res2 = Deserialize(other_buffer, other_msg);
    REQUIRE(res2.has_value());
    REQUIRE(res2.value() == Error::invalid_message_id());
}
