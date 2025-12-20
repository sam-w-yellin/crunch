#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>
#include <crunch/crunch.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/messages/crunch_messages.hpp>
#include <crunch/serdes/crunch_tlv_layout.hpp>

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

TEMPLATE_TEST_CASE("Integrity Failure", "[integrity]", serdes::PackedLayout,
                   serdes::TlvLayout) {
    MyMessage msg;
    REQUIRE_FALSE(msg.f1.set(10).has_value());
    auto buffer = GetBuffer<MyMessage, integrity::CRC16, TestType>();
    static_cast<void>(Serialize(buffer, msg));

    // Tamper with data (Checksum is at end of USED bytes)
    buffer.data[buffer.used_bytes - 3] = static_cast<std::byte>(0xFF);

    auto result = Deserialize(buffer, msg);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == Error::integrity());
}

TEMPLATE_TEST_CASE("Parity Integrity", "[integrity]", serdes::PackedLayout,
                   serdes::TlvLayout) {
    MyMessage msg;
    REQUIRE_FALSE(msg.f1.set(10).has_value());

    auto buffer = GetBuffer<MyMessage, integrity::Parity, TestType>();
    static_cast<void>(Serialize(buffer, msg));

    MyMessage out_msg;
    auto result = Deserialize(buffer, out_msg);
    REQUIRE(!result.has_value());
    REQUIRE(out_msg == msg);

    // Flip a bit in the header/payload
    buffer.data[0] ^= std::byte{0xFF};
    auto err_result = Deserialize(buffer, out_msg);
    REQUIRE(err_result.has_value());
    REQUIRE(err_result.value() == Error::integrity());
}
