#include <catch2/catch_test_macros.hpp>
#include <crunch/crunch.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/messages/crunch_messages.hpp>
#include <crunch/validators/crunch_validators.hpp>
#include <cstring>

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

TEST_CASE("Deserialize Validation Failure", "[validation]") {
    static auto buffer =
        GetBuffer<MyMessage, integrity::CRC16, serdes::PackedLayout>();
    MyMessage msg;
    REQUIRE_FALSE(msg.f1.set(1).has_value());
    static_cast<void>(Serialize(buffer, msg));

    static auto no_int_buffer =
        GetBuffer<MyMessage, integrity::None, serdes::PackedLayout>();
    static_cast<void>(Serialize(no_int_buffer, msg));

    // Corrupt f1 value to -1 (0xFFFFFFFF)
    // Layout: Header(5) + MsgID(4) = 9.
    // f1 is_set = 1 byte (index 9).
    // f1 value = 4 bytes (index 10).
    std::memset(no_int_buffer.data.data() + 10, 0xFF, 4);

    MyMessage out_msg;
    auto result = Deserialize(no_int_buffer, out_msg);
    REQUIRE(result.has_value());
    REQUIRE(result.value().code == ErrorCode::ValidationFailed);
}

// Cross-field validation
struct CrossFieldMessage {
    CRUNCH_MESSAGE_FIELDS(mode, value);
    static constexpr MessageId message_id = 0x9999;
    Field<1, Required, Int8<None>> mode;
    Field<2, Required, Int32<Positive>> value;

    constexpr auto Validate() const -> std::optional<Error> {
        auto mode_opt = mode.get();
        auto value_opt = value.get();
        if (mode_opt.has_value() && *mode_opt == 1 && *value_opt <= 100) {
            return Error::validation(2, "mode 1 requires value > 100");
        }
        return std::nullopt;
    }
    bool operator==(const CrossFieldMessage&) const = default;
};

TEST_CASE("Cross-Field Validation", "[validation]") {
    CrossFieldMessage msg;
    REQUIRE_FALSE(msg.mode.set(static_cast<int8_t>(1)).has_value());
    REQUIRE_FALSE(msg.value.set(50).has_value());  // Invalid

    auto buffer =
        GetBuffer<CrossFieldMessage, integrity::None, serdes::PackedLayout>();
    auto err = Serialize(buffer, msg);
    REQUIRE(err.has_value());
    REQUIRE(err.value().field_id == 2);

    REQUIRE_FALSE(msg.value.set(150).has_value());
    err = Serialize(buffer, msg);
    REQUIRE(!err.has_value());
}

struct SetMessage {
    CRUNCH_MESSAGE_FIELDS(val);
    static constexpr MessageId message_id = 0x8888;
    Field<1, Required, Int32<Positive>> val;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const SetMessage&) const = default;
};

TEST_CASE("Set API Validation", "[validation]") {
    SetMessage msg;

    REQUIRE_FALSE(msg.val.get().has_value());

    // Invalid Set -> Should return Error and NOT update presence/value
    auto err = msg.val.set(-1);
    REQUIRE(err.has_value());
    REQUIRE(err->code == ErrorCode::ValidationFailed);
    REQUIRE_FALSE(msg.val.get().has_value());

    //  Valid Set -> Should succeed
    err = msg.val.set(10);
    REQUIRE_FALSE(err.has_value());
    REQUIRE(msg.val.get().value() == 10);

    // Set Without Validation -> Should succeed (bypass logic)
    // -1 is logically invalid (Positive) but we bypass it.
    msg.val.set_without_validation(-1);

    REQUIRE(msg.val.get().value() == -1);

    // Subsequent Validate() on field should fail (manual check)
    REQUIRE(msg.val.Validate().has_value());
}
