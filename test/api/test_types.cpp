#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cmath>
#include <crunch/crunch.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/fields/crunch_string.hpp>
#include <crunch/messages/crunch_messages.hpp>
#include <crunch/serdes/crunch_tlv_layout.hpp>

using namespace Crunch;
using namespace Crunch::messages;
using namespace Crunch::fields;
using namespace Crunch::serdes;

struct FloatMessage {
    CRUNCH_MESSAGE_FIELDS(f1, f2);
    static constexpr MessageId message_id = 0xABC;

    Field<1, Required, Float32<IsFinite>> f1;
    Field<2, Optional, Float64<Around<3, 1>>> f2;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const FloatMessage&) const = default;
};

TEMPLATE_TEST_CASE("Float Serialization", "[types][float]",
                   serdes::PackedLayout, serdes::TlvLayout,
                   serdes::Aligned32Layout, serdes::Aligned64Layout) {
    FloatMessage msg;
    REQUIRE_FALSE(msg.f1.set(1.23f).has_value());
    REQUIRE_FALSE(msg.f2.set(3.14159).has_value());

    auto buffer = GetBuffer<FloatMessage, integrity::CRC16, TestType>();
    REQUIRE(!Serialize(buffer, msg).has_value());

    FloatMessage out_msg;
    REQUIRE(!Deserialize(buffer, out_msg).has_value());
    REQUIRE(std::abs(out_msg.f1.get().value() - 1.23f) < 0.0001f);
}

struct BoolMessage {
    CRUNCH_MESSAGE_FIELDS(b1, b2, b3);
    static constexpr MessageId message_id = 0xB001;
    Field<1, Required, Bool<True>> b1;
    Field<2, Required, Bool<False>> b2;
    Field<3, Optional, Bool<None>> b3;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const BoolMessage&) const = default;
};

TEMPLATE_TEST_CASE("Bool Serialization", "[types][bool]", serdes::PackedLayout,
                   serdes::TlvLayout, serdes::Aligned32Layout,
                   serdes::Aligned64Layout) {
    BoolMessage msg;
    REQUIRE_FALSE(msg.b1.set(true).has_value());
    REQUIRE_FALSE(msg.b2.set(false).has_value());
    REQUIRE_FALSE(msg.b3.set(true).has_value());

    auto buffer = GetBuffer<BoolMessage, integrity::CRC16, TestType>();
    REQUIRE(!Serialize(buffer, msg).has_value());

    BoolMessage out_msg;
    REQUIRE(!Deserialize(buffer, out_msg).has_value());
    REQUIRE(out_msg.b1.get().value() == true);
}

enum class TestStatus : int32_t { V0 = 0, V1 = 1, V2 = 2, V3 = 3 };

struct EnumMessage {
    CRUNCH_MESSAGE_FIELDS(status);
    static constexpr MessageId message_id = 0xE001;

    Field<1, Required, Enum<TestStatus, OneOf<TestStatus::V1, TestStatus::V2>>>
        status;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const EnumMessage&) const = default;
};

TEMPLATE_TEST_CASE("Enum Serialization", "[types][enum]", serdes::PackedLayout,
                   serdes::TlvLayout, serdes::Aligned32Layout,
                   serdes::Aligned64Layout) {
    EnumMessage msg;
    REQUIRE_FALSE(msg.status.set(TestStatus::V1).has_value());
    auto buffer = GetBuffer<EnumMessage, integrity::None, TestType>();
    REQUIRE(!Serialize(buffer, msg).has_value());

    msg.status.set_without_validation(TestStatus::V3);
    REQUIRE(msg.status.Validate().has_value());
    REQUIRE(Serialize(buffer, msg).has_value());
}

struct StringMessage {
    CRUNCH_MESSAGE_FIELDS(str_field);
    static constexpr MessageId message_id = 0xA001;

    Field<1, Required, String<10, Length<3>>> str_field;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const StringMessage&) const = default;
};

TEMPLATE_TEST_CASE("String Serialization", "[types][string]",
                   serdes::PackedLayout, serdes::TlvLayout,
                   serdes::Aligned32Layout, serdes::Aligned64Layout) {
    StringMessage msg;
    REQUIRE_FALSE(msg.str_field.set("foo").has_value());

    auto buffer = GetBuffer<StringMessage, integrity::None, TestType>();
    REQUIRE(!Serialize(buffer, msg).has_value());

    StringMessage out_msg;
    REQUIRE(!Deserialize(buffer, out_msg).has_value());
    REQUIRE(out_msg.str_field.get() == "foo");
}

struct ArrayMessage {
    CRUNCH_MESSAGE_FIELDS(arr);
    static constexpr MessageId message_id = 0xAA05;

    // Using None validator for test simplicity
    ArrayField<1, Int32<None>, 4, LengthAtLeast<2>> arr;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const ArrayMessage&) const = default;
};

TEMPLATE_TEST_CASE("Array Serialization", "[types][array]",
                   serdes::PackedLayout, serdes::TlvLayout,
                   serdes::Aligned32Layout, serdes::Aligned64Layout) {
    ArrayMessage msg;
    msg.arr.add(10);
    msg.arr.add(20);
    REQUIRE(msg.arr.size() == 2);
    REQUIRE(msg.arr.get().size() == 2);
    REQUIRE(msg.arr.get()[0].get() == 10);
    REQUIRE(msg.arr.get()[1].get() == 20);

    auto buffer = GetBuffer<ArrayMessage, integrity::None, TestType>();
    auto err = Serialize(buffer, msg);
    if (err.has_value()) {
        FAIL("Serialize failed: " << err.value().message);
    }

    ArrayMessage out_msg;
    REQUIRE(!Deserialize(buffer, out_msg).has_value());

    const auto out_arr = out_msg.arr.get();
    REQUIRE(out_arr.size() == 2);
    REQUIRE(out_arr[0].get() == 10);
    REQUIRE(out_arr[1].get() == 20);

    // Fail length validation
    msg.arr.clear();
    msg.arr.add(5);
    REQUIRE(msg.arr.Validate().has_value());  // < 2 elements
    REQUIRE(Serialize(buffer, msg).has_value());
}

struct StringArrayMessage {
    static constexpr MessageId message_id = 901;

    // Array of up to 4 strings, each max 16 chars.
    ArrayField<1, String<16, None>, 4, None> strings;

    CRUNCH_MESSAGE_FIELDS(strings);

    constexpr std::optional<Error> Validate() const { return std::nullopt; }

    bool operator==(const StringArrayMessage& other) const {
        return get_fields() == other.get_fields();
    }
};

TEMPLATE_TEST_CASE("Array of Strings Serialization", "[array][string]",
                   serdes::PackedLayout, serdes::TlvLayout,
                   serdes::Aligned32Layout, serdes::Aligned64Layout) {
    using Layout = TestType;

    SECTION("Empty array") {
        StringArrayMessage msg;
        // strings is empty by default
        REQUIRE(msg.strings.empty());

        std::vector<std::byte> buffer(
            Layout::template Size<StringArrayMessage>());
        std::size_t bytes_written = Layout::Serialize(msg, buffer);

        StringArrayMessage decoded;
        auto err = Layout::Deserialize(std::span{buffer}.first(bytes_written),
                                       decoded);
        REQUIRE(!err.has_value());
        REQUIRE(decoded.strings.empty());
    }

    SECTION("Populated array") {
        StringArrayMessage msg;
        REQUIRE_FALSE(msg.strings.add(String<16, None>("hello")).has_value());
        REQUIRE_FALSE(msg.strings.add(String<16, None>("world")).has_value());

        std::vector<std::byte> buffer(
            Layout::template Size<StringArrayMessage>());
        std::size_t bytes_written = Layout::Serialize(msg, buffer);

        StringArrayMessage decoded;
        auto err = Layout::Deserialize(std::span{buffer}.first(bytes_written),
                                       decoded);
        REQUIRE(!err.has_value());
        REQUIRE(decoded.strings.size() == 2);
        REQUIRE(decoded.strings[0].get() == "hello");
        REQUIRE(decoded.strings[1].get() == "world");
    }

    SECTION("Max capacity") {
        StringArrayMessage msg;
        REQUIRE_FALSE(msg.strings.add(String<16, None>("one")).has_value());
        REQUIRE_FALSE(msg.strings.add(String<16, None>("two")).has_value());
        REQUIRE_FALSE(msg.strings.add(String<16, None>("three")).has_value());
        REQUIRE_FALSE(msg.strings.add(String<16, None>("four")).has_value());

        // Fifth add should fail
        REQUIRE(msg.strings.add(String<16, None>("five")).has_value());

        std::vector<std::byte> buffer(
            Layout::template Size<StringArrayMessage>());
        std::size_t bytes_written = Layout::Serialize(msg, buffer);

        StringArrayMessage decoded;
        auto err = Layout::Deserialize(std::span{buffer}.first(bytes_written),
                                       decoded);
        REQUIRE(!err.has_value());
        REQUIRE(decoded.strings.size() == 4);
        REQUIRE(decoded.strings[3].get() == "four");
    }
}

struct InnerMsg {
    CRUNCH_MESSAGE_FIELDS(val);
    static constexpr MessageId message_id = 0x8888;
    Field<1, Required, Int32<None>> val;
    constexpr std::optional<Error> Validate() const { return std::nullopt; }
    bool operator==(const InnerMsg&) const = default;
};

struct SimpleMapMessage {
    CRUNCH_MESSAGE_FIELDS(map_field);
    static constexpr MessageId message_id = 0x401;
    MapField<1, Int32<None>, String<16, None>, 4, None> map_field;
    constexpr std::optional<Error> Validate() const { return std::nullopt; }
    bool operator==(const SimpleMapMessage&) const = default;
};

struct ArrayKeyMapMessage {
    CRUNCH_MESSAGE_FIELDS(map_field);
    static constexpr MessageId message_id = 0x402;
    // Map with Array as key: Key=Array<Int>, Value=Enum
    using KeyType = ArrayField<2, Int32<None>, 3, None>;
    // Using TestStatus enum from above
    MapField<1, KeyType, Enum<TestStatus, None>, 4, None> map_field;

    constexpr std::optional<Error> Validate() const { return std::nullopt; }
    bool operator==(const ArrayKeyMapMessage&) const = default;
};

struct MessageMapMessage {
    CRUNCH_MESSAGE_FIELDS(map_field);
    static constexpr MessageId message_id = 0x403;
    // Key=String, Value=InnerMsg
    MapField<1, String<10, None>, InnerMsg, 4, None> map_field;
    constexpr std::optional<Error> Validate() const { return std::nullopt; }
    bool operator==(const MessageMapMessage&) const = default;
};

TEMPLATE_TEST_CASE("MapField Serialization", "[types][map]",
                   serdes::PackedLayout, serdes::TlvLayout,
                   serdes::Aligned32Layout, serdes::Aligned64Layout) {
    SECTION("Simple Map (Int -> String)") {
        SimpleMapMessage msg;
        REQUIRE_FALSE(msg.map_field.insert(1, "one").has_value());
        REQUIRE_FALSE(msg.map_field.insert(2, "two").has_value());

        auto buffer = GetBuffer<SimpleMapMessage, integrity::None, TestType>();
        REQUIRE(!Serialize(buffer, msg).has_value());

        SimpleMapMessage out;
        REQUIRE(!Deserialize(buffer, out).has_value());
        REQUIRE(out == msg);
        REQUIRE(out.map_field.size() == 2);
        REQUIRE(out.map_field.at(1).value()->get() == "one");
    }

    SECTION("Array Key Map (Array -> Enum)") {
        ArrayKeyMapMessage msg;
        ArrayKeyMapMessage::KeyType k1;
        REQUIRE_FALSE(k1.add(10).has_value());
        REQUIRE_FALSE(k1.add(20).has_value());

        REQUIRE_FALSE(msg.map_field.insert(k1, TestStatus::V1).has_value());

        auto buffer =
            GetBuffer<ArrayKeyMapMessage, integrity::None, TestType>();
        REQUIRE(!Serialize(buffer, msg).has_value());

        ArrayKeyMapMessage out;
        REQUIRE(!Deserialize(buffer, out).has_value());
        REQUIRE(out == msg);
        REQUIRE(out.map_field.size() == 1);

        // Verify key lookup works
        REQUIRE(out.map_field.at(k1).has_value());
        REQUIRE(out.map_field.at(k1).value()->get() == TestStatus::V1);
    }

    SECTION("Message Value Map (String -> Message)") {
        MessageMapMessage msg;
        InnerMsg m1;
        REQUIRE_FALSE(m1.val.set(123).has_value());
        InnerMsg m2;
        REQUIRE_FALSE(m2.val.set(456).has_value());

        REQUIRE_FALSE(msg.map_field.insert("key1", m1).has_value());
        REQUIRE_FALSE(msg.map_field.insert("key2", m2).has_value());

        auto buffer = GetBuffer<MessageMapMessage, integrity::None, TestType>();
        REQUIRE(!Serialize(buffer, msg).has_value());

        MessageMapMessage out;
        REQUIRE(!Deserialize(buffer, out).has_value());
        REQUIRE(out == msg);
        REQUIRE(out.map_field.at("key1").has_value());
        REQUIRE(*(out.map_field.at("key1").value()) == m1);
    }
}
