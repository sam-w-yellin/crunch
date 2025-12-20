#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <crunch/fields/crunch_enum.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/fields/crunch_string.hpp>
#include <crunch/messages/crunch_field.hpp>
#include <crunch/messages/crunch_messages.hpp>
#include <crunch/validators/crunch_validators.hpp>
#include <string_view>
#include <utility>

using namespace Crunch::messages;
using namespace Crunch::fields;
using namespace Crunch;

enum class TestEnum : int32_t { A = 1, B = 2, C = 3 };

struct TestMessage {
    CRUNCH_MESSAGE_FIELDS(val);
    static constexpr MessageId message_id = 0x9999;
    Field<1, Required, Int32<None>> val;
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const TestMessage&) const = default;
};

TEST_CASE("MapField Basic Operations", "[MapField]") {
    // Map<Int32, String>
    using KeyField = Int32<None>;
    using ValueField = String<10, None>;
    using TestMap = MapField<1, KeyField, ValueField, 5, None>;

    TestMap map;

    SECTION("Initial state") {
        REQUIRE(map.size() == 0);
        REQUIRE(map.empty());
    }

    SECTION("Insertion and retrieval") {
        REQUIRE(map.insert(1, std::string_view("one")) == std::nullopt);
        REQUIRE(map.size() == 1);

        REQUIRE(map.insert(2, std::string_view("two")) == std::nullopt);
        REQUIRE(map.size() == 2);

        // Find existing
        auto val1 = map.at(1);
        REQUIRE(val1.has_value());
        REQUIRE((*val1)->get() == std::string_view("one"));

        auto val2 = map.at(2);
        REQUIRE(val2.has_value());
        REQUIRE((*val2)->get() == std::string_view("two"));

        // Find missing
        REQUIRE(!map.at(3).has_value());
    }

    SECTION("at() access") {
        map.insert(10, "ten");
        const auto val = map.at(10);
        REQUIRE(val.has_value());
        REQUIRE((*val)->get() == std::string_view("ten"));
    }

    SECTION("Duplicate keys") {
        REQUIRE(map.insert(1, "one") == std::nullopt);
        // Duplicate key insertion should fail
        auto err = map.insert(1, "uno");
        REQUIRE(err.has_value());
        REQUIRE_THAT(std::string(err->message),
                     Catch::Matchers::ContainsSubstring("Duplicate key"));

        REQUIRE(map.size() == 1);
        // Value should remain "one"
        const auto val = map.at(1);
        REQUIRE(val.has_value());
        REQUIRE((*val)->get() == std::string_view("one"));
    }

    SECTION("Capacity exceeded") {
        for (int i = 0; i < 5; ++i) {
            REQUIRE(map.insert(i, "val") == std::nullopt);
        }
        REQUIRE(map.size() == 5);

        // Insert 6th element
        auto err = map.insert(99, "overflow");
        REQUIRE(err.has_value());
        REQUIRE(err->message.find("capacity exceeded") != std::string::npos);
    }

    SECTION("Clear") {
        map.insert(1, "one");
        map.insert(2, "two");
        REQUIRE(map.size() == 2);

        map.clear();
        REQUIRE(map.size() == 0);
        REQUIRE(map.empty());
        REQUIRE(!map.at(1).has_value());
    }

    SECTION("Equality") {
        TestMap map1;
        map1.insert(1, "one");
        map1.insert(2, "two");

        TestMap map2;
        map2.insert(2, "two");
        map2.insert(1, "one");

        // Order independent equality
        REQUIRE(map1 == map2);

        TestMap map3;
        map3.insert(1, "one");
        map3.insert(2, "three");  // Different value

        REQUIRE_FALSE(map1 == map3);

        TestMap map4;
        map4.insert(1, "one");
        // missing second element

        REQUIRE_FALSE(map1 == map4);
    }

    SECTION("Remove") {
        map.insert(1, "one");
        map.insert(2, "two");
        map.insert(3, "three");
        REQUIRE(map.size() == 3);

        // Remove middle element
        REQUIRE(map.remove(2));
        REQUIRE(map.size() == 2);
        REQUIRE(!map.at(2).has_value());
        REQUIRE(map.at(1).has_value());
        REQUIRE(map.at(3).has_value());

        // Remove non-existent
        REQUIRE_FALSE(map.remove(99));
        REQUIRE(map.size() == 2);

        // Remove last element
        REQUIRE(map.remove(3));
        REQUIRE(map.size() == 1);
        REQUIRE(map.at(1).has_value());

        // Remove remaining
        REQUIRE(map.remove(1));
        REQUIRE(map.size() == 0);
        REQUIRE(map.empty());

        // Remove from empty
        REQUIRE_FALSE(map.remove(1));
    }

    SECTION("Complex Value Type") {
        // Map<Int32, Array<Int32>>
        using ValueArray = ArrayField<2, Int32<None>, 3, None>;
        using ComplexMap = MapField<3, Int32<None>, ValueArray, 2, None>;

        ComplexMap c_map;
        ValueArray arr1;
        arr1.add(10);
        arr1.add(20);

        REQUIRE(c_map.insert(1, arr1) == std::nullopt);

        auto val = c_map.at(1);
        REQUIRE(val.has_value());
        REQUIRE((*val)->size() == 2);
        REQUIRE((*val)->at(0) == 10);
    }
}

TEST_CASE("MapField Validation", "[MapField]") {
    // Map<Int32, Int32> with some constraints on keys and values
    using KeyField = Int32<GreaterThanOrEqualTo<1>, LessThanOrEqualTo<100>>;
    using ValueFieldRel =
        Int32<GreaterThanOrEqualTo<10>, LessThanOrEqualTo<20>>;

    using ValidatedMap = MapField<2, KeyField, ValueFieldRel, 3, None>;

    ValidatedMap map;

    SECTION("Valid insertion") { REQUIRE(map.insert(5, 15) == std::nullopt); }

    SECTION("Invalid Key insertion") {
        // Key 0 violates Range<1, 100>
        auto err = map.insert(0, 15);
        REQUIRE(err.has_value());
    }

    SECTION("Invalid Value insertion") {
        // Value 5 violates Range<10, 20>
        auto err = map.insert(5, 5);
        REQUIRE(err.has_value());
    }
}

TEST_CASE("MapField Comprehensive Types", "[MapField]") {
    SECTION("Map with String Keys") {
        using StringKeyMap =
            MapField<10, String<10, None>, Int32<None>, 5, None>;
        StringKeyMap map;
        REQUIRE(map.insert("key1", 100) == std::nullopt);
        REQUIRE(map.insert("key2", 200) == std::nullopt);

        REQUIRE(map.at("key1").has_value());
        REQUIRE(*map.at("key1").value() == 100);
        REQUIRE(map.at("key3") == std::nullopt);
    }

    SECTION("Map with Enum Keys and Values") {
        using EnumKeyMap =
            MapField<0, Enum<TestEnum, None>, Enum<TestEnum, None>, 5, None>;
        EnumKeyMap map;
        REQUIRE(map.insert(TestEnum::A, TestEnum::B) == std::nullopt);
        REQUIRE(map.insert(TestEnum::B, TestEnum::C) == std::nullopt);

        REQUIRE(map.at(TestEnum::A).has_value());
        REQUIRE(*map.at(TestEnum::A).value() == TestEnum::B);
    }

    SECTION("Map with Array Keys") {
        using KeyArray = ArrayField<0, Int32<None>, 3, None>;
        using ArrayKeyMap = MapField<1, KeyArray, String<10, None>, 5, None>;

        ArrayKeyMap map;
        KeyArray k1;
        k1.add(1);
        KeyArray k2;
        k2.add(2);

        REQUIRE(map.insert(k1, "val1") == std::nullopt);
        REQUIRE(map.insert(k2, "val2") == std::nullopt);

        REQUIRE(map.at(k1).has_value());
        REQUIRE(map.at(k1).value()->get() == "val1");

        // Ensure k1 != k2 lookup
        KeyArray k3;
        k3.add(1);  // Same content as k1
        REQUIRE(map.at(k3).has_value());
        REQUIRE(map.at(k3).value()->get() == "val1");
    }

    SECTION("Map with Submessage Values") {
        using MessageMap = MapField<0, Int32<None>, TestMessage, 5, None>;
        MessageMap map;
        TestMessage m1;
        m1.val.set_without_validation(10);
        TestMessage m2;
        m2.val.set_without_validation(20);

        REQUIRE(map.insert(1, m1) == std::nullopt);
        REQUIRE(map.insert(2, m2) == std::nullopt);

        auto res = map.at(1);
        REQUIRE(res.has_value());
        REQUIRE(res.value()->val.get() == 10);
    }

    SECTION("Nested Maps") {
        using InnerMap = MapField<0, Int32<None>, Int32<None>, 3, None>;
        using OuterMap = MapField<0, String<10, None>, InnerMap, 3, None>;

        OuterMap out;
        InnerMap in1;
        in1.insert(1, 11);
        InnerMap in2;
        in2.insert(2, 22);

        REQUIRE(out.insert("m1", in1) == std::nullopt);
        REQUIRE(out.insert("m2", in2) == std::nullopt);

        auto ret = out.at("m1");
        REQUIRE(ret.has_value());
        REQUIRE(ret.value()->at(1).has_value());
        REQUIRE(*ret.value()->at(1).value() == 11);
    }

    SECTION("Map with Submessage Keys") {
        using MessageKeyMap = MapField<0, TestMessage, Int32<None>, 5, None>;
        MessageKeyMap map;
        TestMessage k1;
        k1.val.set_without_validation(1);
        TestMessage k2;
        k2.val.set_without_validation(2);

        REQUIRE(map.insert(k1, 100) == std::nullopt);
        REQUIRE(map.insert(k2, 200) == std::nullopt);

        REQUIRE(map.at(k1).has_value());
        REQUIRE(*map.at(k1).value() == 100);

        TestMessage k3;
        k3.val.set_without_validation(1);
        REQUIRE(map.at(k3).has_value());
        REQUIRE(*map.at(k3).value() == 100);
    }

    SECTION("Map with Map Keys") {
        using KeyMap = MapField<0, Int32<None>, Int32<None>, 3, None>;
        using MapKeyMap = MapField<0, KeyMap, Int32<None>, 3, None>;

        MapKeyMap map;
        KeyMap k1;
        k1.insert(1, 11);
        KeyMap k2;
        k2.insert(2, 22);

        REQUIRE(map.insert(k1, 100) == std::nullopt);
        REQUIRE(map.insert(k2, 200) == std::nullopt);

        REQUIRE(map.at(k1).has_value());
        REQUIRE(*map.at(k1).value() == 100);

        KeyMap k3;
        k3.insert(1, 11);  // Same content as k1
        REQUIRE(map.at(k3).has_value());
        REQUIRE(*map.at(k3).value() == 100);
    }
}
