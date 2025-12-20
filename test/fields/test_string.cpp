#include <catch2/catch_test_macros.hpp>
#include <crunch/fields/crunch_string.hpp>
#include <crunch/validators/crunch_validators.hpp>

using namespace Crunch;
using namespace Crunch::fields;

TEST_CASE("String Set and Get") {
    // String<MaxSize, Validators...>
    String<10, None> str;

    REQUIRE(str.get().empty());
    REQUIRE(str.current_len_ == 0);

    // Valid set
    auto err = str.set("hello");
    REQUIRE_FALSE(err.has_value());
    REQUIRE(str.get() == "hello");
    REQUIRE(str.current_len_ == 5);

    // Clear
    str.clear();
    REQUIRE(str.get().empty());

    // Capacity Exceeded
    err = str.set("0123456789A");  // 11 chars
    REQUIRE(err.has_value());
    REQUIRE(err->code == ErrorCode::CapacityExceeded);

    // Boundary check (exactly 10 chars)
    err = str.set("0123456789");
    REQUIRE_FALSE(err.has_value());
    REQUIRE(str.get() == "0123456789");
}

TEST_CASE("String Length Validator") {
    String<10, Length<3>> str;

    auto err = str.set("abc");
    REQUIRE_FALSE(err.has_value());
    REQUIRE_FALSE(str.Validate().has_value());

    err = str.set("abcd");
    REQUIRE(err.has_value());
    // Since set failed, value is unchanged ("abc")
    REQUIRE(str.get() == "abc");
}

TEST_CASE("String NullTerminated Validator") {
    String<10, NullTerminated> str;

    // Invalid (no null terminator check)
    auto err = str.set("abc");
    REQUIRE(err.has_value());

    // Valid
    char buf[] = {'a', 'b', 'c', '\0'};
    err = str.set(std::string_view(buf, 4));
    REQUIRE_FALSE(err.has_value());

    // Invalid (no null)
    err = str.set("abcde");
    REQUIRE(err.has_value());
}

TEST_CASE("String Zero Padding") {
    // Check internal buffer via public access
    String<10, None> str;
    str.set("hi");
    // Check padding
    REQUIRE(str.buffer_[2] == '\0');
    REQUIRE(str.buffer_[9] == '\0');
}

TEST_CASE("String Constructor") {
    String<10, None> str("hello");
    REQUIRE(str.get() == "hello");
}
