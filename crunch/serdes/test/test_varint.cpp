#include <array>
#include <catch2/catch_test_macros.hpp>
#include <crunch_varint.hpp>
#include <cstddef>
#include <limits>
#include <span>
#include <vector>

using Crunch::serdes::Varint;

TEST_CASE("Varint Encoding/Decoding", "[varint]") {
    std::array<std::byte, 16> buffer;

    SECTION("Zero") {
        std::size_t bytes = Varint::encode(0, buffer, 0);
        REQUIRE(bytes == 1);
        REQUIRE(static_cast<uint8_t>(buffer[0]) == 0x00);

        auto res = Varint::decode(buffer, 0);
        REQUIRE(res.has_value());
        REQUIRE(res->first == 0);
        REQUIRE(res->second == 1);
    }

    SECTION("Single Byte Max (127)") {
        std::size_t bytes = Varint::encode(127, buffer, 0);
        REQUIRE(bytes == 1);
        REQUIRE(static_cast<uint8_t>(buffer[0]) == 0x7F);

        auto res = Varint::decode(buffer, 0);
        REQUIRE(res.has_value());
        REQUIRE(res->first == 127);
        REQUIRE(res->second == 1);
    }

    SECTION("Two Bytes (128)") {
        std::size_t bytes = Varint::encode(128, buffer, 0);
        REQUIRE(bytes == 2);
        REQUIRE(static_cast<uint8_t>(buffer[0]) == 0x80);  // 1000 0000
        REQUIRE(static_cast<uint8_t>(buffer[1]) == 0x01);  // 0000 0001

        auto res = Varint::decode(buffer, 0);
        REQUIRE(res.has_value());
        REQUIRE(res->first == 128);
        REQUIRE(res->second == 2);
    }

    SECTION("Max UInt64") {
        uint64_t val = std::numeric_limits<uint64_t>::max();
        std::size_t bytes = Varint::encode(val, buffer, 0);
        REQUIRE(bytes == 10);

        auto res = Varint::decode(buffer, 0);
        REQUIRE(res.has_value());
        REQUIRE(res->first == val);
        REQUIRE(res->second == 10);
    }
}

TEST_CASE("Varint Error Handling", "[varint]") {
    SECTION("Buffer Overflow (Truncated)") {
        std::array<std::byte, 1> buffer;
        buffer[0] = std::byte{0x80};  // Continuation bit set, but no more data

        auto res = Varint::decode(buffer, 0);
        REQUIRE(!res.has_value());
    }

    SECTION("Value Overflow (> 64 bits)") {
        std::array<std::byte, 11> buffer;
        buffer.fill(std::byte{0x80});  // All continuation bits set
        buffer[10] = std::byte{0x00};  // Terminator

        // This represents a value with > 70 bits, which should fail
        auto res = Varint::decode(buffer, 0);
        REQUIRE(!res.has_value());
    }
}

TEST_CASE("Varint Size Calculation", "[varint]") {
    REQUIRE(Varint::size(0) == 1);
    REQUIRE(Varint::size(127) == 1);
    REQUIRE(Varint::size(128) == 2);
    REQUIRE(Varint::size(16383) == 2);
    REQUIRE(Varint::size(16384) == 3);
    REQUIRE(Varint::size(std::numeric_limits<uint64_t>::max()) == 10);
}
