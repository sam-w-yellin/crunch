#include <catch2/catch_test_macros.hpp>
#include <crunch_integrity.hpp>

using namespace Crunch;
using namespace Crunch::integrity;

// Compile-time check that policies satisfy the concept
static_assert(IntegrityPolicy<None>);
static_assert(IntegrityPolicy<CRC16>);
static_assert(IntegrityPolicy<Parity>);

TEST_CASE("None policy has zero size") { REQUIRE(None::size() == 0); }

TEST_CASE("None policy returns empty array") {
    std::array<std::byte, 4> data = {std::byte{0x01}, std::byte{0x02},
                                     std::byte{0x03}, std::byte{0x04}};
    auto result = None::calculate(data);
    REQUIRE(result.size() == 0);
}

TEST_CASE("Parity policy has size 1") { REQUIRE(Parity::size() == 1); }

TEST_CASE("Parity calculates XOR correctly") {
    std::array<std::byte, 4> data = {std::byte{0x01}, std::byte{0x02},
                                     std::byte{0x03}, std::byte{0x04}};
    auto result = Parity::calculate(data);
    REQUIRE(result.size() == 1);
    // 0x01 ^ 0x02 ^ 0x03 ^ 0x04 = 0x04
    REQUIRE(result[0] == std::byte{0x04});
}

TEST_CASE("Parity of identical bytes is zero") {
    std::array<std::byte, 2> data = {std::byte{0xFF}, std::byte{0xFF}};
    auto result = Parity::calculate(data);
    REQUIRE(result[0] == std::byte{0x00});
}

TEST_CASE("CRC16 policy has size 2") { REQUIRE(CRC16::size() == 2); }

TEST_CASE("CRC16 calculates known value") {
    // "123456789" -> CRC-16-CCITT = 0x29B1 (using 0xFFFF init, no final XOR)
    std::array<std::byte, 9> data = {
        std::byte{'1'}, std::byte{'2'}, std::byte{'3'},
        std::byte{'4'}, std::byte{'5'}, std::byte{'6'},
        std::byte{'7'}, std::byte{'8'}, std::byte{'9'}};
    auto result = CRC16::calculate(data);
    REQUIRE(result.size() == 2);
    // Expected: 0x29B1
    REQUIRE(result[0] == std::byte{0x29});
    REQUIRE(result[1] == std::byte{0xB1});
}

TEST_CASE("CRC16 empty data") {
    std::span<const std::byte> empty;
    auto result = CRC16::calculate(empty);
    // CRC of empty data with init 0xFFFF stays 0xFFFF
    REQUIRE(result[0] == std::byte{0xFF});
    REQUIRE(result[1] == std::byte{0xFF});
}

TEST_CASE("CRC16 is constexpr") {
    constexpr std::array<std::byte, 3> data = {std::byte{0x01}, std::byte{0x02},
                                               std::byte{0x03}};
    constexpr auto result = CRC16::calculate(data);
    static_assert(result.size() == 2);
}
