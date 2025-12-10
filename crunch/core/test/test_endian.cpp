#include <catch2/catch_test_macros.hpp>
#include <crunch_endian.hpp>
#include <cstdint>

TEST_CASE("Endianness Utilities", "[endian]") {
    SECTION("LittleEndian identity on LE host") {
        if constexpr (std::endian::native == std::endian::little) {
            uint32_t val = 0x12345678;
            REQUIRE(Crunch::LittleEndian(val) == 0x12345678);
        }
    }

    SECTION("LittleEndian swaps on BE host") {
        if constexpr (std::endian::native == std::endian::big) {
            uint32_t val = 0x12345678;
            REQUIRE(Crunch::LittleEndian(val) == 0x78563412);
        }
    }

    SECTION("Round Trip") {
        uint64_t original = 0xDEADBEEFCAFEBABE;
        uint64_t le = Crunch::LittleEndian(original);
        uint64_t host = Crunch::LittleEndian(le);
        REQUIRE(host == original);
    }

    SECTION("Floats") {
        float f = 1.5f;
        float le_f = Crunch::LittleEndian(f);
        REQUIRE(Crunch::LittleEndian(le_f) == f);

        double d = 3.14159;
        double le_d = Crunch::LittleEndian(d);
        REQUIRE(Crunch::LittleEndian(le_d) == d);
    }

    SECTION("Enums") {
        enum class Color : uint16_t { Red = 0x1234 };
        Color c = Color::Red;
        Color le_c = Crunch::LittleEndian(c);
        REQUIRE(Crunch::LittleEndian(le_c) == c);

        if constexpr (std::endian::native == std::endian::little) {
            REQUIRE(le_c == Color::Red);
        } else {
            REQUIRE(static_cast<uint16_t>(le_c) == 0x3412);
        }
    }
}
