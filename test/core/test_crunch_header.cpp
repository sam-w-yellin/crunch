#include <array>
#include <catch2/catch_test_macros.hpp>
#include <crunch/core/crunch_header.hpp>
#include <crunch/serdes/crunch_static_layout.hpp>
#include <crunch/serdes/crunch_tlv_layout.hpp>
#include <cstring>

using namespace Crunch;
using namespace Crunch::serdes;

// Test message type
struct TestMessage {
    static constexpr MessageId message_id = 0x12345678;
};

struct OtherMessage {
    static constexpr MessageId message_id =
        0x07654321;  // Positive signed value
};

TEST_CASE("GetHeader: parses header from buffer", "[header]") {
    std::array<std::byte, StandardHeaderSize> buffer{};

    // Write version
    CrunchVersionId version = CrunchVersion;
    std::memcpy(buffer.data(), &version, sizeof(version));

    // Write format
    Format format = Format::Packed;
    std::memcpy(buffer.data() + sizeof(CrunchVersionId), &format,
                sizeof(format));

    // Write message ID (little endian)
    constexpr MessageId test_msg_id = 0x0ABBCCDD;
    MessageId msg_id = LittleEndian(test_msg_id);
    std::memcpy(buffer.data() + sizeof(CrunchVersionId) + sizeof(Format),
                &msg_id, sizeof(MessageId));

    auto result = GetHeader(std::span{buffer});
    REQUIRE(result.has_value());

    const CrunchHeader& header = *result;
    REQUIRE(header.version == CrunchVersion);
    REQUIRE(header.format == Format::Packed);
    REQUIRE(header.message_id == 0x0ABBCCDD);
}

TEST_CASE("GetHeader: fails if buffer too small", "[header][error]") {
    std::array<std::byte, 4> small_buffer{};  // Less than 6 bytes

    auto result = GetHeader(std::span{small_buffer});
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().message == "buffer too small for header");
}

TEST_CASE("WriteHeader: writes correct header bytes", "[header]") {
    std::array<std::byte, StandardHeaderSize> buffer{};

    std::size_t bytes_written =
        WriteHeader<TestMessage, PackedLayout>(std::span{buffer});

    REQUIRE(bytes_written == StandardHeaderSize);

    // Verify version (offset 0)
    REQUIRE(buffer[0] == static_cast<std::byte>(CrunchVersion));

    // Verify format (offset 1)
    REQUIRE(buffer[1] == static_cast<std::byte>(Format::Packed));

    // Verify message ID (offset 2-5, little endian)
    // 0x12345678 in little endian: 78 56 34 12
    REQUIRE(buffer[2] == std::byte{0x78});
    REQUIRE(buffer[3] == std::byte{0x56});
    REQUIRE(buffer[4] == std::byte{0x34});
    REQUIRE(buffer[5] == std::byte{0x12});
}

TEST_CASE("WriteHeader: works with different layouts", "[header]") {
    std::array<std::byte, StandardHeaderSize> buffer{};

    static_cast<void>(WriteHeader<TestMessage, TlvLayout>(std::span{buffer}));

    REQUIRE(buffer[1] == static_cast<std::byte>(Format::TLV));
}

TEST_CASE("ValidateHeader: succeeds with correct header", "[header]") {
    std::array<std::byte, StandardHeaderSize> buffer{};
    static_cast<void>(
        WriteHeader<TestMessage, PackedLayout>(std::span{buffer}));

    auto result = ValidateHeader<TestMessage, PackedLayout>(std::span{buffer});
    REQUIRE(result.has_value());
    REQUIRE(*result == StandardHeaderSize);
}

TEST_CASE("ValidateHeader: fails with wrong version", "[header][error]") {
    std::array<std::byte, StandardHeaderSize> buffer{};
    static_cast<void>(
        WriteHeader<TestMessage, PackedLayout>(std::span{buffer}));

    // Corrupt version
    buffer[0] = std::byte{0xFF};

    auto result = ValidateHeader<TestMessage, PackedLayout>(std::span{buffer});
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().message == "unsupported crunch version");
}

TEST_CASE("ValidateHeader: fails with wrong format", "[header][error]") {
    std::array<std::byte, StandardHeaderSize> buffer{};
    static_cast<void>(
        WriteHeader<TestMessage, PackedLayout>(std::span{buffer}));

    // Corrupt format (change from Packed to TLV)
    buffer[1] = static_cast<std::byte>(Format::TLV);

    auto result = ValidateHeader<TestMessage, PackedLayout>(std::span{buffer});
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().code == ErrorCode::InvalidFormat);
}

TEST_CASE("ValidateHeader: fails with wrong message ID", "[header][error]") {
    std::array<std::byte, StandardHeaderSize> buffer{};
    static_cast<void>(
        WriteHeader<TestMessage, PackedLayout>(std::span{buffer}));

    // Try to validate as OtherMessage
    auto result = ValidateHeader<OtherMessage, PackedLayout>(std::span{buffer});
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().code == ErrorCode::InvalidMessageId);
}

TEST_CASE("ValidateHeader: fails with buffer too small", "[header][error]") {
    std::array<std::byte, 4> small_buffer{};

    auto result =
        ValidateHeader<TestMessage, PackedLayout>(std::span{small_buffer});
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().message == "buffer too small for header");
}
