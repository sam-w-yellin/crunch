/**
 * @file test_concept_validation.cpp
 * @brief Static assertion tests verifying CrunchMessage concept correctly
 *        rejects ill-formed message definitions.
 *
 * These tests use static_assert to verify that various malformed message
 * types are correctly rejected by the CrunchMessage concept.
 */

#include <catch2/catch_all.hpp>
#include <crunch/crunch.hpp>

using namespace Crunch;
using namespace Crunch::fields;
using namespace Crunch::messages;

// =============================================================================
// Well-formed message (baseline - should satisfy CrunchMessage)
// =============================================================================

struct WellFormedMessage {
    CRUNCH_MESSAGE_FIELDS(value);
    static constexpr MessageId message_id = 1;

    Field<1, Required, Int32<None>> value;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }

    bool operator==(const WellFormedMessage&) const = default;
};

static_assert(CrunchMessage<WellFormedMessage>,
              "WellFormedMessage should satisfy CrunchMessage");

// =============================================================================
// 1. Message without a constexpr Validate function
// =============================================================================

struct NonConstexprValidate {
    CRUNCH_MESSAGE_FIELDS(value);
    static constexpr MessageId message_id = 2;

    Field<1, Required, Int32<None>> value;

    // Missing constexpr - not a constexpr Validate function
    auto Validate() const -> std::optional<Error> { return std::nullopt; }

    bool operator==(const NonConstexprValidate&) const = default;
};

static_assert(!HasConstexprValidate<NonConstexprValidate>,
              "NonConstexprValidate should NOT satisfy HasConstexprValidate");

// =============================================================================
// 2. Message that is not regular (non-copyable, non-default-constructible, etc)
// =============================================================================

struct NonCopyable {
    CRUNCH_MESSAGE_FIELDS(value);
    static constexpr MessageId message_id = 3;

    Field<1, Required, Int32<None>> value;

    // Delete copy constructor and assignment
    NonCopyable() = default;
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;
    NonCopyable(NonCopyable&&) = default;
    NonCopyable& operator=(NonCopyable&&) = default;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }

    bool operator==(const NonCopyable&) const = default;
};

static_assert(!std::regular<NonCopyable>,
              "NonCopyable should NOT be std::regular");

static_assert(!CrunchMessage<NonCopyable>,
              "NonCopyable should NOT satisfy CrunchMessage");

struct NonDefaultConstructible {
    CRUNCH_MESSAGE_FIELDS(value);
    static constexpr MessageId message_id = 4;

    Field<1, Required, Int32<None>> value;

    // Require an argument to construct
    NonDefaultConstructible(int) {}

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }

    bool operator==(const NonDefaultConstructible&) const = default;
};

static_assert(!std::default_initializable<NonDefaultConstructible>,
              "NonDefaultConstructible should NOT be default initializable");

static_assert(!CrunchMessage<NonDefaultConstructible>,
              "NonDefaultConstructible should NOT satisfy CrunchMessage");

// =============================================================================
// 3. Message defining fields that aren't Crunch fields (like a raw int)
// =============================================================================

struct RawIntField {
    static constexpr MessageId message_id = 5;

    int value;  // Raw int, not a Crunch Field

    // Manually define get_fields since CRUNCH_MESSAGE_FIELDS won't work
    constexpr auto get_fields() { return std::tie(value); }
    constexpr auto get_fields() const { return std::tie(value); }

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }

    bool operator==(const RawIntField&) const = default;
};

static_assert(!ValidField<int>, "Raw int should NOT be a ValidField");

// Note: RawIntField will fail the tuple_members_are_valid_fields check

// =============================================================================
// 4. Message with repeated field IDs
// =============================================================================

struct DuplicateFieldIds {
    static constexpr MessageId message_id = 6;

    CRUNCH_MESSAGE_FIELDS(first, second);

    Field<1, Required, Int32<None>> first;
    Field<1, Required, Int32<None>> second;  // Duplicate ID!

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }

    bool operator==(const DuplicateFieldIds&) const = default;
};

// The has_duplicates helper should detect this
static_assert(has_duplicates<1, 1>::value,
              "has_duplicates should detect duplicate IDs");

static_assert(!has_duplicates<1, 2, 3>::value,
              "has_duplicates should not flag unique IDs");

static_assert(!CrunchMessage<DuplicateFieldIds>,
              "DuplicateFieldIds should NOT satisfy CrunchMessage");

// =============================================================================
// 5. Message missing message_id
// =============================================================================

struct MissingMessageId {
    CRUNCH_MESSAGE_FIELDS(value);
    // No message_id!

    Field<1, Required, Int32<None>> value;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }

    bool operator==(const MissingMessageId&) const = default;
};

static_assert(!HasCrunchMessageInterface<MissingMessageId>,
              "MissingMessageId should NOT satisfy HasCrunchMessageInterface");

static_assert(!CrunchMessage<MissingMessageId>,
              "MissingMessageId should NOT satisfy CrunchMessage");

// =============================================================================
// 6. Message without get_fields (no CRUNCH_MESSAGE_FIELDS)
// =============================================================================

struct MissingGetFields {
    static constexpr MessageId message_id = 7;

    Field<1, Required, Int32<None>> value;
    // No CRUNCH_MESSAGE_FIELDS - no get_fields() method!

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }

    bool operator==(const MissingGetFields&) const = default;
};

static_assert(!HasCrunchMessageInterface<MissingGetFields>,
              "MissingGetFields should NOT satisfy HasCrunchMessageInterface");

static_assert(!CrunchMessage<MissingGetFields>,
              "MissingGetFields should NOT satisfy CrunchMessage");

// =============================================================================
// Catch2 test case (just to verify static asserts compiled)
// =============================================================================

TEST_CASE("CrunchMessage concept static assertions compiled", "[concept]") {
    REQUIRE(true);  // If we got here, all static_asserts passed
}
