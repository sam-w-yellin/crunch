#include <catch2/catch_all.hpp>
#include <cmath>
#include <crunch_validators.hpp>
#include <limits>
#include <optional>

using namespace Crunch;

constexpr int FIELD_ID = 42;

TEST_CASE("TestPositive") {
    REQUIRE_FALSE(Positive::Check(10, FIELD_ID).has_value());
    REQUIRE_FALSE(Positive::Check(0, FIELD_ID).has_value());
    REQUIRE(Positive::Check(-10, FIELD_ID).has_value());

    REQUIRE_FALSE(Positive::Check(10.0, FIELD_ID).has_value());
    REQUIRE_FALSE(Positive::Check(0.0, FIELD_ID).has_value());
    REQUIRE(Positive::Check(-10.0, FIELD_ID).has_value());
}

TEST_CASE("TestNegative") {
    REQUIRE_FALSE(Negative::Check(-10, FIELD_ID).has_value());
    REQUIRE(Negative::Check(10, FIELD_ID).has_value());
    REQUIRE(Negative::Check(0, FIELD_ID).has_value());

    REQUIRE_FALSE(Negative::Check(-10.0, FIELD_ID).has_value());
    REQUIRE(Negative::Check(10.0, FIELD_ID).has_value());
    REQUIRE(Negative::Check(0.0, FIELD_ID).has_value());
}

TEST_CASE("TestNotZero") {
    REQUIRE_FALSE(NotZero::Check(10u, FIELD_ID).has_value());
    REQUIRE_FALSE(NotZero::Check(10, FIELD_ID).has_value());
    REQUIRE_FALSE(NotZero::Check(-10, FIELD_ID).has_value());
    REQUIRE(NotZero::Check(0, FIELD_ID).has_value());

    REQUIRE_FALSE(NotZero::Check(10.0, FIELD_ID).has_value());
    REQUIRE_FALSE(NotZero::Check(-10.0, FIELD_ID).has_value());
    REQUIRE(NotZero::Check(0.0, FIELD_ID).has_value());
}

TEST_CASE("TestLessThan") {
    REQUIRE_FALSE(LessThan<20>::Check(10, FIELD_ID).has_value());
    REQUIRE_FALSE(LessThan<20u>::Check(10u, FIELD_ID).has_value());
    REQUIRE(LessThan<20>::Check(30, FIELD_ID).has_value());
    REQUIRE(LessThan<10>::Check(10, FIELD_ID).has_value());

    REQUIRE_FALSE(LessThan<20>::Check(10.0, FIELD_ID).has_value());
    REQUIRE(LessThan<20>::Check(30.0, FIELD_ID).has_value());
    REQUIRE(LessThan<10>::Check(10.0, FIELD_ID).has_value());
}

TEST_CASE("TestGreaterThan") {
    REQUIRE_FALSE(GreaterThan<5>::Check(10, FIELD_ID).has_value());
    REQUIRE_FALSE(GreaterThan<5u>::Check(10u, FIELD_ID).has_value());
    REQUIRE(GreaterThan<20>::Check(10, FIELD_ID).has_value());
    REQUIRE(GreaterThan<10>::Check(10, FIELD_ID).has_value());

    REQUIRE_FALSE(GreaterThan<5>::Check(10.0, FIELD_ID).has_value());
    REQUIRE(GreaterThan<20>::Check(10.0, FIELD_ID).has_value());
}

TEST_CASE("TestLessThanOrEqualTo") {
    REQUIRE_FALSE(LessThanOrEqualTo<20>::Check(10, FIELD_ID).has_value());
    REQUIRE_FALSE(LessThanOrEqualTo<20u>::Check(10u, FIELD_ID).has_value());
    REQUIRE_FALSE(LessThanOrEqualTo<10>::Check(10, FIELD_ID).has_value());
    REQUIRE(LessThanOrEqualTo<20>::Check(30, FIELD_ID).has_value());
}

TEST_CASE("TestGreaterThanOrEqualTo") {
    REQUIRE_FALSE(GreaterThanOrEqualTo<5>::Check(10, FIELD_ID).has_value());
    REQUIRE_FALSE(GreaterThanOrEqualTo<5u>::Check(10u, FIELD_ID).has_value());
    REQUIRE_FALSE(GreaterThanOrEqualTo<10>::Check(10, FIELD_ID).has_value());
    REQUIRE(GreaterThanOrEqualTo<20>::Check(10, FIELD_ID).has_value());
}

TEST_CASE("TestEqualTo") {
    REQUIRE_FALSE(EqualTo<10>::Check(10, FIELD_ID).has_value());
    REQUIRE(EqualTo<5>::Check(10, FIELD_ID).has_value());
}

TEST_CASE("TestNotEqualTo") {
    REQUIRE_FALSE(NotEqualTo<20>::Check(10, FIELD_ID).has_value());
    REQUIRE(NotEqualTo<10>::Check(10, FIELD_ID).has_value());
}

TEST_CASE("TestIsFinite") {
    REQUIRE_FALSE(IsFinite::Check(10.0, FIELD_ID).has_value());
    REQUIRE_FALSE(IsFinite::Check(-5.5f, FIELD_ID).has_value());
    REQUIRE_FALSE(IsFinite::Check(0.0, FIELD_ID).has_value());

    REQUIRE(IsFinite::Check(std::numeric_limits<double>::infinity(), FIELD_ID)
                .has_value());
    REQUIRE(IsFinite::Check(-std::numeric_limits<float>::infinity(), FIELD_ID)
                .has_value());
    REQUIRE(IsFinite::Check(std::numeric_limits<double>::quiet_NaN(), FIELD_ID)
                .has_value());
}

TEST_CASE("TestAround") {
    REQUIRE_FALSE(Around<10, 1>::Check(10.0, FIELD_ID).has_value());
    REQUIRE_FALSE(Around<10, 1>::Check(10.5, FIELD_ID).has_value());
    REQUIRE_FALSE(Around<10, 1>::Check(9.5, FIELD_ID).has_value());
    REQUIRE(Around<10, 1>::Check(11.1, FIELD_ID).has_value());
    REQUIRE(Around<10, 1>::Check(8.9, FIELD_ID).has_value());
}

TEST_CASE("TestTrue") {
    REQUIRE(True::Check(true, FIELD_ID).has_value() == false);
    REQUIRE(True::Check(false, FIELD_ID).has_value());
}

TEST_CASE("TestFalse") {
    REQUIRE(False::Check(false, FIELD_ID).has_value() == false);
    REQUIRE(False::Check(true, FIELD_ID).has_value());
}

enum class MyEnum : int32_t { A = 0, B = 1, C = 2 };

template <>
struct std::is_enum<MyEnum> : std::true_type {};

TEST_CASE("TestOneOf") {
    // Int
    REQUIRE_FALSE(OneOf<1, 2, 3>::Check(1, FIELD_ID).has_value());
    REQUIRE_FALSE(OneOf<1, 2, 3>::Check(2, FIELD_ID).has_value());
    REQUIRE(OneOf<1, 2, 3>::Check(4, FIELD_ID).has_value());

    // Float - Compiler limitation (FP NTTP not fully supported)
    // REQUIRE_FALSE(OneOf<1.1, 2.2>::Check(1.1, FIELD_ID).has_value());
    // REQUIRE(OneOf<1.1, 2.2>::Check(3.3, FIELD_ID).has_value());

    // Enum
    REQUIRE_FALSE(
        OneOf<MyEnum::A, MyEnum::B>::Check(MyEnum::A, FIELD_ID).has_value());
    REQUIRE(
        OneOf<MyEnum::A, MyEnum::B>::Check(MyEnum::C, FIELD_ID).has_value());
}

TEST_CASE("TestEnumEquality") {
    REQUIRE_FALSE(EqualTo<MyEnum::A>::Check(MyEnum::A, FIELD_ID).has_value());
    REQUIRE(EqualTo<MyEnum::A>::Check(MyEnum::B, FIELD_ID).has_value());

    REQUIRE_FALSE(
        NotEqualTo<MyEnum::A>::Check(MyEnum::B, FIELD_ID).has_value());
    REQUIRE(NotEqualTo<MyEnum::A>::Check(MyEnum::A, FIELD_ID).has_value());
}

// Test concepts
static_assert(!Validator<True, int>);
static_assert(Validator<True, bool>);

static_assert(Validator<Positive, int>);
static_assert(Validator<Positive, float>);
static_assert(!Validator<Positive, unsigned int>);
static_assert(!Validator<Positive, bool>);

static_assert(Validator<Negative, int>);
static_assert(Validator<Negative, float>);
static_assert(!Validator<Negative, unsigned int>);
static_assert(!Validator<Negative, bool>);

static_assert(Validator<NotZero, int>);
static_assert(Validator<NotZero, float>);
static_assert(Validator<NotZero, unsigned int>);
static_assert(!Validator<NotZero, bool>);

static_assert(Validator<Even, int>);
static_assert(Validator<Even, unsigned int>);
static_assert(!Validator<Even, float>);
static_assert(!Validator<Even, bool>);

static_assert(Validator<Odd, int>);
static_assert(!Validator<Odd, float>);
static_assert(!Validator<Odd, bool>);

static_assert(Validator<LessThan<10>, int>);
static_assert(Validator<LessThan<10>, float>);
static_assert(!Validator<LessThan<10>, bool>);

static_assert(Validator<EqualTo<10>, int>);
static_assert(Validator<EqualTo<10>, float>);

static_assert(Validator<OneOf<1>, int>);
static_assert(Validator<OneOf<MyEnum::A>, MyEnum>);
