#include <catch2/catch_test_macros.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/validators/crunch_validators.hpp>

using namespace Crunch;
using namespace Crunch::fields;

TEST_CASE("TestBasicScalar") {
    // Int32<Validators...>
    Int32<Positive, NotZero> f;

    // Default init
    REQUIRE(f.get() == 0);
    // Validate(0, id=0) -> NotZero fails?
    REQUIRE(f.Validate().has_value());

    // Valid set (using constructor or direct access)
    f = Int32<Positive, NotZero>(10);
    REQUIRE_FALSE(f.Validate().has_value());
    REQUIRE(f.get() == 10);

    // Violates Positive (and NotZero if < 0?)
    f = Int32<Positive, NotZero>(-10);
    REQUIRE(f.Validate().has_value());
    REQUIRE(f.get() == -10);

    // Violates NotZero
    f = Int32<Positive, NotZero>(0);
    REQUIRE(f.Validate().has_value());
    REQUIRE(f.get() == 0);
}

TEST_CASE("Scalar Equality") {
    using TestType = Int32<None>;

    TestType f1;
    TestType f2;

    // Both default (0) -> Equal
    REQUIRE(f1 == f2);

    f1 = 10;
    REQUIRE_FALSE(f1 == f2);
    REQUIRE_FALSE(f2 == f1);

    f2 = 20;
    REQUIRE_FALSE(f1 == f2);

    f2 = 10;
    REQUIRE(f1 == f2);
}

static_assert(is_scalar_v<Int8<None>>);
static_assert(!is_scalar_v<int>);

// Verify that Scalar requires at least one validator (if we kept that
// requirement) The concept in scalar.hpp checks sizeof...(Validators) > 0. So
// Int32<> should fail. Int32<None> should pass. We can't easily test
// compilation failure in unit tests without external tools.
static_assert(is_scalar_v<Int32<None>>);
