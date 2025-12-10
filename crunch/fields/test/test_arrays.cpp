#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <crunch_field.hpp>
#include <crunch_scalar.hpp>
#include <crunch_validators.hpp>
#include <numeric>
#include <ranges>
#include <vector>

using namespace Crunch::messages;
using namespace Crunch::fields;
using namespace Crunch;

TEST_CASE("ArrayField STL Compatibility", "[ArrayField]") {
    ArrayField<1, Int32<None>, 10, LengthAtLeast<0>> arr;

    for (int i = 0; i < 5; ++i) {
        arr.add(i * 10);
    }

    SECTION("Range-based for loop") {
        std::vector<int32_t> values;
        for (const auto& val : arr) {
            values.push_back(val.get());
        }
        REQUIRE(values.size() == 5);
        REQUIRE(values[0] == 0);
        REQUIRE(values[4] == 40);
    }

    SECTION("std::find") {
        auto it = std::find(arr.begin(), arr.end(), Int32<None>{20});
        REQUIRE(it != arr.end());
        REQUIRE(it->get() == 20);

        auto it_missing = std::find(arr.begin(), arr.end(), Int32<None>{99});
        REQUIRE(it_missing == arr.end());
    }

    SECTION("std::accumulate") {
        int32_t sum = std::accumulate(
            arr.begin(), arr.end(), 0,
            [](int32_t acc, const auto& val) { return acc + val.get(); });
        REQUIRE(sum == 100);
    }

    SECTION("std::ranges::copy") {
        std::vector<Int32<None>> dest;
        std::ranges::copy(arr, std::back_inserter(dest));
        REQUIRE(dest.size() == 5);
        REQUIRE(dest[1].get() == 10);
    }

    SECTION("std::ranges::transform") {
        auto View = arr | std::views::transform(
                              [](const auto& val) { return val.get() + 1; });
        std::vector<int32_t> results(View.begin(), View.end());
        REQUIRE(results[0] == 1);
        REQUIRE(results[4] == 41);
    }

    SECTION("std::sort compatibility") {
        ArrayField<2, Int32<None>, 10, LengthAtLeast<0>> mixed;
        mixed.add(30);
        mixed.add(10);
        mixed.add(20);

        std::sort(mixed.begin(), mixed.end(), [](const auto& a, const auto& b) {
            return a.get() < b.get();
        });

        REQUIRE(mixed[0].get() == 10);
        REQUIRE(mixed[1].get() == 20);
        REQUIRE(mixed[2].get() == 30);
    }

    SECTION("Set from std::array") {
        ArrayField<3, Int32<None>, 10, None> arr2;
        std::array<Int32<None>, 3> source;
        source[0] = 5;
        source[1] = 15;
        source[2] = 25;

        arr2.set(source);

        REQUIRE(arr2.size() == 3);
        REQUIRE(arr2[0].get() == 5);
        REQUIRE(arr2[1].get() == 15);
        REQUIRE(arr2[2].get() == 25);
    }
}
