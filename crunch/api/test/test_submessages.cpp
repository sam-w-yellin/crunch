#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>
#include <crunch.hpp>
#include <crunch_messages.hpp>
#include <crunch_scalar.hpp>
#include <crunch_tlv_layout.hpp>

using namespace Crunch;
using namespace Crunch::messages;
using namespace Crunch::fields;
// using namespace Crunch::validators; // Invalid namespace

struct InnerSimple {
    CRUNCH_MESSAGE_FIELDS(val);
    static constexpr MessageId message_id = 0xAA01;
    Field<1, Required, Int32<None>> val;
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const InnerSimple&) const = default;
};

struct OuterMixed {
    CRUNCH_MESSAGE_FIELDS(f1, inner, f2);
    static constexpr MessageId message_id = 0xAA02;
    Field<1, Required, Int32<None>> f1;
    Field<2, Required, InnerSimple> inner;
    Field<3, Required, Int16<None>> f2;

    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const OuterMixed&) const = default;
};

TEMPLATE_TEST_CASE("Mixed Scalar and Submessage Serialization", "[submessage]",
                   serdes::PackedLayout, serdes::TlvLayout) {
    OuterMixed msg;
    REQUIRE_FALSE(msg.f1.set(0x11223344).has_value());

    InnerSimple in;
    REQUIRE_FALSE(in.val.set(0x55667788).has_value());
    msg.inner.set(in);

    REQUIRE_FALSE(msg.f2.set(static_cast<int16_t>(0x99)).has_value());

    auto buffer = GetBuffer<OuterMixed, integrity::CRC16, TestType>();
    REQUIRE(!Serialize(buffer, msg).has_value());

    OuterMixed out_msg;
    REQUIRE(!Deserialize(buffer, out_msg).has_value());

    // Messages use pointers for get()
    REQUIRE(out_msg.inner.get()->val.get().value() == 0x55667788);
}

struct Point {
    CRUNCH_MESSAGE_FIELDS(x, y);
    static constexpr MessageId message_id = 0x1001;
    Field<1, Required, Int32<None>> x;
    Field<2, Required, Int32<None>> y;
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const Point&) const = default;
};

struct Rect {
    CRUNCH_MESSAGE_FIELDS(top_left, bottom_right);
    static constexpr MessageId message_id = 0x2002;
    Field<1, Required, Point> top_left;
    Field<2, Required, Point> bottom_right;
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const Rect&) const = default;
};

TEMPLATE_TEST_CASE("Submessage Serialization", "[submessage]",
                   serdes::PackedLayout, serdes::TlvLayout) {
    Rect rect;
    Point p1;
    REQUIRE_FALSE(p1.x.set(10).has_value());
    REQUIRE_FALSE(p1.y.set(20).has_value());
    Point p2;
    REQUIRE_FALSE(p2.x.set(30).has_value());
    REQUIRE_FALSE(p2.y.set(40).has_value());
    rect.top_left.set(p1);
    rect.bottom_right.set(p2);

    auto buffer = GetBuffer<Rect, integrity::None, TestType>();
    REQUIRE(!Serialize(buffer, rect).has_value());

    Rect outs;
    REQUIRE(!Deserialize(buffer, outs).has_value());
    REQUIRE(outs.top_left.get()->x.get().value() == 10);
    REQUIRE(outs.bottom_right.get()->y.get().value() == 40);
}

TEST_CASE("Submessage Validation Recursion", "[submessage]") {
    Rect rect;
    Point p1;
    REQUIRE_FALSE(p1.x.set(10).has_value());
    REQUIRE_FALSE(p1.y.set(20).has_value());
    rect.top_left.set(p1);
    // bottom_right missing
    auto err = Validate(rect);
    REQUIRE(err.has_value());
    REQUIRE(err->code == ErrorCode::ValidationFailed);
    REQUIRE(err->field_id == 2);
}

struct InnerMsg {
    CRUNCH_MESSAGE_FIELDS(f3);
    static constexpr MessageId message_id = 0x3001;
    Field<1, Required, Int32<None>> f3;
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const InnerMsg&) const = default;
};

struct OuterMsg {
    CRUNCH_MESSAGE_FIELDS(f1, f2);
    static constexpr MessageId message_id = 0x4001;
    Field<1, Required, Int32<None>> f1;
    Field<2, Required, InnerMsg> f2;

    constexpr auto Validate() const -> std::optional<Error> {
        const auto* f2_ptr = f2.get();
        if (f2_ptr) {
            const auto f3_opt = f2_ptr->f3.get();
            if (f3_opt.has_value() && *f3_opt > 10) {
                const auto f1_opt = f1.get();
                if (f1_opt.has_value() && *f1_opt != 5) {
                    return Error::validation(1, "f1 must be 5 if f2.f3 > 10");
                }
            }
        }
        return std::nullopt;
    }
    bool operator==(const OuterMsg&) const = default;
};

TEST_CASE("Cross-Field Validation with Submessage", "[submessage]") {
    OuterMsg msg;
    InnerMsg inner;
    REQUIRE_FALSE(inner.f3.set(10).has_value());
    msg.f2.set(inner);
    REQUIRE_FALSE(msg.f1.set(999).has_value());
    REQUIRE(!Validate(msg).has_value());

    REQUIRE_FALSE(inner.f3.set(11).has_value());  // > 10
    msg.f2.set(inner);
    REQUIRE_FALSE(msg.f1.set(5).has_value());  // Must be 5
    REQUIRE(!Validate(msg).has_value());

    REQUIRE_FALSE(msg.f1.set(6).has_value());  // Invalid
    auto err = Validate(msg);
    REQUIRE(err.has_value());
    REQUIRE(err->field_id == 1);
}

TEST_CASE("Submessage Equality", "[submessage]") {
    using TestField = Field<1, Optional, Point>;
    TestField s1;
    TestField s2;

    REQUIRE(s1 == s2);

    Point p1;
    REQUIRE_FALSE(p1.x.set(1).has_value());
    REQUIRE_FALSE(p1.y.set(2).has_value());
    s1.set(p1);
    REQUIRE_FALSE(s1 == s2);

    Point p2;
    REQUIRE_FALSE(p2.x.set(3).has_value());
    REQUIRE_FALSE(p2.y.set(4).has_value());
    s2.set(p2);
    REQUIRE_FALSE(s1 == s2);

    Point p3;
    REQUIRE_FALSE(p3.x.set(1).has_value());
    REQUIRE_FALSE(p3.y.set(2).has_value());
    s2.set(p3);
    REQUIRE(s1 == s2);
}

struct Polygon {
    CRUNCH_MESSAGE_FIELDS(vertices);
    static constexpr MessageId message_id = 0x5001;
    ArrayField<1, Point, 4, LengthAtLeast<3>> vertices;
    constexpr auto Validate() const -> std::optional<Error> {
        return std::nullopt;
    }
    bool operator==(const Polygon&) const = default;
};

TEMPLATE_TEST_CASE("Array of Submessages Serialization", "[submessage]",
                   serdes::PackedLayout, serdes::TlvLayout) {
    Polygon poly;

    Point p1;
    REQUIRE_FALSE(p1.x.set(0).has_value());
    REQUIRE_FALSE(p1.y.set(0).has_value());
    Point p2;
    REQUIRE_FALSE(p2.x.set(10).has_value());
    REQUIRE_FALSE(p2.y.set(0).has_value());
    Point p3;
    REQUIRE_FALSE(p3.x.set(0).has_value());
    REQUIRE_FALSE(p3.y.set(10).has_value());

    poly.vertices.add(p1);
    poly.vertices.add(p2);
    poly.vertices.add(p3);

    auto buffer = GetBuffer<Polygon, integrity::None, TestType>();
    REQUIRE(!Serialize(buffer, poly).has_value());

    Polygon out_poly;
    REQUIRE(!Deserialize(buffer, out_poly).has_value());

    const auto& out_points = out_poly.vertices.get();
    REQUIRE(out_points.size() == 3);
    REQUIRE(out_points[0].x.get().value() == 0);
    REQUIRE(out_points[1].x.get().value() == 10);
    REQUIRE(out_points[2].y.get().value() == 10);
}
