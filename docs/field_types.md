# Field Types {#field_types}

Crunch supports a variety of field types for message definition. Each field type can have validators attached.

## Scalars

Integer and floating-point types with optional validators.

```cpp
struct ScalarExample {
    CRUNCH_MESSAGE_FIELDS(count, value, flag);
    static constexpr MessageId message_id = 10;

    // Int32 that must be positive and odd
    Field<1, Required, Int32<Positive, Odd>> count;
    
    // Float64 that must be within 3.0 ± 0.25
    Field<2, Optional, Float64<Around<3.0, 0.25>>> value;
    
    // Bool that must be true
    Field<3, Required, Bool<True>> flag;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const ScalarExample&) const = default;
};

ScalarExample msg;
if (auto err = msg.count.set(-5); err) {
    // Fails: -5 is not positive
}
msg.count.set(7);  // OK: positive and odd
msg.value.set(3.1);  // OK: within tolerance
msg.flag.set(true);  // OK
```

## Enums

Custom enums with value constraints.

```cpp
enum class Status : int32_t { IDLE = 0, RUNNING = 1, ERROR = 2 };

struct EnumExample {
    CRUNCH_MESSAGE_FIELDS(status);
    static constexpr MessageId message_id = 11;
    
    // Enum constrained to specific values
    Field<1, Required, Enum<Status, OneOf<Status::IDLE, Status::RUNNING>>> status;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const EnumExample&) const = default;
};

EnumExample msg;
msg.status.set(Status::RUNNING);  // OK
if (auto err = msg.status.set(Status::ERROR); err) {
    // Fails: ERROR not in allowed set
}
```

## Strings

Fixed-capacity strings with optional validators.

```cpp
struct StringExample {
    CRUNCH_MESSAGE_FIELDS(name, code);
    static constexpr MessageId message_id = 12;
    
    // String with max 64 characters
    Field<1, Required, String<64, None>> name;
    
    // String that cannot equal "INVALID"
    Field<2, Optional, String<32, StringNotEquals<"INVALID">>> code;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const StringExample&) const = default;
};

StringExample msg;
msg.name.set("Alice");
msg.code.set("ABC123");
```

## Submessages

Nested message types.

```cpp
struct Inner {
    CRUNCH_MESSAGE_FIELDS(x, y);
    static constexpr MessageId message_id = 20;
    
    Field<1, Required, Int32<None>> x;
    Field<2, Required, Int32<None>> y;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const Inner&) const = default;
};

struct Outer {
    CRUNCH_MESSAGE_FIELDS(point);
    static constexpr MessageId message_id = 21;
    
    Field<1, Required, Inner> point;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const Outer&) const = default;
};

Inner inner;
inner.x.set(10);
inner.y.set(20);

Outer msg;
msg.point.set(inner);
```

## Arrays

Fixed-capacity arrays with element and aggregate validators.

```cpp
struct ArrayExample {
    CRUNCH_MESSAGE_FIELDS(values, names);
    static constexpr MessageId message_id = 13;
    
    // Array of up to 10 positive integers, must have at least 2 elements
    ArrayField<1, Int32<Positive>, 10, LengthAtLeast<2>> values;
    
    // Array of up to 5 strings
    ArrayField<2, String<32, None>, 5, None> names;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const ArrayExample&) const = default;
};

ArrayExample msg;

// Add elements one at a time
msg.values.add(1);
msg.values.add(2);
msg.values.add(3);

// Or set from STL array
std::array<int32_t, 3> arr = {10, 20, 30};
msg.values.set(arr);

// Iterate like STL container
for (const auto& val : msg.values) {
    // val.get() returns the value
}
```

## Maps

Fixed-capacity maps supporting any key/value types.

> **Performance Note:** Map keys are not hashed or sorted. This means:
> - Key lookup is **O(n)** linear scan
> - Equality comparison is **O(n²)** 
> - Insertion checks key uniqueness via **O(n)** scan
> 
> When using complex key types (submessages, arrays, nested maps), each key comparison requires full deep equality, which can be slow for large maps.

```cpp
struct MapExample {
    CRUNCH_MESSAGE_FIELDS(config, scores);
    static constexpr MessageId message_id = 14;
    
    // Map from string keys to int32 values, max 10 entries
    MapField<1, String<32, None>, Int32<None>, 10> config;
    
    // Map from int32 keys to float64 values
    MapField<2, Int32<None>, Float64<None>, 5> scores;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const MapExample&) const = default;
};

MapExample msg;

// Insert key-value pairs
msg.config.insert("timeout", 30);
msg.config.insert("retries", 3);

// Lookup by key
if (auto* val = msg.config.find("timeout")) {
    // val->get() returns 30
}

// Access with at() (returns optional)
auto timeout = msg.config.at("timeout");  // optional<int32_t>
```

### Complex Key Types

Unlike most serialization formats, Crunch supports submessages, arrays, and even nested maps as map keys.

> **Warning:** Complex key types have significant performance implications. Each insertion requires an O(n) scan comparing all existing keys, and each key comparison requires deep equality checking of the entire key structure.

```cpp
// A coordinate that can be used as a map key
struct Coordinate {
    CRUNCH_MESSAGE_FIELDS(x, y);
    static constexpr MessageId message_id = 15;
    
    Field<1, Required, Int32<None>> x;
    Field<2, Required, Int32<None>> y;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const Coordinate&) const = default;
};

struct GridData {
    CRUNCH_MESSAGE_FIELDS(cells);
    static constexpr MessageId message_id = 16;
    
    // Map from Coordinate keys to string values
    MapField<1, Coordinate, String<64, None>, 100> cells;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const GridData&) const = default;
};

GridData grid;

Coordinate origin;
origin.x.set(0);
origin.y.set(0);
grid.cells.insert(origin, "start");

Coordinate target;
target.x.set(10);
target.y.set(5);
grid.cells.insert(target, "goal");
```

## Cross-Field Validation

The `Validate()` method enables custom logic across fields.

```cpp
struct OrderMessage {
    CRUNCH_MESSAGE_FIELDS(quantity, unit_price, total);
    static constexpr MessageId message_id = 30;
    
    Field<1, Required, Int32<Positive>> quantity;
    Field<2, Required, Float64<Positive>> unit_price;
    Field<3, Required, Float64<Positive>> total;
    
    constexpr auto Validate() const -> std::optional<Error> {
        // Ensure total matches quantity * unit_price
        auto expected = *quantity.get() * *unit_price.get();
        if (std::abs(*total.get() - expected) > 0.01) {
            return Error::validation(3, "total does not match quantity * unit_price");
        }
        return std::nullopt;
    }
    
    bool operator==(const OrderMessage&) const = default;
};
```
