# Crunch

![Crunch Logo](logo/crunch.png)
**Crunch** is a C++ message definition and serialization framework for mission-critical, resource-constrained systems where message semantics matter as much as structure.

See the [Doxygen](https://sam-w-yellin.github.io/crunch/) for more details.

## Key Features

- **Opt-out validation:** Semantic field and cross-field validation are first-class, built-in, and happen by default.
- **Static memory allocation:** For use in resource-constrained systems.
- **Flexible serialization:** Swap serialization formats (e.g., TLV, static layout) without changing message definitions.
- **Built-in integrity checks:** Support for CRC16 or parity is built-in.
- **Zero exceptions:** Uses `std::expected` and `std::optional` for error handling to be compatible with real-time requirements.

## Validation Flow
When serializing or deserializing, validation occurs in a strict order:
1. **Field Presence**: Checks that all `Required` fields are set.
2. **Field Values**: Checks that all set fields satisfy their attached validators (e.g., `Positive`, `Even`). All aggregate fields validate each element and the aggregate as a whole.
3. **Message Logic**: Executes the user-defined `Validate()` method on the message struct for cross-field logic.

Only if all three stages pass does `Serialize` succeed.

Note that validation can be bypassed by using `SerializeWithoutValidation`.

# Dependencies
*Crunch* requires C++23 and uses some STL libraries. 

*None of the STL libraries used by Crunch perform dynamic memory allocation.*

# Message Definition & Fields
Messages must define the following:
1. A unique `MessageId`
2. A `CRUNCH_MESSAGE_FIELDS` macro that lists all fields in the message
3. A `Validate` method that returns an `std::optional<Error>`
4. A `operator==` method for equality comparison.

Fields must define the following:
1. A unique field index
2. A type
3. A set of validators
4. A default value

Crunch supports the following field types:
- `Int8`
- `Int16`
- `Int32`
- `Int64`
- `UInt8`
- `UInt16`
- `UInt32`
- `UInt64`
- `Float32`
- `Float64`
- `Bool`
- `String`
- `Enum`

The `Submessage` type can be used to define another message as a field. 

The `Array` type can be used to define an array (with a fixed maximum size) of any other field type, including other submessages. `Array` is fully compatible with STL algorithms.

# Example Usage

```c++
#include <crunch.hpp>
#include <iostream>

using namespace Crunch;
using namespace Crunch::fields;
using namespace Crunch::messages;

// Messages define their fields, validators, and cross-field logic.
struct MySubmessage {
    // Declarative field list required for compile-time reflection
    CRUNCH_MESSAGE_FIELDS(f1, f2, f3, f4, f5, f6);
    
    static constexpr MessageId message_id = 100;

    // f1: Int32, Required. Must be positive and odd.
    Field<1, Required, Int32<Positive, Odd>> f1;

    // f2: Uint16, Optional. Must be even.
    Field<2, Optional, UInt16<Even>> f2;

    // f3: Bool, Required. Must be True.
    Field<3, Required, Bool<True>> f3;
    
    // f4: Float64, Required. Must be 3 +/- 0.25.
    Field<4, Required, Float64<Around<3.0, 0.25>>> f4;

    // Custom Enum
    enum class Status : int32_t { IDLE = 0, RUNNING = 1, ERROR = 2 };
    // f5: Enum, Optional. Must be one of IDLE, RUNNING.
    Field<5, Optional, Enum<Status, OneOf<Status::IDLE, Status::RUNNING>>> f5;

    // f6: max 128 character string. Cannot be "BAD".
    Field<6, Required, String<128, StringNotEquals<"BAD">>> f6;
    
    // Custom Validation logic for cross-field dependencies
    constexpr auto Validate() const -> std::optional<Error> {
        // Example: if f2 is set, f1 must be > 100
        if (f2.get().has_value() && f1.get().value_or(0) <= 100) {
             return Error::validation(1, "f1 must be > 100 if f2 is set");
        }
        return std::nullopt;
    }
    
    bool operator==(const MySubmessage&) const = default;
};

// Messages can contain submessages
struct MyMessage {
    CRUNCH_MESSAGE_FIELDS(submsg, array_field);
    static constexpr MessageId message_id = 101;

    Field<1, Required, MySubmessage> submsg;

    // Array of Float32, max 3 elements, must have at least 2 elements.
    ArrayField<2, Float32<None>, 3, LengthAtLeast<2>> array_field;
    
    constexpr auto Validate() const -> std::optional<Error> { return std::nullopt; }
    bool operator==(const MyMessage&) const = default;
};

int main() {
    // Create and populate the submessage
    MySubmessage sub_msg;
    
    // Field-level validation runs AUTOMATICALLY on set()
    // Returns std::optional<Error> to indicate success or failure.
    if (auto err = sub_msg.f1.set(-4); err) {
        // This fails because -4 is not Positive.
        std::cerr << "Failed to set f1: " << err->message << "\n";
    }

    // Use set_without_validation to bypass validation (e.g. for performance or testing)
    // Note: Strings do not support set_without_validation.
    sub_msg.f1.set_without_validation(-4); // Sets -4, validation bypassed.



    // Set valid values and check for errors
    if (auto err = sub_msg.f1.set(151); err) return 1;
    
    // f2 is optional, we can skip it or set it
    if (auto err = sub_msg.f2.set(42); err) return 1;

    // f3 must be true
    if (auto err = sub_msg.f3.set(true); err) return 1;

    // f4 must be around 3 +/- 0.25
    if (auto err = sub_msg.f4.set(3.5); err) return 1;

    // f5 must be one of IDLE, RUNNING
    if (auto err = sub_msg.f5.set(Status::RUNNING); err) return 1;
    
    // f6 must be a string of length <= 128
    if (auto err = sub_msg.f6.set("hello"); err) return 1;
    
    // Create the top-level message
    MyMessage msg;
    
    // Submessages are set by assignment/copy (no validation on set)
    msg.submsg.set(sub_msg);
    
    // Can set Arrays from a STL array.
    // Note that you can set an array that is smaller than the max size.
    std::array<float, 2> vals = {1.0, 2.0};
    if (auto err = msg.array_field.set(vals); err) return 1;

    // Serialize using CRC16 integrity and Packed layout
    auto buffer = Crunch::GetBuffer<MyMessage, Crunch::integrity::CRC16,                  
                                     Crunch::serdes::PackedLayout>();
    
    // Message-level validation runs before serialization
    if (const auto err = Crunch::Serialize(buffer, msg); err) {
        std::cerr << "Serialization failed: " << err->message << "\n";
        return 1;
    }
    
    // Deserialize into new object
    MyMessage decoded_msg;
    if (const auto err = Crunch::Deserialize(buffer, decoded_msg); err) {
        std::cerr << "Deserialization failed: " << err->message << "\n";
        return 1;
    }
    
    // submsg.get() returns a pointer to the MySubmessage instance
    std::cout << "Decoded f1: " 
              << *decoded_msg.submsg.get()->f1.get() << "\n";
    return 0;
}
```

# Serialization Layouts

Crunch supports pluggable serialization layouts. The `serdes::StaticLayout<Alignment>` policy provides a deterministic, fixed-size binary format. All multi-byte values are serialized in **Little Endian** byte order.

## Header
Every message serialized with `Serialize` currently includes a header.
- **Version (1 byte)**: Protocol version (currently `0x00`).
- **Format (1 byte)**: Identifier for the serialization format.
    - `0x01`: Packed (Alignment = 1)
    - `0x02`: Aligned 4-byte (Alignment = 4)
    - `0x03`: Aligned 8-byte (Alignment = 8)

## Static Layout
`serdes::StaticLayout<Alignment>` serializes fields in the order they are defined in `CRUNCH_MESSAGE_FIELDS`.
The payload begins with the **Message ID**.

- **Message ID (4 bytes)**: Little-endian integer matching `Message::message_id` (at start of payload).
- **Format** following ID:
    - **is_set (1 byte)**: Precedes every field. `1` if set, `0` otherwise.
    - **Padding**: Bytes `0x00` inserted to align the field value to `min(sizeof(FieldType), Alignment)`.
    - **Value (sizeof(FieldType))**: The field value in **Little Endian**.
    - **Submessages**: Serialized recursively (is_set, padding, **ID**, fields).

### Example: Alignment = 4
Consider `Int32 f1`, `Int16 f2`. `Alignment = 4`. Header is 2 bytes `[Ver][Fmt]`.

| Offset | Content | Description |
|--------|---------|-------------|
| 0 | Version | 1 byte |
| 1 | Format | 1 byte |
| 2-3 | **Padding** | 2 bytes (Align PayloadStart (4) to 4-byte boundary) |
| 4-7 | **Message ID** | 4 bytes (Start of Payload) |
| 8 | `f1` is_set | 1 byte |
| 9-11 | **Padding** | 3 bytes (Align `f1` (4 bytes) to 4-byte boundary: next 12) |
| 12-15 | `f1` Value | 4 bytes |

## Tag-Length-Value (TLV) Layout
`serdes::TlvLayout` serializes fields using a standard Protobuf-compatible Tag-Length-Value format. This layout is compact and allows for forward/backward compatibility with an evolving message format.

### Wire Types
Fields are prefixed with a **Tag**, which encodes the field ID and Wire Type:
`Tag = (FieldId << 3) | WireType`

Supported Wire Types:
- **0 (Varint)**: Int32, Int64, UInt32, UInt64, Bool, Enum. Floats are currently bit-casted and encoded as Varints.
- **1 (Length Delimited)**: String, Submessage, Array.

### Example: TLV Layout
Consider `Int32 f1` (ID=1), `String f2` (ID=2).
`f1 = 150`, `f2 = "testing"`.

**Tag ID=1 (Varint)**: `(1 << 3) | 0 = 0x08`.
**Value `150`**: Varint encoded (`10010110 00000001` -> `0x96 0x01`).

**Tag ID=2 (String)**: `(2 << 3) | 2 = 0x12`.
**Length**: `7`.
**Value**: `"testing"` (7 bytes).

Serialized payload: `0x08 0x96 0x01 0x11 0x07 't' 'e' 's' 't' 'i' 'n' 'g'`

| Offset | Content | Description |
|--------|---------|-------------|
| 0 | Version | 1 byte |
| 1 | Format | 1 byte (0x04 for TLV) |
| 2-5 | Length | 4 bytes (Payload length: 12) |
| 6 | Tag (ID=1) | 1 byte (0x08) |
| 7-8 | `f1` Value (150) | 2 bytes (0x96 0x01) |
| 9 | Tag (ID=2) | 1 byte (0x11: ID=2, Type=1) |
| 10 | `f2` Length | 1 byte (7) |
| 11-17 | `f2` Value | 7 bytes ("testing") |


# Roadmap
Already done:
- Basic message definitions
- Field and message-level validation
- Scalar fields (ints, uints, bools, floats)
- Enums
- Submessages
- Array fields
- Static layout serialization
- TLV serialization
- CRC16 and parity integrity checking
- Robust unit testing
- Documentation gen and publishing in CI
- CI/CD through GitHub Actions tests on clang and gcc

Upcoming: 
- Maps
- cppcheck
- Test coverage reporting
- QEMU based cross-platform communication testing
- Fuzz testing infrastructure
- Performance comparison of C++ impl against other message formats
- C, Rust, Python bindings

Follow along with [the dev blog](volatileint.dev) for more info on the roadmap!