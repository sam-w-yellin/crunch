# Decoder

The `Decoder` class deserializes one of multiple possible message types from a buffer based on the message ID in the header. This is used to decode messages received from an interface that may send multiple different message types.

## Usage

```cpp
#include <crunch/crunch.hpp>

using namespace Crunch;

// Define message types (each with a unique message_id)
struct MessageA {
    static constexpr MessageId message_id = 0x0001;
    // ... fields
};

struct MessageB {
    static constexpr MessageId message_id = 0x0002;
    // ... fields
};

// Create a decoder for these message types
using MyDecoder = Decoder<serdes::PackedLayout, integrity::CRC16,
                          MessageA, MessageB>;

// Decode a buffer
MyDecoder decoder;
MyDecoder::VariantType message;
auto err = decoder.Decode(buffer_span, message);

if (!err) {
    // Success - check which message type was decoded
    if (std::holds_alternative<MessageA>(message)) {
        auto& msgA = std::get<MessageA>(message);
        // Handle MessageA
    } else if (std::holds_alternative<MessageB>(message)) {
        auto& msgB = std::get<MessageB>(message);
        // Handle MessageB
    }
} else {
    // Handle error
}
```

## Error Handling

| Error | Cause |
|-------|-------|
| `buffer too small for header` | Buffer smaller than 6 bytes (header size) |
| `invalid_message_id` | Header's message ID doesn't match any registered type |
| Deserialization errors | Field parsing failures (passed through from `Deserialize`) |
