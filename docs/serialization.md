# Serialization Formats {#serialization}

Crunch supports pluggable serialization layouts. This document provides comprehensive wire format specifications for each layout.

**All multi-byte values are serialized in Little Endian byte order.**

---

## Common Header

Every message includes a 2-byte header before the payload:

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | Version | 1 byte | Protocol version (`0x00`) |
| 1 | Format | 1 byte | Serialization format identifier |

**Format Values:**
- `0x01`: Packed (Alignment = 1)
- `0x02`: Aligned4 (Alignment = 4)
- `0x03`: Aligned8 (Alignment = 8)
- `0x04`: TLV

---

# Static Layout

`serdes::StaticLayout<Alignment>` produces a deterministic, fixed-size binary format. Buffer size is calculated at compile time.

> **Zero-Fill Guarantee:** All padding bytes and unset field regions are explicitly zeroed during serialization. This ensures consistent CRC/checksum values regardless of uninitialized memory content.

## Alignment Behavior

The alignment parameter controls padding insertion. For each value, padding is inserted to align the value to:

```
AlignTo = min(sizeof(ValueType), Alignment)
```

This means:
- **`StaticLayout<1>`** (Packed): No padding ever inserted
- **`StaticLayout<4>`**:
  - `Bool` (1 byte) → no padding (AlignTo = 1)
  - `Int16` (2 bytes) → aligned to 2 bytes
  - `Int32` (4 bytes) → aligned to 4 bytes
  - `Int64` (8 bytes) → aligned to 4 bytes (capped at Alignment)
- **`StaticLayout<8>`**:
  - `Bool` (1 byte) → no padding
  - `Int16` (2 bytes) → aligned to 2 bytes
  - `Int32` (4 bytes) → aligned to 4 bytes
  - `Int64` (8 bytes) → aligned to 8 bytes

## Payload Start

After the 2-byte header, the payload is aligned to `Alignment`:

| Alignment | Header End | Padding | Payload Start |
|-----------|------------|---------|---------------|
| 1 | 2 | 0 | 2 |
| 4 | 2 | 2 | 4 |
| 8 | 2 | 6 | 8 |

The payload begins with a 4-byte **Message ID** (little-endian).

## Scalar Serialization

For each scalar field:

1. **is_set byte** (1 byte): `0x01` if set, `0x00` otherwise
2. **Padding**: Bytes to align value to `min(sizeof(T), Alignment)`
3. **Value**: `sizeof(T)` bytes, little-endian

```
[is_set:1][padding:0-7][value:1-8]
```

### Type Sizes

| Type | sizeof(T) | Alignment=4 AlignTo | Alignment=8 AlignTo |
|------|-----------|---------------------|---------------------|
| Bool | 1 | 1 | 1 |
| Int8/UInt8 | 1 | 1 | 1 |
| Int16/UInt16 | 2 | 2 | 2 |
| Int32/UInt32 | 4 | 4 | 4 |
| Int64/UInt64 | 8 | 4 | 8 |
| Float32 | 4 | 4 | 4 |
| Float64 | 8 | 4 | 8 |

### Example: Bool + Int64 with Alignment=8

Offset 0 is start of payload (after message ID at offset 8).

| Offset | Content | Description |
|--------|---------|-------------|
| 12 | `f1` is_set | 1 byte |
| 13 | **No padding** | Bool aligns to 1 |
| 13 | `f1` Bool value | 1 byte |
| 14 | `f2` is_set | 1 byte |
| 15-15 | **Padding** | 1 byte to align Int64 to offset 16 (8-byte boundary) |
| 16-23 | `f2` Int64 value | 8 bytes |

## String Serialization

```
[is_set:1][padding][length:4][data:MaxSize]
```

1. **is_set** (1 byte)
2. **Padding** to align `uint32_t` length
3. **Length** (4 bytes, little-endian): Current string length
4. **Data** (`MaxSize` bytes): String content (full capacity, zero-padded)

> **Note:** The full `MaxSize` is always written, regardless of current length. This ensures fixed buffer sizes.

## Submessage Serialization

```
[is_set:1][padding][MessageId:4][fields...]
```

1. **is_set** (1 byte)
2. **Padding** to align to `Alignment` bytes
3. **MessageId** (4 bytes, little-endian)
4. **Fields** recursively serialized

If `is_set = 0`, the submessage region is zero-filled.

## Array Serialization

Arrays do **not** have an `is_set` byte.

```
[padding][length:4][element_0][element_1]...[element_MaxSize-1]
```

1. **Padding** to align `uint32_t` length
2. **Length** (4 bytes): Number of active elements
3. **Elements**: All `MaxSize` slots serialized (active elements have values, inactive are zero-filled)

### Element Serialization

Elements are serialized based on their type:
- **Scalars**: `[padding][value]` (no is_set byte)
- **Strings**: `[padding][length:4][data:MaxSize]`
- **Submessages**: `[padding][MessageId:4][fields...]`

## Map Serialization

Maps do **not** have an `is_set` byte.

```
[padding][length:4][pair_0][pair_1]...[pair_MaxSize-1]
```

1. **Padding** to align `uint32_t` length
2. **Length** (4 bytes): Number of active entries
3. **Pairs**: All `MaxSize` key-value pairs serialized

Each pair is:
```
[key][value]
```

Where `key` and `value` are serialized according to their type (scalar, string, submessage, array, or nested map).

---

# TLV Layout

`serdes::TlvLayout` uses Tag-Length-Value encoding for compact, forward-compatible serialization.

## Overall Structure

```
[Header:2][PayloadLength:4][Fields...]
```

After the 2-byte header:
1. **Payload Length** (4 bytes, little-endian): Total size of all fields
2. **Fields**: Variable-size field encodings

## Wire Types

Each field is prefixed with a **tag** that encodes both the field ID and wire type:

```
Tag = (FieldId << 3) | WireType
```

| Wire Type | Value | Used For |
|-----------|-------|----------|
| Varint | 0 | Int8-64, UInt8-64, Bool, Enum, Float32, Float64 |
| LengthDelimited | 1 | String, Submessage, Packed Array, Map Entry |

## Varint Encoding

All integers, bools, and floats are encoded as varints:

- **Integers**: Bit-cast to unsigned, then varint encoded
- **Floats**: Bit-cast to uint32/uint64, then varint encoded  
- **Bools**: `1` for true, `0` for false

Varint format: 7 bits per byte, MSB indicates continuation.

### Maximum Varint Size

A 64-bit value requires up to **10 bytes** as a varint. Crunch does not support a size that enforces fixed types.

If required, a new serialization policy that enforces fixed-sized encoding can be written if.

## Scalar Serialization (TLV)

```
[Tag:1-5][Value:1-10]
```

Only set fields are serialized. Unset fields are omitted entirely.

## String Serialization (TLV)

```
[Tag][Length:1-10][Data:N]
```

1. **Tag** with WireType = LengthDelimited
2. **Length** as varint
3. **Data**: Actual string bytes (only current length, not max capacity)

## Submessage Serialization (TLV)

```
[Tag][Length:1-10][NestedFields...]
```

1. **Tag** with WireType = LengthDelimited
2. **Length** as varint (size of nested content)
3. **Nested Fields**: Recursively TLV-encoded

### The "Shifting" Optimization

When serializing a submessage (or any length-delimited content), we don't know the final length until all content is written. Crunch handles this by:

1. **Reserve maximum space**: Write 10 bytes of placeholder for the length varint
2. **Serialize content**: Write the nested fields
3. **Calculate actual length**: Determine how many bytes were written
4. **Shift if needed**: If the actual length varint is smaller than 10 bytes, `memmove` the content backwards

For example, if nested content is 50 bytes:
- Length varint for 50 = 1 byte
- Reserved space = 10 bytes
- We shift the 50 bytes backwards by 9 positions

This avoids needing to calculate sizes in a separate pass.

## Array Serialization (TLV)

All arrays use a unified packed encoding with element count:

```
[Tag][TotalLength][Count][Elem1][Elem2]...
```

- **Tag**: Field ID with WireType = LengthDelimited
- **TotalLength**: Varint size of everything after this field
- **Count**: Varint number of elements
- **Elements**: Serialized values (no per-element tags)

For length-delimited elements (strings, submessages), each element includes its length prefix:

```
[Tag][TotalLength][Count][Len1][String1][Len2][String2]...
```

Example: `ArrayField<1, Int32<None>, 5>` with values `[1, 2, 3]`:
```
[Tag:0x09][Len:4][Count:3][01][02][03]
```

Example: `ArrayField<1, String<32>, 5>` with values `["hi", "bye"]`:
```
[Tag:0x09][Len:10][Count:2][02]"hi"[03]"bye"
```

## Map Serialization (TLV)

Maps use packed encoding with entry count:

```
[Tag][TotalLength][Count][Key1][Value1][Key2][Value2]...
```

- **Tag**: Field ID with WireType = LengthDelimited
- **TotalLength**: Varint size of map content
- **Count**: Varint number of entries
- **Key/Value pairs**: Serialized values without tags

For length-delimited keys/values, each includes its length prefix.

Example: `MapField<1, Int32<None>, String<32>, 10>` with `{42: "foo"}`:
```
[Tag:0x09][Len:6][Count:1][2A][03]"foo"
```

### Complex Keys and Values

Maps support any field type as keys or values:

| Entry Type | Encoding (no tag) |
|------------|-------------------|
| Scalar | Varint |
| String | [Length][Data] |
| Submessage | [Length][NestedFields...] |
| Array | [Length][Count][Elements...] |
| Nested Map | [Length][Count][Pairs...] |

Each nested container uses the same packed format.

---

## Size Comparison

| Layout | Size Predictability | Compact | Best For |
|--------|---------------------|---------|----------|
| `StaticLayout<1>` | Fixed at compile time | Moderate | Deterministic protocols |
| `StaticLayout<4>` | Fixed at compile time | Less compact | 32-bit aligned systems |
| `StaticLayout<8>` | Fixed at compile time | Least compact | 64-bit aligned systems |
| `TlvLayout` | Variable(*) | Most compact(*) | Evolved protocols, bandwidth-constrained |

(*) For any given message type, the encoding is variable *up to a statically determinable maximum size*. No dynamic memory allocation is required.
(*) TlvLayout is not the most compact for all data due to the varint encoding. For example, very large integers require more space than a fixed-size encoding.
