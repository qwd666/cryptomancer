# BLAKE2bp

## API Usage

### Quick Start

**Simple hashing:**
```crystal
# Hash a string with default fanout (4)
hash = Cryptomancer::Hash::Blake2bp.hash("hello")
# => Returns hex string

# Hash with custom fanout
hash = Cryptomancer::Hash::Blake2bp.hash("hello", fanout: 8_u8)
# => Uses 8 parallel threads

# Get hash as bytes
hash_bytes = Cryptomancer::Hash::Blake2bp.hash("hello", as_bytes: true)
# => Bytes[228, 207, 163, 154, ...]
```

**Keyed hashing (MAC mode):**
```crystal
key = "secret_key".to_slice
mac = Cryptomancer::Hash::Blake2bp.keyed_hash("message", key, fanout: 4_u8)
# Computes Message Authentication Code using parallel processing
```

**Streaming API:**
```crystal
ctx = Cryptomancer::Hash::Blake2bp.new(fanout: 4_u8)
ctx.update("chunk1")
ctx.update("chunk2")
hash = ctx.final
```

### Method Reference

#### `.hash(data, digest_length = 64, fanout = 4, as_bytes = false)`

Computes hash of data using parallel processing.

**Parameters:**
- `data`: String or Bytes to hash
- `digest_length`: Output length in bytes (1-64, default: 64)
- `fanout`: Number of parallel threads (1-255, default: 4)
- `as_bytes`: If `true`, returns Bytes; if `false`, returns hex String

**Returns:** Bytes or String

**Examples:**
```crystal
# Default: 64-byte hash as hex string with fanout=4
hash = Cryptomancer::Hash::Blake2bp.hash("data")

# Custom digest length and fanout
hash32 = Cryptomancer::Hash::Blake2bp.hash("data", digest_length: 32_u8, fanout: 8_u8)

# Get bytes instead of hex string
hash_bytes = Cryptomancer::Hash::Blake2bp.hash("data", as_bytes: true)
```

#### `.keyed_hash(data, key, digest_length = 64, fanout = 4, as_bytes = false)`

Computes keyed hash (MAC) using parallel processing.

**Parameters:**
- `data`: String or Bytes to hash
- `key`: Secret key (Bytes, max 64 bytes)
- `digest_length`: Output length in bytes (1-64, default: 64)
- `fanout`: Number of parallel threads (1-255, default: 4)
- `as_bytes`: If `true`, returns Bytes; if `false`, returns hex String

**Returns:** Bytes or String

**Examples:**
```crystal
key = "my_secret_key".to_slice
mac = Cryptomancer::Hash::Blake2bp.keyed_hash("message", key, fanout: 4_u8)

# Verify MAC
computed_mac = Cryptomancer::Hash::Blake2bp.keyed_hash("message", key, fanout: 4_u8)
if computed_mac == received_mac
  # Message is authentic
end
```

#### `.new(digest_length = 64, fanout = 4, key = nil, salt = nil, personalization = nil, as_bytes = false)`

Creates a new parallel hash context for streaming.

**Parameters:**
- `digest_length`: Output length in bytes (1-64, default: 64)
- `fanout`: Number of parallel threads (1-255, default: 4)
- `key`: Optional key for MAC mode (Bytes, max 64 bytes)
- `salt`: Optional salt for domain separation (Bytes, exactly 16 bytes) - Applied at root node per RFC 7693
- `personalization`: Optional personalization string (Bytes, exactly 16 bytes) - Applied at root node per RFC 7693
- `as_bytes`: If `true`, `final` returns Bytes; if `false`, returns hex String

**Returns:** Blake2bp instance

**Examples:**
```crystal
# Basic usage with default fanout (4)
ctx = Cryptomancer::Hash::Blake2bp.new

# With custom fanout
ctx = Cryptomancer::Hash::Blake2bp.new(fanout: 8_u8)

# With custom digest length and fanout
ctx = Cryptomancer::Hash::Blake2bp.new(digest_length: 32_u8, fanout: 4_u8)

# With key (MAC mode)
key = "secret".to_slice
ctx = Cryptomancer::Hash::Blake2bp.new(fanout: 4_u8, key: key)

# With salt and personalization (applied at root node per RFC 7693)
salt = "random_salt_16b".to_slice
pers = "my_app_v1".to_slice[0..15]
ctx = Cryptomancer::Hash::Blake2bp.new(fanout: 4_u8, salt: salt, personalization: pers)
```

#### `.update(data)`

Adds data to the hash context. Data is distributed across parallel leaf contexts.

**Parameters:**
- `data`: String or Bytes to add

**Returns:** Nil

**Examples:**
```crystal
ctx = Cryptomancer::Hash::Blake2bp.new(fanout: 4_u8)
ctx.update("chunk1")
ctx.update("chunk2")
ctx.update("chunk3")
hash = ctx.final
```

#### `.final`

Finalizes hash computation and returns digest. All leaf contexts are finalized in parallel.

**Returns:** Bytes or String (depending on `as_bytes` option)

**Examples:**
```crystal
ctx = Cryptomancer::Hash::Blake2bp.new(fanout: 4_u8)
ctx.update("data")
hash = ctx.final  # Returns hex string by default

ctx2 = Cryptomancer::Hash::Blake2bp.new(fanout: 4_u8, as_bytes: true)
ctx2.update("data")
hash_bytes = ctx2.final  # Returns Bytes
```

### Use Cases

#### 1. High-performance file hashing
```crystal
# Hash large files using parallel processing
ctx = Cryptomancer::Hash::Blake2bp.new(fanout: 8_u8)
File.open("large_file.bin") do |file|
  while chunk = file.read(1024 * 1024) # Read 1MB chunks
    ctx.update(chunk)
  end
end
hash = ctx.final
```

#### 2. Parallel data processing
```crystal
# Process multiple data streams in parallel
data = "large_data_stream" * 10000
hash = Cryptomancer::Hash::Blake2bp.hash(data, fanout: 8_u8)
```

#### 3. API authentication with parallel MAC
```crystal
api_key = "secret_api_key".to_slice
message = "GET /api/users"
mac = Cryptomancer::Hash::Blake2bp.keyed_hash(message, api_key, fanout: 4_u8)
# Send message + mac to server
```

#### 4. Optimal fanout selection
```crystal
# For large data, use more threads
large_data = File.read("huge_file.dat")
hash = Cryptomancer::Hash::Blake2bp.hash(large_data, fanout: 16_u8)

# For small data, fewer threads may be better
small_data = "hello"
hash = Cryptomancer::Hash::Blake2bp.hash(small_data, fanout: 2_u8)
```

#### 5. Streaming with parallel processing
```crystal
ctx = Cryptomancer::Hash::Blake2bp.new(fanout: 4_u8)
File.each_line("large_file.txt") do |line|
  ctx.update(line)
end
hash = ctx.final
```

## Choosing Optimal Fanout

The choice of optimal `fanout` value depends on several factors:

- **Data size**: For large data (>1MB) use more threads (8-16)
- **Number of cores**: Usually optimal to use the number of CPU cores
- **Overhead**: For small data (<10KB) use fewer threads (1-2)
- **Default**: `fanout=4` is a good compromise for most cases

**Recommendations:**
- Small data (<100KB): `fanout=1` or `fanout=2`
- Medium data (100KB-10MB): `fanout=4` (default)
- Large data (>10MB): `fanout=8` or `fanout=16`

## Differences from BLAKE2b

- **Parallelization**: BLAKE2bp uses multiple threads, BLAKE2b uses one
- **Performance**: BLAKE2bp is faster on multi-core systems for large data
- **Overhead**: BLAKE2bp has overhead for thread coordination
- **Results**: Different fanout values produce different results (due to tree hashing structure)
- **Salt and Personalization**: In BLAKE2bp they are applied only at the root node level (RFC 7693), in BLAKE2b they are applied directly to the context

## References

- [RFC 7693](https://tools.ietf.org/html/rfc7693)
- [BLAKE2 Official Website](https://www.blake2.net/)
- [BLAKE2 Specification](https://github.com/BLAKE2/BLAKE2/blob/master/spec/blake2.pdf)
- [BLAKE2b Documentation](blake2b.md) - Sequential version documentation
