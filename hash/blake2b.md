# BLAKE2b

## API Usage

### Quick Start

**Simple hashing:**
```crystal
# Hash a string (returns hex string by default)
hash = Cryptomancer::Hash::Blake2b.hash("hello")
# => "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65af1e2cdb19c407749b64eea16b86b0a2b115e2c3c2a7ae68556b3e46b3e5b5bd"

# Get hash as bytes
hash_bytes = Cryptomancer::Hash::Blake2b.hash("hello", as_bytes: true)
# => Bytes[228, 207, 163, 154, ...]
```

**Keyed hashing (MAC mode):**
```crystal
key = "secret_key".to_slice
mac = Cryptomancer::Hash::Blake2b.keyed_hash("message", key)
# Computes Message Authentication Code using the secret key
```

**Streaming API:**
```crystal
ctx = Cryptomancer::Hash::Blake2b.new
ctx.update("hello")
ctx.update(" world")
hash = ctx.final
```

### Method Reference

#### `.hash(data, digest_length = 64, as_bytes = false)`

Computes hash of data in one call.

**Parameters:**
- `data`: String or Bytes to hash
- `digest_length`: Output length in bytes (1-64, default: 64)
- `as_bytes`: If `true`, returns Bytes; if `false`, returns hex String

**Returns:** Bytes or String

**Examples:**
```crystal
# Default: 64-byte hash as hex string
hash = Cryptomancer::Hash::Blake2b.hash("data")

# Custom digest length
hash32 = Cryptomancer::Hash::Blake2b.hash("data", digest_length: 32)

# Get bytes instead of hex string
hash_bytes = Cryptomancer::Hash::Blake2b.hash("data", as_bytes: true)
```

#### `.keyed_hash(data, key, digest_length = 64, as_bytes = false)`

Computes keyed hash (MAC) for message authentication.

**Parameters:**
- `data`: String or Bytes to hash
- `key`: Secret key (Bytes, max 64 bytes)
- `digest_length`: Output length in bytes (1-64, default: 64)
- `as_bytes`: If `true`, returns Bytes; if `false`, returns hex String

**Returns:** Bytes or String

**Examples:**
```crystal
key = "my_secret_key".to_slice
mac = Cryptomancer::Hash::Blake2b.keyed_hash("message", key)

# Verify MAC
computed_mac = Cryptomancer::Hash::Blake2b.keyed_hash("message", key)
if computed_mac == received_mac
  # Message is authentic
end
```

#### `.new(digest_length = 64, key = nil, salt = nil, personalization = nil, as_bytes = false)`

Creates a new hash context for streaming.

**Parameters:**
- `digest_length`: Output length in bytes (1-64, default: 64)
- `key`: Optional key for MAC mode (Bytes, max 64 bytes)
- `salt`: Optional salt for domain separation (Bytes, exactly 16 bytes)
- `personalization`: Optional personalization string (Bytes, exactly 16 bytes)
- `as_bytes`: If `true`, `final` returns Bytes; if `false`, returns hex String

**Returns:** Blake2b instance

**Examples:**
```crystal
# Basic usage
ctx = Cryptomancer::Hash::Blake2b.new

# With custom digest length
ctx = Cryptomancer::Hash::Blake2b.new(digest_length: 32)

# With key (MAC mode)
key = "secret".to_slice
ctx = Cryptomancer::Hash::Blake2b.new(key: key)

# With salt and personalization
salt = "random_salt_16b".to_slice
pers = "my_app_v1".to_slice[0..15]
ctx = Cryptomancer::Hash::Blake2b.new(salt: salt, personalization: pers)

# Return bytes instead of hex string
ctx = Cryptomancer::Hash::Blake2b.new(as_bytes: true)
```

#### `.update(data)`

Adds data to the hash context. Can be called multiple times.

**Parameters:**
- `data`: String or Bytes to add

**Returns:** Nil

**Examples:**
```crystal
ctx = Cryptomancer::Hash::Blake2b.new
ctx.update("hello")
ctx.update(" ")
ctx.update("world")
hash = ctx.final
```

#### `.final`

Finalizes hash computation and returns digest. Can only be called once per context.

**Returns:** Bytes or String (depending on `as_bytes` option)

**Examples:**
```crystal
ctx = Cryptomancer::Hash::Blake2b.new
ctx.update("data")
hash = ctx.final  # Returns hex string by default

ctx2 = Cryptomancer::Hash::Blake2b.new(as_bytes: true)
ctx2.update("data")
hash_bytes = ctx2.final  # Returns Bytes
```

### Use Cases

#### 1. File integrity verification
```crystal
file_content = File.read("file.txt")
hash = Cryptomancer::Hash::Blake2b.hash(file_content)
# Store hash for later verification
```

#### 2. Password hashing (with salt)
```crystal
password = "user_password"
salt = Random::Secure.random_bytes(16)
hash = Cryptomancer::Hash::Blake2b.new(salt: salt).hash(password)
```

#### 3. API authentication (MAC mode)
```crystal
api_key = "secret_api_key".to_slice
message = "GET /api/users"
mac = Cryptomancer::Hash::Blake2b.keyed_hash(message, api_key)
# Send message + mac to server
```

#### 4. Domain separation (with personalization)
```crystal
# Different contexts produce different hashes for same input
pers1 = "password_hash".to_slice[0..15]
pers2 = "key_derivation".to_slice[0..15]

hash1 = Cryptomancer::Hash::Blake2b.new(personalization: pers1).hash("data")
hash2 = Cryptomancer::Hash::Blake2b.new(personalization: pers2).hash("data")
# hash1 != hash2
```

#### 5. Streaming large data
```crystal
ctx = Cryptomancer::Hash::Blake2b.new
File.each_line("large_file.txt") do |line|
  ctx.update(line)
end
hash = ctx.final
```

## References

- [RFC 7693](https://tools.ietf.org/html/rfc7693)
- [BLAKE2 Official Website](https://www.blake2.net/)
- [BLAKE2 Specification](https://github.com/BLAKE2/BLAKE2/blob/master/spec/blake2.pdf)

