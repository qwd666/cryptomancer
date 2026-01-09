# cryptomancer

A comprehensive cryptographic library for Crystal providing implementations of fundamental cryptographic algorithms following industry standards and RFC specifications.

## Overview

`cryptomancer` is a pure Crystal implementation of essential cryptographic primitives, designed to be fast, secure, and easy to use. The library focuses on providing well-tested, standards-compliant implementations of hash functions, ciphers, and other cryptographic building blocks.

### Features

- **Standards-compliant**: Implements algorithms according to RFC specifications and industry standards
- **Pure Crystal**: No external dependencies, written entirely in Crystal
- **Well-documented**: Comprehensive documentation with examples and use cases
- **Type-safe**: Leverages Crystal's type system for safer cryptographic operations
- **Performance-focused**: Optimized implementations for production use
- **Extensible**: Clean architecture for adding new algorithms

### What's Included

- **Hash Functions**: Cryptographic hash algorithms (BLAKE2b, BLAKE2bp, and more coming)
- **Ciphers**: Symmetric encryption algorithms (planned)
- **Digital Signatures**: Signature algorithms (planned)
- **Key Exchange**: Key agreement protocols (planned)

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     cryptomancer:
       github: qwd666/cryptomancer
   ```

2. Run `shards install`

## Usage

```crystal
require "cryptomancer"
```

### Available Classes

- **[`Cryptomancer::Hash::Blake2b`](docs/hash/blake2b.md)** - Fast and secure cryptographic hash function (RFC 7693)
- **[`Cryptomancer::Hash::Blake2bp`](docs/hash/blake2bp.md)** - Parallel version of BLAKE2b for multi-core systems (RFC 7693)

## Development

TODO: Write development instructions here

## Contributing

1. Fork it (<https://github.com/qwd666/cryptomancer/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Temirlan Narvsky](https://github.com/qwd666) - creator and maintainer
