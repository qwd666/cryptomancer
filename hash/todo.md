# TODO: Hash Algorithms

## SHA-256 (SHA-2)

**Standards:**
- FIPS PUB 180-4: Secure Hash Standard (SHS)
- RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
- ISO/IEC 10118-3: Information technology — Security techniques — Hash-functions — Part 3: Dedicated hash-functions

**Description:**
SHA-256 is a cryptographic hash function from the SHA-2 family, producing a 256-bit (32-byte) hash value. Designed by the NSA and standardized by NIST in 2001. Uses the Merkle-Damgård construction with 64 rounds of compression. Widely used in TLS/SSL, Bitcoin, digital signatures, and data integrity verification. Provides 128-bit collision resistance and 256-bit preimage resistance. Currently secure and recommended for most applications.

**References:**
- [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [RFC 6234](https://tools.ietf.org/html/rfc6234)
- [NIST Cryptographic Standards](https://csrc.nist.gov/publications/detail/fips/180/4/final)

---

## SHA-512 (SHA-2)

**Standards:**
- FIPS PUB 180-4: Secure Hash Standard (SHS)
- RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
- ISO/IEC 10118-3: Information technology — Security techniques — Hash-functions — Part 3: Dedicated hash-functions

**Description:**
SHA-512 is a cryptographic hash function from the SHA-2 family, producing a 512-bit (64-byte) hash value. Uses 80 rounds of compression and operates on 64-bit words, making it faster than SHA-256 on 64-bit platforms. Provides 256-bit collision resistance and 512-bit preimage resistance. Used in high-security applications, digital signatures requiring longer hashes, and when higher security margins are needed. SHA-384 is a truncated version of SHA-512.

**References:**
- [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [RFC 6234](https://tools.ietf.org/html/rfc6234)
- [NIST Cryptographic Standards](https://csrc.nist.gov/publications/detail/fips/180/4/final)

---

## SHA-384 (SHA-2)

**Standards:**
- FIPS PUB 180-4: Secure Hash Standard (SHS)
- RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
- ISO/IEC 10118-3: Information technology — Security techniques — Hash-functions — Part 3: Dedicated hash-functions

**Description:**
SHA-384 is a truncated version of SHA-512, producing a 384-bit (48-byte) hash value. Uses the same algorithm as SHA-512 but with different initial hash values and truncates the output to 384 bits. Provides 192-bit collision resistance and 384-bit preimage resistance. Commonly used in TLS/SSL certificates and digital signatures where a balance between security and output size is needed. Recommended for applications requiring security between SHA-256 and SHA-512.

**References:**
- [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [RFC 6234](https://tools.ietf.org/html/rfc6234)

---

## SHA3-256

**Standards:**
- FIPS PUB 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- ISO/IEC 10118-3: Information technology — Security techniques — Hash-functions — Part 3: Dedicated hash-functions (includes SHA-3)

**Description:**
SHA3-256 is a cryptographic hash function from the SHA-3 family, producing a 256-bit (32-byte) hash value. Based on the Keccak-f[1600] permutation, fundamentally different from SHA-2's Merkle-Damgård construction. Provides 128-bit collision resistance and 256-bit preimage resistance. Designed to be secure even if SHA-2 is broken, offering an alternative hash function. Uses sponge construction and is resistant to length-extension attacks. Recommended for applications requiring diversity from SHA-2 or when SHA-3's properties are needed.

**References:**
- [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [Keccak Team](https://keccak.team/)

---

## SHA3-512

**Standards:**
- FIPS PUB 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- ISO/IEC 10118-3: Information technology — Security techniques — Hash-functions — Part 3: Dedicated hash-functions (includes SHA-3)

**Description:**
SHA3-512 is a cryptographic hash function from the SHA-3 family, producing a 512-bit (64-byte) hash value. Based on the Keccak-f[1600] permutation using sponge construction. Provides 256-bit collision resistance and 512-bit preimage resistance. Offers the highest security level in the SHA-3 family. Used in high-security applications, digital signatures requiring long hashes, and when maximum security is needed. Resistant to length-extension attacks and provides security even if SHA-2 is compromised.

**References:**
- [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [Keccak Team](https://keccak.team/)

---

## SHA3-384

**Standards:**
- FIPS PUB 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- ISO/IEC 10118-3: Information technology — Security techniques — Hash-functions — Part 3: Dedicated hash-functions (includes SHA-3)

**Description:**
SHA3-384 is a cryptographic hash function from the SHA-3 family, producing a 384-bit (48-byte) hash value. Based on the Keccak-f[1600] permutation using sponge construction. Provides 192-bit collision resistance and 384-bit preimage resistance. Offers a balance between security and output size in the SHA-3 family. Used in applications requiring security between SHA3-256 and SHA3-512. Resistant to length-extension attacks and provides an alternative to SHA-384.

**References:**
- [FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [Keccak Team](https://keccak.team/)

---

## BLAKE2b

**Standards:**
- RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
- BLAKE2 Specification: Official BLAKE2 specification document

**Description:**
BLAKE2b is a cryptographic hash function designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein. Produces variable-length output (1-64 bytes, default 64 bytes). Faster than MD5, SHA-1, SHA-2, and SHA-3 on modern CPUs. Uses 12 rounds of compression based on ChaCha stream cipher. Supports keyed hashing (MAC mode), salt, and personalization strings. Widely used in password hashing, file integrity verification, and high-performance applications. Provides 256-bit collision resistance for 64-byte output.

**References:**
- [RFC 7693](https://tools.ietf.org/html/rfc7693)
- [BLAKE2 Official Website](https://www.blake2.net/)
- [BLAKE2 Specification](https://github.com/BLAKE2/BLAKE2/blob/master/spec/blake2.pdf)

---

## BLAKE2bp

**Standards:**
- RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
- BLAKE2 Specification: Official BLAKE2 specification document

**Description:**
BLAKE2bp is the parallel version of BLAKE2b, designed for multi-core systems. Uses tree hashing with multiple parallel BLAKE2b instances (fanout parameter, typically 1-255). Distributes data across parallel leaf contexts and combines results at the root. Significantly faster than BLAKE2b on multi-core systems for large data. Supports the same features as BLAKE2b (keyed hashing, salt, personalization). Optimal for high-performance file hashing and parallel data processing. Salt and personalization are applied only at the root node level per RFC 7693.

**References:**
- [RFC 7693](https://tools.ietf.org/html/rfc7693)
- [BLAKE2 Official Website](https://www.blake2.net/)
- [BLAKE2 Specification](https://github.com/BLAKE2/BLAKE2/blob/master/spec/blake2.pdf)

---

## BLAKE3

**Standards:**
- BLAKE3 Specification: Official BLAKE3 specification (draft/RFC in process)
- C2SP: BLAKE3 specification document

**Description:**
BLAKE3 is a cryptographic hash function designed by Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn. Improved version of BLAKE2 with better performance, built-in parallelization, and simpler design. Uses Merkle tree structure (Merkle-DAG) enabling parallel hashing and incremental verification. Produces variable-length output up to 2^64-1 bytes (extendable output function, XOF). Uses 7 rounds (reduced from 12 in BLAKE2) while maintaining security through better diffusion. Typically 2-3 times faster than BLAKE2. Supports keyed hashing, context strings, and incremental hashing. Provides 256-bit security level.

**References:**
- [BLAKE3 Official Website](https://github.com/BLAKE3-team/BLAKE3)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [C2SP BLAKE3](https://github.com/C2SP/C2SP/blob/main/BLAKE3.md)
