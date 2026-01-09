# TODO: Cipher Algorithms

## AES (Advanced Encryption Standard)

**Standards:**
- FIPS PUB 197: Advanced Encryption Standard (AES)
- ISO/IEC 18033-3: Information technology — Security techniques — Encryption algorithms — Part 3: Block ciphers
- NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation
- RFC 3394: Advanced Encryption Standard (AES) Key Wrap Algorithm
- RFC 3602: The AES-CBC Cipher Algorithm and Its Use with IPsec

**Description:**
AES is a symmetric block cipher selected by NIST in 2001 to replace DES. Supports key sizes of 128, 192, and 256 bits with corresponding number of rounds (10, 12, 14). Widely used in TLS/SSL, VPN, disk encryption, and is the de facto standard for symmetric encryption. Supports multiple modes of operation including CBC, CTR, GCM (recommended for authenticated encryption).

**References:**
- [FIPS PUB 197](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
- [NIST SP 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [ISO/IEC 18033-3](https://www.iso.org/standard/54531.html)

---

## ChaCha20

**Standards:**
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- RFC 7905: ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
- RFC 7539: ChaCha20 and Poly1305 for IETF Protocols (obsolete, replaced by RFC 8439)

**Description:**
ChaCha20 is a stream cipher designed by Daniel J. Bernstein, a variant of Salsa20 with improved diffusion. Uses a 256-bit key, 96-bit nonce, and performs 20 rounds. Widely used in TLS 1.3, WireGuard, and the Signal protocol. Typically used in combination with Poly1305 for authenticated encryption (ChaCha20-Poly1305). Faster than AES in pure software implementations and does not require hardware acceleration.

**References:**
- [RFC 8439](https://tools.ietf.org/html/rfc8439)
- [RFC 7905](https://tools.ietf.org/html/rfc7905)

---

## ECDSA (Elliptic Curve Digital Signature Algorithm)

**Standards:**
- FIPS PUB 186-4: Digital Signature Standard (DSS)
- FIPS PUB 186-5: Digital Signature Standard (DSS) - updated version
- SEC 1: Elliptic Curve Cryptography (from Certicom)
- RFC 6090: Fundamental Elliptic Curve Cryptography Algorithms
- ISO/IEC 15946: Information technology — Security techniques — Cryptographic techniques based on elliptic curves

**Description:**
ECDSA is a digital signature algorithm on elliptic curves that provides the same level of security as RSA but with much smaller key sizes. Supports NIST curves (P-224, P-256, P-384, P-521) and secp256k1 (used in Bitcoin). Widely used in TLS/SSL certificates, cryptocurrencies, and digital signatures. Requires cryptographically strong random number generation for each signature; deterministic ECDSA (RFC 6979) is recommended.

**References:**
- [FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- [FIPS PUB 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
- [SEC 1](https://www.secg.org/sec1-v2.pdf)
- [RFC 6090](https://tools.ietf.org/html/rfc6090)
- [RFC 6979](https://tools.ietf.org/html/rfc6979) - Deterministic ECDSA

---

## Ed25519

**Standards:**
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- FIPS PUB 186-5: Digital Signature Standard (DSS) - includes EdDSA

**Description:**
Ed25519 is a modern digital signature algorithm based on the EdDSA scheme using the Curve25519 curve. Designed by Daniel J. Bernstein et al. Uses 256-bit keys and creates 512-bit signatures, providing ~128-bit security. Deterministic signatures do not require random number generation for each signature, simplifying secure implementation. Widely used in SSH, code signing (Git), cryptocurrencies (Monero, Stellar), and modern security protocols.

**References:**
- [RFC 8032](https://tools.ietf.org/html/rfc8032)
- [Ed25519 Paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf)
- [Daniel J. Bernstein's Ed25519 Page](https://ed25519.cr.yp.to/)
- [FIPS PUB 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)

---

## RSA

**Standards:**
- PKCS #1: RSA Cryptography Specifications Version 2.2 (RFC 8017)
- FIPS PUB 186-4: Digital Signature Standard (DSS)
- RFC 3447: Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1
- RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2
- ISO/IEC 18033-2: Information technology — Security techniques — Encryption algorithms — Part 2: Asymmetric ciphers

**Description:**
RSA is one of the first public-key cryptosystems, based on the mathematical complexity of factoring large composite numbers. Typically uses key sizes of 2048, 3072, or 4096 bits (1024-bit keys are obsolete). Can be used for encryption, digital signatures, and key exchange. Widely used in TLS/SSL certificates, digital signatures, and email encryption. OAEP is recommended for encryption and PSS for signatures instead of the obsolete PKCS#1 v1.5.

**References:**
- [RFC 8017](https://tools.ietf.org/html/rfc8017)
- [RFC 3447](https://tools.ietf.org/html/rfc3447)
- [FIPS PUB 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)

---

## X25519

**Standards:**
- RFC 7748: Elliptic Curves for Security
- RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Version 1.2 and Earlier
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3

**Description:**
X25519 is an elliptic curve Diffie-Hellman (ECDH) key exchange protocol using the Curve25519 curve, designed by Daniel J. Bernstein. Uses 256-bit keys (32 bytes) and provides ~128-bit security. One of the preferred key exchange methods in TLS 1.3, also used in WireGuard, SSH, and the Signal protocol. Provides fast key exchange with constant-time operations resistant to timing attacks.

**References:**
- [RFC 7748](https://tools.ietf.org/html/rfc7748)
- [RFC 8446](https://tools.ietf.org/html/rfc8446)
- [Curve25519 Paper](https://cr.yp.to/ecdh/curve25519-20060209.pdf)
- [Daniel J. Bernstein's Curve25519 Page](https://cr.yp.to/ecdh.html)
