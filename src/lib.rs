//! # RustySSL: Advanced Cryptographic Library for Modern Applications
//!
//! This library provides comprehensive cryptographic functions inspired by OpenSSL, within the Rust ecosystem.
//! The vision behind RustySSL is to establish a solid foundation within the Rust language by seamlessly integrating with
//! its core library. As a result, RustySSL furnishes a reliable, user-friendly, standards-compliant, and
//! platform-agnostic suite of encryption tools.
//!
//! ## Usage
//!
//! This create delivers its functionality via an API that seamlessly integrates with Rust's core library. By adhering
//! to the [`Hash`, `Hasher`, and `BuildHasher` design pattern from Rust's core library](https://doc.rust-lang.org/core/hash/index.html) design pattern from Rust's core library, the API enables users to
//! effortlessly employ any algorithm, provided they possess a basic understanding of these traits.
//!
//! ## Examples
//!
//! The following example demonstrate how to use some of the functionalities provided by RustySSL.
//!
//! Although only the SHA-1 example is demonstrated, this pattern for extracting an `u64`, or `[u8; N]`, or a `String`
//! will be consistent with all implementations below.
//!
//! ### SHA-1
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_hasher_ctx_lib::HasherContext;
//! # use rs_ssl::Sha1State;
//! let mut sha1hasher = Sha1State::default().build_hasher();
//! sha1hasher.write(b"hello");
//! let u64result = sha1hasher.finish();
//! let bytes_result = HasherContext::finish(&mut sha1hasher);
//!
//! assert_eq!(u64result, 0xAAF4C61DDCC5E8A2);
//! assert_eq!(
//!     bytes_result,
//!     [
//!         0xAA, 0xF4, 0xC6, 0x1D, 0xDC, 0xC5, 0xE8, 0xA2, 0xDA, 0xBE,
//!         0xDE, 0x0F, 0x3B, 0x48, 0x2C, 0xD9, 0xAE, 0xA9, 0x43, 0x4D
//!     ]
//! );
//! assert_eq!(format!("{bytes_result:02x}"), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
//! ```
//!
//! For examples on a specific algorithm click on it below:
//!
//! ## Current algorithms
//!
//! | Ciphers                       | Hashing Functions                                            | Public-key                                  |
//! | :---------------------------- | :----------------------------------------------------------- | :------------------------------------------ |
//! | AES - `coming soon`           | SHA-1 - [`rs_sha1`](../rs_sha1/index.html)                   | RSA - `coming soon`                         |
//! | Blowfish - `coming soon`      | SHA-224  - [`rs_sha224`](../rs_sha224/index.html)            | DSA - `coming soon`                         |
//! | Camellia - `coming soon`      | SHA-256 - [`rs_sha256`](../rs_sha256/index.html)             | Diffie-Hellman key exchange - `coming soon` |
//! | Chacha20 - `coming soon`      | SHA-384 - [`rs_sha384`](../rs_sha384/index.html)             | Elliptic curve - `coming soon`              |
//! | Poly1305 - `coming soon`      | SHA-512 - [`rs_sha512`](../rs_sha512/index.html)             | X25519 - `coming soon`                      |
//! | SEED - `coming soon`          | SHA-512/224 - [`rs_sha512_224`](../rs_sha512_224/index.html) | Ed25519 - `coming soon`                     |
//! | CAST-128 - `coming soon`      | SHA-512/256 - [`rs_sha512_256`](../rs_sha512_256/index.html) | X448 - `coming soon`                        |
//! | DES - `coming soon`           | SHA3-224 - [`rs_sha3_224`](../rs_sha3_224/index.html)        | Ed448 - `coming soon`                       |
//! | IDEA - `coming soon`          | SHA3-256 - [`rs_sha3_256`](../rs_sha3_256/index.html)        | GOST R 34.10-2001 - `coming soon`           |
//! | RC2 - `coming soon`           | SHA3-384 - [`rs_sha3_384`](../rs_sha3_384/index.html)        | SM2 - `coming soon`                         |
//! | RC4 - `coming soon`           | SHA3-512 - [`rs_sha3_512`](../rs_sha3_512/index.html)        |                                             |
//! | RC5 - `coming soon`           | SHAKE128 - [`rs_shake128`](../rs_shake128/index.html)        |                                             |
//! | Triple DES - `coming soon`    | SHAKE256 - [`rs_shake256`](../rs_shake256/index.html)        |                                             |
//! | GOST 28147-89 - `coming soon` | HMAC - [`rs_hmac`](../rs_hmac/index.html)                    |                                             |
//! | SM4 - `coming soon`           | Generic Keccak {200, 400, 800, 1600} - [`rs_keccak_nbits`](../rs_keccak_nbits/index.html) |                                             |
//! |                               | BLAKE2 - `coming soon`                                       |                                             |
//! |                               | GOST R 34.11-94 - `coming soon`                              |                                             |
//! |                               | MD2 - `coming soon`                                          |                                             |
//! |                               | MD4 - `coming soon`                                          |                                             |
//! |                               | MD5 - `coming soon`                                          |                                             |
//! |                               | MDC-2 - `coming soon`                                        |                                             |
//! |                               | RIPEMD-160 - `coming soon`                                   |                                             |
//! |                               | SM3 - `coming soon`                                          |                                             |
//! |                               | Whirlpool - `coming soon`                                    |                                             |
//!
//!  ## On Hash Trait and Trailing Byte
//!
//! The Rust `Hash` trait includes [a mechanism to guard against prefix collision attacks](https://doc.rust-lang.org/1.69.0/std/hash/trait.Hash.html#prefix-collisions) that appends a
//!  trailing byte `0xFF` if to the data fed is of type `&str` and is passed through the hash function.
//!
//! This behavior can have implications when using the `Hash` trait for data processing. If you pass data to the hash
//! function through the `Hash` trait, it will include this additional `0xFF` byte at the end. While this does not
//! affect the general usage of the hash function, it does modify the input data.
//!
//! Therefore, if you need to get a hash of exact input data (without a trailing `0xFF`), you should not use the `Hash`
//! trait. Instead, directly use the provided hashing algorithm API.
//!
//! It's worth noting that this `0xFF` trailing byte is not a part of the original algorithm specification, but a part
//! of the Rust `Hash` trait's design to prevent prefix collision attacks. Thus, when comparing hash values generated
//! from this library with values generated by different implementations, ensure the input data includes the `0xFF`
//! trailing byte or pass the input data as a byte slice to the `Hasher::write()` on this API.
//!

#![no_std]

pub use rs_hasher_ctx_lib::HasherContext;
pub use rs_hmac::Hmac;
pub use rs_keccak_nbits::{NBitKeccakHasher, NBitKeccakState};
pub use rs_sha1::{Sha1Hasher, Sha1State};
pub use rs_sha224::{Sha224Hasher, Sha224State};
pub use rs_sha256::{Sha256Hasher, Sha256State};
pub use rs_sha384::{Sha384Hasher, Sha384State};
pub use rs_sha3_224::{Sha3_224Hasher, Sha3_224State};
pub use rs_sha3_256::{Sha3_256Hasher, Sha3_256State};
pub use rs_sha3_384::{Sha3_384Hasher, Sha3_384State};
pub use rs_sha3_512::{Sha3_512Hasher, Sha3_512State};
pub use rs_sha512::{Sha512Hasher, Sha512State};
pub use rs_sha512_224::{Sha512_224Hasher, Sha512_224State};
pub use rs_sha512_256::{Sha512_256Hasher, Sha512_256State};
pub use rs_shake128::{Shake128Hasher, Shake128State};
pub use rs_shake256::{Shake256Hasher, Shake256State};
