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
//! ### Examples
//!
//! The following example demonstrate how to use some of the functionalities provided by RustySSL.
//!
//! Although only the SHA-1 example is demonstrated, this pattern for extracting an `u64`, or `[u8; N]`, or a `String`
//! will be consistent with all implementations below.
//!
//! #### SHA-1
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use hash_ctx_lib::HasherContext;
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

#![no_std]

pub use hash_ctx_lib::HasherContext;
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
