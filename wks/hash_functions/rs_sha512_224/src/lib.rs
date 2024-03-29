//! # SHA-512/224 `rs_sha512_224` - Secure Hash Algorithm 512/224
//!
//! The SHA-512/224 hash function is part of the SHA-2 family, which was developed by the National Institute of
//! Standards and Technology (NIST). This hash function is a variant of SHA-512 that outputs a hash value of 224 bits.
//!
//! This SHA-512/224 hash function is recommended by NIST for most cryptographic functions as it is designed to provide
//! a high level of security and resist known types of cryptographic attacks.
//!
//! ## Usage
//!
//! The crate provides a simple and intuitive API. Users can create a new SHA-512/224 hasher instance, update it with
//! input data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHA-512/224 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha512_224::{HasherContext, Sha512_224State};
//! let mut sha512_224hasher = Sha512_224State::default().build_hasher();
//! sha512_224hasher.write(b"hello world");
//! let u64result = sha512_224hasher.finish();
//! let bytes_result = HasherContext::finish(&mut sha512_224hasher);
//! assert_eq!(u64result, 0x22E0D52336F64A99);
//! assert_eq!(
//!     format!("{bytes_result:02x}"),
//!     "22e0d52336f64a998085078b05a6e37b26f8120f43bf4db4c43a64ee"
//! );
//! assert_eq!(
//!     format!("{bytes_result:02X}"),
//!     "22E0D52336F64A998085078B05A6E37B26F8120F43BF4DB4C43A64EE"
//! );
//! assert_eq!(
//!     bytes_result,
//!     [
//!         0x22, 0xE0, 0xD5, 0x23, 0x36, 0xF6, 0x4A, 0x99, 0x80, 0x85, 0x07, 0x8B, 0x05, 0xA6, 0xE3, 0x7B, 0x26, 0xF8, 0x12,
//!         0x0F, 0x43, 0xBF, 0x4D, 0xB4, 0xC4, 0x3A, 0x64, 0xEE
//!     ]
//! )
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha512_224::Sha512_224Hasher;
//! let hello = "hello";
//! let mut sha512_224hasher1 = Sha512_224Hasher::default();
//! let mut sha512_224hasher2 = Sha512_224Hasher::default();
//! let mut sha512_224hasher3 = Sha512_224Hasher::default();
//!
//! sha512_224hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha512_224hasher2);
//! sha512_224hasher3.write(hello.as_bytes());
//! sha512_224hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha512_224hasher1.finish();
//! let u64result2 = sha512_224hasher2.finish();
//! let u64result3 = sha512_224hasher3.finish();
//!
//! assert_eq!(u64result1, 0xFE8509ED1FB7DCEF);
//! assert_eq!(u64result2, 0x22D64CC041AA25EA);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA-512/224 is widely used in various security-critical tasks, such as:
//!
//! - Ensuring data integrity in cryptographic systems.
//! - Digital signatures and certificate thumbprints.
//! - In checksumming, where a unique identifier for data is needed.
//! - Fingerprinting, where unique identifiers are used to mark or identify unique data elements.
//!
//! [NIST](https://www.nist.gov/) recommends using SHA-512/224 for most cryptographic functions, as it provides a good balance
//! between security and performance.
//!

#![no_std]

pub use rs_hasher_ctx::HasherContext;
pub use sha512_224hasher::Sha512_224Hasher;
pub use sha512_224state::Sha512_224State;

mod sha512_224hasher;
mod sha512_224state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 28;
