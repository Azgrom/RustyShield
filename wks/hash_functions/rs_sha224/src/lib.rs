//! # SHA-224 `rs_sha224` - Secure Hash Algorithm 224
//!
//! The SHA-224 hash function is a variant of SHA-2, a set of cryptographic hash functions designed by the National
//! Institute of Standards and Technology (NIST). It is often used in cryptographic applications and protocols where a
//! shorter hash value is preferred over the SHA-256 variant.
//!
//! ## Usage
//!
//! The crate provides a user-friendly API. Users can create a new SHA-224 hasher instance, update it with input data,
//! and finalize to acquire the resultant hash.
//!
//! ### Example
//!
//! Here's an example showcasing the usage of SHA-224 in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha224::Sha224State;
//! let mut sha224hasher = Sha224State::default().build_hasher();
//! sha224hasher.write(b"hello world");
//! let result = sha224hasher.finish();
//! assert_eq!(result, 0x2F05477FC24BB4FA);
//! ```
//!
//! Additionally, as a `HashSet`:
//!
//! ```rust
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha224::Sha224Hasher;
//! let hello = "hello";
//! let mut sha224hasher1 = Sha224Hasher::default();
//! let mut sha224hasher2 = Sha224Hasher::default();
//! let mut sha224hasher3 = Sha224Hasher::default();
//!
//! sha224hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha224hasher2);
//! sha224hasher3.write(hello.as_bytes());
//! sha224hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha224hasher1.finish();
//! let u64result2 = sha224hasher2.finish();
//! let u64result3 = sha224hasher3.finish();
//!
//! assert_eq!(u64result1, 0xEA09AE9CC6768C50);
//! assert_eq!(u64result2, 0xA9AA04A46DD5B8F7);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA-224 is frequently employed in numerous cryptographic applications and protocols, including:
//!
//! - TLS and SSL, IPsec, SSH, and IPsec for network communication security.
//! - Digital signatures and certificate authorities for data integrity and sender authentication.
//!
//! According to [NIST](https://www.nist.gov/), SHA-224 is recommended for most applications until 2030, except when
//! SHA-384, SHA-512, SHA-512/224 or SHA-512/256 is required.
//!

#![no_std]

pub use rs_hasher_ctx::HasherContext;
pub use sha224hasher::Sha224Hasher;
pub use sha224state::Sha224State;

mod sha224hasher;
mod sha224state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 28;
