//! # SHA3-256 `rs_sha3_256` - Secure Hash Algorithm 3 variant
//!
//! The SHA3-256 hash function is a member of the SHA-3 family, crafted by the National Institute of Standards and
//! Technology (NIST). Unlike SHAKE256, SHA3-256 generates a fixed-size hash output of 256 bits, making it an ideal candidate for tasks requiring consistent, known-length hash values.
//!
//! SHA3-256 is applicable for a variety of cryptographic uses, such as generating unique identifiers, data integrity validation, and digital signatures. According to NIST, it is recommended for most applications that previously used SHA-2.
//!
//! ## Usage
//!
//! This crate provides an easy-to-understand API. Users can construct a new SHA3-256 hasher instance, feed it with input
//! data, and finalize it to acquire the resulting hash.
//!
//! ### Example
//!
//! Here is an example showcasing how to utilize the SHA3-256 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha3_256::Sha3_256State;
//! let mut sha3_256hasher = Sha3_256State::default().build_hasher();
//! sha3_256hasher.write(b"hello world");
//! let result = sha3_256hasher.finish();
//! assert_eq!(result, 0x644BCC7E56437304);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```rust
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha3_256::Sha3_256State;
//! let hello = "hello";
//! let sha3_256state = Sha3_256State::default();
//! let mut sha3_256hasher1 = sha3_256state.build_hasher();
//! let mut sha3_256hasher2 = sha3_256state.build_hasher();
//! let mut sha3_256hasher3 = sha3_256state.build_hasher();
//!
//! sha3_256hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha3_256hasher2);
//! sha3_256hasher3.write(hello.as_bytes());
//! sha3_256hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha3_256hasher1.finish();
//! let u64result2 = sha3_256hasher2.finish();
//! let u64result3 = sha3_256hasher3.finish();
//!
//! assert_eq!(u64result1, 0x3338BE694F50C5F3);
//! assert_eq!(u64result2, 0x230DF1A3EA0EEC77);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA3-256 is advantageous for a wide spectrum of tasks, including:
//!
//! - Ensuring cryptographic security due to its robustness against collision attacks.
//! - Crafting unique identifiers for data.
//! - Verifying data integrity in scenarios where a fixed-length hash is preferable.
//!
//! [NIST](https://www.nist.gov/) endorses SHA3-256 for cryptographic purposes owing to its security and consistency. Its fixed-size output makes it particularly favorable when a stable-length hash is indispensable.
//!

#![no_std]
#![no_main]

pub use rs_hasher_ctx::HasherContext;
pub use sha3_256hasher::Sha3_256Hasher;
pub use sha3_256state::Sha3_256State;

mod sha3_256hasher;
mod sha3_256state;

#[cfg(test)]
mod unit_tests;

const OUTPUT_SIZE: usize = 32;
