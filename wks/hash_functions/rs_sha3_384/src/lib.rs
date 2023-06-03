//! # SHA3-384 `rs-sha3-384` - Secure Hash Algorithm KECCAK-based variant
//!
//! The SHA3-384 hash function is part of the SHA-3 family, which was developed by the National Institute of Standards and
//! Technology (NIST). Unlike SHAKE256, SHA3-384 produces a fixed-size output of 384 bits.
//!
//! SHA3-384 is suitable for a variety of cryptographic purposes, including generating unique identifiers and ensuring data integrity. It's widely trusted and remains a popular choice for hash functions that require longer digests.
//!
//! ## Usage
//!
//! The crate provides a straightforward and intuitive API. Users can create a new SHA3-384 hasher instance, update it with input
//! data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHA3-384 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha3_384::Sha3_384State;
//! let mut sha3_384hasher = Sha3_384State::default().build_hasher();
//! sha3_384hasher.write(b"hello world");
//! let result = sha3_384hasher.finish();
//! assert_eq!(result, 0xF51B1BDE8DF2BF83);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha3_384::Sha3_384State;
//! let hello = "hello";
//! let sha3_384state = Sha3_384State::default();
//! let mut sha3_384hasher1 = sha3_384state.build_hasher();
//! let mut sha3_384hasher2 = sha3_384state.build_hasher();
//! let mut sha3_384hasher3 = sha3_384state.build_hasher();
//!
//! sha3_384hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha3_384hasher2);
//! sha3_384hasher3.write(hello.as_bytes());
//! sha3_384hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha3_384hasher1.finish();
//! let u64result2 = sha3_384hasher2.finish();
//! let u64result3 = sha3_384hasher3.finish();
//!
//! assert_eq!(u64result1, 0x64F09E0111EA0A72);
//! assert_eq!(u64result2, 0x475114145D6365DE);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA3-384 is recommended for a wide variety of tasks, including:
//!
//! - Cryptographic security, due to its resistance to collision attacks.
//! - Creating unique identifiers for data.
//! - Ensuring data integrity in situations where a larger hash value is beneficial.
//!
//! [NIST](https://www.nist.gov/) recommends SHA3-384 for cryptographic functions due to its security and versatility. Its fixed-length output makes it particularly suitable when a longer hash value is required.
//!

#![no_std]

pub use rs_hasher_ctx::HasherContext;
pub use sha3_384hasher::Sha3_384Hasher;
pub use sha3_384state::Sha3_384State;

mod sha3_384hasher;
mod sha3_384state;

#[cfg(test)]
mod unit_tests;

const OUTPUT_SIZE: usize = 48;
