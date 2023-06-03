//! # SHAKE256 `rs-shake256` - Secure Hash Algorithm KECCAK-based variant
//!
//! The SHAKE256 hash function is part of the SHA-3 family, which was developed by the National Institute of Standards and
//! Technology (NIST). It's an Extendable Output Function (XOF), meaning it can generate a hash value of any length.
//!
//! SHAKE256 is suitable for a range of cryptographic purposes, including generating unique identifiers and ensuring data integrity. It has not been deprecated for any uses and remains one of the most versatile hash functions available.
//!
//! ## Usage
//!
//! The crate provides a simple and intuitive API. Users can create a new SHAKE256 hasher instance, update it with input
//! data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHAKE256 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_shake256::Shake256State;
//! let mut shake256hasher = Shake256State::<20>::default().build_hasher();
//! shake256hasher.write(b"hello world");
//! let result = shake256hasher.finish();
//! assert_eq!(result, 0xB0D2B92CBB719736);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_shake256::Shake256State;
//! let hello = "hello";
//! let shake256state = Shake256State::<20>::default();
//! let mut shake256hasher1 = shake256state.build_hasher();
//! let mut shake256hasher2 = shake256state.build_hasher();
//! let mut shake256hasher3 = shake256state.build_hasher();
//!
//! shake256hasher1.write(hello.as_bytes());
//! hello.hash(&mut shake256hasher2);
//! shake256hasher3.write(hello.as_bytes());
//! shake256hasher3.write(&[0xFF]);
//!
//! let u64result1 = shake256hasher1.finish();
//! let u64result2 = shake256hasher2.finish();
//! let u64result3 = shake256hasher3.finish();
//!
//! assert_eq!(u64result1, 0x73E7A1E45A073412);
//! assert_eq!(u64result2, 0x7A658A3353BC20C4);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHAKE256 is recommended for a wide variety of tasks, including:
//!
//! - Cryptographic security, due to its resistance to collision attacks.
//! - Creating unique identifiers for data.
//! - Ensuring data integrity in situations where a variable-length hash is beneficial.
//!
//! [NIST](https://www.nist.gov/) recommends SHAKE256 for cryptographic functions due to its security and versatility. Its extendable output makes it particularly suitable when a variable-length hash is required.
//!

#![no_std]

pub use rs_hasher_ctx_lib::HasherContext;
pub use shake256hasher::Shake256Hasher;
pub use shake256state::Shake256State;

mod shake256hasher;
mod shake256state;

#[cfg(test)]
mod unit_tests;
