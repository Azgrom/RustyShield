//! # SHA3-512 `rs-sha3-512` - Secure Hash Algorithm KECCAK-based variant
//!
//! The SHA3-512 hash function is part of the SHA-3 family, which was developed by the National Institute of Standards and
//! Technology (NIST). It's a traditional, fixed output length hash function, generating a hash value of 512 bits.
//!
//! SHA3-512 is suitable for a range of cryptographic purposes, including generating unique identifiers and ensuring data integrity. It is among the most secure hash functions available and has not been deprecated for any uses.
//!
//! ## Usage
//!
//! The crate provides a simple and intuitive API. Users can create a new SHA3-512 hasher instance, update it with input
//! data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHA3-512 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha3_512::Sha3_512State;
//! let mut sha3_512hasher = Sha3_512State::default().build_hasher();
//! sha3_512hasher.write(b"hello world");
//! let result = sha3_512hasher.finish();
//! assert_eq!(result, 0x840006653E9AC9E9);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha3_512::Sha3_512State;
//! let hello = "hello";
//! let sha3_512state = Sha3_512State::default();
//! let mut sha3_512hasher1 = sha3_512state.build_hasher();
//! let mut sha3_512hasher2 = sha3_512state.build_hasher();
//! let mut sha3_512hasher3 = sha3_512state.build_hasher();
//!
//! sha3_512hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha3_512hasher2);
//! sha3_512hasher3.write(hello.as_bytes());
//! sha3_512hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha3_512hasher1.finish();
//! let u64result2 = sha3_512hasher2.finish();
//! let u64result3 = sha3_512hasher3.finish();
//!
//! assert_eq!(u64result1, 0x75D527C368F2EFE8);
//! assert_eq!(u64result2, 0xC72E23F0158225F8);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA3-512 is recommended for a wide variety of tasks, including:
//!
//! - Cryptographic security, due to its resistance to collision and pre-image attacks.
//! - Creating unique identifiers for data.
//! - Ensuring data integrity in situations where a high-security level is needed.
//!
//! [NIST](https://www.nist.gov/) recommends SHA3-512 for cryptographic functions when security is paramount. Its fixed output length delivers a balance between performance and security.
//!

#![no_std]

pub use rs_hasher_ctx::HasherContext;
pub use sha3_512hasher::Sha3_512Hasher;
pub use sha3_512state::Sha3_512State;

mod sha3_512hasher;
mod sha3_512state;

#[cfg(test)]
mod unit_tests;

const OUTPUT_SIZE: usize = 64;
