//! # SHA3-224 `rs-sha3-224` - Secure Hash Algorithm 3 variant
//!
//! The SHA3-224 hash function is part of the SHA-3 family, which was developed by the National Institute of Standards
//! and Technology (NIST). It generates a 224-bit hash value, making it a strong choice for cryptographic security.
//!
//! SHA3-224 is recommended for use in a variety of security contexts, including digital signatures, message
//! authentication codes, and other forms of data integrity assurance. It has not been deprecated for any uses and is
//! regarded as a reliable hash function.
//!
//! ## Usage
//!
//! The crate provides a simple and intuitive API. Users can create a new SHA3-224 hasher instance, update it with input
//! data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHA3-224 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha3_224::Sha3_224State;
//! let mut sha3_224hasher = Sha3_224State::default().build_hasher();
//! sha3_224hasher.write(b"hello world");
//! let result = sha3_224hasher.finish();
//! assert_eq!(result, 0xBB28E9778CF1B7DF);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha3_224::Sha3_224State;
//! let hello = "hello";
//! let sha3_224state = Sha3_224State::default();
//! let mut sha3_224hasher1 = sha3_224state.build_hasher();
//! let mut sha3_224hasher2 = sha3_224state.build_hasher();
//! let mut sha3_224hasher3 = sha3_224state.build_hasher();
//!
//! sha3_224hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha3_224hasher2);
//! sha3_224hasher3.write(hello.as_bytes());
//! sha3_224hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha3_224hasher1.finish();
//! let u64result2 = sha3_224hasher2.finish();
//! let u64result3 = sha3_224hasher3.finish();
//!
//! assert_eq!(u64result1, 0xF1FF0227C7887FB8);
//! assert_eq!(u64result2, 0x1B446C59745E8379);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA3-224 is suitable for a range of tasks, including:
//!
//! - Cryptographic security, including digital signatures and message authentication.
//! - Ensuring data integrity and creating unique identifiers for data.
//!
//! [NIST](https://www.nist.gov/) recommends SHA3-224 for cryptographic purposes due to its robust security and reliable performance. Its 224-bit output is large enough to resist all known practical collision attacks, making it an ideal choice for many applications.
//!
#![no_std]

pub use rs_hasher_ctx::HasherContext;
pub use sha3_224hasher::Sha3_224Hasher;
pub use sha3_224state::Sha3_224State;

mod sha3_224hasher;
mod sha3_224state;

#[cfg(test)]
mod unit_tests;

const OUTPUT_SIZE: usize = 28;
