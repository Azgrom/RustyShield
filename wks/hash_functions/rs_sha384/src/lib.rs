//! # SHA-384 `rs-sha384` - Secure Hash Algorithm 384
//!
//! The SHA-384 hash function is part of the SHA-2 family, which was developed by the National Institute of Standards
//! and Technology (NIST). SHA-384 provides a higher level of security than SHA-1 and SHA-256, producing a 384-bit hash
//! from input data.
//!
//! ## Usage
//!
//! The crate provides a simple and intuitive API. Users can create a new SHA-384 hasher instance, update it with input
//! data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHA-384 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha384::Sha384State;
//! let mut sha384hasher = Sha384State::default().build_hasher();
//! sha384hasher.write(b"hello world");
//! let result = sha384hasher.finish();
//! assert_eq!(result, 0xA7FFE9F7385E2E23);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha384::Sha384Hasher;
//! let hello = "hello";
//! let mut sha384hasher1 = Sha384Hasher::default();
//! let mut sha384hasher2 = Sha384Hasher::default();
//! let mut sha384hasher3 = Sha384Hasher::default();
//!
//! sha384hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha384hasher2);
//! sha384hasher3.write(hello.as_bytes());
//! sha384hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha384hasher1.finish();
//! let u64result2 = sha384hasher2.finish();
//! let u64result3 = sha384hasher3.finish();
//!
//! assert_eq!(u64result1, 0xFF6F8C6D7A33BBFB);
//! assert_eq!(u64result2, 0xF7FBF5FBC24F22D3);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA-384 is recommended for most cryptographic security applications and is commonly used in various fields such as:
//!
//! - Digital signatures and certificate authorities which require a higher level of security.
//! - Cryptographic hardware and software standards that require a strong hash function.
//!
//! [NIST](https://www.nist.gov/) recommends the use of SHA-384 for security functions due to its resistance to
//! collision attacks and its higher security level than SHA-1 and SHA-256. SHA-384 is thus widely used and considered
//! safe for cryptographic and even most non-cryptographic functions

#![no_std]

pub use rs_hasher_ctx_lib::HasherContext;
pub use sha384hasher::Sha384Hasher;
pub use sha384state::Sha384State;

mod sha384hasher;
mod sha384state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 48;
