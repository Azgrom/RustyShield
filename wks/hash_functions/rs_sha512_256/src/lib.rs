//! # SHA-512/256 `rs-sha512_256` - Secure Hash Algorithm 512/256
//!
//! The SHA-512/256 hash function is a member of the SHA-2 (Secure Hash Algorithm 2) family, which was developed by the
//! National Institute of Standards and
//! Technology (NIST). Unlike SHA-1, SHA-512/256 is not known to be vulnerable to collision attacks and provides a
//! stronger level of security.
//!
//! ## Usage
//!
//! This crate offers an easy-to-use and intuitive API. Users can create a new SHA-512/256 hasher instance, feed it with
//! input data,
//! and finally call the finish method to obtain the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHA-512/256 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha512_256::Sha512_256State;
//! let mut sha512_256hasher = Sha512_256State::default().build_hasher();
//! sha512_256hasher.write(b"hello world");
//! let result = sha512_256hasher.finish();
//! assert_eq!(result, 0xFF3E5ADF07B4BEE3)
//! ```
//!
//! Or, using a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha512_256::Sha512_256State;
//! let hello = "hello";
//! let sha512_256state = Sha512_256State::default();
//! let mut sha512_256hasher1 = sha512_256state.build_hasher();
//! let mut sha512_256hasher2 = sha512_256state.build_hasher();
//! let mut sha512_256hasher3 = sha512_256state.build_hasher();
//!
//! sha512_256hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha512_256hasher2);
//! sha512_256hasher3.write(hello.as_bytes());
//! sha512_256hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha512_256hasher1.finish();
//! let u64result2 = sha512_256hasher2.finish();
//! let u64result3 = sha512_256hasher3.finish();
//!
//! assert_eq!(u64result1, 0xE7EFDDF71BAF9703);
//! assert_eq!(u64result2, 0xE996EDF76043D00D);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA-512/256 is used in a wide range of security-critical tasks, such as:
//!
//! - Cryptographic signatures, where it serves as a basis for creating a unique signature for a given input.
//! - Password storage, where it is used to create a hash of the user's password.
//! - Data integrity checks, where a unique identifier for data is needed.
//!
//! [NIST](https://www.nist.gov/) recommends the use of SHA-512/256 for cryptographic functions due to its resistance to
//! known vulnerabilities and its strong security properties.
//!

#![no_std]

pub use rs_hasher_ctx::HasherContext;
pub use sha512_256hasher::Sha512_256Hasher;
pub use sha512_256state::Sha512_256State;

mod sha512_256hasher;
mod sha512_256state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 32;
