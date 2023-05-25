//! # SHA-512 `rs-sha512` - Secure Hash Algorithm 512
//!
//! The SHA-512 hash function is part of the SHA-2 family, which was developed by the National Institute of Standards and
//! Technology (NIST). It is commonly used for cryptographic security, providing a significantly higher security margin
//! than SHA-1 and SHA-256.
//!
//! ## Usage
//!
//! The crate provides a simple and intuitive API. Users can create a new SHA-512 hasher instance, update it with input
//! data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHA-512 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha512::Sha512State;
//! let mut sha512hasher = Sha512State::default().build_hasher();
//! sha512hasher.write(b"hello world");
//! let result = sha512hasher.finish();
//! assert_eq!(result, 0xDCD6DFFBC902F2B4);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha512::Sha512State;
//! let hello = "hello";
//! let sha512state = Sha512State::default();
//! let mut sha512hasher1 = sha512state.build_hasher();
//! let mut sha512hasher2 = sha512state.build_hasher();
//! let mut sha512hasher3 = sha512state.build_hasher();
//!
//! sha512hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha512hasher2);
//! sha512hasher3.write(hello.as_bytes());
//! sha512hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha512hasher1.finish();
//! let u64result2 = sha512hasher2.finish();
//! let u64result3 = sha512hasher3.finish();
//!
//! assert_eq!(u64result1, 0xFDF6F77AD3EA3D73);
//! assert_eq!(u64result2, 0x7F95FBFFBD799AF2);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2)
//! ```
//!
//! ## Use Cases
//!
//! SHA-512 is suitable for a wide range of applications, including but not limited to:
//!
//! - Digital Signatures and Certificate authorities: for ensuring the authenticity of digital assets.
//! - Password Storage: it is often used in password hashing schemes, such as bcrypt, scrypt, and Argon2.
//! - Ensuring the integrity of data transmitted over networks.
//!
//! [NIST](https://www.nist.gov/) recommends SHA-512 for cryptographic functions where a stronger security guarantee
//! is required. In addition, SHA-512 is also often used for checksumming and fingerprinting.
//!

#![no_std]

pub use crate::{sha512hasher::Sha512Hasher, sha512state::Sha512State};

mod sha512hasher;
mod sha512state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 64;
