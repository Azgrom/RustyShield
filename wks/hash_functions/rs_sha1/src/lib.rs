//! # SHA-1 `rs-sha1` - Secure Hash Algorithm 1
//!
//! The SHA-1 hash function is part of the SHA family, which was developed by the National Institute of Standards and
//! Technology (NIST).
//! While it has been deprecated for many cryptographic uses due to vulnerabilities to collision attacks, SHA-1 is still
//! considered safe for non-cryptographic functions such as checksumming and fingerprinting.
//!
//! ## Usage
//!
//! The crate provides a simple and intuitive API. Users can create a new SHA-1 hasher instance, update it with input
//! data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the SHA-1 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha1::Sha1State;
//! let mut sha1hasher = Sha1State::default().build_hasher();
//! sha1hasher.write(b"hello world");
//! let result = sha1hasher.finish();
//! assert_eq!(result, 0x2AAE6C35C94FCFB4);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha1::Sha1State;
//! let hello = "hello";
//! let sha1state = Sha1State::default();
//! let mut sha1hasher1 = sha1state.build_hasher();
//! let mut sha1hasher2 = sha1state.build_hasher();
//! let mut sha1hasher3 = sha1state.build_hasher();
//!
//! sha1hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha1hasher2);
//! sha1hasher3.write(hello.as_bytes());
//! sha1hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha1hasher1.finish();
//! let u64result2 = sha1hasher2.finish();
//! let u64result3 = sha1hasher3.finish();
//!
//! assert_eq!(u64result1, 0xAAF4C61DDCC5E8A2);
//! assert_eq!(u64result2, 0xC8D8A4368F3A43D7);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! While not recommended for cryptographic security, SHA-1 is often used in various non-security critical tasks, such as:
//!
//! - Git for version control uses SHA-1 not for security but for ensuring data integrity.
//! - In checksumming, where a unique identifier for data is needed.
//! - Fingerprinting, where unique identifiers are used to mark or identify unique data elements.
//!
//! [NIST](https://www.nist.gov/) advises against using SHA-1 for cryptographic functions due to potential
//! vulnerabilities to collision attacks. For non-cryptographic functions, however, SHA-1 is still widely used and
//! deemed safe.
//!

#![no_std]

pub use crate::sha1hasher::Sha1Hasher;
pub use crate::sha1state::Sha1State;

mod sha1hasher;
mod sha1state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 20;
