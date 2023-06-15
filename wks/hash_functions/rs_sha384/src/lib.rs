//! # SHA-384 `rs_sha384` - Secure Hash Algorithm 384
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
//! # use rs_sha384::{HasherContext, Sha384State};
//! let mut sha384hasher = Sha384State::default().build_hasher();
//! sha384hasher.write(b"hello world");
//! let u64result = sha384hasher.finish();
//! let bytes_result = HasherContext::finish(&mut sha384hasher);
//! assert_eq!(u64result, 0xFDBD8E75A67F29F7);
//! assert_eq!(
//!     format!("{bytes_result:02x}"),
//!     "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
//! );
//! assert_eq!(
//!     format!("{bytes_result:02X}"),
//!     "FDBD8E75A67F29F701A4E040385E2E23986303EA10239211AF907FCBB83578B3E417CB71CE646EFD0819DD8C088DE1BD"
//! );
//! assert_eq!(
//!     bytes_result,
//!     [
//!         0xFD, 0xBD, 0x8E, 0x75, 0xA6, 0x7F, 0x29, 0xF7, 0x01, 0xA4, 0xE0, 0x40, 0x38, 0x5E, 0x2E, 0x23, 0x98, 0x63,
//!         0x03, 0xEA, 0x10, 0x23, 0x92, 0x11, 0xAF, 0x90, 0x7F, 0xCB, 0xB8, 0x35, 0x78, 0xB3, 0xE4, 0x17, 0xCB, 0x71,
//!         0xCE, 0x64, 0x6E, 0xFD, 0x08, 0x19, 0xDD, 0x8C, 0x08, 0x8D, 0xE1, 0xBD
//!     ]
//! )
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
//! assert_eq!(u64result1, 0x59E1748777448c69);
//! assert_eq!(u64result2, 0x133C4471D73375AB);
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

pub use rs_hasher_ctx::HasherContext;
pub use sha384hasher::Sha384Hasher;
pub use sha384state::Sha384State;

mod sha384hasher;
mod sha384state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 48;
