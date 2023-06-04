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
//! # use rs_sha512_256::{HasherContext, Sha512_256State};
//! let mut sha512_256hasher = Sha512_256State::default().build_hasher();
//! sha512_256hasher.write(b"hello world");
//! let u64result = sha512_256hasher.finish();
//! let bytes_result = HasherContext::finish(&mut sha512_256hasher);
//! assert_eq!(u64result, 0x0AC561FAC838104E);
//! assert_eq!(
//!     format!("{bytes_result:02x}"),
//!     "0ac561fac838104e3f2e4ad107b4bee3e938bf15f2b15f009ccccd61a913f017"
//! );
//! assert_eq!(
//!     format!("{bytes_result:02X}"),
//!     "0AC561FAC838104E3F2E4AD107B4BEE3E938BF15F2B15F009CCCCD61A913F017"
//! );
//! assert_eq!(
//!     bytes_result,
//!     [
//!         0x0A, 0xC5, 0x61, 0xFA, 0xC8, 0x38, 0x10, 0x4E, 0x3F, 0x2E, 0x4A, 0xD1, 0x07, 0xB4, 0xBE, 0xE3, 0xE9, 0x38, 0xBF,
//!         0x15, 0xF2, 0xB1, 0x5F, 0x00, 0x9C, 0xCC, 0xCD, 0x61, 0xA9, 0x13, 0xF0, 0x17
//!     ]
//! )
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
//! assert_eq!(u64result1, 0xE30D87CFA2A75DB5);
//! assert_eq!(u64result2, 0xB4840548C986E994);
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
