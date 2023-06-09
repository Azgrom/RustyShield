//! # SHAKE128 `rs_shake128` - Secure Hash Algorithm KECCAK 128
//!
//! SHAKE128 is a member of the SHA-3 family of cryptographic hash functions, specifically a part of the extendable-output
//! function (XOF) instances based on KECCAK. It was designed by the National Institute of Standards and
//! Technology (NIST).
//!
//! Unlike fixed output hash functions, SHAKE128 is capable of producing output of arbitrary length, making it versatile
//! for a variety of cryptographic applications.
//!
//! ## Usage
//!
//! The crate offers a straightforward API. Users can create a new SHAKE128 hasher instance, update it with input
//! data, and finalize to get the resultant hash of arbitrary length.
//!
//! ### Example
//!
//! Here is an example of how to use the SHAKE128 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_shake128::Shake128State;
//! let mut shake128hasher = Shake128State::<20>::default().build_hasher();
//! shake128hasher.write(b"hello world");
//! let result = shake128hasher.finish();
//! assert_eq!(result, 0x3A9159F071E4DD1C);
//! ```
//!
//! As a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_shake128::Shake128State;
//! let hello = "hello";
//! let shake128state = Shake128State::<20>::default();
//! let mut shake128hasher1 = shake128state.build_hasher();
//! let mut shake128hasher2 = shake128state.build_hasher();
//! let mut shake128hasher3 = shake128state.build_hasher();
//!
//! shake128hasher1.write(hello.as_bytes());
//! hello.hash(&mut shake128hasher2);
//! shake128hasher3.write(hello.as_bytes());
//! shake128hasher3.write(&[0xFF]);
//!
//! let u64result1 = shake128hasher1.finish();
//! let u64result2 = shake128hasher2.finish();
//! let u64result3 = shake128hasher3.finish();
//!
//! assert_eq!(u64result1, 0x8EB4B6A932F28033);
//! assert_eq!(u64result2, 0x358DBED83C354C39);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHAKE128 is recommended for a wide range of cryptographic functions, such as:
//!
//! - In digital signatures, where a unique identifier for data is necessary.
//! - Cryptographic key derivation, where it's important to generate a secure key from a password or passphrase.
//! - As a component in encryption algorithms to ensure the security of encrypted data.
//!
//! [NIST](https://www.nist.gov/) recommends using SHAKE128 for cryptographic functions due to its strength against known
//! cryptographic vulnerabilities and its flexibility in generating hash outputs of arbitrary length.
//!

#![no_std]
#![no_main]

pub use rs_hasher_ctx::HasherContext;
pub use shake128hasher::Shake128Hasher;
pub use shake128state::Shake128State;

mod shake128hasher;
mod shake128state;

#[cfg(test)]
mod unit_tests;
