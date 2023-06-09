//! # SHA-512 `rs_sha512` - Secure Hash Algorithm 512
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
//! # use rs_sha512::{HasherContext, Sha512State};
//! let mut sha512hasher = Sha512State::default().build_hasher();
//! sha512hasher.write(b"hello world");
//! let u64result = sha512hasher.finish();
//! let bytes_result = HasherContext::finish(&mut sha512hasher);
//! assert_eq!(u64result, 0x309ECC489C12D6EB);
//! assert_eq!(
//!     format!("{bytes_result:02x}"),
//!     "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
//! );
//! assert_eq!(
//!     format!("{bytes_result:02X}"),
//!     "309ECC489C12D6EB4CC40F50C902F2B4D0ED77EE511A7C7A9BCD3CA86D4CD86F989DD35BC5FF499670DA34255B45B0CFD830E81F605DCF7DC5542E93AE9CD76F"
//! );
//! assert_eq!(
//!     bytes_result,
//!     [
//!         0x30, 0x9E, 0xCC, 0x48, 0x9C, 0x12, 0xD6, 0xEB, 0x4C, 0xC4, 0x0F, 0x50, 0xC9, 0x02, 0xF2, 0xB4, 0xD0, 0xED,
//!         0x77, 0xEE, 0x51, 0x1A, 0x7C, 0x7A, 0x9B, 0xCD, 0x3C, 0xA8, 0x6D, 0x4C, 0xD8, 0x6F, 0x98, 0x9D, 0xD3, 0x5B,
//!         0xC5, 0xFF, 0x49, 0x96, 0x70, 0xDA, 0x34, 0x25, 0x5B, 0x45, 0xB0, 0xCF, 0xD8, 0x30, 0xE8, 0x1F, 0x60, 0x5D,
//!         0xCF, 0x7D, 0xC5, 0x54, 0x2E, 0x93, 0xAE, 0x9C, 0xD7, 0x6F
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
//! # use rs_sha512::Sha512Hasher;
//! let hello = "hello";
//! let mut sha512hasher1 = Sha512Hasher::default();
//! let mut sha512hasher2 = Sha512Hasher::default();
//! let mut sha512hasher3 = Sha512Hasher::default();
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
//! assert_eq!(u64result1, 0x9B71D224BD62F378);
//! assert_eq!(u64result2, 0x186CCD043395B8D8);
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
#![no_main]

pub use crate::sha512hasher::Sha512Hasher;
pub use crate::sha512state::Sha512State;
pub use rs_hasher_ctx::HasherContext;

mod sha512hasher;
mod sha512state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 64;
