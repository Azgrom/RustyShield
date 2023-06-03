//! # SHA-256 `rs-sha256` - Secure Hash Algorithm 256
//!
//! SHA-256 is a member of the SHA-2 cryptographic hash functions designed by the National Institute of Standards and
//! Technology (NIST). It is commonly employed in various security communication protocols and data integrity checks.
//!
//! ## Usage
//!
//! The crate offers a straightforward API, enabling users to instantiate a new SHA-256 hasher, update it with input
//! data, and finalize to obtain the resultant hash.
//!
//! ### Example
//!
//! This is an illustration of using the SHA-256 hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_sha256::Sha256State;
//! let mut sha256hasher = Sha256State::default().build_hasher();
//! sha256hasher.write(b"hello world");
//! let result = sha256hasher.finish();
//! assert_eq!(result, 0xB94D27B9934D3E08);
//! ```
//!
//! Additionally, in a `HashSet` context:
//!
//! ```rust
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_sha256::Sha256Hasher;
//! let hello = "hello";
//! let mut sha256hasher1 = Sha256Hasher::default();
//! let mut sha256hasher2 = Sha256Hasher::default();
//! let mut sha256hasher3 = Sha256Hasher::default();
//!
//! sha256hasher1.write(hello.as_bytes());
//! hello.hash(&mut sha256hasher2);
//! sha256hasher3.write(hello.as_bytes());
//! sha256hasher3.write(&[0xFF]);
//!
//! let u64result1 = sha256hasher1.finish();
//! let u64result2 = sha256hasher2.finish();
//! let u64result3 = sha256hasher3.finish();
//!
//! assert_eq!(u64result1, 0x2CF24DBA5FB0A30E);
//! assert_eq!(u64result2, 0xFCFE450961C66DC3);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! SHA-256 is broadly used in various security-critical tasks, including:
//!
//! - TLS and SSL, IPsec, and SSH for network communication security.
//! - Digital signatures and certificate authorities for data integrity and sender authentication.
//! - Blockchain applications for ensuring data integrity.
//!
//! [NIST](https://www.nist.gov/) recommends SHA-256 for most applications until 2030, marking it as a secure option for
//! cryptographic functions in the current landscape.
//!

#![no_std]

pub use rs_hasher_ctx_lib::HasherContext;
pub use sha256hasher::Sha256Hasher;
pub use sha256state::Sha256State;

mod sha256hasher;
mod sha256state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 32;
