//! # Keccak-nBits - `rs_keccak_nbits` - Keccak Variable-Length Hash Function
//!
//! The Keccak hash function is part of the Keccak family, developed by Guido Bertoni, Joan Daemen, Michael Peeters,
//! and Gilles Van Assche. Keccak was selected as the winner of the NIST hash function competition and became SHA-3.
//!
//! Keccak-nBits allows for a variable-length hash output, providing flexibility depending on the required security
//! level.
//!
//! ## Usage
//!
//! The crate provides a simple and intuitive API. Users can create a new Keccak-nBits hasher instance, update it with
//! input data, and finalize to get the resultant hash.
//!
//! ### Example
//!
//! Here is an example of how to use the Keccak-nBits hash function in Rust:
//!
//! ```rust
//! # use std::hash::{BuildHasher, Hasher};
//! # use rs_keccak_nbits::{NBitKeccakState};
//! let mut keccakhasher = NBitKeccakState::<u32, 10, 24>::default().build_hasher();
//! keccakhasher.write(b"hello world");
//! let result = keccakhasher.finish();
//! assert_eq!(result, 0xE4B4C1F4C2BBD6E6);
//! ```
//!
//! Or, as a `HashSet`:
//!
//! ```
//! # use std::{
//! #     collections::HashSet,
//! #     hash::{BuildHasher, Hash, Hasher}
//! # };
//! # use rs_keccak_nbits::NBitKeccakHasher;
//! let hello = "hello";
//! let mut keccakhasher1: NBitKeccakHasher<u32, 18, 24> = NBitKeccakHasher::default();
//! let mut keccakhasher2: NBitKeccakHasher<u32, 18, 24> = NBitKeccakHasher::default();
//! let mut keccakhasher3: NBitKeccakHasher<u32, 18, 24> = NBitKeccakHasher::default();
//!
//! keccakhasher1.write(hello.as_bytes());
//! hello.hash(&mut keccakhasher2);
//! keccakhasher3.write(hello.as_bytes());
//! keccakhasher3.write(&[0xFF]);
//!
//! let u64result1 = keccakhasher1.finish();
//! let u64result2 = keccakhasher2.finish();
//! let u64result3 = keccakhasher3.finish();
//!
//! assert_eq!(u64result1, 0x5A6B41FBBA8E0EFE);
//! assert_eq!(u64result2, 0xA77CCB556D1FAE0A);
//! assert_eq!(u64result2, u64result3);
//! assert_ne!(u64result1, u64result2);
//! ```
//!
//! ## Use Cases
//!
//! Keccak-nBits is utilized for a range of cryptographic and data integrity applications, including:
//!
//! - SHA-3 and SHAKE hash functions.
//! - Duplex constructions such as Ketje and Keyak authenticated encryption ciphers.
//! - In checksumming, where a unique identifier for data is needed.
//! - Fingerprinting, where unique identifiers are used to mark or identify unique data elements.
//!
//! While Keccak-nBits is approved by [NIST](https://www.nist.gov/) for cryptographic functions, the specific security
//! characteristics should be considered in relation to each use case.

#![no_std]

pub use crate::{n_bit_keccak_hasher::NBitKeccakHasher, n_bit_keccak_state::NBitKeccakState};

mod n_bit_keccak_hasher;
mod n_bit_keccak_state;

#[cfg(test)]
mod unit_tests;
