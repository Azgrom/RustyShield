//! # BLAKE2 - `rs_blake2` - Cryptographic Hash Function
//!
//! **Important Note: This crate is still a work in progress and is not ready for consumption.**
//!
//! BLAKE2 is a cryptographic hash function that is faster than MD5, SHA-1, SHA-2, and SHA-3, yet is at least as secure
//! as the latest standard, SHA-3. Published by Aumasson, Neves, Wilcox-O'Hearn, and Winnerlein in 2012, it is used in
//! various applications such as:
//! - Cryptographic libraries and frameworks, for instance, libsodium.
//! - File integrity checking and deduplication.
//! - Secure communication protocols like Transport Layer Security (TLS), Secure Shell (SSH), Internet Protocol Security
//! (IPSec), etc.
//!
//! This crate implements BLAKE2 as part of the [RustyShield](https://docs.rs/rs_shield/latest/rs_shield/) project.

#![no_std]
