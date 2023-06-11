//! # Poly1305 - `rs_poly1305` - Poly1305 Message Authentication Code
//!
//! **Important Note: This crate is still a work in progress and is not ready for consumption.**
//!
//! Poly1305 is a message authentication code (MAC) invented by Daniel J. Bernstein in 2005. It's currently used in:
//! - ChaCha20-Poly1305, a high-speed cipher for encryption and message authentication
//! - XSalsa20-Poly1305, a public-key authenticated-encryption scheme
//!
//! This crate implements Poly1305 as part of the [RustyShield](https://docs.rs/rs_shield/latest/rs_shield/) project.

#![no_std]
