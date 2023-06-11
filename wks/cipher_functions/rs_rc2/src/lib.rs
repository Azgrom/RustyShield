//! # RC2 - `rs_rc2` - Rivest Cipher 2
//!
//! **Important Note: This crate is still a work in progress and is not ready for consumption.**
//!
//! RC2 is a symmetric key block cipher designed by Ronald Rivest in 1987. Despite being considered old, it's still used
//! in:
//! - Secure/Multipurpose Internet Mail Extensions (S/MIME), a standard for public key encryption and signing of MIME
//! data.
//! - Transport Layer Security (TLS), and its predecessor, Secure Sockets Layer (SSL), cryptographic protocols designed
//! to provide communications security.
//!
//! This crate implements RC2 as part of the [RustyShield](https://docs.rs/rs_shield/latest/rs_shield/) project.

#![no_std]
