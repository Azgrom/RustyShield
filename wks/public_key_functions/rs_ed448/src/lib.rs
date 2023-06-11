//! # ED448 - `rs_ed448` - Ed448-Goldilocks
//!
//! **Important Note: This crate is still a work in progress and is not ready for consumption.**
//!
//! Ed448-Goldilocks, usually referred as Ed448, is an elliptic curve offering 224 bits of security (448-bit key size) and designed for efficient implementation. It was introduced in 2015 and is used in applications like:
//! - Transport Layer Security (TLS) protocol.
//! - Secure Shell (SSH) protocol.
//! - Internet Key Exchange (IKE) protocol.
//!
//! This crate implements Ed448 as part of the [RustyShield](https://docs.rs/rs_shield/latest/rs_shield/) project.

#![no_std]
