//! # Diffie-Hellman - `rs_diffie_hellman` - Key Exchange Algorithm
//!
//! **Important Note: This crate is still a work in progress and is not ready for consumption.**
//!
//! Diffie-Hellman (DH) is a key exchange protocol that was published by Whitfield Diffie and Martin Hellman in 1976. It is currently used in various applications such as:
//! - Establishing a shared secret over an insecure communication channel.
//! - Secure communication protocols like Transport Layer Security (TLS), Secure Shell (SSH), Internet Protocol Security (IPSec), etc.
//! - Secure email, instant messaging, and Voice over IP (VoIP).
//!
//! This crate implements the Diffie-Hellman protocol as part of the [RustyShield](https://docs.rs/rs_shield/latest/rs_shield/) project.

#![no_std]
