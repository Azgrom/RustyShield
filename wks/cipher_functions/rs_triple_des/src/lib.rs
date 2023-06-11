//! # Triple DES - `rs_triple_des` - Triple Data Encryption Algorithm
//!
//! **Important Note: This crate is still a work in progress and is not ready for consumption.**
//!
//! Triple DES (3DES) is a symmetric-key block cipher, which applies the older Data Encryption Standard (DES) cipher
//! algorithm three times to each data block. Developed in 1998 to counteract the weaknesses of DES, it has been widely
//! used in the following applications:
//! - Financial services: Adopted by the financial industry for secure transactions.
//! - Communication systems: Used in various secure communication protocols such as Secure Sockets Layer (SSL),
//! Transport Layer Security (TLS), and Internet Protocol Security (IPSec), among others.
//! - Electronic Key Management System (EKMS) of the United States National Security Agency.
//!
//! This crate implements Triple DES as part of the [RustyShield](https://docs.rs/rs_shield/latest/rs_shield/) project.

#![no_std]
