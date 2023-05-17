//! # rs-sha256 - API Documentation for SHA-256
//!
//!

#![no_std]

pub use crate::sha256hasher::Sha256Hasher;
pub use crate::sha256state::Sha256State;

mod sha256hasher;
mod sha256state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 32;
