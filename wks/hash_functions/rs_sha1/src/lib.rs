//! # rs-sha1 - API Documentation
//!
//! rs-sha1 is a implementation of the first Secure Hash Algorithm designed to provide a compliant
//! standard library  SHA-1 API
//!
#![no_std]
extern crate alloc;

pub use crate::{sha1hasher::Sha1Hasher, sha1state::Sha1State};

mod sha1hasher;
mod sha1state;

#[cfg(test)]
mod unit_tests;
