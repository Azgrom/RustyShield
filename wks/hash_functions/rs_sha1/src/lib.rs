//! # rs-sha1 - API Documentation
//!
//! rs-sha1 is a implementation of the first Secure Hash Algorithm designed to provide a compliant
//! standard library  SHA-1 API
//!
#![no_std]

use hash_ctx_lib::GenericHasher;
pub use crate::sha1state::Sha1State;

mod sha1state;

#[cfg(test)]
mod unit_tests;

pub type Sha1Hasher = GenericHasher<Sha1State>;
