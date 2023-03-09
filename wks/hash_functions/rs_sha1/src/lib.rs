//! # rs-sha1 - API Documentation
//!
//! rs-sha1 is a implementation of the first Secure Hash Algorithm designed to provide a compliant
//! standard library  SHA-1 API
//!
#![no_std]
extern crate alloc;

pub use crate::{sha1hasher::Sha1Hasher, sha1state::Sha1State};

pub mod sha1hasher;
mod sha1padding;
pub mod sha1state;

#[cfg(test)]
mod unit_tests;

const U32_BYTES_COUNT: usize = 4;
const SHA1_WORD_COUNT: usize = 16;
const SHA1_BLOCK_SIZE: usize = SHA1_WORD_COUNT * U32_BYTES_COUNT;
const SHA_CBLOCK_LAST_INDEX: usize = SHA1_BLOCK_SIZE - 1;
