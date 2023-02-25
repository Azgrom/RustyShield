//! # rs-sha1 - API Documentation
//!
//! rs-sha1 is a implementation of the first Secure Hash Algorithm designed to provide a compliant
//! standard library  SHA-1 API
//!
#![no_std]
extern crate alloc;

pub use crate::{sha1hasher::Sha1Hasher, sha1state::Sha1State};

pub mod sha1hasher;
pub mod sha1state;
mod sha1words;

#[cfg(test)]
mod use_cases;
#[cfg(test)]
mod fips_pub_180_1_coverage;
#[cfg(test)]
mod hypothesis_and_coverage_assurance;
#[cfg(test)]
mod test_state_trait_impls;

const U32_BYTES_COUNT: usize = 4;
const SHA1_WORD_COUNT: u32 = 16;
const SHA1_BLOCK_SIZE: u32 = SHA1_WORD_COUNT * U32_BYTES_COUNT as u32;
const SHA_OFFSET_PAD: u32 = SHA1_BLOCK_SIZE + 8;
const SHA_CBLOCK_LAST_INDEX: u32 = SHA1_BLOCK_SIZE - 1;
