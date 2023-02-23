//! # rs-sha1 - API Documentation
//!
//! rs-sha1 is a implementation of the first Secure Hash Algorithm designed to provide a compliant
//! standard library  SHA-1 API
//!
#![no_std]
extern crate alloc;

pub use crate::{sha1_context::Sha1Context, sha1_hasher::Sha1Hasher, sha1_state::Sha1State};

pub mod sha1_context;
pub mod sha1_hasher;
pub mod sha1_state;
mod sha1_words;

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;
const T_0_19: u32 = 0x5A827999;
const T_20_39: u32 = 0x6ED9EBA1;
const T_40_59: u32 = 0x8F1BBCDC;
const T_60_79: u32 = 0xCA62C1D6;

const U32_BYTES_COUNT: usize = 4;
const SHA1_WORD_COUNT: u32 = 16;
const SHA1_BLOCK_SIZE: u32 = SHA1_WORD_COUNT * U32_BYTES_COUNT as u32;
const SHA_OFFSET_PAD: u32 = SHA1_BLOCK_SIZE + 8;
const SHA_CBLOCK_LAST_INDEX: u32 = SHA1_BLOCK_SIZE - 1;

#[cfg(test)]
mod use_cases;

#[cfg(test)]
mod fips_pub_180_1_coverage;

#[cfg(test)]
mod hypothesis_and_coverage_assurance;
