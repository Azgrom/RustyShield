#![no_std]

extern crate alloc;

pub use crate::{sha256hasher::Sha256Hasher, sha256state::Sha256State};

mod sha256comp;
mod sha256hasher;
mod sha256state;
mod sha256words;

#[cfg(test)]
mod unit_tests;

const SHA256_PADDING_U8_WORDS_COUNT: u8 = 64;
const SHA256_PADDING_U32_WORDS_COUNT: u8 = 16;
