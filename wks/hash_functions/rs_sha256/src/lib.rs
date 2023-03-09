#![no_std]

extern crate alloc;

pub use crate::{sha256hasher::Sha256Hasher, sha256state::Sha256State};

mod sha256hasher;
mod sha256padding;
mod sha256state;

#[cfg(test)]
mod unit_tests;

const SHA256_PADDING_U8_WORDS_COUNT: usize = 64;
