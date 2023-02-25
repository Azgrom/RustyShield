#![no_std]

extern crate alloc;

pub use crate::{sha256hasher::Sha256Hasher, sha256state::Sha256State};

mod sha256comp;
mod sha256hasher;
mod sha256state;
mod sha256words;

#[cfg(test)]
mod use_cases;

const SHA256_SCHEDULE_U32_WORDS_COUNT: u32 = 64;
const SHA256_PADDING_U8_WORDS_COUNT: u32 = SHA256_SCHEDULE_U32_WORDS_COUNT;
