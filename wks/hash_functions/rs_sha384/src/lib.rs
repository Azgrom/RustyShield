#![no_std]

extern crate alloc;

pub use crate::{sha384hasher::Sha384Hasher, sha384state::Sha384State};

mod sha384hasher;
mod sha384padding;
mod sha384state;

#[cfg(test)]
mod unit_tests;

const SHA384_HEX_HASH_SIZE: usize = 48;
const SHA384_U8_WORDS_COUNT: usize = 128;
