#![no_std]

extern crate alloc;

pub use crate::{sha384hasher::Sha384Hasher, sha384state::Sha384State};

mod sha384hasher;
mod sha384state;
mod sha384words;

#[cfg(test)]
mod unit_tests;

const SHA384PADDING_SIZE: u8 = 48;
const SHA384BLOCK_SIZE: u8 = 128;
