#![no_std]

pub use crate::{sha3_384hasher::Sha3_384Hasher, sha3_384state::Sha3_384State};

mod sha3_384hasher;
mod sha3_384state;

#[cfg(test)]
mod unit_tests;

const OUTPUT_SIZE: usize = 48;
