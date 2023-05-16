#![no_std]

pub use crate::{sha3_256hasher::Sha3_256Hasher, sha3_256state::Sha3_256State};

mod sha3_256hasher;
mod sha3_256state;

#[cfg(test)]
mod unit_tests;

const OUTPUT_SIZE: usize = 32;
