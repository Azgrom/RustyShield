#![no_std]

pub use crate::{sha3_512hasher::Sha3_512Hasher, sha3_512state::Sha3_512State};

mod sha3_512hasher;
mod sha3_512state;

#[cfg(test)]
mod unit_tests;

const OUTPUT_SIZE: usize = 64;
