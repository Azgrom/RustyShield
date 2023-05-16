#![no_std]

pub use crate::{sha224hasher::Sha224Hasher, sha224state::Sha224State};

mod sha224hasher;
mod sha224state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 28;
