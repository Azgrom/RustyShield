#![no_std]

pub use crate::{sha512_256hasher::Sha512_256Hasher, sha512_256state::Sha512_256State};

mod sha512_256hasher;
mod sha512_256state;

#[cfg(test)]
mod unit_tests;

const BYTES_LEN: usize = 32;
