#![no_std]

pub use crate::{sha512hasher::Sha512Hasher, sha512state::Sha512State};

mod sha512hasher;
mod sha512state;

#[cfg(test)]
mod unit_tests;
