#![no_std]

pub use crate::{shake256hasher::Shake256Hasher, shake256state::Shake256State};

mod shake256state;
mod shake256hasher;

#[cfg(test)]
mod unit_tests;
