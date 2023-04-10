#![no_std]

use hash_ctx_lib::GenericHasher;
pub use crate::sha256state::Sha256State;

mod sha256state;

#[cfg(test)]
mod unit_tests;

pub type Sha256Hasher = GenericHasher<Sha256State>;
