#![no_std]

extern crate alloc;

use hash_ctx_lib::GenericHasher;
pub use crate::sha224state::Sha224State;

mod sha224state;

#[cfg(test)]
mod unit_tests;

pub type Sha224Hasher = GenericHasher<Sha224State>;
