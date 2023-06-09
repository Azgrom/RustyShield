#![no_std]
#![no_main]

pub use crate::{n_bit_keccak_hasher::NBitKeccakHasher, n_bit_keccak_state::NBitKeccakState};

mod n_bit_keccak_hasher;
mod n_bit_keccak_state;

#[cfg(test)]
mod unit_tests;
