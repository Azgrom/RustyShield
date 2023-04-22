#![no_std]

pub use shake128hasher::Shake128Hasher;
pub use shake128state::Shake128State;

mod shake128hasher;
mod shake128state;

#[cfg(test)]
mod unit_tests;
