#![no_std]
pub use u32_words::U32Word;
pub use u64_words::U64Word;

mod u32_words;
mod u64_words;

#[cfg(test)]
mod unit_tests;
