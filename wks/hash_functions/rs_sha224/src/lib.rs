#![no_std]

extern crate alloc;

mod sha224comp;
mod sha224hasher;
mod sha224state;
mod sha224words;

#[cfg(test)]
mod unit_tests;

const SHA224_SCHEDULE_U32_WORDS_COUNT: u32 = 64;
const SHA224_PADDING_U8_WORDS_COUNT: u32 = SHA224_SCHEDULE_U32_WORDS_COUNT;
