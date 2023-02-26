#![no_std]

extern crate alloc;

mod sha384comp;
mod sha384hasher;
mod sha384state;
mod sha384words;

#[cfg(test)]
mod unit_tests;

const SHA384PADDING_SIZE: usize = 48;
const SHA384BLOCK_SIZE: usize = 128;
