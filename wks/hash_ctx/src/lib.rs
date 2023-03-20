#![no_std]

pub use crate::{
    hasher_stating::GenericStateHasher,
    block_hasher::BlockHasher,
    hasher_words::HasherWords
};
use core::{
    hash::Hasher,
    ops::BitAnd
};

mod hasher_macro_definition;
mod block_hasher;
mod hasher_stating;
mod hasher_words;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext<T, S>: BlockHasher<T, S> + Hasher
where
    S: BitAnd + From<u32> + From<u64>,
{
    fn finish(&mut self) -> Self::State;
}
