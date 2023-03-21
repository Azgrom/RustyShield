#![no_std]

pub use crate::{block_hasher::BlockHasher, hasher_stating::GenericStateHasher, hasher_words::HasherWords};
use core::{hash::Hasher, ops::BitAnd};

mod block_hasher;
mod hasher_macro_definition;
mod hasher_stating;
mod hasher_words;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext<T, S>: BlockHasher<T, S> + Hasher
where
    S: BitAnd + From<u32> + From<u64>,
{
    fn finish(&mut self) -> Self::State;
}
