#![no_std]

use core::{
    hash::Hasher,
    ops::BitAnd
};
use internal_hasher::BlockHasher;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext<T, S>: BlockHasher<T, S> + Hasher
where
    S: BitAnd + From<u32> + From<u64>,
{
    fn finish(&mut self) -> Self::State;
}
