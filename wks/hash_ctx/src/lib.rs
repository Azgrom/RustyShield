#![no_std]

extern crate alloc;

use core::hash::Hasher;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext: Hasher {
    type State;

    fn finish(&mut self) -> Self::State;
}
