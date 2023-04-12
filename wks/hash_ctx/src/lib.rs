#![no_std]

pub use generic_hasher::GenericHasher;

mod generic_hasher;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext {
    type State;

    fn finish(&mut self) -> Self::State;
}
