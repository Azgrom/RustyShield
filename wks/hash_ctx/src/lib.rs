#![no_std]

pub use u128_max_generic_hasher::U128MaxGenericHasher;
pub use u64_max_generic_hasher::U64MaxGenericHasher;

mod u64_max_generic_hasher;
mod u128_max_generic_hasher;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext {
    type State;

    fn finish(&mut self) -> Self::State;
}
