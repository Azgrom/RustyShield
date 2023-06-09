#![no_std]
#![no_main]

pub use byte_array_wrapper::ByteArrayWrapper;
pub use generic_hasher::GenericHasher;

mod byte_array_wrapper;
mod generic_hasher;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext<const OUTPUT_LEN: usize> {
    type Output;

    fn finish(&mut self) -> Self::Output;
}
