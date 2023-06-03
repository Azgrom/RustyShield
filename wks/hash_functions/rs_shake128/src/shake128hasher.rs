use crate::Shake128State;
use core::hash::Hasher;
use rs_internal_hasher::HashAlgorithm;
use rs_internal_state::ExtendedOutputFunction;
use rs_hasher_ctx::{ByteArrayWrapper, GenericHasher, HasherContext};

/// `Shake128Hasher` is a type that provides the SHAKE128 hashing algorithm in Rust.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that manages the process of converting input
/// data into a variable-size sequence of bytes. The Hasher is responsible for maintaining the internal state of the
/// hashing process and providing methods to add more data and retrieve the resulting hash.
///
/// The `Shake128Hasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other hashers
/// in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples demonstrate using `Shake128Hasher` with both `Hash` and `Hasher`, and from where the difference
/// comes from:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_shake128::Shake128State;
/// let data = b"hello";
///
/// // Using Hash
/// let mut shake128hasher = Shake128State::<20>::default().build_hasher();
/// data.hash(&mut shake128hasher);
/// let result_via_hash = shake128hasher.finish();
///
/// // Using Hasher
/// let mut shake128hasher = Shake128State::<20>::default().build_hasher();
/// shake128hasher.write(data);
/// let result_via_hasher = shake128hasher.finish();
///
/// // Simulating the Hash inners
/// let mut shake128hasher = Shake128State::<20>::default().build_hasher();
/// shake128hasher.write_usize(data.len());
/// shake128hasher.write(data);
/// let simulated_hash_result = shake128hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Shake128Hasher<const OUTPUT_SIZE: usize>(GenericHasher<Shake128State<OUTPUT_SIZE>, OUTPUT_SIZE>);

impl<const OUTPUT_SIZE: usize> From<Shake128Hasher<OUTPUT_SIZE>> for Shake128State<OUTPUT_SIZE> {
    fn from(value: Shake128Hasher<OUTPUT_SIZE>) -> Self {
        value.0.state
    }
}

impl<const OUTPUT_SIZE: usize> From<Shake128State<OUTPUT_SIZE>> for Shake128Hasher<OUTPUT_SIZE> {
    fn from(value: Shake128State<OUTPUT_SIZE>) -> Self {
        Self(GenericHasher {
            padding: <Shake128State<OUTPUT_SIZE> as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl<const OUTPUT_SIZE: usize> Hasher for Shake128Hasher<OUTPUT_SIZE> {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<const OUTPUT_SIZE: usize> HasherContext<OUTPUT_SIZE> for Shake128Hasher<OUTPUT_SIZE> {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        ByteArrayWrapper::from(HasherContext::finish(&mut self.0).squeeze())
    }
}
