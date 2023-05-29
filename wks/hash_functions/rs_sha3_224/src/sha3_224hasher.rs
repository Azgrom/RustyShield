use crate::{Sha3_224State, OUTPUT_SIZE};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;
use internal_state::ExtendedOutputFunction;

/// `Sha3_224Hasher` is a type that provides the SHA3-224 hashing algorithm in Rust.
///
/// In the context of cryptographic hashing, a "Hasher" refers to the object that orchestrates the conversion of input
/// data into a fixed-size sequence of bytes. The Hasher is tasked with maintaining the internal state of the hashing
/// process and providing the necessary methods to both add more data and retrieve the resultant hash.
///
/// `Sha3_224Hasher` conforms to Rust's `Hasher` trait. This allows it to be used interchangeably with other Rust hashers.
/// It can be utilized wherever a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples show how to use `Sha3_224Hasher` with both `Hash` and `Hasher`, illustrating the difference
/// between the two:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha3_224::Sha3_224State;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha3_224hasher = Sha3_224State::default().build_hasher();
/// data.hash(&mut sha3_224hasher);
/// let result_via_hash = sha3_224hasher.finish();
///
/// // Using Hasher
/// let mut sha3_224hasher = Sha3_224State::default().build_hasher();
/// sha3_224hasher.write(data);
/// let result_via_hasher = sha3_224hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha3_224hasher = Sha3_224State::default().build_hasher();
/// sha3_224hasher.write_usize(data.len());
/// sha3_224hasher.write(data);
/// let simulated_hash_result = sha3_224hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct Sha3_224Hasher(GenericHasher<Sha3_224State, OUTPUT_SIZE>);

impl From<Sha3_224Hasher> for Sha3_224State {
    fn from(value: Sha3_224Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha3_224State> for Sha3_224Hasher {
    fn from(value: Sha3_224State) -> Self {
        Self(GenericHasher{
            padding: <Sha3_224State as HashAlgorithm>::Padding::default(),
            state: value
        })
    }
}

impl Hasher for Sha3_224Hasher {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<OUTPUT_SIZE> for Sha3_224Hasher {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
