use crate::{Sha3_512State, OUTPUT_SIZE};
use core::hash::Hasher;
use rs_hasher_ctx::{ByteArrayWrapper, GenericHasher, HasherContext};
use rs_internal_hasher::HashAlgorithm;
use rs_internal_state::ExtendedOutputFunction;

/// `Sha3_512Hasher` is a type that provides the SHA3-512 hashing algorithm in Rust.
///
/// In the context of cryptographic hashing, a "Hasher" is the object that manages the process of transforming input
/// data into a fixed-size sequence of bytes. The Hasher is in charge of maintaining the internal state of the
/// hashing process and offering methods to append more data and obtain the resultant hash.
///
/// The `Sha3_512Hasher` struct conforms to Rust's `Hasher` trait, allowing you to use it interchangeably with other hashers
/// in Rust. It can be utilized wherever a type implementing `Hasher` is needed.
///
/// ## Examples
///
/// The following examples illustrate using `Sha3_512Hasher` with both `Hash` and `Hasher`, and explain the differences
/// between the two:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha3_512::Sha3_512State;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha3_512hasher = Sha3_512State::default().build_hasher();
/// data.hash(&mut sha3_512hasher);
/// let result_via_hash = sha3_512hasher.finish();
///
/// // Using Hasher
/// let mut sha3_512hasher = Sha3_512State::default().build_hasher();
/// sha3_512hasher.write(data);
/// let result_via_hasher = sha3_512hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha3_512hasher = Sha3_512State::default().build_hasher();
/// sha3_512hasher.write_usize(data.len());
/// sha3_512hasher.write(data);
/// let simulated_hash_result = sha3_512hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_512Hasher(GenericHasher<Sha3_512State, OUTPUT_SIZE>);

impl From<Sha3_512Hasher> for Sha3_512State {
    fn from(value: Sha3_512Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha3_512State> for Sha3_512Hasher {
    fn from(value: Sha3_512State) -> Self {
        Self(GenericHasher {
            padding: <Sha3_512State as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl Hasher for Sha3_512Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<OUTPUT_SIZE> for Sha3_512Hasher {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
