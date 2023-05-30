use crate::{Sha3_256State, OUTPUT_SIZE};
use core::hash::Hasher;
use rs_hasher_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;
use internal_state::ExtendedOutputFunction;

/// `Sha3_256Hasher` is a type that implements the SHA3-256 hashing algorithm in Rust.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that oversees the process of converting input
/// data into a fixed-size sequence of bytes. The Hasher is tasked with maintaining the internal state of the
/// hashing operation and offering methods to add more data and retrieve the resulting hash.
///
/// The `Sha3_256Hasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other hashers
/// in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples demonstrate using `Sha3_256Hasher` with both `Hash` and `Hasher`, and highlight where the differences
/// arise:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha3_256::Sha3_256State;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha3_256hasher = Sha3_256State::default().build_hasher();
/// data.hash(&mut sha3_256hasher);
/// let result_via_hash = sha3_256hasher.finish();
///
/// // Using Hasher
/// let mut sha3_256hasher = Sha3_256State::default().build_hasher();
/// sha3_256hasher.write(data);
/// let result_via_hasher = sha3_256hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha3_256hasher = Sha3_256State::default().build_hasher();
/// sha3_256hasher.write_usize(data.len());
/// sha3_256hasher.write(data);
/// let simulated_hash_result = sha3_256hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_256Hasher(GenericHasher<Sha3_256State, OUTPUT_SIZE>);

impl From<Sha3_256Hasher> for Sha3_256State {
    fn from(value: Sha3_256Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha3_256State> for Sha3_256Hasher {
    fn from(value: Sha3_256State) -> Self {
        Self(GenericHasher{
            padding: <Sha3_256State as HashAlgorithm>::Padding::default(),
            state: value
        })
    }
}

impl Hasher for Sha3_256Hasher {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<OUTPUT_SIZE> for Sha3_256Hasher {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
