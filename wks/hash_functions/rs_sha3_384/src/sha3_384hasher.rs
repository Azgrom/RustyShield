use crate::{Sha3_384State, OUTPUT_SIZE};
use core::hash::Hasher;
use internal_hasher::HashAlgorithm;
use internal_state::ExtendedOutputFunction;
use rs_hasher_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};

/// `Sha3_384Hasher` is a type that provides the SHA3-384 hashing algorithm in Rust.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that manages the process of converting input
/// data into a fixed-size sequence of bytes. The Hasher is responsible for maintaining the internal state of the
/// hashing process and providing methods to add more data and retrieve the resulting hash.
///
/// The `Sha3_384Hasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other hashers
/// in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples demonstrate using `Sha3_384Hasher` with both `Hash` and `Hasher`, and from where the difference
/// comes from:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha3_384::Sha3_384State;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha3_384hasher = Sha3_384State::default().build_hasher();
/// data.hash(&mut sha3_384hasher);
/// let result_via_hash = sha3_384hasher.finish();
///
/// // Using Hasher
/// let mut sha3_384hasher = Sha3_384State::default().build_hasher();
/// sha3_384hasher.write(data);
/// let result_via_hasher = sha3_384hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha3_384hasher = Sha3_384State::default().build_hasher();
/// sha3_384hasher.write_usize(data.len());
/// sha3_384hasher.write(data);
/// let simulated_hash_result = sha3_384hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_384Hasher(GenericHasher<Sha3_384State, OUTPUT_SIZE>);

impl From<Sha3_384Hasher> for Sha3_384State {
    fn from(value: Sha3_384Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha3_384State> for Sha3_384Hasher {
    fn from(value: Sha3_384State) -> Self {
        Self(GenericHasher {
            padding: <Sha3_384State as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl Hasher for Sha3_384Hasher {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<OUTPUT_SIZE> for Sha3_384Hasher {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
