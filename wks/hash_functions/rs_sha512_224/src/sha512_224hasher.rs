use crate::{Sha512_224State, BYTES_LEN};
use core::hash::Hasher;
use rs_hasher_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;

/// `Sha512_224Hasher` is a type that provides the SHA-512/224 hashing algorithm in RustySSL.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that manages the process of converting input
/// data into a fixed-size sequence of bytes. The Hasher is responsible for maintaining the internal state of the
/// hashing process and providing methods to add more data and retrieve the resulting hash.
///
/// The `Sha512_224Hasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other hashers
/// in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples demonstrate using `Sha512_224Hasher` with both `Hash` and `Hasher`, and how the results can differ:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha512_224::Sha512_224Hasher;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha512_224hasher = Sha512_224Hasher::default();
/// data.hash(&mut sha512_224hasher);
/// let result_via_hash = sha512_224hasher.finish();
///
/// // Using Hasher
/// let mut sha512_224hasher = Sha512_224Hasher::default();
/// sha512_224hasher.write(data);
/// let result_via_hasher = sha512_224hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha512_224hasher = Sha512_224Hasher::default();
/// sha512_224hasher.write_usize(data.len());
/// sha512_224hasher.write(data);
/// let simulated_hash_result = sha512_224hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha512_224Hasher(GenericHasher<Sha512_224State, BYTES_LEN>);

impl From<Sha512_224Hasher> for Sha512_224State {
    fn from(value: Sha512_224Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha512_224State> for Sha512_224Hasher {
    fn from(value: Sha512_224State) -> Self {
        Self(GenericHasher {
            padding: <Sha512_224State as HashAlgorithm>::Padding::default(),
            state: value
        })
    }
}

impl Hasher for Sha512_224Hasher {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<BYTES_LEN> for Sha512_224Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).into()
    }
}
