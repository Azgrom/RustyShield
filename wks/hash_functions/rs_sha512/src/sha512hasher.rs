use crate::{Sha512State, BYTES_LEN};
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;

/// `Sha512Hasher` is a type that provides the SHA-512 hashing algorithm in RustySSL.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that manages the process of converting input
/// data into a fixed-size sequence of bytes. The Hasher is responsible for maintaining the internal state of the
/// hashing process and providing methods to add more data and retrieve the resulting hash.
///
/// The `Sha512Hasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other hashers
/// in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples demonstrate using `Sha512Hasher` with both `Hash` and `Hasher`, and from where the difference
/// comes from:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha512::Sha512State;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha512hasher = Sha512State::default().build_hasher();
/// data.hash(&mut sha512hasher);
/// let result_via_hash = sha512hasher.finish();
///
/// // Using Hasher
/// let mut sha512hasher = Sha512State::default().build_hasher();
/// sha512hasher.write(data);
/// let result_via_hasher = sha512hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha512hasher = Sha512State::default().build_hasher();
/// sha512hasher.write_usize(data.len());
/// sha512hasher.write(data);
/// let simulated_hash_result = sha512hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default)]
pub struct Sha512Hasher(GenericHasher<Sha512State, BYTES_LEN>);

impl From<Sha512Hasher> for Sha512State {
    fn from(value: Sha512Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha512State> for Sha512Hasher {
    fn from(value: Sha512State) -> Self {
        Self(GenericHasher {
            padding: <Sha512State as HashAlgorithm>::Padding::default(),
            state: value
        })
    }
}

impl Hasher for Sha512Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<BYTES_LEN> for Sha512Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        ByteArrayWrapper::from(HasherContext::finish(&mut self.0))
    }
}
