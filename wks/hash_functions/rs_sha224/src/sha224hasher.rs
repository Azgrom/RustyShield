use crate::{Sha224State, BYTES_LEN};
use core::hash::Hasher;
use rs_hasher_ctx::{ByteArrayWrapper, GenericHasher, HasherContext};
use rs_internal_hasher::HashAlgorithm;

/// `Sha224Hasher` is a type that provides the SHA-224 hashing algorithm in RustyShield.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that manages the process of converting input
/// data into a fixed-size sequence of bytes. The Hasher is responsible for maintaining the internal state of the
/// hashing process and providing methods to add more data and retrieve the resulting hash.
///
/// The `Sha224Hasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other
/// hashers in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// # Examples
///
/// The following examples demonstrate using `Sha1Hasher` with both `Hash` and `Hasher`, and from where the difference
/// comes from:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha224::Sha224Hasher;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha224hasher = Sha224Hasher::default();
/// data.hash(&mut sha224hasher);
/// let result_via_hash = sha224hasher.finish();
///
/// // Using Hasher
/// let mut sha224hasher = Sha224Hasher::default();
/// sha224hasher.write(data);
/// let result_via_hasher = sha224hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha224hasher = Sha224Hasher::default();
/// sha224hasher.write_usize(data.len());
/// sha224hasher.write(data);
/// let simulated_hash_result = sha224hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
/// ```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha224Hasher(GenericHasher<Sha224State, BYTES_LEN>);

impl From<Sha224Hasher> for Sha224State {
    fn from(value: Sha224Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha224State> for Sha224Hasher {
    fn from(value: Sha224State) -> Self {
        Self(GenericHasher {
            padding: <Sha224State as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl Hasher for Sha224Hasher {
    /// Finish the hash and return the hash value as a `u64`.
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    /// Write a byte array to the hasher.
    /// This hasher can digest up to `u64::MAX` bytes. If more bytes are written, the hasher will panic.
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<BYTES_LEN> for Sha224Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).into()
    }
}
