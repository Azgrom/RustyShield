use crate::{Sha1State, BYTES_LEN};
use core::hash::Hasher;
use rs_hasher_ctx::{ByteArrayWrapper, GenericHasher, HasherContext};
use rs_internal_hasher::HashAlgorithm;

/// `Sha1Hasher` is a type that provides the SHA-1 hashing algorithm in RustySSL.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that manages the process of converting input
/// data into a fixed-size sequence of bytes. The Hasher is responsible for maintaining the internal state of the
/// hashing process and providing methods to add more data and retrieve the resulting hash.
///
/// The `Sha1Hasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other hashers
/// in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples demonstrate using `Sha1Hasher` with both `Hash` and `Hasher`, and from where the difference
/// comes from:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha1::Sha1Hasher;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha1hasher = Sha1Hasher::default();
/// data.hash(&mut sha1hasher);
/// let result_via_hash = sha1hasher.finish();
///
/// // Using Hasher
/// let mut sha1hasher = Sha1Hasher::default();
/// sha1hasher.write(data);
/// let result_via_hasher = sha1hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha1hasher = Sha1Hasher::default();
/// sha1hasher.write_usize(data.len());
/// sha1hasher.write(data);
/// let simulated_hash_result = sha1hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha1Hasher(GenericHasher<Sha1State, BYTES_LEN>);

impl From<Sha1Hasher> for Sha1State {
    fn from(value: Sha1Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha1State> for Sha1Hasher {
    fn from(value: Sha1State) -> Self {
        Self(GenericHasher {
            padding: <Sha1State as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl Hasher for Sha1Hasher {
    /// Finish the hash and return the hash value as a `u64`.
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    /// Write a byte array to the hasher.
    /// This hasher can digest up to `u64::MAX` bytes. If more bytes are written, the hasher will panic.
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<BYTES_LEN> for Sha1Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        ByteArrayWrapper::from(HasherContext::finish(&mut self.0))
    }
}
