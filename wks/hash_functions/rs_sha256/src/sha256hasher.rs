use crate::{Sha256State, BYTES_LEN};
use core::hash::Hasher;
use rs_internal_hasher::HashAlgorithm;
use rs_hasher_ctx::{ByteArrayWrapper, GenericHasher, HasherContext};

/// `Sha256Hasher` is a type in RustySSL that facilitates the SHA-256 hashing algorithm.
///
/// A "Hasher" in cryptographic hashing encapsulates the object managing the transformation of input data into a
/// fixed-size byte sequence. The Hasher is tasked with maintaining the internal state of the hashing operation,
/// providing methods to append more data, and retrieve the resulting hash.
///
/// The `Sha256Hasher` struct conforms to Rust's `Hasher` trait, enabling interchangeability with other hashers in Rust.
/// It can be deployed wherever a `Hasher` implementing type is needed.
///
/// ## Examples
///
/// The following examples illustrate the use of `Sha256Hasher` with both `Hash` and `Hasher`, indicating the source of
/// the discrepancy:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha256::Sha256Hasher;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha256hasher = Sha256Hasher::default();
/// data.hash(&mut sha256hasher);
/// let result_via_hash = sha256hasher.finish();
///
/// // Using Hasher
/// let mut sha256hasher = Sha256Hasher::default();
/// sha256hasher.write(data);
/// let result_via_hasher = sha256hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha256hasher = Sha256Hasher::default();
/// sha256hasher.write_usize(data.len());
/// sha256hasher.write(data);
/// let simulated_hash_result = sha256hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha256Hasher(GenericHasher<Sha256State, BYTES_LEN>);

impl From<Sha256Hasher> for Sha256State {
    fn from(value: Sha256Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha256State> for Sha256Hasher {
    fn from(value: Sha256State) -> Self {
        Self(GenericHasher {
            padding: <Sha256State as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl Hasher for Sha256Hasher {
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

impl HasherContext<BYTES_LEN> for Sha256Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).into()
    }
}
