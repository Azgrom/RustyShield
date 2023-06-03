use crate::{Sha384State, BYTES_LEN};
use core::hash::Hasher;
use rs_internal_hasher::HashAlgorithm;
use rs_hasher_ctx::{ByteArrayWrapper, GenericHasher, HasherContext};

/// `Sha384Hasher` is a type that provides the SHA-384 hashing algorithm in RustySSL.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that manages the process of converting input
/// data into a fixed-size sequence of bytes. The Hasher is responsible for maintaining the internal state of the
/// hashing process and providing methods to add more data and retrieve the resulting hash.
///
/// The `Sha384Hasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other hashers
/// in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples demonstrate using `Sha384Hasher` with both `Hash` and `Hasher`, and explain where the difference
/// comes from:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha384::Sha384Hasher;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha384hasher = Sha384Hasher::default();
/// data.hash(&mut sha384hasher);
/// let result_via_hash = sha384hasher.finish();
///
/// // Using Hasher
/// let mut sha384hasher = Sha384Hasher::default();
/// sha384hasher.write(data);
/// let result_via_hasher = sha384hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha384hasher = Sha384Hasher::default();
/// sha384hasher.write_usize(data.len());
/// sha384hasher.write(data);
/// let simulated_hash_result = sha384hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha384Hasher(GenericHasher<Sha384State, BYTES_LEN>);

impl From<Sha384Hasher> for Sha384State {
    fn from(value: Sha384Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha384State> for Sha384Hasher {
    fn from(value: Sha384State) -> Self {
        Self(GenericHasher {
            padding: <Sha384State as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl Hasher for Sha384Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<BYTES_LEN> for Sha384Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        ByteArrayWrapper::from(HasherContext::finish(&mut self.0))
    }
}
