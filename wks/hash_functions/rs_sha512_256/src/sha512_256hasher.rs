use crate::{Sha512_256State, BYTES_LEN};
use core::hash::Hasher;
use internal_hasher::HashAlgorithm;
use rs_hasher_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};

/// `Sha512_256Hasher` is a type that provides the SHA-512/256 hashing algorithm in RustySSL.
///
/// In the context of cryptographic hashing, a "Hasher" is the entity that manages the conversion of input
/// data into a fixed-size sequence of bytes. The Hasher maintains the internal state of the
/// hashing process and offers methods to append more data and retrieve the resultant hash.
///
/// The `Sha512_256Hasher` struct complies with Rust's `Hasher` trait, permitting its usage interchangeably with other hashers
/// in Rust. It can be deployed wherever a type implementing `Hasher` is necessitated.
///
/// ## Examples
///
/// The following examples demonstrate using `Sha512_256Hasher` with both `Hash` and `Hasher`, and elucidate the difference
/// between the two:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha512_256::Sha512_256State;
/// let data = b"hello";
///
/// // Using Hash
/// let mut sha512_256hasher = Sha512_256State::default().build_hasher();
/// data.hash(&mut sha512_256hasher);
/// let result_via_hash = sha512_256hasher.finish();
///
/// // Using Hasher
/// let mut sha512_256hasher = Sha512_256State::default().build_hasher();
/// sha512_256hasher.write(data);
/// let result_via_hasher = sha512_256hasher.finish();
///
/// // Simulating the Hash inners
/// let mut sha512_256hasher = Sha512_256State::default().build_hasher();
/// sha512_256hasher.write_usize(data.len());
/// sha512_256hasher.write(data);
/// let simulated_hash_result = sha512_256hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha512_256Hasher(GenericHasher<Sha512_256State, BYTES_LEN>);

impl From<Sha512_256Hasher> for Sha512_256State {
    fn from(value: Sha512_256Hasher) -> Self {
        value.0.state
    }
}

impl From<Sha512_256State> for Sha512_256Hasher {
    fn from(value: Sha512_256State) -> Self {
        Self(GenericHasher {
            padding: <Sha512_256State as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl Hasher for Sha512_256Hasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl HasherContext<BYTES_LEN> for Sha512_256Hasher {
    type Output = ByteArrayWrapper<BYTES_LEN>;

    fn finish(&mut self) -> Self::Output {
        ByteArrayWrapper::from(HasherContext::finish(&mut self.0))
    }
}
