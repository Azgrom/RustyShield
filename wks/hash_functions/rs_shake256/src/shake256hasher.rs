use crate::Shake256State;
use core::hash::Hasher;
use rs_hasher_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;
use internal_state::ExtendedOutputFunction;

/// `Shake256Hasher` is a type that provides the SHAKE256 hashing algorithm in Rust.
///
/// Within the realm of cryptographic hashing, a "Hasher" designates the object that oversees the transformation of input
/// data into a variable-size sequence of bytes. The Hasher's responsibilities include preserving the internal state of the
/// hashing process and offering methods to both append more data and obtain the resulting hash.
///
/// `Shake256Hasher` complies with Rust's `Hasher` trait. This trait compliance enables its interchangeable use with other Rust hashers.
/// It can be leveraged in any context where a type implementing `Hasher` is needed.
///
/// ## Examples
///
/// The following examples show how to use `Shake256Hasher` with both `Hash` and `Hasher`, and demonstrate the difference
/// between the two:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_shake256::Shake256State;
/// let data = b"hello";
///
/// // Using Hash
/// let mut shake256hasher = Shake256State::<20>::default().build_hasher();
/// data.hash(&mut shake256hasher);
/// let result_via_hash = shake256hasher.finish();
///
/// // Using Hasher
/// let mut shake256hasher = Shake256State::<20>::default().build_hasher();
/// shake256hasher.write(data);
/// let result_via_hasher = shake256hasher.finish();
///
/// // Simulating the Hash inners
/// let mut shake256hasher = Shake256State::<20>::default().build_hasher();
/// shake256hasher.write_usize(data.len());
/// shake256hasher.write(data);
/// let simulated_hash_result = shake256hasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Shake256Hasher<const OUTPUT_SIZE: usize>(GenericHasher<Shake256State<OUTPUT_SIZE>, OUTPUT_SIZE>);

impl<const OUTPUT_SIZE: usize> From<Shake256Hasher<OUTPUT_SIZE>> for Shake256State<OUTPUT_SIZE> {
    fn from(value: Shake256Hasher<OUTPUT_SIZE>) -> Self {
        value.0.state
    }
}

impl<const OUTPUT_SIZE: usize> From<Shake256State<OUTPUT_SIZE>> for Shake256Hasher<OUTPUT_SIZE> {
    fn from(value: Shake256State<OUTPUT_SIZE>) -> Self {
        Self(GenericHasher{
            padding: <Shake256State<OUTPUT_SIZE> as HashAlgorithm>::Padding::default(),
            state: value
        })
    }
}

impl<const OUTPUT_SIZE: usize> Hasher for Shake256Hasher<OUTPUT_SIZE> {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<const OUTPUT_SIZE: usize> HasherContext<OUTPUT_SIZE> for Shake256Hasher<OUTPUT_SIZE> {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
