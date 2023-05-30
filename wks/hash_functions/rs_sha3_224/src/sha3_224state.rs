use crate::{Sha3_224Hasher, OUTPUT_SIZE};
use core::hash::BuildHasher;
use rs_hasher_ctx_lib::ByteArrayWrapper;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};

const RATE: usize = 144;

/// `Sha3_224State` represents the state of a SHA3-224 hashing process.
///
/// This state holds intermediate hash calculations. However, it's important to understand that starting a hashing process from an
/// arbitrary `Sha3_224State` is not equivalent to resuming the original process that produced that state. It effectively begins a new
/// hashing process with a distinct set of initial values.
///
/// Consequently, a `Sha3_224State` extracted from a `Sha3_224Hasher` should not be used with the anticipation of continuing the
/// hashing operation from the point it left off in the original `Sha3_224Hasher`. It represents a snapshot of a specific point in
/// the hashing process, not a mechanism to resume the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHA3-224 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha3_224::{Sha3_224Hasher, Sha3_224State};
/// let hello = b"hello";
/// let world = b" world";
/// let default_sha3_224state = Sha3_224State::default();
///
/// let mut default_sha3_224hasher = default_sha3_224state.build_hasher();
/// default_sha3_224hasher.write(hello);
///
/// let intermediate_state: Sha3_224State = default_sha3_224hasher.clone().into();
///
/// default_sha3_224hasher.write(world);
///
/// let mut from_sha3_224state: Sha3_224Hasher = intermediate_state.into();
/// from_sha3_224state.write(world);
///
/// let default_hello_world_result = default_sha3_224hasher.finish();
/// let from_arbitrary_state_result = from_sha3_224state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal states are the same between `default_sha3_224hasher` and `from_sha3_224state`
/// before the `Hasher::finish` call, the results are different because `from_sha3_224state` starts with an empty
/// pad, while `default_sha3_224hasher`'s pad already contains `b"hello"`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_224State {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl ExtendedOutputFunction<OUTPUT_SIZE> for Sha3_224State {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl BuildHasher for Sha3_224State {
    type Hasher = Sha3_224Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha3_224Hasher::default()
    }
}

impl BytesLen for Sha3_224State {
    fn len() -> usize {
        RATE
    }
}

impl From<Sha3_224State> for ByteArrayWrapper<OUTPUT_SIZE> {
    fn from(mut value: Sha3_224State) -> Self {
        value.squeeze().into()
    }
}

impl HashAlgorithm for Sha3_224State {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x06>;
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
