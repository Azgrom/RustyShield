use crate::{Sha3_512Hasher, OUTPUT_SIZE};
use core::hash::BuildHasher;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};
use rs_hasher_ctx_lib::ByteArrayWrapper;

const RATE: usize = 72;

/// `Sha3_512State` represents the state of a SHA3-512 hashing process.
///
/// It maintains the intermediate hash computations. It's crucial to understand that initiating a hashing process from an
/// arbitrary `Sha3_512State` doesn't equate to resuming the original process that yielded that state. Instead, it
/// commences a new hashing process with a distinct set of initial values.
///
/// Thus, a `Sha3_512State` derived from a `Sha3_512Hasher` should not be utilized with the intention of continuing
/// the hashing operation from where it left off in the original `Sha3_512Hasher`. It merely provides a snapshot of a particular
/// stage in the process, rather than a mechanism to continue the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHA3-512 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha3_512::{Sha3_512Hasher, Sha3_512State};
/// let hello = b"hello";
/// let world = b" world";
/// let default_sha3_512state = Sha3_512State::default();
///
/// let mut default_sha3_512hasher = default_sha3_512state.build_hasher();
/// default_sha3_512hasher.write(hello);
///
/// let intermediate_state: Sha3_512State = default_sha3_512hasher.clone().into();
///
/// default_sha3_512hasher.write(world);
///
/// let mut from_sha3_512state: Sha3_512Hasher = intermediate_state.into();
/// from_sha3_512state.write(world);
///
/// let default_hello_world_result = default_sha3_512hasher.finish();
/// let from_arbitrary_state_result = from_sha3_512state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal states are the same between `default_sha3_512hasher` and `from_sha3_512state`
/// before the `Hasher::finish` call, the results differ due to `from_sha3_512state` starting with an empty
/// pad while the `default_sha3_512hasher`'s pad is already populated with `b"hello"`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_512State {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl ExtendedOutputFunction<OUTPUT_SIZE> for Sha3_512State {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl BuildHasher for Sha3_512State {
    type Hasher = Sha3_512Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha3_512Hasher::default()
    }
}

impl BytesLen for Sha3_512State {
    fn len() -> usize {
        RATE
    }
}

impl From<Sha3_512State> for ByteArrayWrapper<OUTPUT_SIZE> {
    fn from(value: Sha3_512State) -> Self {
        value.sponge.into()
    }
}

impl HashAlgorithm for Sha3_512State {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x06>;
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
