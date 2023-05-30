use crate::{Sha3_384Hasher, OUTPUT_SIZE};
use core::hash::BuildHasher;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};
use rs_hasher_ctx_lib::ByteArrayWrapper;

const RATE: usize = 104;

/// `Sha3_384State` represents the state of a SHA3-384 hashing process.
///
/// It holds intermediate hash calculations. However, it's important to note that starting a hashing process from an
/// arbitrary `Sha3_384State` is not equivalent to resuming the original process that produced that state. Instead, it
/// begins a new hashing process with a different set of initial values.
///
/// Therefore, a `Sha3_384State` extracted from a `Sha3_384Hasher` should not be used with the expectation of continuing
/// the hashing operation from where it left off in the original `Sha3_384Hasher`. It is a snapshot of a particular
/// point in the process, not a means to resume the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHA3-384 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha3_384::{Sha3_384Hasher, Sha3_384State};
/// let hello = b"hello";
/// let world = b" world";
/// let default_sha3_384state = Sha3_384State::default();
///
/// let mut default_sha3_384hasher = default_sha3_384state.build_hasher();
/// default_sha3_384hasher.write(hello);
///
/// let intermediate_state: Sha3_384State = default_sha3_384hasher.clone().into();
///
/// default_sha3_384hasher.write(world);
///
/// let mut from_sha3_384state: Sha3_384Hasher = intermediate_state.into();
/// from_sha3_384state.write(world);
///
/// let default_hello_world_result = default_sha3_384hasher.finish();
/// let from_arbitrary_state_result = from_sha3_384state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal states are the same between `default_sha3_384hasher` and `from_sha3_384state`
/// before the `Hasher::finish` call, the results are different due to `from_sha3_384state` being instantiated with an empty
/// pad while the `default_sha3_384hasher`'s pad is already populated with `b"hello"`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_384State {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl ExtendedOutputFunction<OUTPUT_SIZE> for Sha3_384State {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl BuildHasher for Sha3_384State {
    type Hasher = Sha3_384Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha3_384Hasher::default()
    }
}

impl BytesLen for Sha3_384State {
    fn len() -> usize {
        RATE
    }
}

impl From<Sha3_384State> for ByteArrayWrapper<OUTPUT_SIZE> {
    fn from(mut value: Sha3_384State) -> Self {
        value.squeeze().into()
    }
}

impl HashAlgorithm for Sha3_384State {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x06>;
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
