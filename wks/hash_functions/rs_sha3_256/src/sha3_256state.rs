use crate::{Sha3_256Hasher, OUTPUT_SIZE};
use core::hash::BuildHasher;
use hash_ctx_lib::ByteArrayWrapper;
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};

const RATE: usize = 136;

/// `Sha3_256State` embodies the state of a SHA3-256 hashing operation.
///
/// It maintains intermediate hash computations. Nonetheless, it's essential to understand that initiating a hashing process from an
/// arbitrary `Sha3_256State` does not equate to resuming the original operation that yielded that state. Instead, it
/// commences a new hashing operation with a distinct set of initial values.
///
/// As such, a `Sha3_256State` retrieved from a `Sha3_256Hasher` should not be used with the intention of continuing
/// the hashing activity from where it stopped in the original `Sha3_256Hasher`. It serves as a snapshot of a specific
/// moment in the operation, not a tool to resume the process.
///
/// # Example
///
/// This example illustrates how to persist the state of a SHA3-256 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_sha3_256::{Sha3_256Hasher, Sha3_256State};
/// let hello = b"hello";
/// let world = b" world";
/// let default_sha3_256state = Sha3_256State::default();
///
/// let mut default_sha3_256hasher = default_sha3_256state.build_hasher();
/// default_sha3_256hasher.write(hello);
///
/// let intermediate_state: Sha3_256State = default_sha3_256hasher.clone().into();
///
/// default_sha3_256hasher.write(world);
///
/// let mut from_sha3_256state: Sha3_256Hasher = intermediate_state.into();
/// from_sha3_256state.write(world);
///
/// let default_hello_world_result = default_sha3_256hasher.finish();
/// let from_arbitrary_state_result = from_sha3_256state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, despite the internal states being identical between `default_sha3_256hasher` and `from_sha3_256state`
/// before the `Hasher::finish` call, the results diverge due to `from_sha3_256state` being instantiated with an empty
/// pad whereas the `default_sha3_256hasher`'s pad is pre-populated with `b"hello"`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Sha3_256State {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl ExtendedOutputFunction<OUTPUT_SIZE> for Sha3_256State {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl BuildHasher for Sha3_256State {
    type Hasher = Sha3_256Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        Sha3_256Hasher::default()
    }
}

impl BytesLen for Sha3_256State {
    fn len() -> usize {
        RATE
    }
}

impl From<Sha3_256State> for ByteArrayWrapper<OUTPUT_SIZE> {
    fn from(mut value: Sha3_256State) -> Self {
        value.squeeze().into()
    }
}

impl HashAlgorithm for Sha3_256State {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x06>;
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
