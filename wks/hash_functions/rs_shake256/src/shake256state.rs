use crate::Shake256Hasher;
use core::hash::BuildHasher;
use rs_internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use rs_internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};
use rs_hasher_ctx::ByteArrayWrapper;

const RATE: usize = 136;

/// `Shake256State` represents the state of a SHAKE256 hashing process.
///
/// It holds intermediate hash calculations. However, it's important to note that starting a hashing process from an
/// arbitrary `Shake256State` is not equivalent to resuming the original process that produced that state. Instead, it
/// begins a new hashing process with a different set of initial values.
///
/// Therefore, a `Shake256State` extracted from a `Shake256Hasher` should not be used with the expectation of continuing
/// the hashing operation from where it left off in the original `Shake256Hasher`. It is a snapshot of a particular
/// point in the process, not a means to resume the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHAKE256 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_shake256::{Shake256Hasher, Shake256State};
/// let hello = b"hello";
/// let world = b" world";
/// let default_shake256state = Shake256State::<32>::default();
///
/// let mut default_shake256hasher = default_shake256state.build_hasher();
/// default_shake256hasher.write(hello);
///
/// let intermediate_state: Shake256State<32> = default_shake256hasher.clone().into();
///
/// default_shake256hasher.write(world);
///
/// let mut from_shake256state: Shake256Hasher<32> = intermediate_state.into();
/// from_shake256state.write(world);
///
/// let default_hello_world_result = default_shake256hasher.finish();
/// let from_arbitrary_state_result = from_shake256state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal states are the same between `default_shake256hasher` and `from_shake256state`
/// before the `Hasher::finish_xof` call, the results are different due to `from_shake256state` being instantiated with an empty
/// pad while the `default_shake256hasher`'s pad is already populated with `b"hello"`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Shake256State<const OUTPUT_SIZE: usize> {
    sponge: KeccakSponge<u64, RATE, OUTPUT_SIZE>,
}

impl<const OUTPUT_SIZE: usize> BuildHasher for Shake256State<OUTPUT_SIZE> {
    type Hasher = Shake256Hasher<OUTPUT_SIZE>;

    fn build_hasher(&self) -> Self::Hasher {
        Shake256Hasher::default()
    }
}

impl<const OUTPUT_SIZE: usize> BytesLen for Shake256State<OUTPUT_SIZE> {
    fn len() -> usize {
        RATE
    }
}

impl<const OUTPUT_SIZE: usize> ExtendedOutputFunction<OUTPUT_SIZE> for Shake256State<OUTPUT_SIZE> {
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl<const OUTPUT_SIZE: usize> From<Shake256State<OUTPUT_SIZE>> for ByteArrayWrapper<OUTPUT_SIZE> {
    fn from(mut value: Shake256State<OUTPUT_SIZE>) -> Self {
        value.squeeze().into()
    }
}

impl<const OUTPUT_SIZE: usize> HashAlgorithm for Shake256State<OUTPUT_SIZE> {
    type Padding = GenericPad<KeccakU128Size, RATE, 0x1F>;
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
