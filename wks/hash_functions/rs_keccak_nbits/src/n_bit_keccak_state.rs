use crate::NBitKeccakHasher;
use core::hash::BuildHasher;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub};
use rs_hasher_ctx::ByteArrayWrapper;
use rs_internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use rs_internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};
use rs_n_bit_words::{LittleEndianBytes, NBitWord, Rotate, TSize};

/// `NBitKeccakState` represents the state of a Keccak-nBits hashing process.
///
/// It holds intermediate hash calculations. However, it's important to note that starting a hashing process from an
/// arbitrary `NBitKeccakState` is not equivalent to resuming the original process that produced that state. Instead, it
/// begins a new hashing process with a different set of initial values.
///
/// Therefore, a `NBitKeccakState` extracted from a `KeccakNBitsHasher` should not be used with the expectation of
/// continuing the hashing operation from where it left off in the original `KeccakNBitsHasher`. It is  a snapshot of a
/// particular point in the process, not a means to resume the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a Keccak-nBits hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_keccak_nbits::{NBitKeccakHasher, NBitKeccakState};
/// let hello = b"hello";
/// let world = b" world";
///
/// const RATE: usize = 6;
/// const OUTPUT_SIZE: usize = 24;
/// let mut default_keccakhasher = NBitKeccakState::<u8, RATE, OUTPUT_SIZE>::default().build_hasher();
///
/// default_keccakhasher.write(hello);
///
/// let intermediate_state: NBitKeccakState<u8, RATE, OUTPUT_SIZE> = default_keccakhasher.clone().into();
///
/// default_keccakhasher.write(world);
/// let mut from_keccakstate: NBitKeccakHasher<u8, RATE, OUTPUT_SIZE> = intermediate_state.into();
/// from_keccakstate.write(world);
///
/// let default_hello_world_result = default_keccakhasher.finish();
/// let from_arbitrary_state_result = from_keccakstate.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal state are the same between `default_keccakhasher` and `from_keccakstate`
/// before the `Hasher::finish` call, the results are different due to `from_keccakstate` being instantiated with an
/// empty pad while the `default_keccakhasher`'s pad is already populated with `b"hello"`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct NBitKeccakState<T, const RATE: usize, const OUTPUT_SIZE: usize>
where
    T: Copy + Default,
{
    sponge: KeccakSponge<T, RATE, OUTPUT_SIZE>,
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> BuildHasher for NBitKeccakState<T, RATE, OUTPUT_SIZE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    type Hasher = NBitKeccakHasher<T, RATE, OUTPUT_SIZE>;

    fn build_hasher(&self) -> Self::Hasher {
        NBitKeccakHasher::default()
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> BytesLen for NBitKeccakState<T, RATE, OUTPUT_SIZE>
where
    T: Copy + Default,
{
    fn len() -> usize {
        RATE
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> ExtendedOutputFunction<OUTPUT_SIZE>
    for NBitKeccakState<T, RATE, OUTPUT_SIZE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn squeeze_u64(&self) -> u64 {
        self.sponge.squeeze_u64()
    }

    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE] {
        self.sponge.squeeze()
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> From<NBitKeccakState<T, RATE, OUTPUT_SIZE>>
    for ByteArrayWrapper<OUTPUT_SIZE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn from(value: NBitKeccakState<T, RATE, OUTPUT_SIZE>) -> Self {
        value.sponge.into()
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> HashAlgorithm for NBitKeccakState<T, RATE, OUTPUT_SIZE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    type Padding = GenericPad<KeccakU128Size, RATE, 0x1F>;
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}
