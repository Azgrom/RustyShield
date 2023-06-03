use crate::NBitKeccakHasher;
use core::hash::BuildHasher;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub};
use rs_internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use rs_internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};
use rs_n_bit_words::{LittleEndianBytes, NBitWord, Rotate, TSize};
use rs_hasher_ctx::ByteArrayWrapper;

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
    T: BitAnd + BitAndAssign + BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor + BitXorAssign + Copy + Default + Not,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
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
    T: BitAnd + BitAndAssign + BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor + BitXorAssign + Copy + Default + Not,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
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
