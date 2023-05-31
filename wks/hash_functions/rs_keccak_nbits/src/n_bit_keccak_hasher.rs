use crate::NBitKeccakState;
use core::hash::Hasher;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub};
use rs_internal_state::ExtendedOutputFunction;
use rs_n_bit_words::{LittleEndianBytes, NBitWord, Rotate, TSize};
use rs_hasher_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};

#[derive(Default)]
pub struct NBitKeccakHasher<T, const RATE: usize, const OUTPUT_SIZE: usize>(
    GenericHasher<NBitKeccakState<T, RATE, OUTPUT_SIZE>, OUTPUT_SIZE>,
)
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
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>;

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> Hasher for NBitKeccakHasher<T, RATE, OUTPUT_SIZE>
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
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> HasherContext<OUTPUT_SIZE>
    for NBitKeccakHasher<T, RATE, OUTPUT_SIZE>
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
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
