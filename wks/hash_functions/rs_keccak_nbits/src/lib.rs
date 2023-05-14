#![no_std]

use core::{
    hash::{BuildHasher, Hasher},
    ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub},
};
use hash_ctx_lib::{GenericHasher, HasherContext};
use internal_hasher::{GenericPad, HashAlgorithm, KeccakU128Size};
use internal_state::{BytesLen, ExtendedOutputFunction, KeccakSponge};
use n_bit_words_lib::{LittleEndianBytes, NBitWord, Rotate, TSize};

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
struct NBitKeccakState<T, const RATE: usize, const OUTPUT_SIZE: usize>
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
    type Output = [u8; OUTPUT_SIZE];

    fn hash_block(&mut self, bytes: &[u8]) {
        self.sponge.absorb(bytes)
    }

    fn state_to_u64(&self) -> u64 {
        self.squeeze_u64()
    }
}

#[derive(Default)]
struct NBitKeccakHasher<T, const RATE: usize, const OUTPUT_SIZE: usize>(
    GenericHasher<NBitKeccakState<T, RATE, OUTPUT_SIZE>>,
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
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> HasherContext for NBitKeccakHasher<T, RATE, OUTPUT_SIZE>
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
    type State = <NBitKeccakState<T, RATE, OUTPUT_SIZE> as HashAlgorithm>::Output;

    fn finish(&mut self) -> Self::State {
        HasherContext::finish(&mut self.0).squeeze()
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::NBitKeccakState;
    use core::hash::{BuildHasher, Hasher};
    use hash_ctx_lib::HasherContext;

    #[test]
    fn test() {
        let quick_fox = b"The quick brown fox jumps over the lazy dog";

        let keccak: NBitKeccakState<u8, 18, 24> = NBitKeccakState::default();
        let mut hasher = keccak.build_hasher();

        hasher.write(quick_fox);

        let i = hasher.finish();
        let context = HasherContext::finish(&mut hasher);
    }
}
