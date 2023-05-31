use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Index, Not, Sub},
};
use rs_internal_state::{ExtendedOutputFunction, KeccakSponge};
use rs_n_bit_words::{LittleEndianBytes, NBitWord, Rotate, TSize};

pub const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
pub const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ByteArrayWrapper<const LEN: usize>([u8; LEN]);

impl<const LEN: usize> ByteArrayWrapper<LEN> {
    pub fn state_to_u64(&self) -> u64 {
        debug_assert!(LEN >= 2);
        ((self[0] as u64) << 32) | (self[1] as u64)
    }
}

impl<const LEN: usize> AsRef<[u8]> for ByteArrayWrapper<LEN> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const LEN: usize> Default for ByteArrayWrapper<LEN> {
    fn default() -> Self {
        [0u8; LEN].into()
    }
}

impl<const LEN: usize> From<[u8; LEN]> for ByteArrayWrapper<LEN> {
    fn from(value: [u8; LEN]) -> Self {
        Self(value)
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> From<KeccakSponge<T, RATE, OUTPUT_SIZE>>
    for ByteArrayWrapper<OUTPUT_SIZE>
where
    T: BitAnd + BitAndAssign + BitOr<NBitWord<T>, Output = NBitWord<T>> + BitXor + BitXorAssign + Copy + Default + Not,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn from(mut value: KeccakSponge<T, RATE, OUTPUT_SIZE>) -> Self {
        value.squeeze().into()
    }
}

impl<const LEN: usize> From<ByteArrayWrapper<LEN>> for [u8; LEN] {
    fn from(value: ByteArrayWrapper<LEN>) -> Self {
        value.0
    }
}

impl<const LEN: usize> Index<usize> for ByteArrayWrapper<LEN> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<const LEN: usize> LowerHex for ByteArrayWrapper<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let f_n_minus_one = self.0.iter().take(LEN - 1).fold(f, |f, b| {
            LowerHex::fmt(b, f).expect(LOWER_HEX_ERR);
            f
        });
        LowerHex::fmt(&self.0[LEN - 1], f_n_minus_one)
    }
}

impl<const LEN: usize> PartialEq<[u8; LEN]> for ByteArrayWrapper<LEN> {
    fn eq(&self, other: &[u8; LEN]) -> bool {
        self.0 == *other
    }
}

impl<const LEN: usize> UpperHex for ByteArrayWrapper<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let f_n_minus_one = self.0.iter().take(LEN - 1).fold(f, |f, b| {
            UpperHex::fmt(b, f).expect(UPPER_HEX_ERR);
            f
        });
        UpperHex::fmt(&self.0[LEN - 1], f_n_minus_one)
    }
}
