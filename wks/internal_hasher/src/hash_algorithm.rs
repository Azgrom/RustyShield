use crate::{BigEndianBytes, BytePad, LenPad};
use core::ops::{AddAssign, BitAnd, Index, IndexMut, Mul, RangeTo};
use internal_state::BytesLen;

pub trait HashAlgorithm: BytesLen + Clone {
    type Padding: AsRef<[u8]>
        + AsMut<[u8]>
        + BytePad
        + Clone
        + Default
        + LenPad
        + Index<usize, Output = u8>
        + IndexMut<usize>
        + Index<RangeTo<usize>, Output = [u8]>;
    type Output: AsRef<[u8]> + Index<usize, Output = u8>;
    type SizeBigEndianByteArray: AddAssign<u64>
        + Clone
        + Copy
        + BigEndianBytes
        + BitAnd<u64, Output = u64>
        + From<u64>
        + From<u128>
        + Mul<u32, Output = Self::SizeBigEndianByteArray>;

    fn hash_block(&mut self, bytes: &[u8]);
    fn state_to_u64(&self) -> u64;
}
