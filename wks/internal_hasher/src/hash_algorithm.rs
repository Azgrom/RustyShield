use crate::{BytePad, DigestThroughPad, LenPad};
use core::ops::{Index, IndexMut, RangeTo};
use internal_state::BytesLen;

pub trait HashAlgorithm: BytesLen + Clone {
    type Padding: AsRef<[u8]>
        + AsMut<[u8]>
        + BytePad
        + Clone
        + Default
        + DigestThroughPad<Self>
        + LenPad
        + Index<usize, Output = u8>
        + IndexMut<usize>
        + Index<RangeTo<usize>, Output = [u8]>;
    type Output: AsRef<[u8]> + Index<usize, Output = u8>;

    fn hash_block(&mut self, bytes: &[u8]);
    fn state_to_u64(&self) -> u64;
}
