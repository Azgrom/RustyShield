use crate::{BytePad, DigestThroughPad, LenPad};
use core::fmt::Debug;
use core::hash::Hash;
use core::ops::{Index, IndexMut, RangeTo};
use rs_internal_state::BytesLen;

pub trait HashAlgorithm: BytesLen + Clone {
    type Padding: AsRef<[u8]>
        + AsMut<[u8]>
        + BytePad
        + Clone
        + Debug
        + Default
        + DigestThroughPad<Self>
        + Eq
        + Hash
        + LenPad
        + Index<usize, Output = u8>
        + IndexMut<usize>
        + Index<RangeTo<usize>, Output = [u8]>;
    type Output: AsRef<[u8]> + Index<usize, Output = u8>;

    fn hash_block(&mut self, bytes: &[u8]);
    fn state_to_u64(&self) -> u64;
}
