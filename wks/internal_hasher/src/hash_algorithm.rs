use crate::{BytePad, LenPad};
use core::ops::{Index, IndexMut, RangeTo};

pub trait HashAlgorithm: Clone {
    type Padding:
        AsRef<[u8]>
        + AsMut<[u8]>
        + BytePad
        + Clone
        + Default
        + LenPad
        + Index<usize, Output = u8>
        + IndexMut<usize>
        + Index<RangeTo<usize>, Output = [u8]>;
    type Output;

    fn hash_block(&mut self, bytes: &[u8]);
    fn state_to_u64(&self) -> u64;
}
