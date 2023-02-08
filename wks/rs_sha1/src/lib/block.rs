use crate::SHA_CBLOCK;
use core::{
    hash::{Hash, Hasher},
    ops::{Index, IndexMut, Range, RangeTo},
};

#[derive(Clone, Debug)]
pub(crate) struct Block {
    data: [u8; SHA_CBLOCK as usize],
}

impl Default for Block {
    fn default() -> Self {
        Self {
            data: [0; SHA_CBLOCK as usize],
        }
    }
}

impl Index<usize> for Block {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<usize>> for Block {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<Range<usize>> for Block {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl Index<RangeTo<usize>> for Block {
    type Output = [u8];

    fn index(&self, range: RangeTo<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<RangeTo<usize>> for Block {
    fn index_mut(&mut self, range: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl PartialEq<[u8; SHA_CBLOCK as usize]> for Block {
    fn eq(&self, other: &[u8; SHA_CBLOCK as usize]) -> bool {
        self.data == *other
    }
}

impl Block {
    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src);
    }

    pub(crate) fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}
