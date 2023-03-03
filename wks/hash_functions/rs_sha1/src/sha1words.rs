use crate::SHA1_BLOCK_SIZE;
use core::ops::RangeFrom;
use core::{
    hash::{Hash, Hasher},
    ops::{Index, IndexMut, Range, RangeTo},
};
use n_bit_words_lib::U32Word;

#[derive(Clone, Debug)]
pub(crate) struct Sha1Padding {
    data: [u8; SHA1_BLOCK_SIZE as usize],
}

impl Sha1Padding {
    pub(crate) fn to_be_u32(&self, i: usize) -> U32Word {
        U32Word::from_be_bytes([self[(i * 4)], self[(i * 4) + 1], self[(i * 4) + 2], self[(i * 4) + 3]])
    }

    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src);
    }
}

impl Default for Sha1Padding {
    fn default() -> Self {
        Self {
            data: [u8::MIN; SHA1_BLOCK_SIZE as usize],
        }
    }
}

impl Hash for Sha1Padding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Index<usize> for Sha1Padding {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<u8>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range: Range<u8>) -> &Self::Output {
        &self.data[range.start as usize..range.end as usize]
    }
}

impl Index<RangeFrom<u8>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range: RangeFrom<u8>) -> &Self::Output {
        &self.data[range.start as usize..]
    }
}

impl IndexMut<Range<u8>> for Sha1Padding {
    fn index_mut(&mut self, range: Range<u8>) -> &mut Self::Output {
        &mut self.data[range.start as usize..range.end as usize]
    }
}

impl IndexMut<RangeFrom<u8>> for Sha1Padding {
    fn index_mut(&mut self, range: RangeFrom<u8>) -> &mut Self::Output {
        &mut self.data[range.start as usize..]
    }
}

impl Index<Range<usize>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<Range<usize>> for Sha1Padding {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl Index<RangeTo<u8>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<u8>) -> &Self::Output {
        &self.data[..range_to.end as usize]
    }
}

impl Index<RangeTo<usize>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<usize>) -> &Self::Output {
        &self.data[range_to]
    }
}

impl IndexMut<RangeTo<usize>> for Sha1Padding {
    fn index_mut(&mut self, range_to: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range_to]
    }
}

impl PartialEq for Sha1Padding {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl PartialEq<[u8; SHA1_BLOCK_SIZE as usize]> for Sha1Padding {
    fn eq(&self, other: &[u8; SHA1_BLOCK_SIZE as usize]) -> bool {
        self.data == *other
    }
}
