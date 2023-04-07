use core::ops::{Index, IndexMut, Range, RangeFrom, RangeTo};
use crate::{BytePad, LenPad, PAD_FOR_U32_WORDS, U8_PAD_FOR_U32_SIZE};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct U32Pad (pub [u8; U8_PAD_FOR_U32_SIZE]);

impl AsMut<[u8]> for U32Pad {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for U32Pad {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl BytePad for U32Pad {
    fn last_index(&self) -> usize {
        self.0.len() - 1
    }

    fn offset(&self) -> usize {
        self.0.len() * 7 / 8 - 1
    }
}

impl Default for U32Pad {
    fn default() -> Self {
        Self (PAD_FOR_U32_WORDS)
    }
}

impl LenPad for U32Pad {
    fn len() -> usize {
        U8_PAD_FOR_U32_SIZE
    }
}

impl Index<usize> for U32Pad {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl Index<Range<usize>> for U32Pad {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.0[range]
    }
}

impl Index<RangeFrom<usize>> for U32Pad {
    type Output = [u8];

    fn index(&self, range_from: RangeFrom<usize>) -> &Self::Output {
        &self.0[range_from]
    }
}

impl Index<RangeTo<usize>> for U32Pad {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<usize>) -> &Self::Output {
        &self.0[range_to]
    }
}

impl IndexMut<usize> for U32Pad {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl IndexMut<Range<usize>> for U32Pad {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.0[range]
    }
}

impl IndexMut<RangeFrom<usize>> for U32Pad {
    fn index_mut(&mut self, range_from: RangeFrom<usize>) -> &mut Self::Output {
        &mut self.0[range_from]
    }
}

impl PartialEq<[u8; U8_PAD_FOR_U32_SIZE]> for U32Pad {
    fn eq(&self, other: &[u8; U8_PAD_FOR_U32_SIZE]) -> bool {
        self.0 == *other
    }
}
