use core::ops::{AddAssign, Index, IndexMut, RangeTo};
use crate::{BytePad, LenPad};
use crate::constants::{PAD_FOR_U64_WORDS, U8_PAD_FOR_U64_SIZE};

pub struct U64Pad {
    pub size: u128,
    pub pad: [u8; U8_PAD_FOR_U64_SIZE],
}

impl AddAssign<usize> for U64Pad {
    fn add_assign(&mut self, rhs: usize) {
        self.size += rhs as u128;
    }
}

impl AsMut<[u8]> for U64Pad {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.pad
    }
}

impl AsRef<[u8]> for U64Pad {
    fn as_ref(&self) -> &[u8] {
        &self.pad
    }
}

impl BytePad for U64Pad {
    fn last_index(&self) -> usize {
        self.pad.len() - 1
    }

    fn offset(&self) -> usize {
        self.pad.len() * 7 / 8 - 1
    }
}

impl Default for U64Pad {
    fn default() -> Self {
        Self {
            size: 0,
            pad: PAD_FOR_U64_WORDS
        }
    }
}

impl LenPad for U64Pad {
    fn len() -> usize {
        U8_PAD_FOR_U64_SIZE
    }
}

impl Index<usize> for U64Pad {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.pad[index]
    }
}

impl IndexMut<usize> for U64Pad {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.pad[index]
    }
}

impl Index<RangeTo<usize>> for U64Pad {
    type Output = [u8];

    fn index(&self, range: RangeTo<usize>) -> &Self::Output {
        &self.pad[range]
    }
}
