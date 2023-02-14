use crate::SHA1_BLOCK_SIZE;
use core::{
    hash::{Hash, Hasher},
    ops::{Index, IndexMut, Range, RangeTo},
};

#[derive(Clone, Debug)]
pub(crate) struct Sha1Words {
    data: [u8; SHA1_BLOCK_SIZE as usize],
}

impl Default for Sha1Words {
    fn default() -> Self {
        Self {
            data: [0; SHA1_BLOCK_SIZE as usize],
        }
    }
}

impl Hash for Sha1Words {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Index<usize> for Sha1Words {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<usize>> for Sha1Words {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<Range<usize>> for Sha1Words {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl Index<RangeTo<usize>> for Sha1Words {
    type Output = [u8];

    fn index(&self, range: RangeTo<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<RangeTo<usize>> for Sha1Words {
    fn index_mut(&mut self, range: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl PartialEq<[u8; SHA1_BLOCK_SIZE as usize]> for Sha1Words {
    fn eq(&self, other: &[u8; SHA1_BLOCK_SIZE as usize]) -> bool {
        self.data == *other
    }
}

impl Sha1Words {
    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src);
    }
}
