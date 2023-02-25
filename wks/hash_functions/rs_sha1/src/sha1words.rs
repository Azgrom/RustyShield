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
            data: [u8::MIN; SHA1_BLOCK_SIZE as usize],
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

impl Index<Range<u8>> for Sha1Words {
    type Output = [u8];

    fn index(&self, range: Range<u8>) -> &Self::Output {
        let range = Range {
            start: range.start as usize,
            end: range.end as usize
        };
        &self.data[range]
    }
}

impl IndexMut<Range<u8>> for Sha1Words {
    fn index_mut(&mut self, range: Range<u8>) -> &mut Self::Output {
        let range = Range {
            start: range.start as usize,
            end: range.end as usize
        };
        &mut self.data[range]
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

impl Index<RangeTo<u8>> for Sha1Words {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<u8>) -> &Self::Output {
        let range_to = RangeTo {
            end: range_to.end as usize
        };
        &self.data[range_to]
    }
}

impl Index<RangeTo<usize>> for Sha1Words {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<usize>) -> &Self::Output {
        &self.data[range_to]
    }
}

impl IndexMut<RangeTo<usize>> for Sha1Words {
    fn index_mut(&mut self, range_to: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range_to]
    }
}

impl PartialEq for Sha1Words {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
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
