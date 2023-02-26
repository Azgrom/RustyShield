use crate::SHA384BLOCK_SIZE;
use core::{
    ops::{Index, IndexMut, Range, RangeTo},
    hash::{Hash, Hasher},
    slice::Chunks
};

#[derive(Clone, Debug)]
pub(crate) struct Sha384Words {
    data: [u8; SHA384BLOCK_SIZE]
}

impl Sha384Words {
    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src);
    }

    pub(crate) fn u64_chunks(&self) -> Chunks<'_, u8> {
        self.data.chunks(8)
    }
}

impl Default for Sha384Words {
    fn default() -> Self {
        Self {
            data: [u8::MIN; SHA384BLOCK_SIZE]
        }
    }
}

impl Hash for Sha384Words {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Index<usize> for Sha384Words {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<u8>> for Sha384Words {
    type Output = [u8];

    fn index(&self, range: Range<u8>) -> &Self::Output {
        let range = Range {
            start: range.start as usize,
            end: range.end as usize
        };
        &self.data[range]
    }
}

impl Index<Range<usize>> for Sha384Words {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl Index<RangeTo<usize>> for Sha384Words {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<usize>) -> &Self::Output {
        &self.data[range_to]
    }
}

impl IndexMut<Range<u8>> for Sha384Words {
    fn index_mut(&mut self, range: Range<u8>) -> &mut Self::Output {
        let range = Range {
            start: range.start as usize,
            end: range.end as usize
        };
        &mut self.data[range]
    }
}

impl IndexMut<Range<usize>> for Sha384Words {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl IndexMut<RangeTo<usize>> for Sha384Words {
    fn index_mut(&mut self, range_to: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range_to]
    }
}
