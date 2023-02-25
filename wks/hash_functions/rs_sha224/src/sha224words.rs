use core::{
    hash::Hash,
    ops::{Index, IndexMut, Range, RangeTo},
    slice::Chunks
};
use core::hash::Hasher;
use crate::SHA224_PADDING_U8_WORDS_COUNT;

#[derive(Clone)]
pub(crate) struct Sha224Words {
    data: [u8; SHA224_PADDING_U8_WORDS_COUNT as usize]
}

impl Sha224Words {
    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src)
    }

    pub(crate) fn u32_chunks(&self) -> Chunks<'_, u8> {
        self.data.chunks(4)
    }
}

impl Default for Sha224Words {
    fn default() -> Self {
        Self {
            data: [u8::MIN; SHA224_PADDING_U8_WORDS_COUNT as usize]
        }
    }
}

impl Hash for Sha224Words {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Index<usize> for Sha224Words {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<usize>> for Sha224Words {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl Index<RangeTo<usize>> for Sha224Words {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<usize>) -> &Self::Output {
        &self.data[range_to]
    }
}

impl IndexMut<Range<usize>> for Sha224Words {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl IndexMut<RangeTo<usize>> for Sha224Words {
    fn index_mut(&mut self, range_to: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range_to]
    }
}
