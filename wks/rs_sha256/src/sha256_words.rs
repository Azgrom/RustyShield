use crate::SHA256_PADDING_U8_WORDS_COUNT;
use core::{
    hash::{Hash, Hasher},
    ops::{Index, IndexMut, Range, RangeTo},
    slice::Chunks,
};

#[derive(Clone, Debug)]
pub struct Sha256Words {
    data: [u8; SHA256_PADDING_U8_WORDS_COUNT as usize],
}

impl Sha256Words {
    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src);
    }

    pub(crate) fn u32_chunks(&self) -> Chunks<'_, u8> {
        self.data.chunks(4)
    }
}

impl Default for Sha256Words {
    fn default() -> Self {
        Self {
            data: [u8::MIN; SHA256_PADDING_U8_WORDS_COUNT as usize],
        }
    }
}

impl Hash for Sha256Words {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Index<usize> for Sha256Words {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<usize>> for Sha256Words {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<Range<usize>> for Sha256Words {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl Index<RangeTo<usize>> for Sha256Words {
    type Output = [u8];

    fn index(&self, range: RangeTo<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<RangeTo<usize>> for Sha256Words {
    fn index_mut(&mut self, range: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}
