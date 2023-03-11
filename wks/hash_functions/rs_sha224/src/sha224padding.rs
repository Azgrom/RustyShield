use core::hash::Hasher;
use core::{
    hash::Hash,
    ops::{Index, IndexMut, Range, RangeTo},
};
use hash_ctx_lib::HasherWords;

const U8_PADDING_COUNT: usize = 64;
#[derive(Clone)]
pub(crate) struct Sha224Padding {
    data: [u8; U8_PADDING_COUNT],
}

impl Sha224Padding {
    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src)
    }
}

impl Default for Sha224Padding {
    fn default() -> Self {
        Self {
            data: [u8::MIN; U8_PADDING_COUNT],
        }
    }
}

impl From<&Sha224Padding> for HasherWords<u32> {
    fn from(value: &Sha224Padding) -> Self {
        HasherWords::from(value.data)
    }
}

impl Hash for Sha224Padding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Index<usize> for Sha224Padding {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<usize>> for Sha224Padding {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl Index<RangeTo<usize>> for Sha224Padding {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<usize>) -> &Self::Output {
        &self.data[range_to]
    }
}

impl IndexMut<Range<usize>> for Sha224Padding {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl IndexMut<RangeTo<usize>> for Sha224Padding {
    fn index_mut(&mut self, range_to: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range_to]
    }
}
