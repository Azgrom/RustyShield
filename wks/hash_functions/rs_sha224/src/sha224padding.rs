use core::hash::Hasher;
use core::{
    hash::Hash,
    ops::{Index, IndexMut, Range, RangeTo},
};
use hash_ctx_lib::Hasher32BitsPadding;
use n_bit_words_lib::NBitWord;

type U32Word = NBitWord<u32>;

#[derive(Clone)]
pub(crate) struct Sha224Padding {
    data: [u8; Self::U8_PADDING_COUNT],
}

impl Default for Sha224Padding {
    fn default() -> Self {
        Self {
            data: [u8::MIN; Self::U8_PADDING_COUNT],
        }
    }
}

impl Hash for Sha224Padding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Hasher32BitsPadding for Sha224Padding {
    const U8_PADDING_COUNT: usize = 64;

    fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src)
    }

    fn to_be_word(&self, i: usize) -> U32Word {
        u32::from_be_bytes([self[(i * 4)], self[(i * 4) + 1], self[(i * 4) + 2], self[(i * 4) + 3]]).into()
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
