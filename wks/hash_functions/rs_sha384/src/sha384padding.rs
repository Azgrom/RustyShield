use crate::SHA384_U8_WORDS_COUNT;
use core::{
    hash::{Hash, Hasher},
    ops::{Index, IndexMut, Range, RangeTo},
};
use n_bit_words_lib::U64Word;

#[derive(Clone, Debug)]
pub(crate) struct Sha384Padding {
    data: [u8; SHA384_U8_WORDS_COUNT],
}

impl Sha384Padding {
    pub(crate) fn to_be_u64(&self, i: usize) -> U64Word {
        U64Word::from_be_bytes([
            self[i * 8],
            self[(i * 8) + 1],
            self[(i * 8) + 2],
            self[(i * 8) + 3],
            self[(i * 8) + 4],
            self[(i * 8) + 5],
            self[(i * 8) + 6],
            self[(i * 8) + 7],
        ])
    }

    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src);
    }
}

impl Default for Sha384Padding {
    fn default() -> Self {
        Self {
            data: [u8::MIN; SHA384_U8_WORDS_COUNT],
        }
    }
}

impl Hash for Sha384Padding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Index<usize> for Sha384Padding {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<u8>> for Sha384Padding {
    type Output = [u8];

    fn index(&self, range: Range<u8>) -> &Self::Output {
        let range = Range {
            start: range.start as usize,
            end: range.end as usize,
        };
        &self.data[range]
    }
}

impl Index<Range<usize>> for Sha384Padding {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl Index<RangeTo<usize>> for Sha384Padding {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<usize>) -> &Self::Output {
        &self.data[range_to]
    }
}

impl IndexMut<Range<u8>> for Sha384Padding {
    fn index_mut(&mut self, range: Range<u8>) -> &mut Self::Output {
        let range = Range {
            start: range.start as usize,
            end: range.end as usize,
        };
        &mut self.data[range]
    }
}

impl IndexMut<Range<usize>> for Sha384Padding {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl IndexMut<RangeTo<usize>> for Sha384Padding {
    fn index_mut(&mut self, range_to: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range_to]
    }
}
