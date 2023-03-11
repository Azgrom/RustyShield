use crate::SHA384_U8_WORDS_COUNT;
use core::{
    hash::{Hash, Hasher},
    ops::{Index, IndexMut, Range, RangeTo},
};
use hash_ctx_lib::HasherWords;

const U8_PADDING_COUNT: usize = 128;
#[derive(Clone, Debug)]
pub(crate) struct Sha384Padding {
    data: [u8; U8_PADDING_COUNT],
}

impl Sha384Padding {
    pub(crate) fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src)
    }
}

impl Default for Sha384Padding {
    fn default() -> Self {
        Self {
            data: [u8::MIN; SHA384_U8_WORDS_COUNT],
        }
    }
}

impl From<[u8; U8_PADDING_COUNT]> for Sha384Padding {
    fn from(value: [u8; U8_PADDING_COUNT]) -> Self {
        Self { data: value }
    }
}

impl From<&Sha384Padding> for HasherWords<u64> {
    fn from(value: &Sha384Padding) -> Self {
        HasherWords::from(value.data)
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
