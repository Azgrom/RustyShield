use core::ops::RangeFrom;
use core::{
    hash::{Hash, Hasher},
    ops::{Index, IndexMut, Range, RangeTo},
};
use hash_ctx_lib::Hasher32BitsPadding;
use n_bit_words_lib::U32Word;

#[derive(Clone, Debug)]
pub(crate) struct Sha1Padding {
    data: [u8; Self::U8_PADDING_COUNT],
}

impl Default for Sha1Padding {
    fn default() -> Self {
        Self {
            data: [u8::MIN; Self::U8_PADDING_COUNT],
        }
    }
}

impl From<&[u8]> for Sha1Padding {
    fn from(value: &[u8]) -> Self {
        TryFrom::try_from(value).unwrap_or_default()
    }
}

impl From<&Sha1Padding> for [U32Word; 16] {
    fn from(value: &Sha1Padding) -> Self {
        let c = value.data;
        [
            u32::from_be_bytes([c[0], c[1], c[2], c[3]]).into(),
            u32::from_be_bytes([c[4], c[5], c[6], c[7]]).into(),
            u32::from_be_bytes([c[8], c[9], c[10], c[11]]).into(),
            u32::from_be_bytes([c[12], c[13], c[14], c[15]]).into(),
            u32::from_be_bytes([c[16], c[17], c[18], c[19]]).into(),
            u32::from_be_bytes([c[20], c[21], c[22], c[23]]).into(),
            u32::from_be_bytes([c[24], c[25], c[26], c[27]]).into(),
            u32::from_be_bytes([c[28], c[29], c[30], c[31]]).into(),
            u32::from_be_bytes([c[32], c[33], c[34], c[35]]).into(),
            u32::from_be_bytes([c[36], c[37], c[38], c[39]]).into(),
            u32::from_be_bytes([c[40], c[41], c[42], c[43]]).into(),
            u32::from_be_bytes([c[44], c[45], c[46], c[47]]).into(),
            u32::from_be_bytes([c[48], c[49], c[50], c[51]]).into(),
            u32::from_be_bytes([c[52], c[53], c[54], c[55]]).into(),
            u32::from_be_bytes([c[56], c[57], c[58], c[59]]).into(),
            u32::from_be_bytes([c[60], c[61], c[62], c[63]]).into(),
        ]
    }
}

impl Hash for Sha1Padding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state)
    }
}

impl Hasher32BitsPadding for Sha1Padding {
    const U8_PADDING_COUNT: usize = 64;

    fn clone_from_slice(&mut self, src: &[u8]) {
        self.data.clone_from_slice(src);
    }

    fn to_be_word(&self, i: usize) -> U32Word {
        U32Word::from_be_bytes([self[(i * 4)], self[(i * 4) + 1], self[(i * 4) + 2], self[(i * 4) + 3]])
    }
}

impl Index<usize> for Sha1Padding {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl Index<Range<u8>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range: Range<u8>) -> &Self::Output {
        &self.data[range.start as usize..range.end as usize]
    }
}

impl Index<RangeFrom<u8>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range: RangeFrom<u8>) -> &Self::Output {
        &self.data[range.start as usize..]
    }
}

impl IndexMut<Range<u8>> for Sha1Padding {
    fn index_mut(&mut self, range: Range<u8>) -> &mut Self::Output {
        &mut self.data[range.start as usize..range.end as usize]
    }
}

impl IndexMut<RangeFrom<u8>> for Sha1Padding {
    fn index_mut(&mut self, range: RangeFrom<u8>) -> &mut Self::Output {
        &mut self.data[range.start as usize..]
    }
}

impl Index<Range<usize>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.data[range]
    }
}

impl IndexMut<Range<usize>> for Sha1Padding {
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.data[range]
    }
}

impl Index<RangeTo<u8>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<u8>) -> &Self::Output {
        &self.data[..range_to.end as usize]
    }
}

impl Index<RangeTo<usize>> for Sha1Padding {
    type Output = [u8];

    fn index(&self, range_to: RangeTo<usize>) -> &Self::Output {
        &self.data[range_to]
    }
}

impl IndexMut<RangeTo<usize>> for Sha1Padding {
    fn index_mut(&mut self, range_to: RangeTo<usize>) -> &mut Self::Output {
        &mut self.data[range_to]
    }
}

impl PartialEq for Sha1Padding {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl PartialEq<[u8; Self::U8_PADDING_COUNT]> for Sha1Padding {
    fn eq(&self, other: &[u8; Self::U8_PADDING_COUNT]) -> bool {
        self.data == *other
    }
}
