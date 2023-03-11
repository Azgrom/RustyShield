#![no_std]

use core::fmt::{LowerHex, UpperHex};
use core::hash::{BuildHasher, Hash, Hasher};
use core::ops::{AddAssign, Index, IndexMut, Range, RangeTo};
use n_bit_words_lib::NBitWord;

type U32Word = NBitWord<u32>;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext: Hasher {
    type State;

    fn finish(&mut self) -> Self::State;
}

pub trait Hasher32BitsPadding:
    Clone
    + Default
    + Hash
    + Index<usize>
    + Index<Range<usize>>
    + Index<RangeTo<usize>>
    + IndexMut<Range<usize>>
    + IndexMut<RangeTo<usize>>
{
    const U8_PADDING_COUNT: usize;

    fn clone_from_slice(&mut self, src: &[u8]);
    fn load_words(&self) -> [U32Word; 16] {
        [
            self.to_be_word(0),
            self.to_be_word(1),
            self.to_be_word(2),
            self.to_be_word(3),
            self.to_be_word(4),
            self.to_be_word(5),
            self.to_be_word(6),
            self.to_be_word(7),
            self.to_be_word(8),
            self.to_be_word(9),
            self.to_be_word(10),
            self.to_be_word(11),
            self.to_be_word(12),
            self.to_be_word(13),
            self.to_be_word(14),
            self.to_be_word(15),
        ]
    }
    fn to_be_word(&self, i: usize) -> U32Word;
}

pub trait Hasher32BitState: AddAssign + BuildHasher + Clone + Default + Hash + LowerHex + UpperHex {
    fn block_00_15(&mut self, w: &[U32Word; 16]);
    fn block_16_31(&mut self, w: &mut [U32Word; 16]);
    fn block_32_47(&mut self, w: &mut [U32Word; 16]);
    fn block_48_63(&mut self, w: &mut [U32Word; 16]);
    fn block_64_79(&mut self, w: &mut [U32Word; 16]);
}

pub trait InternalHasherContext: Hasher + HasherContext {
    const U8_PADDING_COUNT: usize;
    const U8_PAD_LAST_INDEX: usize;

    fn hash_block(pad: &impl Hasher32BitsPadding, src: &mut impl Hasher32BitState) {
        let mut w = pad.load_words();
        let mut state = src.clone();

        state.block_00_15(&w);
        state.block_16_31(&mut w);
        state.block_32_47(&mut w);
        state.block_48_63(&mut w);
        state.block_64_79(&mut w);

        *src += state;
    }

    fn incomplete_padding(len_w: u8, left: u8) -> bool {
        (len_w + left) & Self::U8_PAD_LAST_INDEX as u8 != 0
    }

    fn remaining_pad(lw: u8, bytes: &&[u8]) -> u8 {
        let left = Self::U8_PADDING_COUNT as u8 - lw;
        let bytes_len = bytes.len() as u8;

        if bytes_len < left { bytes_len } else { left }
    }

    fn zeros_pad_length(size: usize) -> usize {
        1 + (Self::U8_PAD_LAST_INDEX & (55usize.wrapping_sub(size & Self::U8_PAD_LAST_INDEX)))
    }
}
