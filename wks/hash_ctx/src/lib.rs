#![no_std]

pub use core::hash::Hasher;
pub use crate::hasher_stating::GenericStateHasher;
pub use crate::hasher_words::HasherWords;

mod hasher_stating;
mod hasher_words;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext: Hasher {
    type State;

    fn finish(&mut self) -> Self::State;
}

pub trait BlockHasher<T>: Hasher + HasherContext {
    const U8_PADDING_COUNT: usize;
    const U8_PAD_LAST_INDEX: usize;

    fn hash_block(mut words: HasherWords<T>, st: &mut impl GenericStateHasher<T>){
        let mut state = st.clone();

        state.block_00_15(&words);
        state.block_16_31(&mut words);
        state.block_32_47(&mut words);
        state.block_48_63(&mut words);
        state.block_64_79(&mut words);

        *st += state;
    }

    fn incomplete_padding(len_w: u8, left: u8) -> bool {
        (len_w + left) & Self::U8_PAD_LAST_INDEX as u8 != 0
    }

    fn remaining_pad(lw: u8, bytes: &&[u8]) -> u8 {
        let left = Self::U8_PADDING_COUNT as u8 - lw;
        let bytes_len = bytes.len() as u8;

        if bytes_len < left { bytes_len } else { left }
    }

    fn zeros_pad_length(size: usize) -> usize;
}
