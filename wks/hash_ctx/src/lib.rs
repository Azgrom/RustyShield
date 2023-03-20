#![no_std]

pub use crate::hasher_stating::GenericStateHasher;
pub use crate::hasher_words::HasherWords;
pub use core::hash::Hasher;
use core::ops::BitAnd;

mod hasher_stating;
mod hasher_words;

/// Overloads the finish Hasher method for a version that mutates itself
pub trait HasherContext<T, S>: BlockHasher<T, S> + Hasher
where S: BitAnd + From<u32> + From<u64>
{
    fn finish(&mut self) -> Self::State;
}

pub trait BlockHasher<T, S>: Hasher
where S: BitAnd + From<u32> + From<u64>,
{
    const U8_PAD_SIZE: u32;
    const U8_PAD_LAST_INDEX: u32;
    const U8_PAD_OFFSET: u32;
    type State;

    fn hash_block(&mut self)
    where
        Self::State: GenericStateHasher<T>,
    {
        let mut state = self.clone_state();
        let mut words = self.get_dw();

        state.block_00_15(&words);
        state.block_16_31(&mut words);
        state.block_32_47(&mut words);
        state.block_48_63(&mut words);
        state.block_64_79(&mut words);

        self.add_assign_state(state);
    }

    fn incomplete_padding(len_w: usize, left: usize) -> bool {
        (len_w + left) & Self::U8_PAD_LAST_INDEX as usize != 0
    }

    fn remaining_pad(lw: usize, bytes: &&[u8]) -> usize {
        let left = Self::U8_PAD_SIZE as usize - lw;
        let bytes_len = bytes.len();

        if bytes_len < left {
            bytes_len
        } else {
            left
        }
    }

    fn write(&mut self, mut bytes: &[u8])
    where
        Self::State: GenericStateHasher<T>,
    {
        let len_w = self.get_lw();
        self.add_assign_size(bytes.len());

        if len_w != 0 {
            let left = Self::remaining_pad(len_w, &bytes);
            self.clone_pad_range(len_w, len_w + left, &bytes[..left]);

            if Self::incomplete_padding(len_w, left) {
                return;
            }

            self.hash_block();
            bytes = &bytes[left..];
        }

        let pad_size = Self::U8_PAD_SIZE as usize;
        while bytes.len() >= pad_size {
            self.clone_pad_range(0, pad_size, &bytes[..pad_size]);
            self.hash_block();
            bytes = &bytes[pad_size..];
        }

        if !bytes.is_empty() {
            self.clone_pad_range(0, bytes.len(), bytes);
        }
    }

    fn zeros_pad_length(&self) -> usize
    {
        1
            + (Self::U8_PAD_LAST_INDEX
            & (Self::U8_PAD_OFFSET
                .wrapping_sub(self.get_modulo_pad_size()))) as usize
    }

    fn add_assign_size(&mut self, len: usize);

    fn add_assign_state(&mut self, state: Self::State);

    fn clone_pad_range(&mut self, start: usize, end: usize, bytes: &[u8]);

    fn clone_state(&self) -> Self::State;

    fn get_dw(&self) -> HasherWords<T>;

    fn get_lw(&self) -> usize;

    fn get_modulo_pad_size(&self) -> u32;

    fn get_size(&self) -> S;
}
