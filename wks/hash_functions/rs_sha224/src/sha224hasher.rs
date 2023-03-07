use crate::{
    sha224state::Sha224State, sha224words::Sha224Words, SHA224_PADDING_U8_WORDS_COUNT, SHA224_SCHEDULE_U32_WORDS_COUNT,
};
pub use core::fmt::{Formatter, LowerHex, UpperHex};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U32Word;

const SHA224_SCHEDULE_LAST_INDEX: u32 = SHA224_SCHEDULE_U32_WORDS_COUNT - 1;

#[derive(Clone)]
pub struct Sha224Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha224State,
    pub(crate) words: Sha224Words,
}

impl Sha224Hasher {
    pub(crate) fn hash_block(&mut self) {
        let mut w = self.load_words();
        let mut state = self.state.clone();

        state.block_00_15(&w);
        state.block_16_31(&mut w);
        state.block_32_47(&mut w);
        state.block_48_63(&mut w);

        self.state += state;
    }

    fn load_words(&self) -> [U32Word; 16] {
        let mut w: [U32Word; 16] = [U32Word::default(); 16];

        for (w, c) in w.iter_mut().zip(self.words.u32_chunks()) {
            *w = u32::from_be_bytes([c[0], c[1], c[2], c[3]]).into()
        }

        w
    }

    fn zero_padding_length(&self) -> usize {
        1 + (SHA224_SCHEDULE_LAST_INDEX as u64 & (55u64.wrapping_sub(self.size & SHA224_SCHEDULE_LAST_INDEX as u64)))
            as usize
    }

    fn finish_with_len(&mut self, len: u64) -> Sha224State {
        let pad_len: [u8; 8] = (len * 8).to_be_bytes();
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA224_SCHEDULE_U32_WORDS_COUNT as usize] =
            [0u8; SHA224_SCHEDULE_U32_WORDS_COUNT as usize];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_length]);
        self.write(&pad_len);

        self.state.clone()
    }
}

impl Default for Sha224Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha224State::default(),
            words: Sha224Words::default(),
        }
    }
}

impl From<Sha224Hasher> for [u8; 28] {
    fn from(value: Sha224Hasher) -> Self {
        Into::<[u8; 28]>::into(value.state)
    }
}

impl Hash for Sha224Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha224Hasher {
    fn finish(&self) -> u64 {
        let state = self.clone().finish_with_len(self.size);
        Into::<u64>::into(state.0.0) << 32 | Into::<u64>::into(state.0.1)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let len_w = (self.size & SHA224_SCHEDULE_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = (SHA224_PADDING_U8_WORDS_COUNT - len_w as u32) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[(len_w as usize)..((len_w + left) as usize)].clone_from_slice(&bytes[..(left as usize)]);

            if (len_w + left) & SHA224_SCHEDULE_LAST_INDEX as u8 != 0 {
                return;
            }

            self.hash_block();
            bytes = &bytes[(left as usize)..];
        }

        let mut chunks_exact = bytes.chunks_exact(SHA224_PADDING_U8_WORDS_COUNT as usize);
        for schedule_chunk in chunks_exact.by_ref() {
            self.words.clone_from_slice(schedule_chunk);
            self.hash_block();
        }

        let schedule_remainder = chunks_exact.remainder();
        if !schedule_remainder.is_empty() {
            self.words[..schedule_remainder.len()].clone_from_slice(schedule_remainder);
        }
    }
}

impl HasherContext for Sha224Hasher {
    type State = Sha224State;

    fn finish(&mut self) -> Self::State {
        self.finish_with_len(self.size)
    }
}
