use crate::{
    sha256state::Sha256State, sha256words::Sha256Words, SHA256_PADDING_U32_WORDS_COUNT, SHA256_PADDING_U8_WORDS_COUNT,
};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U32Word;

const SHA256_SCHEDULE_LAST_INDEX: u8 = 63;

#[derive(Clone, Debug)]
pub struct Sha256Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha256State,
    pub(crate) words: Sha256Words,
}

impl Sha256Hasher {
    fn load_words(&self) -> [U32Word; SHA256_PADDING_U32_WORDS_COUNT as usize] {
        let mut w: [U32Word; SHA256_PADDING_U32_WORDS_COUNT as usize] =
            [U32Word::default(); SHA256_PADDING_U32_WORDS_COUNT as usize];

        for (w, c) in w.iter_mut().zip(self.words.u32_chunks()) {
            *w = u32::from_be_bytes([c[0], c[1], c[2], c[3]]).into();
        }

        w
    }

    pub(crate) fn hash_block(&mut self) {
        let mut w = self.load_words();
        let mut state = self.state.clone();

        state.block_00_15(&w);
        state.block_16_31(&mut w);
        state.block_32_47(&mut w);
        state.block_48_63(&mut w);

        self.state += state;
    }

    fn zero_padding_length(&self) -> usize {
        1 + (SHA256_SCHEDULE_LAST_INDEX as u64 & (55u64.wrapping_sub(self.size & SHA256_SCHEDULE_LAST_INDEX as u64)))
            as usize
    }

    fn finish_with_len(&mut self, len: u64) -> Sha256State {
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA256_PADDING_U8_WORDS_COUNT as usize] =
            [0u8; SHA256_PADDING_U8_WORDS_COUNT as usize];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_length]);
        self.write(&(len * 8).to_be_bytes());

        self.state.clone()
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha256State::default(),
            words: Sha256Words::default(),
        }
    }
}

impl From<Sha256Hasher> for [u8; 32] {
    fn from(value: Sha256Hasher) -> Self {
        Into::<[u8; 32]>::into(value.state)
    }
}

impl Hash for Sha256Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha256Hasher {
    fn finish(&self) -> u64 {
        let state = self.clone().finish_with_len(self.size);
        Into::<u64>::into(state.0.0) << 32 | Into::<u64>::into(state.0.1)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let len_w = (self.size & SHA256_SCHEDULE_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = SHA256_PADDING_U8_WORDS_COUNT - len_w;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[(len_w as usize)..((len_w + left) as usize)].clone_from_slice(&bytes[..(left as usize)]);

            if (len_w + left) & SHA256_SCHEDULE_LAST_INDEX != 0 {
                return;
            }

            self.hash_block();
            bytes = &bytes[(left as usize)..];
        }

        let mut chunks_exact = bytes.chunks_exact(SHA256_PADDING_U8_WORDS_COUNT as usize);
        while let Some(schedule_chunk) = chunks_exact.next() {
            self.words.clone_from_slice(schedule_chunk);
            self.hash_block();
        }

        let schedule_remainder = chunks_exact.remainder();
        if !schedule_remainder.is_empty() {
            self.words[..schedule_remainder.len()].clone_from_slice(schedule_remainder);
        }
    }
}

impl HasherContext for Sha256Hasher {
    type State = Sha256State;

    fn finish(&mut self) -> Self::State {
        self.finish_with_len(self.size)
    }
}
