use crate::{
    sha256state::Sha256State, sha256words::Sha256Words, SHA256_PADDING_U32_WORDS_COUNT, SHA256_PADDING_U8_WORDS_COUNT,
};
use core::{
    hash::{Hash, Hasher},
};
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

    fn finish_with_len(&mut self, len: u64) -> u64 {
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA256_PADDING_U8_WORDS_COUNT as usize] =
            [0u8; SHA256_PADDING_U8_WORDS_COUNT as usize];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_length]);
        self.write(&(len * 8).to_be_bytes());

        Into::<u64>::into(self.state.0) << 32 | Into::<u64>::into(self.state.1)
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
        self.clone().finish_with_len(self.size)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let mut len_w = (self.size & SHA256_SCHEDULE_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = SHA256_PADDING_U8_WORDS_COUNT - len_w;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[(len_w as usize)..((len_w + left) as usize)].clone_from_slice(&bytes[..(left as usize)]);

            len_w = (len_w + left) & SHA256_SCHEDULE_LAST_INDEX;

            if len_w != 0 {
                return;
            }

            self.hash_block();
            bytes = &bytes[(left as usize)..];
        }

        while bytes.len() >= SHA256_PADDING_U8_WORDS_COUNT as usize {
            self.words
                .clone_from_slice(&bytes[..(SHA256_PADDING_U8_WORDS_COUNT as usize)]);
            self.hash_block();
            bytes = &bytes[(SHA256_PADDING_U8_WORDS_COUNT as usize)..];
        }

        if !bytes.is_empty() {
            self.words[..bytes.len()].clone_from_slice(bytes)
        }
    }
}

impl HasherContext for Sha256Hasher {
    type State = Sha256State;

    fn finish(&mut self) -> Self::State {
        self.finish_with_len(self.size);
        self.state.clone()
    }
}
