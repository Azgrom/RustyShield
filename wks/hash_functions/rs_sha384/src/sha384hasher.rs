use crate::{
    sha384state::Sha384State, sha384words::Sha384Words, SHA384BLOCK_SIZE, SHA384PADDING_SIZE,
};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U64Word;

const SHA384MESSAGE_BLOCK_SCHEDULE_SIZE: usize = 16;
const SHA384BLOCK_LAST_INDEX: usize = 127;

#[derive(Clone)]
pub struct Sha384Hasher {
    pub(crate) size: u128,
    pub(crate) state: Sha384State,
    pub(crate) words: Sha384Words,
}

impl Sha384Hasher {
    fn load_words(&self) -> [U64Word; SHA384MESSAGE_BLOCK_SCHEDULE_SIZE] {
        let mut w: [U64Word; SHA384MESSAGE_BLOCK_SCHEDULE_SIZE] =
            [U64Word::default(); SHA384MESSAGE_BLOCK_SCHEDULE_SIZE];

        for (w, c) in w.iter_mut().zip(self.words.u64_chunks()) {
            *w = u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]).into();
        }

        w
    }

    fn hash_block(&mut self) {
        let mut w = self.load_words();
        let mut state = self.state.clone();

        state.block_00_15(&w);
        state.block_16_31(&mut w);
        state.block_32_47(&mut w);
        state.block_48_63(&mut w);
        state.block_64_79(&mut w);

        self.state += state;
    }

    fn zero_padding_length(&self) -> usize {
        1 + (SHA384BLOCK_LAST_INDEX
            & (111usize.wrapping_sub((self.size & SHA384BLOCK_LAST_INDEX as u128) as usize)))
    }

    fn finish_with_len(&mut self, len: u128) -> Sha384State {
        let zero_padding_len = self.zero_padding_length();
        let mut offset_pad = [0u8; SHA384BLOCK_SIZE as usize];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_len]);
        self.write(&(len * 8).to_be_bytes());

        self.state.clone()
    }
}

impl Default for Sha384Hasher {
    fn default() -> Self {
        Self {
            size: u128::MIN,
            state: Sha384State::default(),
            words: Sha384Words::default(),
        }
    }
}

impl From<Sha384Hasher> for [u8; SHA384PADDING_SIZE as usize] {
    fn from(value: Sha384Hasher) -> Self {
        Into::<[u8; SHA384PADDING_SIZE as usize]>::into(value.state)
    }
}

impl Hash for Sha384Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha384Hasher {
    fn finish(&self) -> u64 {
        let state = self.clone().finish_with_len(self.size);
        Into::<u64>::into(state.0 .0) << 32 | Into::<u64>::into(state.0 .1)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let len_w = (self.size & SHA384BLOCK_LAST_INDEX as u128) as u8;
        self.size += bytes.len() as u128;

        if len_w != 0 {
            let mut left = SHA384BLOCK_SIZE - len_w;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[len_w..(len_w + left)].clone_from_slice(&bytes[..left as usize]);

            if (len_w + left) & SHA384BLOCK_LAST_INDEX as u8 != 0 {
                return;
            }

            self.hash_block();
            bytes = &bytes[(left as usize)..];
        }

        let mut chunks_exact = bytes.chunks_exact(SHA384BLOCK_SIZE as usize);
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

impl HasherContext for Sha384Hasher {
    type State = Sha384State;

    fn finish(&mut self) -> Self::State {
        self.finish_with_len(self.size)
    }
}
