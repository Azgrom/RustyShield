use crate::{sha1state::Sha1State, sha1words::Sha1Padding, SHA1_BLOCK_SIZE, SHA_CBLOCK_LAST_INDEX, SHA_OFFSET_PAD};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U32Word;

#[derive(Clone, Debug)]
pub struct Sha1Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha1State,
    pub(crate) words: Sha1Padding,
}

impl Sha1Hasher {
    pub(crate) fn zero_padding_length(&self) -> usize {
        1 + (SHA_CBLOCK_LAST_INDEX as u64 & (55u64.wrapping_sub(self.size & SHA_CBLOCK_LAST_INDEX as u64))) as usize
    }

    pub(crate) fn u32_words_from_u8_pad(&self) -> [U32Word; 16] {
        [
            self.words.to_be_u32(0),
            self.words.to_be_u32(1),
            self.words.to_be_u32(2),
            self.words.to_be_u32(3),
            self.words.to_be_u32(4),
            self.words.to_be_u32(5),
            self.words.to_be_u32(6),
            self.words.to_be_u32(7),
            self.words.to_be_u32(8),
            self.words.to_be_u32(9),
            self.words.to_be_u32(10),
            self.words.to_be_u32(11),
            self.words.to_be_u32(12),
            self.words.to_be_u32(13),
            self.words.to_be_u32(14),
            self.words.to_be_u32(15),
        ]
    }

    fn hash_block(&mut self) {
        let mut words = self.u32_words_from_u8_pad();
        let mut state = self.state.clone();

        state.block_00_15(&words);
        state.block_16_31(&mut words);
        state.block_32_47(&mut words);
        state.block_48_63(&mut words);
        state.block_64_79(&mut words);

        self.state += state;
    }

    fn finish_with_len(&mut self, len: u64) -> Sha1State {
        let zero_padding_length = self.zero_padding_length();
        let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
        offset_pad[0] = 0x80;

        self.write(&offset_pad[..zero_padding_length]);
        self.write(&(len * 8).to_be_bytes());

        self.state.clone()
    }
}

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha1State::default(),
            words: Sha1Padding::default(),
        }
    }
}

impl From<Sha1Hasher> for [u8; 20] {
    fn from(value: Sha1Hasher) -> Self {
        Into::<[u8; 20]>::into(value.state)
    }
}

impl Hash for Sha1Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.words.hash(state);
    }
}

impl Hasher for Sha1Hasher {
    fn finish(&self) -> u64 {
        let state = self.clone().finish_with_len(self.size);
        Into::<u64>::into(state.0.0) << 32 | Into::<u64>::into(state.0.1)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let len_w = (self.size & SHA_CBLOCK_LAST_INDEX as u64) as u8;

        self.size += bytes.len() as u64;

        if len_w != 0 {
            let mut left = (SHA1_BLOCK_SIZE - len_w as u32) as u8;
            if bytes.len() < left as usize {
                left = bytes.len() as u8;
            }

            self.words[len_w..len_w + left].clone_from_slice(&bytes[..(left as usize)]);

            if (len_w + left) & SHA_CBLOCK_LAST_INDEX as u8 != 0 {
                return;
            }

            self.hash_block();
            bytes = &bytes[(left as usize)..];
        }

        let mut chunks_exact = bytes.chunks_exact(SHA1_BLOCK_SIZE as usize);
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

impl PartialEq for Sha1Hasher {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.state == other.state && self.words == other.words
    }
}

impl HasherContext for Sha1Hasher {
    type State = Sha1State;

    fn finish(&mut self) -> Self::State {
        self.finish_with_len(self.size)
    }
}
