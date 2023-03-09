use crate::{sha384padding::Sha384Padding, sha384state::Sha384State, SHA384_HEX_HASH_SIZE, SHA384_U8_WORDS_COUNT};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::HasherContext;
use n_bit_words_lib::U64Word;

const SHA384BLOCK_LAST_INDEX: usize = SHA384_U8_WORDS_COUNT - 1;

#[derive(Clone)]
pub struct Sha384Hasher {
    pub(crate) size: u128,
    pub(crate) state: Sha384State,
    pub(crate) padding: Sha384Padding,
}

impl Sha384Hasher {
    fn hash_block(&mut self) {
        let mut words = self.load_words();
        let mut state = self.state.clone();

        state.block_00_15(&words);
        state.block_16_31(&mut words);
        state.block_32_47(&mut words);
        state.block_48_63(&mut words);
        state.block_64_79(&mut words);

        self.state += state;
    }

    fn load_words(&self) -> [U64Word; 16] {
        [
            self.padding.to_be_u64(0),
            self.padding.to_be_u64(1),
            self.padding.to_be_u64(2),
            self.padding.to_be_u64(3),
            self.padding.to_be_u64(4),
            self.padding.to_be_u64(5),
            self.padding.to_be_u64(6),
            self.padding.to_be_u64(7),
            self.padding.to_be_u64(8),
            self.padding.to_be_u64(9),
            self.padding.to_be_u64(10),
            self.padding.to_be_u64(11),
            self.padding.to_be_u64(12),
            self.padding.to_be_u64(13),
            self.padding.to_be_u64(14),
            self.padding.to_be_u64(15),
        ]
    }

    fn zero_padding_length(&self) -> usize {
        1 + (SHA384BLOCK_LAST_INDEX & (111usize.wrapping_sub((self.size & SHA384BLOCK_LAST_INDEX as u128) as usize)))
    }

    fn get_len_w(&self) -> u8 {
        (self.size & SHA384BLOCK_LAST_INDEX as u128) as u8
    }

    fn incomplete_padding(len_w: u8, left: u8) -> bool {
        (len_w + left) & SHA384BLOCK_LAST_INDEX as u8 != 0
    }

    fn left(bytes: &&[u8], len_w: u8) -> u8 {
        let left = SHA384_U8_WORDS_COUNT as u8 - len_w;
        let bytes_len = bytes.len() as u8;

        return if bytes_len < left { bytes_len } else { left };
    }
}

impl Default for Sha384Hasher {
    fn default() -> Self {
        Self {
            size: u128::MIN,
            state: Sha384State::default(),
            padding: Sha384Padding::default(),
        }
    }
}

impl From<Sha384Hasher> for [u8; SHA384_HEX_HASH_SIZE as usize] {
    fn from(value: Sha384Hasher) -> Self {
        Into::<[u8; SHA384_HEX_HASH_SIZE as usize]>::into(value.state)
    }
}

impl Hash for Sha384Hasher {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.state.hash(state);
        self.padding.hash(state);
    }
}

impl Hasher for Sha384Hasher {
    fn finish(&self) -> u64 {
        let state = HasherContext::finish(&mut self.clone());
        Into::<u64>::into(state.0 .0) << 32 | Into::<u64>::into(state.0 .1)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let len_w = self.get_len_w();
        self.size += bytes.len() as u128;

        if len_w != 0 {
            let left = Self::left(&bytes, len_w);

            self.padding[len_w..(len_w + left)].clone_from_slice(&bytes[..left as usize]);

            if Self::incomplete_padding(len_w, left) {
                return;
            }

            self.hash_block();
            bytes = &bytes[left as usize..];
        }

        while bytes.len() >= SHA384_U8_WORDS_COUNT as usize {
            self.padding.clone_from_slice(&bytes[..SHA384_U8_WORDS_COUNT]);
            self.hash_block();
            bytes = &bytes[SHA384_U8_WORDS_COUNT..];
        }

        if !bytes.is_empty() {
            self.padding[..bytes.len()].clone_from_slice(bytes);
        }
    }
}

impl HasherContext for Sha384Hasher {
    type State = Sha384State;

    fn finish(&mut self) -> Self::State {
        let zero_padding_len = self.zero_padding_length();
        let mut offset_pad = [0u8; SHA384_U8_WORDS_COUNT as usize];
        offset_pad[0] = 0x80;

        let len = self.size * 8;
        self.write(&offset_pad[..zero_padding_len]);
        self.write(&len.to_be_bytes());

        self.state.clone()
    }
}
