use crate::{
    sha256padding::Sha256Padding, sha256state::Sha256State,
    SHA256_PADDING_U8_WORDS_COUNT,
};
use core::hash::{Hash, Hasher};
use hash_ctx_lib::{Hasher32BitsPadding, HasherContext, InternalHasherContext};

const SHA256_SCHEDULE_LAST_INDEX: u8 = 63;

#[derive(Clone, Debug)]
pub struct Sha256Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha256State,
    pub(crate) padding: Sha256Padding,
}

impl InternalHasherContext for Sha256Hasher {
    const U8_PADDING_COUNT: usize = 64;
    const U8_PAD_LAST_INDEX: usize = Self::U8_PADDING_COUNT - 1;
}

// impl Sha256Hasher {
//     pub(crate) fn hash_block(&mut self) {
//         let mut w = self.padding.load_words();
//         let mut state = self.state.clone();
//
//         state.block_00_15(&w);
//         state.block_16_31(&mut w);
//         state.block_32_47(&mut w);
//         state.block_48_63(&mut w);
//
//         self.state += state;
//     }
//
//     fn zeros_pad_length(&self) -> usize {
//         1 + (SHA256_SCHEDULE_LAST_INDEX as u64 & (55u64.wrapping_sub(self.size & SHA256_SCHEDULE_LAST_INDEX as u64)))
//             as usize
//     }
//
//     fn left(len_w: u8, bytes: &&[u8]) -> u8 {
//         let left = SHA256_PADDING_U8_WORDS_COUNT as u8 - len_w;
//         let bytes_len = bytes.len() as u8;
//
//         return if bytes_len < left { bytes_len } else { left };
//     }
//
//     fn finish_with_len(&mut self, len: u64) -> Sha256State {
//         let zero_padding_length = self.zeros_pad_length();
//         let mut offset_pad: [u8; SHA256_PADDING_U8_WORDS_COUNT as usize] =
//             [0u8; SHA256_PADDING_U8_WORDS_COUNT as usize];
//         offset_pad[0] = 0x80;
//
//         self.write(&offset_pad[..zero_padding_length]);
//         self.write(&(len * 8).to_be_bytes());
//
//         self.state.clone()
//     }
//
// }

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha256State::default(),
            padding: Sha256Padding::default(),
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
        self.padding.hash(state);
    }
}

impl Hasher for Sha256Hasher {
    fn finish(&self) -> u64 {
        let state = HasherContext::finish(&mut self.clone());
        Into::<u64>::into(state.0 .0) << 32 | Into::<u64>::into(state.0 .1)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let len_w = (self.size & SHA256_SCHEDULE_LAST_INDEX as u64) as u8;
        self.size += bytes.len() as u64;

        if len_w != 0 {
            let left = Self::remaining_pad(len_w, &bytes);

            self.padding[(len_w as usize)..((len_w + left) as usize)].clone_from_slice(&bytes[..(left as usize)]);

            if Self::incomplete_padding(len_w, left) {
                return;
            }

            Self::hash_block(&self.padding, &mut self.state);
            bytes = &bytes[(left as usize)..];
        }

        while bytes.len() >= SHA256_PADDING_U8_WORDS_COUNT as usize {
            self.padding.clone_from_slice(&bytes[..SHA256_PADDING_U8_WORDS_COUNT]);
            Self::hash_block(&self.padding, &mut self.state);
            bytes = &bytes[SHA256_PADDING_U8_WORDS_COUNT..];
        }

        if !bytes.is_empty() {
            self.padding[..bytes.len()].clone_from_slice(bytes);
        }
    }
}

impl HasherContext for Sha256Hasher {
    type State = Sha256State;

    fn finish(&mut self) -> Self::State {
        let zero_padding_length = Self::zeros_pad_length(self.size as usize);
        let mut offset_pad: [u8; Self::U8_PADDING_COUNT as usize] = [0u8; Self::U8_PADDING_COUNT as usize];
        offset_pad[0] = 0x80;

        let len = self.size * 8;
        self.write(&offset_pad[..zero_padding_length]);
        self.write(&len.to_be_bytes());

        self.state.clone()
    }
}
