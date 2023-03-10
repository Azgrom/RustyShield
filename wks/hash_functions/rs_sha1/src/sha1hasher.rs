use core::hash::{Hash, Hasher};
use hash_ctx_lib::{Hasher32BitsPadding, HasherContext, InternalHasherContext};
use crate::{
    sha1padding::Sha1Padding,
    Sha1State
};

#[derive(Clone, Debug)]
pub struct Sha1Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha1State,
    pub(crate) padding: Sha1Padding,
}

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha1State::default(),
            padding: Sha1Padding::default(),
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
        self.padding.hash(state);
    }
}

impl Hasher for Sha1Hasher {
    fn finish(&self) -> u64 {
        let state = HasherContext::finish(&mut self.clone());
        Into::<u64>::into(state.0 .0) << 32 | Into::<u64>::into(state.0 .1)
    }

    fn write(&mut self, mut bytes: &[u8]) {
        let len_w = (self.size & Self::U8_PAD_LAST_INDEX as u64) as u8;
        self.size += bytes.len() as u64;

        if len_w != 0 {
            let left = Self::remaining_pad(len_w, &bytes);

            self.padding[len_w..len_w + left].clone_from_slice(&bytes[..left as usize]);

            if Self::incomplete_padding(len_w, left) {
                return;
            }

            Self::hash_block(&self.padding, &mut self.state);
            bytes = &bytes[left as usize..];
        }

        while bytes.len() >= Self::U8_PADDING_COUNT as usize {
            self.padding.clone_from_slice(&bytes[..Self::U8_PADDING_COUNT]);
            Self::hash_block(&self.padding, &mut self.state);
            bytes = &bytes[Self::U8_PADDING_COUNT..];
        }

        if !bytes.is_empty() {
            self.padding[..bytes.len()].clone_from_slice(bytes);
        }
    }
}

impl HasherContext for Sha1Hasher {
    type State = Sha1State;

    fn finish(&mut self) -> Self::State {
        let zero_padding_length = Self::zeros_pad_length(self.size as usize);
        let mut offset_pad: [u8; Self::U8_PADDING_COUNT as usize] = [0u8; Self::U8_PADDING_COUNT as usize];
        offset_pad[0] = 0x80;

        let len = self.size;
        self.write(&offset_pad[..zero_padding_length]);
        self.write(&(len * 8).to_be_bytes());

        self.state.clone()
    }
}

impl InternalHasherContext for Sha1Hasher {
    const U8_PADDING_COUNT: usize = 64;
    const U8_PAD_LAST_INDEX: usize = 63;
}

impl PartialEq for Sha1Hasher {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.state == other.state && self.padding == other.padding
    }
}
