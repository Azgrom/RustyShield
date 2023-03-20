use crate::Sha256State;
use core::hash::{Hash, Hasher};
use hash_ctx_lib::{BlockHasher, HasherContext, HasherWords};

#[derive(Clone, Debug)]
pub struct Sha256Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha256State,
    pub(crate) padding: [u8; Self::U8_PAD_SIZE as usize],
}

impl BlockHasher<u32, u64> for Sha256Hasher {
    const U8_PAD_SIZE: u32 = 64;
    const U8_PAD_LAST_INDEX: u32 = Self::U8_PAD_SIZE - 1;
    const U8_PAD_OFFSET: u32 = 55;
    type State = Sha256State;

    fn add_assign_size(&mut self, len: usize) {
        self.size += len as u64
    }

    fn add_assign_state(&mut self, state: Self::State) {
        self.state += state
    }

    fn clone_pad_range(&mut self, start: usize, end: usize, bytes: &[u8]) {
        self.padding[start..end].clone_from_slice(bytes)
    }

    fn clone_state(&self) -> Self::State {
        self.state.clone()
    }

    fn get_dw(&self) -> HasherWords<u32> {
        HasherWords::<u32>::from(&self.padding)
    }

    fn get_lw(&self) -> usize {
        (self.size & Self::U8_PAD_LAST_INDEX as u64) as usize
    }

    fn get_modulo_pad_size(&self) -> u32 {
        (self.get_size() & Self::U8_PAD_LAST_INDEX as u64) as u32
    }

    fn get_size(&self) -> u64 {
        self.size
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha256State::default(),
            padding: [0u8; Self::U8_PAD_SIZE as usize],
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

    fn write(&mut self, bytes: &[u8]) {
        BlockHasher::write(self, bytes)
    }
}

impl HasherContext<u32, u64> for Sha256Hasher {
    fn finish(&mut self) -> Self::State {
        let zero_padding_length = Self::zeros_pad_length(self);
        let mut offset_pad: [u8; Self::U8_PAD_SIZE as usize] = [0u8; Self::U8_PAD_SIZE as usize];
        offset_pad[0] = 0x80;

        let len = self.size * 8;
        Hasher::write(self, &offset_pad[..zero_padding_length]);
        Hasher::write(self, &len.to_be_bytes());

        self.state.clone()
    }
}
