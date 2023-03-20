use crate::Sha1State;
use core::hash::{Hash, Hasher};
use hash_ctx_lib::{BlockHasher, HasherContext, HasherWords};

#[derive(Clone, Debug)]
pub struct Sha1Hasher {
    pub(crate) size: u64,
    pub(crate) state: Sha1State,
    pub(crate) padding: [u8; Self::U8_PAD_SIZE as usize],
}

impl BlockHasher<u32, u64> for Sha1Hasher {
    const U8_PAD_SIZE: u32 = 64;
    const U8_PAD_LAST_INDEX: u32 = Self::U8_PAD_SIZE - 1;
    const U8_PAD_OFFSET: u32 = 55;
    type State = Sha1State;

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

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self {
            size: u64::MIN,
            state: Sha1State::default(),
            padding: [0u8; Self::U8_PAD_SIZE as usize],
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

    fn write(&mut self, bytes: &[u8]) {
        BlockHasher::write(self, bytes)
    }
}

// impl Sha1Hasher {
//     fn write(&mut self, mut bytes: &[u8]) {
//         let mut left = self.size;
//
//         if left > 0 {
//             left = Self::remaining_pad(left as usize, &bytes) as u64;
//
//             self.write(bytes[..left]);
//         }
//
//         left = (bytes.len() % Self::U8_PAD_SIZE) as u64;
//
//         if bytes.len().saturating_sub(left as usize) > 0 {
//
//         }
//
//         if left > 0 {
//             self.write(bytes[..left])
//         }
//     }
// }

impl HasherContext<u32, u64> for Sha1Hasher {
    fn finish(&mut self) -> Self::State {
        let zero_padding_length = self.zeros_pad_length();
        let mut offset_pad: [u8; Self::U8_PAD_SIZE as usize] = [0u8; Self::U8_PAD_SIZE as usize];
        offset_pad[0] = 0x80;

        let len = self.size;
        Hasher::write(self, &offset_pad[..zero_padding_length]);
        Hasher::write(self, &(len * 8).to_be_bytes());

        self.state.clone()
    }
}

impl PartialEq for Sha1Hasher {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.state == other.state && self.padding == other.padding
    }
}
